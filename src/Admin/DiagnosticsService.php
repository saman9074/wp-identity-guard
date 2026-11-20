<?php
/**
 * Safe environment, database, cryptography, provider, and security readiness diagnostics.
 *
 * @package WPIG\Admin
 */

declare(strict_types=1);

namespace WPIG\Admin;

use wpdb;
use WPIG\Core\EnvironmentChecker;
use WPIG\Security\AuthorizationService;
use WPIG\Security\Capabilities;
use WPIG\Security\CryptoException;
use WPIG\Security\WordPressKeyProvider;
use WPIG\Storage\SchemaDefinition;
use WPIG\Storage\SchemaMigrator;

/**
 * Computes non-sensitive operational diagnostics and readiness states for the admin UI (Tasks 4, 6 & 7).
 *
 * Security Invariants:
 * - Never exposes encryption keys, HMAC keys, authority secrets, provider tokens, SQL queries, or stack traces.
 * - Requires at least `view_wpig_reports` or `manage_wpig_settings` capability before returning diagnostics to an actor.
 * - Distinguishes disposable local HTTP development from production HTTPS requirements, and never marks HTTP
 *   as production-ready for sensitive operations (`ReadinessStatus::BLOCKED`).
 * - Reports `API.ir` and `Zohal` truthfully as `ReadinessStatus::NOT_IMPLEMENTED` with zero live network calls.
 * - Never reports overall plugin readiness as `READY` for production identity verification in P01-D2.
 */
final class DiagnosticsService {

	/**
	 * Minimum supported WooCommerce version when WooCommerce is installed.
	 */
	public const MIN_WC_VERSION = '10.8';

	/**
	 * Option name indicating maintenance mode during key rotation or migration.
	 */
	public const MAINTENANCE_OPTION = 'wpig_maintenance_mode';

	/**
	 * Authorization service.
	 *
	 * @var AuthorizationService
	 */
	private AuthorizationService $authorizer;

	/**
	 * Cryptographic key provider.
	 *
	 * @var WordPressKeyProvider
	 */
	private WordPressKeyProvider $key_provider;

	/**
	 * Settings repository.
	 *
	 * @var SettingsRepository
	 */
	private SettingsRepository $settings_repository;

	/**
	 * Optional wpdb instance.
	 *
	 * @var wpdb|null
	 */
	private ?wpdb $wpdb;

	/**
	 * Runtime environment overrides for deterministic unit testing.
	 *
	 * @var array{
	 *   php_version?: string,
	 *   wp_version?: string,
	 *   wc_version?: string|null,
	 *   sodium_loaded?: bool,
	 *   is_https?: bool,
	 *   site_host?: string,
	 *   maintenance_mode?: bool,
	 *   capabilities_registered?: bool,
	 *   db_connected?: bool,
	 *   installed_schema_version?: string,
	 *   schema_verified?: bool,
	 *   table_statuses?: array<string,bool>
	 * }
	 */
	private array $runtime_overrides;

	/**
	 * Constructor.
	 *
	 * @param AuthorizationService|null $authorizer          Optional authorization service.
	 * @param WordPressKeyProvider|null $key_provider        Optional key provider.
	 * @param SettingsRepository|null   $settings_repository Optional settings repository.
	 * @param wpdb|null                 $custom_wpdb         Optional wpdb override.
	 * @param array<string,mixed>       $runtime_overrides   Optional environment/database overrides for unit tests.
	 */
	public function __construct(
		?AuthorizationService $authorizer = null,
		?WordPressKeyProvider $key_provider = null,
		?SettingsRepository $settings_repository = null,
		?wpdb $custom_wpdb = null,
		array $runtime_overrides = array()
	) {
		$this->authorizer          = $authorizer ?? new AuthorizationService();
		$this->key_provider        = $key_provider ?? new WordPressKeyProvider();
		$this->settings_repository = $settings_repository ?? new SettingsRepository( $this->authorizer );
		$this->wpdb                = $custom_wpdb ?? ( isset( $GLOBALS['wpdb'] ) && $GLOBALS['wpdb'] instanceof wpdb ? $GLOBALS['wpdb'] : null );
		$this->runtime_overrides   = $runtime_overrides;
	}

	/**
	 * Authorize the actor (`manage_wpig_settings` or `view_wpig_reports`) and build the full diagnostic report.
	 *
	 * @param int      $actor_user_id Acting WordPress user ID.
	 * @param int|null $blog_id       Optional expected site blog ID.
	 * @return array{
	 *   overall_verification_readiness: string,
	 *   foundation_readiness: string,
	 *   environment: array{
	 *     status: string,
	 *     plugin_version: string,
	 *     php_version: string,
	 *     min_php_version: string,
	 *     php_supported: bool,
	 *     wp_version: string,
	 *     min_wp_version: string,
	 *     wp_supported: bool,
	 *     wc_installed: bool,
	 *     wc_version: string|null,
	 *     min_wc_version: string,
	 *     wc_supported: bool,
	 *     ext_sodium: bool,
	 *     https: array{
	 *       is_https: bool,
	 *       is_local_dev_http: bool,
	 *       production_ready_for_sensitive_ops: bool,
	 *       status: string,
	 *       summary: string
	 *     }
	 *   },
	 *   database: array{
	 *     status: string,
	 *     db_connected: bool,
	 *     current_schema_version: string,
	 *     target_schema_version: string,
	 *     schema_verified: bool,
	 *     migration_ready: bool,
	 *     maintenance_mode: bool,
	 *     table_statuses: array<string,bool>
	 *   },
	 *   cryptography: array{
	 *     status: string,
	 *     encryption_configured: bool,
	 *     encryption_key_id: string|null,
	 *     encryption_previous_count: int,
	 *     hmac_configured: bool,
	 *     hmac_key_id: string|null,
	 *     hmac_previous_count: int,
	 *     keys_distinct: bool,
	 *     ready: bool,
	 *     error_codes: list<string>
	 *   },
	 *   providers: array{
	 *     status: string,
	 *     default_provider: string,
	 *     sandbox_mode: bool,
	 *     items: array<string,array{
	 *       id: string,
	 *       name: string,
	 *       integration_status: string,
	 *       live_connectivity: bool,
	 *       selected_as_default: bool,
	 *       summary: string
	 *     }>
	 *   },
	 *   security: array{
	 *     status: string,
	 *     capabilities_registered: bool,
	 *     legal_compliance_status: string,
	 *     verification_workflow_status: string,
	 *     overall_verification_readiness: string
	 *   }
	 * }
	 */
	public function get_authorized_report( int $actor_user_id, ?int $blog_id = null ): array {
		$this->assert_can_access_admin_diagnostics( $actor_user_id, $blog_id );

		$environment  = $this->inspect_environment();
		$database     = $this->inspect_database();
		$cryptography = $this->inspect_cryptography();
		$providers    = $this->inspect_providers();

		$caps_registered = $this->resolve_capabilities_registered();

		$critical_statuses = array(
			$environment['status'],
			$environment['https']['status'],
			$database['status'],
			$cryptography['status'],
			$caps_registered ? ReadinessStatus::READY : ReadinessStatus::BLOCKED,
		);

		$foundation_readiness = ReadinessStatus::READY;
		foreach ( $critical_statuses as $crit_status ) {
			if ( ReadinessStatus::BLOCKED === $crit_status ) {
				$foundation_readiness = ReadinessStatus::BLOCKED;
				break;
			}
			if ( ReadinessStatus::ACTION_REQUIRED === $crit_status ) {
				$foundation_readiness = ReadinessStatus::ACTION_REQUIRED;
			}
		}

		// Task 7 Invariant: P01-D2 must NEVER report READY for production identity verification.
		$overall_verification_readiness = ReadinessStatus::compute_overall_verification_readiness(
			array_merge(
				$critical_statuses,
				array(
					$providers['status'],
					ReadinessStatus::ACTION_REQUIRED, // Legal/compliance prerequisites pending.
				)
			),
			false
		);

		$security = array(
			'status'                         => $overall_verification_readiness,
			'capabilities_registered'        => $caps_registered,
			'legal_compliance_status'        => ReadinessStatus::ACTION_REQUIRED,
			'verification_workflow_status'   => ReadinessStatus::NOT_IMPLEMENTED,
			'overall_verification_readiness' => $overall_verification_readiness,
		);

		return array(
			'overall_verification_readiness' => $overall_verification_readiness,
			'foundation_readiness'           => $foundation_readiness,
			'environment'                    => $environment,
			'database'                       => $database,
			'cryptography'                   => $cryptography,
			'providers'                      => $providers,
			'security'                       => $security,
		);
	}

	/**
	 * Verify that the actor has either `manage_wpig_settings` or `view_wpig_reports` on the current site.
	 *
	 * @param int      $actor_user_id Acting WordPress user ID.
	 * @param int|null $blog_id       Optional expected site blog ID.
	 */
	public function assert_can_access_admin_diagnostics( int $actor_user_id, ?int $blog_id = null ): void {
		$this->authorizer->assert_authenticated_actor( $actor_user_id, $blog_id );

		try {
			$this->authorizer->assert_can_manage_settings( $actor_user_id, $blog_id );
			return;
		} catch ( \WPIG\Security\AuthorizationException $e ) {
			unset( $e );
		}

		$this->authorizer->assert_can_view_reports( $actor_user_id, $blog_id );
	}

	/**
	 * Inspect runtime environment versions, `ext-sodium`, and HTTPS readiness (Task 4).
	 *
	 * @return array{
	 *   status: string,
	 *   plugin_version: string,
	 *   php_version: string,
	 *   min_php_version: string,
	 *   php_supported: bool,
	 *   wp_version: string,
	 *   min_wp_version: string,
	 *   wp_supported: bool,
	 *   wc_installed: bool,
	 *   wc_version: string|null,
	 *   min_wc_version: string,
	 *   wc_supported: bool,
	 *   ext_sodium: bool,
	 *   https: array{
	 *     is_https: bool,
	 *     is_local_dev_http: bool,
	 *     production_ready_for_sensitive_ops: bool,
	 *     status: string,
	 *     summary: string
	 *   }
	 * }
	 */
	public function inspect_environment(): array {
		$php_version   = isset( $this->runtime_overrides['php_version'] )
			? (string) $this->runtime_overrides['php_version']
			: PHP_VERSION;
		$wp_version    = isset( $this->runtime_overrides['wp_version'] )
			? (string) $this->runtime_overrides['wp_version']
			: $this->detect_wp_version();
		$sodium_loaded = isset( $this->runtime_overrides['sodium_loaded'] )
			? (bool) $this->runtime_overrides['sodium_loaded']
			: extension_loaded( 'sodium' );

		$env_errors    = EnvironmentChecker::check(
			$php_version,
			$wp_version,
			static fn( string $ext ): bool => 'sodium' === $ext ? $sodium_loaded : extension_loaded( $ext )
		);
		$php_supported = version_compare( $php_version, EnvironmentChecker::MIN_PHP_VERSION, '>=' );
		$wp_supported  = '' !== $wp_version && version_compare( $wp_version, EnvironmentChecker::MIN_WP_VERSION, '>=' );

		$wc_version   = array_key_exists( 'wc_version', $this->runtime_overrides )
			? $this->runtime_overrides['wc_version']
			: $this->detect_wc_version();
		$wc_installed = null !== $wc_version && '' !== $wc_version;
		$wc_supported = ! $wc_installed || version_compare( (string) $wc_version, self::MIN_WC_VERSION, '>=' );

		$https_info = $this->inspect_https();

		$env_ready = array() === $env_errors
			&& $php_supported
			&& $wp_supported
			&& $wc_supported
			&& $sodium_loaded
			&& ReadinessStatus::READY === $https_info['status'];

		$plugin_version = defined( 'WPIG_VERSION' ) ? (string) WPIG_VERSION : '0.1.0-alpha.1';

		return array(
			'status'          => $env_ready ? ReadinessStatus::READY : ReadinessStatus::BLOCKED,
			'plugin_version'  => $plugin_version,
			'php_version'     => $php_version,
			'min_php_version' => EnvironmentChecker::MIN_PHP_VERSION,
			'php_supported'   => $php_supported,
			'wp_version'      => '' !== $wp_version ? $wp_version : 'unknown',
			'min_wp_version'  => EnvironmentChecker::MIN_WP_VERSION,
			'wp_supported'    => $wp_supported,
			'wc_installed'    => $wc_installed,
			'wc_version'      => $wc_installed ? (string) $wc_version : null,
			'min_wc_version'  => self::MIN_WC_VERSION,
			'wc_supported'    => $wc_supported,
			'ext_sodium'      => $sodium_loaded,
			'https'           => $https_info,
		);
	}

	/**
	 * Inspect HTTPS vs local HTTP development transport security.
	 *
	 * Task 4 Invariant:
	 * - Distinguishes between local disposable HTTP development (`localhost`, `127.0.0.1`, `.local`, `.test`)
	 *   and production HTTPS requirements.
	 * - Never marks HTTP as production-ready for sensitive operations (`status = BLOCKED`,
	 *   `production_ready_for_sensitive_ops = false`).
	 *
	 * @return array{
	 *   is_https: bool,
	 *   is_local_dev_http: bool,
	 *   production_ready_for_sensitive_ops: bool,
	 *   status: string,
	 *   summary: string
	 * }
	 */
	public function inspect_https(): array {
		$is_https = isset( $this->runtime_overrides['is_https'] )
			? (bool) $this->runtime_overrides['is_https']
			: $this->detect_https();

		$host = isset( $this->runtime_overrides['site_host'] )
			? strtolower( trim( (string) $this->runtime_overrides['site_host'] ) )
			: $this->detect_site_host();

		if ( $is_https ) {
			return array(
				'is_https'                           => true,
				'is_local_dev_http'                  => false,
				'production_ready_for_sensitive_ops' => true,
				'status'                             => ReadinessStatus::READY,
				'summary'                            => 'HTTPS transport is active.',
			);
		}

		$is_local_host = in_array( $host, array( 'localhost', '127.0.0.1', '::1' ), true )
			|| str_ends_with( $host, '.local' )
			|| str_ends_with( $host, '.test' );

		if ( $is_local_host ) {
			return array(
				'is_https'                           => false,
				'is_local_dev_http'                  => true,
				'production_ready_for_sensitive_ops' => false,
				'status'                             => ReadinessStatus::BLOCKED,
				'summary'                            => 'Local disposable HTTP development detected; blocked for production sensitive identity operations (HTTPS required).',
			);
		}

		return array(
			'is_https'                           => false,
			'is_local_dev_http'                  => false,
			'production_ready_for_sensitive_ops' => false,
			'status'                             => ReadinessStatus::BLOCKED,
			'summary'                            => 'Insecure HTTP transport detected; HTTPS is strictly required before any sensitive identity operation.',
		);
	}

	/**
	 * Inspect database connectivity, schema version, required tables, and maintenance state.
	 *
	 * @return array{
	 *   status: string,
	 *   db_connected: bool,
	 *   current_schema_version: string,
	 *   target_schema_version: string,
	 *   schema_verified: bool,
	 *   migration_ready: bool,
	 *   maintenance_mode: bool,
	 *   table_statuses: array<string,bool>
	 * }
	 */
	public function inspect_database(): array {
		$target_version   = SchemaDefinition::SCHEMA_VERSION;
		$maintenance_mode = isset( $this->runtime_overrides['maintenance_mode'] )
			? (bool) $this->runtime_overrides['maintenance_mode']
			: $this->detect_maintenance_mode();

		$logical_tables = array(
			'wpig_profiles',
			'wpig_verifications',
			'wpig_cards',
			'wpig_otp_challenges',
			'wpig_consents',
			'wpig_audit_events',
		);

		if ( isset( $this->runtime_overrides['db_connected'] ) ) {
			$db_connected    = (bool) $this->runtime_overrides['db_connected'];
			$current_version = isset( $this->runtime_overrides['installed_schema_version'] )
				? (string) $this->runtime_overrides['installed_schema_version']
				: ( $db_connected ? $target_version : '' );
			$schema_verified = isset( $this->runtime_overrides['schema_verified'] )
				? (bool) $this->runtime_overrides['schema_verified']
				: $db_connected;

			$table_statuses = array();
			foreach ( $logical_tables as $logical ) {
				$table_statuses[ $logical ] = isset( $this->runtime_overrides['table_statuses'][ $logical ] )
					? (bool) $this->runtime_overrides['table_statuses'][ $logical ]
					: $schema_verified;
			}
		} elseif ( null === $this->wpdb ) {
			$db_connected    = false;
			$current_version = '';
			$schema_verified = false;
			$table_statuses  = array_fill_keys( $logical_tables, false );
		} else {
			$migrator        = new SchemaMigrator( $this->wpdb );
			$db_connected    = $this->check_db_connection( $this->wpdb );
			$current_version = $db_connected ? $migrator->get_installed_version() : '';
			$schema_verified = $db_connected && array() === $migrator->verify_schema();
			$table_statuses  = $this->inspect_table_presence( $this->wpdb, $logical_tables, $db_connected );
		}

		$all_tables_present = ! in_array( false, $table_statuses, true );
		$migration_ready    = $db_connected
			&& $schema_verified
			&& $all_tables_present
			&& $current_version === $target_version;

		if ( ! $migration_ready ) {
			$status = ReadinessStatus::BLOCKED;
		} elseif ( $maintenance_mode ) {
			$status = ReadinessStatus::ACTION_REQUIRED;
		} else {
			$status = ReadinessStatus::READY;
		}

		return array(
			'status'                 => $status,
			'db_connected'           => $db_connected,
			'current_schema_version' => '' !== $current_version ? $current_version : 'none',
			'target_schema_version'  => $target_version,
			'schema_verified'        => $schema_verified && $all_tables_present,
			'migration_ready'        => $migration_ready,
			'maintenance_mode'       => $maintenance_mode,
			'table_statuses'         => $table_statuses,
		);
	}

	/**
	 * Inspect cryptographic key configuration without exposing any secret key material.
	 *
	 * @return array{
	 *   status: string,
	 *   encryption_configured: bool,
	 *   encryption_key_id: string|null,
	 *   encryption_previous_count: int,
	 *   hmac_configured: bool,
	 *   hmac_key_id: string|null,
	 *   hmac_previous_count: int,
	 *   keys_distinct: bool,
	 *   ready: bool,
	 *   error_codes: list<string>
	 * }
	 */
	public function inspect_cryptography(): array {
		try {
			$enc_key_id   = $this->key_provider->get_active_encryption_key_id();
			$enc_key_ids  = $this->key_provider->get_encryption_key_ids();
			$hmac_key_id  = $this->key_provider->get_active_hmac_key_id();
			$enc_prev_cnt = max( 0, count( $enc_key_ids ) - 1 );

			return array(
				'status'                    => ReadinessStatus::READY,
				'encryption_configured'     => true,
				'encryption_key_id'         => $enc_key_id,
				'encryption_previous_count' => $enc_prev_cnt,
				'hmac_configured'           => true,
				'hmac_key_id'               => $hmac_key_id,
				'hmac_previous_count'       => 0,
				'keys_distinct'             => true,
				'ready'                     => true,
				'error_codes'               => array(),
			);
		} catch ( CryptoException $e ) {
			return array(
				'status'                    => ReadinessStatus::BLOCKED,
				'encryption_configured'     => false,
				'encryption_key_id'         => null,
				'encryption_previous_count' => 0,
				'hmac_configured'           => false,
				'hmac_key_id'               => null,
				'hmac_previous_count'       => 0,
				'keys_distinct'             => false,
				'ready'                     => false,
				'error_codes'               => array( $e->get_safe_code() ),
			);
		}
	}

	/**
	 * Inspect static provider readiness status (`API.ir` and `Zohal`) without performing live calls (Task 6).
	 *
	 * @return array{
	 *   status: string,
	 *   default_provider: string,
	 *   sandbox_mode: bool,
	 *   items: array<string,array{
	 *     id: string,
	 *     name: string,
	 *     integration_status: string,
	 *     live_connectivity: bool,
	 *     selected_as_default: bool,
	 *     summary: string
	 *   }>
	 * }
	 */
	public function inspect_providers(): array {
		$settings         = $this->settings_repository->get_settings();
		$default_provider = $settings['default_provider'];

		$items = array(
			'api_ir' => array(
				'id'                  => 'api_ir',
				'name'                => 'API.ir',
				'integration_status'  => ReadinessStatus::NOT_IMPLEMENTED,
				'live_connectivity'   => false,
				'selected_as_default' => 'api_ir' === $default_provider,
				'summary'             => 'Provider adapter and live verification workflow are not implemented in Phase P01-D2 (reserved for P02).',
			),
			'zohal'  => array(
				'id'                  => 'zohal',
				'name'                => 'Zohal',
				'integration_status'  => ReadinessStatus::NOT_IMPLEMENTED,
				'live_connectivity'   => false,
				'selected_as_default' => 'zohal' === $default_provider,
				'summary'             => 'Provider adapter and live verification workflow are not implemented in Phase P01-D2 (reserved for P02).',
			),
		);

		return array(
			'status'           => ReadinessStatus::NOT_IMPLEMENTED,
			'default_provider' => $default_provider,
			'sandbox_mode'     => $settings['sandbox_mode'],
			'items'            => $items,
		);
	}

	/**
	 * Detect current WordPress version safely.
	 */
	private function detect_wp_version(): string {
		if ( function_exists( 'get_bloginfo' ) ) {
			$ver = get_bloginfo( 'version' );
			if ( '' !== $ver ) {
				return $ver;
			}
		}
		if ( isset( $GLOBALS['wp_version'] ) && is_string( $GLOBALS['wp_version'] ) ) {
			return $GLOBALS['wp_version'];
		}
		return '';
	}

	/**
	 * Detect installed WooCommerce version if present.
	 */
	private function detect_wc_version(): ?string {
		if ( defined( 'WC_VERSION' ) && is_string( WC_VERSION ) && '' !== WC_VERSION ) {
			return WC_VERSION;
		}
		return null;
	}

	/**
	 * Detect whether HTTPS is active for the current site/request.
	 */
	private function detect_https(): bool {
		if ( function_exists( 'is_ssl' ) && is_ssl() ) {
			return true;
		}
		if ( function_exists( 'home_url' ) ) {
			$url = (string) home_url();
			if ( str_starts_with( strtolower( $url ), 'https://' ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Detect current site hostname for local HTTP vs production HTTPS classification.
	 */
	private function detect_site_host(): string {
		if ( function_exists( 'home_url' ) ) {
			$url = (string) home_url();
			if ( function_exists( 'wp_parse_url' ) ) {
				$host = wp_parse_url( $url, PHP_URL_HOST );
				if ( is_string( $host ) && '' !== $host ) {
					return strtolower( $host );
				}
			}
		}
		return 'localhost';
	}

	/**
	 * Detect whether maintenance mode is active.
	 */
	private function detect_maintenance_mode(): bool {
		if ( defined( 'WPIG_MAINTENANCE_MODE' ) && (bool) constant( 'WPIG_MAINTENANCE_MODE' ) ) {
			return true;
		}
		if ( function_exists( 'get_option' ) ) {
			return (bool) get_option( self::MAINTENANCE_OPTION, false );
		}
		return false;
	}

	/**
	 * Resolve whether WP Identity Guard capabilities are registered for the current site.
	 */
	private function resolve_capabilities_registered(): bool {
		if ( isset( $this->runtime_overrides['capabilities_registered'] ) ) {
			return (bool) $this->runtime_overrides['capabilities_registered'];
		}
		if ( function_exists( 'get_option' ) ) {
			return Capabilities::VERSION === get_option( Capabilities::VERSION_OPTION, '' );
		}
		return false;
	}

	/**
	 * Check basic database connectivity without exposing query details.
	 *
	 * @param wpdb $db WordPress database instance.
	 */
	private function check_db_connection( wpdb $db ): bool {
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$val = $db->get_var( 'SELECT 1' );
		return '1' === (string) $val;
	}

	/**
	 * Check presence of each of the 6 required WP Identity Guard tables.
	 *
	 * @param wpdb     $db             WordPress database instance.
	 * @param string[] $logical_tables Logical table names.
	 * @param bool     $db_connected   Whether DB connection succeeded.
	 * @phpstan-param list<string> $logical_tables
	 * @return array<string,bool>
	 */
	private function inspect_table_presence( wpdb $db, array $logical_tables, bool $db_connected ): array {
		if ( ! $db_connected ) {
			return array_fill_keys( $logical_tables, false );
		}

		$physical_map = SchemaDefinition::get_table_names( $db->prefix );
		$statuses     = array();

		foreach ( $logical_tables as $logical ) {
			$physical = $physical_map[ $logical ] ?? '';
			if ( '' === $physical ) {
				$statuses[ $logical ] = false;
				continue;
			}
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$found                = $db->get_var( $db->prepare( 'SHOW TABLES LIKE %s', $physical ) );
			$statuses[ $logical ] = ( $found === $physical );
		}

		return $statuses;
	}
}

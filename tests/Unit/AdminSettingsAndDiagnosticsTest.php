<?php
/**
 * Unit tests for Phase P01-D2 AdminController, SettingsRepository, DiagnosticsService, and ReadinessStatus.
 *
 * @package WPIG\Tests\Unit
 */

declare(strict_types=1);

namespace WPIG\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPIG\Admin\AdminController;
use WPIG\Admin\DiagnosticsService;
use WPIG\Admin\ReadinessStatus;
use WPIG\Admin\SettingsRepository;
use WPIG\Security\AuthenticationContext;
use WPIG\Security\AuthorizationException;
use WPIG\Security\AuthorizationService;
use WPIG\Security\Capabilities;
use WPIG\Security\ValidationException;
use WPIG\Security\WordPressKeyProvider;
use WPIG\Storage\SchemaDefinition;

/**
 * Verifies all 16 Phase P01-D2 admin settings, environment diagnostics, and security readiness requirements.
 */
final class AdminSettingsAndDiagnosticsTest extends TestCase {

	private const SYNTHETIC_ENC_KEY  = 'hex:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20';
	private const SYNTHETIC_HMAC_KEY = 'hex:a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0';

	/**
	 * Active server-authenticated principal ID in unit tests.
	 *
	 * @var int
	 */
	private int $current_user_id = 1;

	/**
	 * Build an in-memory AuthorizationService for unit tests.
	 *
	 * @return AuthorizationService
	 */
	private function make_authorizer(): AuthorizationService {
		$this->current_user_id = 1;
		$users                 = array(
			1 => array(
				'roles' => array( 'administrator' ),
				'caps'  => Capabilities::all(),
			),
			2 => array(
				'roles' => array( 'wpig_report_viewer' ),
				'caps'  => array( Capabilities::VIEW_REPORTS ),
			),
			3 => array(
				'roles' => array( 'subscriber' ),
				'caps'  => array( 'read' ),
			),
			4 => array(
				'roles' => array( 'customer' ),
				'caps'  => array( 'read' ),
			),
		);

		$role_caps = array(
			'administrator'      => Capabilities::all(),
			'wpig_report_viewer' => array( Capabilities::VIEW_REPORTS ),
			'subscriber'         => array(),
			'customer'           => array(),
		);

		return new AuthorizationService(
			static fn( int $uid ): bool => isset( $users[ $uid ] ),
			static fn( int $uid, string $cap ): bool => isset( $users[ $uid ] )
				&& in_array( $cap, $users[ $uid ]['caps'], true ),
			static fn( int $uid ): array => $users[ $uid ]['roles'] ?? array(),
			static fn(): int => 1,
			static fn(): bool => false,
			static fn(): bool => true,
			static fn( string $role, string $cap ): bool => isset( $role_caps[ $role ] )
				&& in_array( $cap, $role_caps[ $role ], true ),
			AuthenticationContext::wordpress_request( fn(): int => $this->current_user_id )
		);
	}

	/**
	 * Build an in-memory SettingsRepository that records option storage and autoload flags.
	 *
	 * @param AuthorizationService $authorizer   Authorization service.
	 * @param array<string,mixed>  $option_store Reference to in-memory option map.
	 * @param array<string,bool>   $autoload_map Reference to in-memory autoload flag map.
	 */
	private function make_settings_repo(
		AuthorizationService $authorizer,
		array &$option_store,
		array &$autoload_map
	): SettingsRepository {
		return new SettingsRepository(
			$authorizer,
			static function ( string $opt, mixed $default_val = false ) use ( &$option_store ): mixed {
				return $option_store[ $opt ] ?? $default_val;
			},
			static function ( string $opt, mixed $val, bool $autoload = false ) use ( &$option_store, &$autoload_map ): bool {
				$option_store[ $opt ] = $val;
				$autoload_map[ $opt ] = $autoload;
				return true;
			},
			static function ( string $opt, mixed $val, bool $autoload = false ) use ( &$option_store, &$autoload_map ): bool {
				$option_store[ $opt ] = $val;
				$autoload_map[ $opt ] = $autoload;
				return true;
			}
		);
	}

	/**
	 * Build a configured WordPressKeyProvider with synthetic test keys.
	 *
	 * @param bool $configured Whether keys are configured.
	 */
	private function make_key_provider( bool $configured = true ): WordPressKeyProvider {
		if ( ! $configured ) {
			return new WordPressKeyProvider( static fn(): mixed => null );
		}

		$constants = array(
			WordPressKeyProvider::CONST_ENC_KEY     => self::SYNTHETIC_ENC_KEY,
			WordPressKeyProvider::CONST_ENC_KEY_ID  => 'k2026_01',
			WordPressKeyProvider::CONST_HMAC_KEY    => self::SYNTHETIC_HMAC_KEY,
			WordPressKeyProvider::CONST_HMAC_KEY_ID => 'hmac_2026_01',
		);

		return new WordPressKeyProvider(
			static fn( string $name ): mixed => $constants[ $name ] ?? null
		);
	}

	/**
	 * Scenarios 1, 2 & 3:
	 * - Admin access allowed for `manage_wpig_settings` (user 1).
	 * - Admin access denied for `subscriber` (user 3) and `customer` (user 4).
	 * - Report viewer (`view_wpig_reports`, user 2) can view diagnostics and render the page in read-only mode,
	 *   but cannot modify settings (`CODE_MISSING_CAPABILITY`).
	 */
	public function test_admin_access_for_manage_settings_report_viewer_and_denial_for_subscriber_customer(): void {
		$authorizer   = $this->make_authorizer();
		$option_store = array();
		$autoload_map = array();
		$settings     = $this->make_settings_repo( $authorizer, $option_store, $autoload_map );
		$diagnostics  = new DiagnosticsService(
			$authorizer,
			$this->make_key_provider( true ),
			$settings,
			null,
			array(
				'php_version'             => '8.3.14',
				'wp_version'              => '7.0.2',
				'sodium_loaded'           => true,
				'is_https'                => true,
				'db_connected'            => true,
				'capabilities_registered' => true,
			)
		);
		$controller   = new AdminController(
			$authorizer,
			$settings,
			$diagnostics,
			static fn( string $nonce, string $action ): bool => 'valid_nonce' === $nonce && AdminController::NONCE_ACTION === $action,
			static fn(): string => 'valid_nonce',
			static fn(): bool => true // Verify RTL rendering too.
		);

		// 1. Admin (user 1) can view diagnostics and render all 7 sections including the editable form.
		$admin_html = $controller->render_page( 1 );
		self::assertStringContainsString( 'dir="rtl"', $admin_html );
		self::assertStringContainsString( 'id="wpig-section-overview"', $admin_html );
		self::assertStringContainsString( 'id="wpig-section-environment"', $admin_html );
		self::assertStringContainsString( 'id="wpig-section-database"', $admin_html );
		self::assertStringContainsString( 'id="wpig-section-cryptography"', $admin_html );
		self::assertStringContainsString( 'id="wpig-section-providers"', $admin_html );
		self::assertStringContainsString( 'id="wpig-section-general-settings"', $admin_html );
		self::assertStringContainsString( 'id="wpig-section-security-diagnostics"', $admin_html );
		self::assertStringContainsString( 'name="settings[default_provider]"', $admin_html );

		// 2. Subscriber (3) and Customer (4) are denied access to diagnostics and admin rendering.
		foreach ( array( 3, 4, 0 ) as $unauthorized_uid ) {
			$this->current_user_id = $unauthorized_uid;
			try {
				$controller->render_page( $unauthorized_uid );
				self::fail( "Unauthorized user {$unauthorized_uid} must be denied admin page rendering." );
			} catch ( AuthorizationException $e ) {
				self::assertContains(
					$e->get_safe_code(),
					array(
						AuthorizationException::CODE_MISSING_CAPABILITY,
						AuthorizationException::CODE_UNAUTHENTICATED,
					)
				);
			}
		}

		// 3. Report viewer (user 2 with view_wpig_reports) CAN view diagnostics in read-only mode,
		// but CANNOT submit settings updates!
		$this->current_user_id = 2;
		$viewer_html           = $controller->render_page( 2 );
		self::assertStringContainsString( 'id="wpig-section-overview"', $viewer_html );
		self::assertStringContainsString( 'Read-only view: manage_wpig_settings capability is required', $viewer_html );
		self::assertStringNotContainsString( 'name="settings[default_provider]"', $viewer_html );

		try {
			$controller->handle_settings_post(
				2,
				'POST',
				array(
					AdminController::NONCE_FIELD => 'valid_nonce',
					'settings'                   => array( 'sandbox_mode' => '1' ),
				)
			);
			self::fail( 'Report viewer must not be allowed to modify general settings.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_MISSING_CAPABILITY, $e->get_safe_code() );
		}
	}

	/**
	 * Scenarios 4, 5, 6, 7, 8 & 9:
	 * - Nonce failure rejected (`CODE_FORBIDDEN`).
	 * - Non-POST settings update rejected (`CODE_FORBIDDEN`).
	 * - Valid settings update saved correctly and preserves D15 flags (`erase_on_uninstall`, `legal_hold_active`).
	 * - Invalid settings values rejected (`ValidationException`).
	 * - Unexpected fields rejected (`ValidationException`) and privilege-escalation claims rejected (`AuthorizationException`).
	 * - Settings stored with `autoload = false`.
	 */
	public function test_csrf_nonce_post_only_validation_allowlist_and_non_autoloaded_persistence(): void {
		$authorizer   = $this->make_authorizer();
		$option_store = array();
		$autoload_map = array();
		$settings     = $this->make_settings_repo( $authorizer, $option_store, $autoload_map );
		$diagnostics  = new DiagnosticsService( $authorizer, $this->make_key_provider( true ), $settings );
		$controller   = new AdminController(
			$authorizer,
			$settings,
			$diagnostics,
			static fn( string $nonce, string $action ): bool => 'valid_nonce_token' === $nonce && AdminController::NONCE_ACTION === $action,
			static fn(): string => 'valid_nonce_token'
		);

		// 4. Nonce failure (missing or wrong nonce) rejected.
		foreach ( array( '', 'wrong_nonce' ) as $bad_nonce ) {
			try {
				$controller->handle_settings_post(
					1,
					'POST',
					array(
						AdminController::NONCE_FIELD => $bad_nonce,
						'settings'                   => array( 'sandbox_mode' => true ),
					)
				);
				self::fail( 'Invalid or missing CSRF nonce must be rejected.' );
			} catch ( AuthorizationException $e ) {
				self::assertSame( AuthorizationException::CODE_FORBIDDEN, $e->get_safe_code() );
			}
		}

		// 5. Non-POST settings update (GET, PUT, DELETE) rejected.
		foreach ( array( 'GET', 'PUT', 'DELETE' ) as $bad_method ) {
			try {
				$controller->handle_settings_post(
					1,
					$bad_method,
					array(
						AdminController::NONCE_FIELD => 'valid_nonce_token',
						'settings'                   => array( 'sandbox_mode' => true ),
					)
				);
				self::fail( "HTTP method {$bad_method} must be rejected." );
			} catch ( AuthorizationException $e ) {
				self::assertSame( AuthorizationException::CODE_FORBIDDEN, $e->get_safe_code() );
			}
		}

		// 6 & 9. Valid settings update saved correctly with autoload = false.
		$saved = $controller->handle_settings_post(
			1,
			'POST',
			array(
				AdminController::NONCE_FIELD => 'valid_nonce_token',
				'settings'                   => array(
					'default_provider'               => 'api_ir',
					'sandbox_mode'                   => '0',
					'daily_request_budget'           => '2500',
					'rate_limit_per_user_hour'       => '10',
					'rate_limit_per_ip_hour'         => '40',
					'security_notifications_enabled' => '1',
					'consent_notice_version'         => '2.1-fa',
				),
			)
		);

		self::assertSame( 'api_ir', $saved['default_provider'] );
		self::assertFalse( $saved['sandbox_mode'] );
		self::assertSame( 2500, $saved['daily_request_budget'] );
		self::assertSame( 10, $saved['rate_limit_per_user_hour'] );
		self::assertSame( 40, $saved['rate_limit_per_ip_hour'] );
		self::assertTrue( $saved['security_notifications_enabled'] );
		self::assertSame( '2.1-fa', $saved['consent_notice_version'] );
		self::assertFalse( $saved['erase_on_uninstall'] );
		self::assertFalse( $saved['legal_hold_active'] );

		// Verify autoload = false!
		self::assertArrayHasKey( SettingsRepository::OPTION_NAME, $autoload_map );
		self::assertFalse( $autoload_map[ SettingsRepository::OPTION_NAME ] );

		// 7. Invalid settings values rejected (out of range, invalid provider, malformed consent version).
		$invalid_payloads = array(
			array( 'default_provider' => 'unknown_provider' ),
			array( 'daily_request_budget' => 100001 ),
			array( 'daily_request_budget' => -1 ),
			array( 'rate_limit_per_user_hour' => 0 ),
			array( 'rate_limit_per_user_hour' => 101 ),
			array( 'rate_limit_per_ip_hour' => 0 ),
			array( 'rate_limit_per_ip_hour' => 501 ),
			array( 'sandbox_mode' => 'not_a_bool' ),
			array( 'consent_notice_version' => '' ),
			array( 'consent_notice_version' => '<script>alert(1)</script>' ),
		);

		foreach ( $invalid_payloads as $bad_settings ) {
			try {
				$controller->handle_settings_post(
					1,
					'POST',
					array(
						AdminController::NONCE_FIELD => 'valid_nonce_token',
						'settings'                   => $bad_settings,
					)
				);
				self::fail( 'Invalid settings value must throw ValidationException.' );
			} catch ( ValidationException $e ) {
				self::assertSame( ValidationException::CODE_INVALID_SETTING, $e->get_safe_code() );
			}
		}

		// 8. Unexpected fields (including credential/secret fields or destructive flags) rejected.
		$unexpected_payloads = array(
			array( 'api_ir_token' => 'secret_token' ),
			array( 'zohal_api_key' => 'secret_key' ),
			array( 'erase_on_uninstall' => true ),
			array( 'unexpected_field' => 'value' ),
		);

		foreach ( $unexpected_payloads as $unexpected ) {
			try {
				$controller->handle_settings_post(
					1,
					'POST',
					array(
						AdminController::NONCE_FIELD => 'valid_nonce_token',
						'settings'                   => $unexpected,
					)
				);
				self::fail( 'Unexpected settings field must be rejected.' );
			} catch ( ValidationException $e ) {
				self::assertSame( ValidationException::CODE_INVALID_SETTING, $e->get_safe_code() );
			}
		}

		// Privilege escalation claims in settings payload fail closed with AuthorizationException.
		try {
			$controller->handle_settings_post(
				1,
				'POST',
				array(
					AdminController::NONCE_FIELD => 'valid_nonce_token',
					'settings'                   => array( 'is_super_admin' => true ),
				)
			);
			self::fail( 'Privilege escalation input must throw AuthorizationException.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_PRIVILEGE_ESCALATION_ATTEMPT, $e->get_safe_code() );
		}
	}

	/**
	 * Scenarios 10, 11, 12, 13, 14, 15 & 16:
	 * - Environment diagnostics when healthy (and HTTPS vs disposable local HTTP distinction).
	 * - Environment/Crypto diagnostics when keys are missing (`BLOCKED`).
	 * - Database diagnostics when tables exist (`READY`).
	 * - Database diagnostics when schema version mismatches (`BLOCKED`).
	 * - Provider statuses (`API.ir`, `Zohal`) remain `NOT_IMPLEMENTED`.
	 * - Overall readiness is never `READY` for production verification in P01-D2.
	 * - No secret material appears in diagnostic report or rendered HTML output.
	 */
	public function test_diagnostics_readiness_model_https_distinction_and_zero_secret_disclosure(): void {
		$authorizer   = $this->make_authorizer();
		$option_store = array();
		$autoload_map = array();
		$settings     = $this->make_settings_repo( $authorizer, $option_store, $autoload_map );

		// 10, 12, 14, 15 & 16: Healthy environment + database + keys + HTTPS.
		$healthy_diag = new DiagnosticsService(
			$authorizer,
			$this->make_key_provider( true ),
			$settings,
			null,
			array(
				'php_version'              => '8.3.14',
				'wp_version'               => '7.0.2',
				'wc_version'               => '10.8.1',
				'sodium_loaded'            => true,
				'is_https'                 => true,
				'site_host'                => 'identity.example.ir',
				'maintenance_mode'         => false,
				'capabilities_registered'  => true,
				'db_connected'             => true,
				'installed_schema_version' => SchemaDefinition::SCHEMA_VERSION,
				'schema_verified'          => true,
			)
		);

		$report = $healthy_diag->get_authorized_report( 1 );

		// 10. Environment is READY when PHP, WP, WC, ext-sodium, and HTTPS are healthy.
		self::assertSame( ReadinessStatus::READY, $report['environment']['status'] );
		self::assertTrue( $report['environment']['https']['is_https'] );
		self::assertTrue( $report['environment']['https']['production_ready_for_sensitive_ops'] );

		// 12. Database is READY when connected, schema version matches, and all 6 tables exist.
		self::assertSame( ReadinessStatus::READY, $report['database']['status'] );
		self::assertTrue( $report['database']['migration_ready'] );
		self::assertCount( 6, $report['database']['table_statuses'] );

		// Cryptography is READY.
		self::assertSame( ReadinessStatus::READY, $report['cryptography']['status'] );
		self::assertSame( 'k2026_01', $report['cryptography']['encryption_key_id'] );
		self::assertSame( 'hmac_2026_01', $report['cryptography']['hmac_key_id'] );

		// 14. Provider statuses remain NOT_IMPLEMENTED for API.ir and Zohal.
		self::assertSame( ReadinessStatus::NOT_IMPLEMENTED, $report['providers']['status'] );
		self::assertSame( ReadinessStatus::NOT_IMPLEMENTED, $report['providers']['items']['api_ir']['integration_status'] );
		self::assertSame( ReadinessStatus::NOT_IMPLEMENTED, $report['providers']['items']['zohal']['integration_status'] );
		self::assertFalse( $report['providers']['items']['api_ir']['live_connectivity'] );
		self::assertFalse( $report['providers']['items']['zohal']['live_connectivity'] );

		// 15. Overall readiness for production identity verification is NEVER READY in P01-D2!
		self::assertNotSame( ReadinessStatus::READY, $report['overall_verification_readiness'] );
		self::assertSame( ReadinessStatus::ACTION_REQUIRED, $report['overall_verification_readiness'] );

		// Verify disposable local HTTP development vs production HTTPS:
		// Even on localhost HTTP, production_ready_for_sensitive_ops is false and status is BLOCKED.
		$local_http_diag   = new DiagnosticsService(
			$authorizer,
			$this->make_key_provider( true ),
			$settings,
			null,
			array(
				'php_version'             => '8.3.14',
				'wp_version'              => '7.0.2',
				'sodium_loaded'           => true,
				'is_https'                => false,
				'site_host'               => 'localhost',
				'db_connected'            => true,
				'capabilities_registered' => true,
			)
		);
		$local_http_report = $local_http_diag->get_authorized_report( 1 );
		self::assertTrue( $local_http_report['environment']['https']['is_local_dev_http'] );
		self::assertFalse( $local_http_report['environment']['https']['production_ready_for_sensitive_ops'] );
		self::assertSame( ReadinessStatus::BLOCKED, $local_http_report['environment']['https']['status'] );
		self::assertSame( ReadinessStatus::BLOCKED, $local_http_report['overall_verification_readiness'] );

		// 11. Diagnostics when keys are missing -> Cryptography & overall status are BLOCKED.
		$missing_keys_diag   = new DiagnosticsService(
			$authorizer,
			$this->make_key_provider( false ),
			$settings,
			null,
			array(
				'php_version'             => '8.3.14',
				'wp_version'              => '7.0.2',
				'sodium_loaded'           => true,
				'is_https'                => true,
				'db_connected'            => true,
				'capabilities_registered' => true,
			)
		);
		$missing_keys_report = $missing_keys_diag->get_authorized_report( 1 );
		self::assertSame( ReadinessStatus::BLOCKED, $missing_keys_report['cryptography']['status'] );
		self::assertSame( ReadinessStatus::BLOCKED, $missing_keys_report['overall_verification_readiness'] );

		// 13. Database diagnostics when schema version mismatches -> Database & overall status are BLOCKED.
		$mismatch_db_diag   = new DiagnosticsService(
			$authorizer,
			$this->make_key_provider( true ),
			$settings,
			null,
			array(
				'php_version'              => '8.3.14',
				'wp_version'               => '7.0.2',
				'sodium_loaded'            => true,
				'is_https'                 => true,
				'db_connected'             => true,
				'installed_schema_version' => '0.9.0-outdated',
				'schema_verified'          => true,
				'capabilities_registered'  => true,
			)
		);
		$mismatch_db_report = $mismatch_db_diag->get_authorized_report( 1 );
		self::assertSame( ReadinessStatus::BLOCKED, $mismatch_db_report['database']['status'] );
		self::assertFalse( $mismatch_db_report['database']['migration_ready'] );
		self::assertSame( ReadinessStatus::BLOCKED, $mismatch_db_report['overall_verification_readiness'] );

		// 16. No secret material appears in diagnostic report dump or rendered HTML output.
		$controller = new AdminController( $authorizer, $settings, $healthy_diag );
		$html       = $controller->render_page( 1 );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Pure unit test without WP functions loaded.
		$report_dump = (string) json_encode( $report );

		$raw_enc_hex  = substr( self::SYNTHETIC_ENC_KEY, 4 );
		$raw_hmac_hex = substr( self::SYNTHETIC_HMAC_KEY, 4 );

		self::assertStringNotContainsString( $raw_enc_hex, $report_dump );
		self::assertStringNotContainsString( $raw_hmac_hex, $report_dump );
		self::assertStringNotContainsString( $raw_enc_hex, $html );
		self::assertStringNotContainsString( $raw_hmac_hex, $html );
	}
}

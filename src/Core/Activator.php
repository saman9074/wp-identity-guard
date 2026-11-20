<?php
/**
 * Plugin activation handler.
 *
 * @package WPIG\Core
 */

declare(strict_types=1);

namespace WPIG\Core;

use wpdb;
use WPIG\Admin\SettingsRepository;
use WPIG\Security\Capabilities;
use WPIG\Storage\MigrationResult;
use WPIG\Storage\SchemaMigrator;

/**
 * Handles WP Identity Guard activation: validates environment floors, runs
 * versioned schema migrations under an exclusive lock, and initializes safe
 * non-autoloaded default settings.
 */
final class Activator {

	/**
	 * Option name for non-autoloaded plugin settings.
	 */
	public const SETTINGS_OPTION = 'wpig_settings';

	/**
	 * Option name for non-autoloaded activation/migration diagnostic state.
	 */
	public const STATUS_OPTION = 'wpig_activation_status';

	/**
	 * WordPress register_activation_hook callback.
	 *
	 * Per docs/p01/P01-B1-database-schema.md §10.2, activation runs for the
	 * current site context without unbounded Multisite network loops. If
	 * environment validation or schema migration fails, activation fails closed.
	 *
	 * @param bool $network_wide Whether activated network-wide on Multisite.
	 */
	public static function activate( bool $network_wide = false ): void {
		unset( $network_wide );

		$result = self::run_for_current_site();
		if ( ! $result->success ) {
			$code = $result->error_code ?? 'ACTIVATION_FAILED';
			wp_die(
				esc_html(
					sprintf(
						'WP Identity Guard activation failed (%s). Please verify PHP >= 8.3, WordPress >= 6.9, ext-sodium, and database privileges.',
						$code
					)
				),
				esc_html( 'WP Identity Guard — Activation Error' ),
				array( 'back_link' => true )
			);
		}
	}

	/**
	 * Execute environment validation, schema migration, and default option
	 * initialization for the current site.
	 *
	 * @param wpdb|null     $custom_wpdb Optional wpdb instance override.
	 * @param string[]|null $env_errors  Optional precomputed environment check result for testing.
	 * @phpstan-param list<string>|null $env_errors
	 * @return MigrationResult
	 */
	public static function run_for_current_site(
		?wpdb $custom_wpdb = null,
		?array $env_errors = null
	): MigrationResult {
		$check_errors = $env_errors ?? EnvironmentChecker::check();
		if ( array() !== $check_errors ) {
			$result = new MigrationResult(
				false,
				'',
				'ENVIRONMENT_UNSUPPORTED',
				$check_errors
			);
			self::record_status( $result, 'failed' );
			return $result;
		}

		$db = $custom_wpdb ?? ( $GLOBALS['wpdb'] ?? null );
		if ( ! $db instanceof wpdb ) {
			$result = new MigrationResult(
				false,
				'',
				'DATABASE_UNAVAILABLE',
				array( 'Global $wpdb instance is not available.' )
			);
			self::record_status( $result, 'failed' );
			return $result;
		}

		$migrator = new SchemaMigrator( $db );
		$result   = $migrator->migrate();

		if ( ! $result->success ) {
			self::record_status( $result, 'failed' );
			return $result;
		}

		self::ensure_default_settings();
		Capabilities::register_for_current_site();
		self::record_status( $result, 'active' );

		return $result;
	}

	/**
	 * Initialize default non-autoloaded plugin settings if not already stored,
	 * preserving any existing settings across reactivations (D15).
	 */
	public static function ensure_default_settings(): void {
		$defaults = SettingsRepository::get_default_settings();

		$existing = get_option( self::SETTINGS_OPTION, false );
		if ( false === $existing ) {
			add_option( self::SETTINGS_OPTION, $defaults, '', false );
			return;
		}

		if ( is_array( $existing ) ) {
			$merged = SettingsRepository::normalize_stored_settings( $existing );
			update_option( self::SETTINGS_OPTION, $merged, false );
		}
	}

	/**
	 * Record safe, non-sensitive activation/migration status in non-autoloaded wp_options.
	 *
	 * @param MigrationResult $result    Migration outcome.
	 * @param string          $lifecycle Lifecycle state ('active' or 'failed').
	 */
	private static function record_status( MigrationResult $result, string $lifecycle ): void {
		if ( ! function_exists( 'get_option' ) ) {
			return;
		}

		$payload = array(
			'lifecycle'      => $lifecycle,
			'success'        => $result->success,
			'schema_version' => $result->schema_version,
			'error_code'     => $result->error_code,
			'updated_at'     => gmdate( 'Y-m-d H:i:s' ),
		);

		if ( false === get_option( self::STATUS_OPTION, false ) ) {
			add_option( self::STATUS_OPTION, $payload, '', false );
			return;
		}
		update_option( self::STATUS_OPTION, $payload, false );
	}
}

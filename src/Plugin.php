<?php
/**
 * Plugin composition root.
 *
 * @package WPIG
 */

declare(strict_types=1);

namespace WPIG;

use wpdb;
use WPIG\Admin\AdminController;
use WPIG\Admin\DiagnosticsService;
use WPIG\Admin\SettingsRepository;
use WPIG\Audit\AuditRepository;
use WPIG\Audit\AuditService;
use WPIG\Core\EnvironmentChecker;
use WPIG\Privacy\ConsentRepository;
use WPIG\Privacy\PrivacyEraserService;
use WPIG\Privacy\PrivacyExporterService;
use WPIG\Security\AuthorizationService;
use WPIG\Security\Capabilities;
use WPIG\Security\IdentityFingerprinter;
use WPIG\Security\SodiumCrypto;
use WPIG\Security\WordPressKeyProvider;
use WPIG\Storage\ProfileRepository;

/**
 * Composition root for WP Identity Guard (Free).
 *
 * P01 Foundation runtime wiring:
 * - Verifies minimum runtime environment floors (`EnvironmentChecker::is_supported()`).
 * - Ensures site-level capabilities are registered idempotently (`Capabilities::ensure_registered()`).
 * - In `wp-admin`, registers `AdminController` wired with `AuthorizationService`,
 *   `SettingsRepository`, `DiagnosticsService`, and `AuditService`.
 * - Registers WordPress Personal Data Exporter (`wp_privacy_personal_data_exporters`)
 *   and Personal Data Eraser (`wp_privacy_personal_data_erasers`) via lazy filter callbacks
 *   that instantiate privacy repositories only when those filters are invoked, avoiding
 *   unnecessary object allocation or database work on ordinary frontend requests.
 * - Preserves inactive verification-provider state and exposes zero public identity endpoints.
 */
final class Plugin {

	/**
	 * Whether boot() has already run in this request.
	 *
	 * @var bool
	 */
	private static bool $booted = false;

	/**
	 * Active AdminController instance when booted in admin context.
	 *
	 * @var AdminController|null
	 */
	private static ?AdminController $admin_controller = null;

	/**
	 * Lazily created PrivacyExporterService instance.
	 *
	 * @var PrivacyExporterService|null
	 */
	private static ?PrivacyExporterService $privacy_exporter = null;

	/**
	 * Lazily created PrivacyEraserService instance.
	 *
	 * @var PrivacyEraserService|null
	 */
	private static ?PrivacyEraserService $privacy_eraser = null;

	/**
	 * Boot the plugin once per request when minimum environment requirements are met.
	 */
	public static function boot(): void {
		if ( self::$booted ) {
			return;
		}
		if ( ! EnvironmentChecker::is_supported() ) {
			return;
		}
		Capabilities::ensure_registered();

		if ( ! function_exists( 'is_admin' ) || is_admin() ) {
			$authorizer          = new AuthorizationService();
			$settings_repository = new SettingsRepository( $authorizer );
			$wpdb                = self::resolve_wpdb();
			$audit_service       = null !== $wpdb ? new AuditService( new AuditRepository( $wpdb ) ) : null;
			$diagnostics_service = new DiagnosticsService(
				$authorizer,
				null,
				$settings_repository,
				$wpdb
			);

			self::$admin_controller = new AdminController(
				$authorizer,
				$settings_repository,
				$diagnostics_service,
				null,
				null,
				null,
				$audit_service
			);
			self::$admin_controller->register_hooks();
		}

		if ( function_exists( 'add_filter' ) ) {
			if ( ! function_exists( 'has_filter' ) || false === has_filter( 'wp_privacy_personal_data_exporters', array( self::class, 'register_privacy_exporter' ) ) ) {
				add_filter( 'wp_privacy_personal_data_exporters', array( self::class, 'register_privacy_exporter' ) );
			}
			if ( ! function_exists( 'has_filter' ) || false === has_filter( 'wp_privacy_personal_data_erasers', array( self::class, 'register_privacy_eraser' ) ) ) {
				add_filter( 'wp_privacy_personal_data_erasers', array( self::class, 'register_privacy_eraser' ) );
			}
		}

		self::$booted = true;
	}

	/**
	 * Lazy WordPress filter callback for `wp_privacy_personal_data_exporters`.
	 *
	 * Instantiates `PrivacyExporterService` and its dependencies only when WordPress
	 * applies the personal data exporters filter.
	 *
	 * @param array<string,array<string,mixed>> $exporters Registered WordPress exporters.
	 * @return array<string,array<string,mixed>>
	 */
	public static function register_privacy_exporter( array $exporters ): array {
		$service = self::get_or_create_privacy_exporter();
		if ( null === $service ) {
			return $exporters;
		}

		return $service->register_exporter( $exporters );
	}

	/**
	 * Lazy WordPress filter callback for `wp_privacy_personal_data_erasers`.
	 *
	 * Instantiates `PrivacyEraserService` and its dependencies only when WordPress
	 * applies the personal data erasers filter.
	 *
	 * @param array<string,array<string,mixed>> $erasers Registered WordPress erasers.
	 * @return array<string,array<string,mixed>>
	 */
	public static function register_privacy_eraser( array $erasers ): array {
		$service = self::get_or_create_privacy_eraser();
		if ( null === $service ) {
			return $erasers;
		}

		return $service->register_eraser( $erasers );
	}

	/**
	 * Whether boot() has run (diagnostics/tests).
	 */
	public static function is_booted(): bool {
		return self::$booted;
	}

	/**
	 * Return the active `AdminController` instance if booted in admin context.
	 */
	public static function get_admin_controller(): ?AdminController {
		return self::$admin_controller;
	}

	/**
	 * Reset composition root state and remove registered hooks for lifecycle testing.
	 *
	 * @internal Reserved for unit and integration lifecycle tests.
	 */
	public static function reset_for_testing(): void {
		if ( null !== self::$admin_controller && function_exists( 'remove_action' ) ) {
			remove_action( 'admin_menu', array( self::$admin_controller, 'register_admin_menu' ) );
		}
		if ( function_exists( 'remove_filter' ) ) {
			remove_filter( 'wp_privacy_personal_data_exporters', array( self::class, 'register_privacy_exporter' ) );
			remove_filter( 'wp_privacy_personal_data_erasers', array( self::class, 'register_privacy_eraser' ) );
		}

		self::$booted           = false;
		self::$admin_controller = null;
		self::$privacy_exporter = null;
		self::$privacy_eraser   = null;
	}

	/**
	 * Lazily construct the runtime `PrivacyExporterService` when `$wpdb` is available.
	 */
	private static function get_or_create_privacy_exporter(): ?PrivacyExporterService {
		if ( null !== self::$privacy_exporter ) {
			return self::$privacy_exporter;
		}

		$wpdb = self::resolve_wpdb();
		if ( null === $wpdb ) {
			return null;
		}

		$authorizer         = new AuthorizationService();
		$audit_service      = new AuditService( new AuditRepository( $wpdb ) );
		$key_provider       = new WordPressKeyProvider();
		$crypto             = new SodiumCrypto( $key_provider );
		$fingerprinter      = new IdentityFingerprinter( $crypto );
		$profile_repository = new ProfileRepository( $wpdb, $crypto, $key_provider, $fingerprinter );
		$consent_repository = new ConsentRepository( $wpdb, $audit_service );

		self::$privacy_exporter = new PrivacyExporterService(
			$profile_repository,
			$consent_repository,
			$authorizer,
			$wpdb,
			$audit_service
		);

		return self::$privacy_exporter;
	}

	/**
	 * Lazily construct the runtime `PrivacyEraserService` when `$wpdb` is available.
	 */
	private static function get_or_create_privacy_eraser(): ?PrivacyEraserService {
		if ( null !== self::$privacy_eraser ) {
			return self::$privacy_eraser;
		}

		$wpdb = self::resolve_wpdb();
		if ( null === $wpdb ) {
			return null;
		}

		$authorizer          = new AuthorizationService();
		$settings_repository = new SettingsRepository( $authorizer );
		$settings            = $settings_repository->get_settings();
		$audit_service       = new AuditService( new AuditRepository( $wpdb ) );
		$key_provider        = new WordPressKeyProvider();
		$crypto              = new SodiumCrypto( $key_provider );
		$fingerprinter       = new IdentityFingerprinter( $crypto );
		$profile_repository  = new ProfileRepository( $wpdb, $crypto, $key_provider, $fingerprinter );
		$consent_repository  = new ConsentRepository( $wpdb, $audit_service );

		self::$privacy_eraser = new PrivacyEraserService(
			$profile_repository,
			$consent_repository,
			$authorizer,
			$wpdb,
			$audit_service,
			(bool) $settings['legal_hold_active']
		);

		return self::$privacy_eraser;
	}

	/**
	 * Resolve the global WordPress `$wpdb` instance if initialized.
	 */
	private static function resolve_wpdb(): ?wpdb {
		if ( isset( $GLOBALS['wpdb'] ) && $GLOBALS['wpdb'] instanceof wpdb ) {
			return $GLOBALS['wpdb'];
		}

		return null;
	}
}

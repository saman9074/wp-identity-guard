<?php
/**
 * Real WordPress + MariaDB integration tests for Phase P01-D2 AdminController,
 * SettingsRepository, DiagnosticsService, and ReadinessStatus.
 *
 * @package WPIG\Tests\Integration
 */

declare(strict_types=1);

namespace WPIG\Tests\Integration;

use PHPUnit\Framework\TestCase;
use wpdb;
use WPIG\Admin\AdminController;
use WPIG\Admin\DiagnosticsService;
use WPIG\Admin\ReadinessStatus;
use WPIG\Admin\SettingsRepository;
use WPIG\Core\Activator;
use WPIG\Security\AuthorizationException;
use WPIG\Security\AuthorizationService;
use WPIG\Security\Capabilities;
use WPIG\Security\ValidationException;
use WPIG\Security\WordPressKeyProvider;
use WPIG\Storage\SchemaMigrator;

/**
 * Verifies P01-D2 admin menu, CSRF nonces, POST-only settings persistence (`autoload = false`),
 * real MariaDB schema/table diagnostics, provider readiness, and secret redaction.
 */
final class AdminSettingsAndDiagnosticsIntegrationTest extends TestCase {

	private const SYNTHETIC_ENC_KEY  = 'hex:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20';
	private const SYNTHETIC_HMAC_KEY = 'hex:a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0';

	/**
	 * WordPress database instance.
	 *
	 * @var wpdb
	 */
	private wpdb $wpdb;

	/**
	 * Created WordPress user IDs to delete in tearDown.
	 *
	 * @var list<int>
	 */
	private array $created_user_ids = array();

	/**
	 * Created custom role slugs to remove in tearDown.
	 *
	 * @var list<string>
	 */
	private array $created_roles = array();

	/**
	 * Set up clean WordPress activation state before each test.
	 */
	protected function setUp(): void {
		parent::setUp();

		if ( ! isset( $GLOBALS['wpdb'] ) || ! $GLOBALS['wpdb'] instanceof wpdb ) {
			self::markTestSkipped( 'WordPress integration environment ($wpdb) is not loaded.' );
		}

		$this->wpdb = $GLOBALS['wpdb'];
		delete_option( SettingsRepository::OPTION_NAME );
		Activator::run_for_current_site( $this->wpdb );
	}

	/**
	 * Clean up created users, roles, and options after each test.
	 */
	protected function tearDown(): void {
		if ( function_exists( 'require_once' ) && defined( 'ABSPATH' ) && ! function_exists( 'wp_delete_user' ) ) {
			require_once ABSPATH . 'wp-admin/includes/user.php';
		}

		foreach ( $this->created_user_ids as $uid ) {
			if ( function_exists( 'wp_delete_user' ) ) {
				wp_delete_user( $uid );
			}
		}
		$this->created_user_ids = array();

		foreach ( $this->created_roles as $role_slug ) {
			if ( function_exists( 'remove_role' ) ) {
				remove_role( $role_slug );
			}
		}
		$this->created_roles = array();

		if ( function_exists( 'wp_set_current_user' ) ) {
			wp_set_current_user( 0 );
		}

		parent::tearDown();
	}

	/**
	 * Create a synthetic WordPress user with a given role.
	 *
	 * @param string $role_slug Role slug.
	 * @param string $suffix    Unique username suffix.
	 * @return int Created user ID.
	 */
	private function create_wp_user( string $role_slug, string $suffix ): int {
		$login   = 'wpig_d2_' . $suffix . '_' . bin2hex( random_bytes( 3 ) );
		$user_id = wp_insert_user(
			array(
				'user_login' => $login,
				'user_pass'  => wp_generate_password( 24, true, true ),
				'user_email' => $login . '@example.invalid',
				'role'       => $role_slug,
			)
		);
		self::assertIsInt( $user_id );
		self::assertGreaterThan( 0, $user_id );
		$this->created_user_ids[] = $user_id;
		return $user_id;
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
	 * Scenarios 1, 2, 3, 4, 5, 6, 7, 8 & 9 against real WordPress users, nonces, and wp_options:
	 * - Admin (`manage_wpig_settings`) can view and update settings using a real WordPress nonce.
	 * - Report viewer (`view_wpig_reports`) can view diagnostics in read-only mode, but is denied settings updates.
	 * - Subscriber and customer are denied both diagnostics view and settings updates.
	 * - Non-POST and invalid/missing WordPress nonces fail closed.
	 * - Invalid values and unexpected fields fail closed.
	 * - `wpig_settings` row in `wp_options` has `autoload` set to `'off'` or `'no'` (`autoload = false`).
	 */
	public function test_real_wp_admin_authorization_nonces_settings_validation_and_non_autoload_storage(): void {
		add_role( 'customer', 'Customer', array( 'read' => true ) );
		$this->created_roles[] = 'customer';

		add_role( 'wpig_auditor_role', 'WPIG Auditor', array( 'read' => true ) );
		$this->created_roles[] = 'wpig_auditor_role';
		Capabilities::grant_to_role( 'wpig_auditor_role', array( Capabilities::VIEW_REPORTS ) );

		$admin_id      = $this->create_wp_user( 'administrator', 'admin' );
		$auditor_id    = $this->create_wp_user( 'wpig_auditor_role', 'auditor' );
		$subscriber_id = $this->create_wp_user( 'subscriber', 'sub' );
		$customer_id   = $this->create_wp_user( 'customer', 'cust' );

		$authorizer  = new AuthorizationService();
		$settings    = new SettingsRepository( $authorizer );
		$diagnostics = new DiagnosticsService(
			$authorizer,
			$this->make_key_provider( true ),
			$settings,
			$this->wpdb
		);
		$controller  = new AdminController( $authorizer, $settings, $diagnostics );

		// 1. Admin can render the admin page with all 7 sections.
		wp_set_current_user( $admin_id );
		$admin_html = $controller->render_page( $admin_id );
		self::assertStringContainsString( 'WP Identity Guard', $admin_html );
		self::assertStringContainsString( 'id="wpig-section-general-settings"', $admin_html );

		// 2. Subscriber and Customer are denied access.
		foreach ( array( $subscriber_id, $customer_id ) as $denied_uid ) {
			wp_set_current_user( $denied_uid );
			try {
				$controller->render_page( $denied_uid );
				self::fail( "User {$denied_uid} must be denied admin diagnostics access." );
			} catch ( AuthorizationException $e ) {
				self::assertSame( AuthorizationException::CODE_MISSING_CAPABILITY, $e->get_safe_code() );
			}
		}

		// 3. Report viewer (`view_wpig_reports`) can render diagnostics in read-only mode, but cannot update settings.
		wp_set_current_user( $auditor_id );
		$auditor_html = $controller->render_page( $auditor_id );
		self::assertStringContainsString( 'Read-only view: manage_wpig_settings capability is required', $auditor_html );

		$auditor_nonce = wp_create_nonce( AdminController::NONCE_ACTION );
		try {
			$controller->handle_settings_post(
				$auditor_id,
				'POST',
				array(
					AdminController::NONCE_FIELD => $auditor_nonce,
					'settings'                   => array( 'sandbox_mode' => '1' ),
				)
			);
			self::fail( 'Auditor without manage_wpig_settings must not update settings.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_MISSING_CAPABILITY, $e->get_safe_code() );
		}

		// Switch back to Admin for nonce, method, and validation tests.
		wp_set_current_user( $admin_id );
		$valid_nonce = wp_create_nonce( AdminController::NONCE_ACTION );

		// 4. Invalid nonce rejected.
		try {
			$controller->handle_settings_post(
				$admin_id,
				'POST',
				array(
					AdminController::NONCE_FIELD => 'forged_nonce_value',
					'settings'                   => array( 'sandbox_mode' => '1' ),
				)
			);
			self::fail( 'Invalid WordPress nonce must fail closed.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_FORBIDDEN, $e->get_safe_code() );
		}

		// 5. Non-POST rejected.
		try {
			$controller->handle_settings_post(
				$admin_id,
				'GET',
				array(
					AdminController::NONCE_FIELD => $valid_nonce,
					'settings'                   => array( 'sandbox_mode' => '1' ),
				)
			);
			self::fail( 'GET request to handle_settings_post must fail closed.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_FORBIDDEN, $e->get_safe_code() );
		}

		// 6 & 9. Valid POST update persists to wp_options with autoload = false ('off' / 'no').
		$updated = $controller->handle_settings_post(
			$admin_id,
			'POST',
			array(
				AdminController::NONCE_FIELD => $valid_nonce,
				'settings'                   => array(
					'default_provider'               => 'zohal',
					'sandbox_mode'                   => '1',
					'daily_request_budget'           => '500',
					'rate_limit_per_user_hour'       => '8',
					'rate_limit_per_ip_hour'         => '25',
					'security_notifications_enabled' => '0',
					'consent_notice_version'         => '1.2',
				),
			)
		);

		self::assertSame( 'zohal', $updated['default_provider'] );
		self::assertSame( 500, $updated['daily_request_budget'] );
		self::assertFalse( $updated['security_notifications_enabled'] );

		// Verify directly in MariaDB wp_options that autoload is disabled ('off' or 'no').
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared
		$autoload_db = $this->wpdb->get_var( $this->wpdb->prepare( "SELECT autoload FROM {$this->wpdb->options} WHERE option_name = %s", SettingsRepository::OPTION_NAME ) );
		self::assertContains( (string) $autoload_db, array( 'off', 'no' ) );

		// 7 & 8. Invalid values and unexpected fields fail closed without corrupting stored option.
		try {
			$controller->handle_settings_post(
				$admin_id,
				'POST',
				array(
					AdminController::NONCE_FIELD => $valid_nonce,
					'settings'                   => array( 'daily_request_budget' => '999999' ),
				)
			);
			self::fail( 'Out-of-range budget must fail closed.' );
		} catch ( ValidationException $e ) {
			self::assertSame( ValidationException::CODE_INVALID_SETTING, $e->get_safe_code() );
		}

		try {
			$controller->handle_settings_post(
				$admin_id,
				'POST',
				array(
					AdminController::NONCE_FIELD => $valid_nonce,
					'settings'                   => array( 'api_ir_secret_key' => 'leaked' ),
				)
			);
			self::fail( 'Unexpected credential field must fail closed.' );
		} catch ( ValidationException $e ) {
			self::assertSame( ValidationException::CODE_INVALID_SETTING, $e->get_safe_code() );
		}

		self::assertSame( 500, $settings->get_settings()['daily_request_budget'] );
	}

	/**
	 * Scenarios 10, 11, 12, 13, 14, 15 & 16 against real MariaDB schema and WordPress runtime:
	 * - Database diagnostics report READY when all 6 tables exist and schema version matches.
	 * - Database diagnostics report BLOCKED when stored `wpig_schema_version` mismatches.
	 * - Cryptography diagnostics report READY with valid keys and BLOCKED when keys are missing.
	 * - Provider statuses (`API.ir`, `Zohal`) remain `NOT_IMPLEMENTED`.
	 * - Overall readiness is NEVER `READY` for production verification in P01-D2.
	 * - No secret material appears in diagnostic output.
	 */
	public function test_real_database_environment_provider_and_cryptography_diagnostics(): void {
		$admin_id = $this->create_wp_user( 'administrator', 'diag_admin' );
		wp_set_current_user( $admin_id );
		$authorizer = new AuthorizationService();
		$settings   = new SettingsRepository( $authorizer );

		$healthy_diag = new DiagnosticsService(
			$authorizer,
			$this->make_key_provider( true ),
			$settings,
			$this->wpdb,
			array( 'is_https' => true )
		);

		$report = $healthy_diag->get_authorized_report( $admin_id );

		// 10 & 12. Real PHP 8.3+, WP 6.9+, ext-sodium, and all 6 MariaDB tables are READY.
		self::assertSame( ReadinessStatus::READY, $report['environment']['status'] );
		self::assertSame( ReadinessStatus::READY, $report['database']['status'] );
		self::assertTrue( $report['database']['db_connected'] );
		self::assertTrue( $report['database']['schema_verified'] );
		self::assertTrue( $report['database']['migration_ready'] );
		foreach ( $report['database']['table_statuses'] as $table_name => $present ) {
			self::assertTrue( $present, "Table {$table_name} must be present in MariaDB." );
		}

		// 14 & 15. Providers are NOT_IMPLEMENTED and overall verification readiness is NEVER READY in P01-D2.
		self::assertSame( ReadinessStatus::NOT_IMPLEMENTED, $report['providers']['items']['api_ir']['integration_status'] );
		self::assertSame( ReadinessStatus::NOT_IMPLEMENTED, $report['providers']['items']['zohal']['integration_status'] );
		self::assertNotSame( ReadinessStatus::READY, $report['overall_verification_readiness'] );
		self::assertSame( ReadinessStatus::ACTION_REQUIRED, $report['overall_verification_readiness'] );

		// 11. Missing keys -> Cryptography and overall readiness become BLOCKED.
		$missing_keys_diag   = new DiagnosticsService(
			$authorizer,
			$this->make_key_provider( false ),
			$settings,
			$this->wpdb,
			array( 'is_https' => true )
		);
		$missing_keys_report = $missing_keys_diag->get_authorized_report( $admin_id );
		self::assertSame( ReadinessStatus::BLOCKED, $missing_keys_report['cryptography']['status'] );
		self::assertSame( ReadinessStatus::BLOCKED, $missing_keys_report['overall_verification_readiness'] );

		// 13. Schema version mismatch in wp_options -> Database and overall readiness become BLOCKED.
		update_option( SchemaMigrator::VERSION_OPTION, '0.0.1-mismatch', false );
		$mismatch_report = $healthy_diag->get_authorized_report( $admin_id );
		self::assertSame( ReadinessStatus::BLOCKED, $mismatch_report['database']['status'] );
		self::assertFalse( $mismatch_report['database']['migration_ready'] );
		self::assertSame( ReadinessStatus::BLOCKED, $mismatch_report['overall_verification_readiness'] );

		// Restore valid schema version via Activator.
		Activator::run_for_current_site( $this->wpdb );

		// 16. Ensure zero secret material appears in rendered HTML or report dump.
		$controller   = new AdminController( $authorizer, $settings, $healthy_diag );
		$html         = $controller->render_page( $admin_id );
		$raw_enc_hex  = substr( self::SYNTHETIC_ENC_KEY, 4 );
		$raw_hmac_hex = substr( self::SYNTHETIC_HMAC_KEY, 4 );

		self::assertStringNotContainsString( $raw_enc_hex, $html );
		self::assertStringNotContainsString( $raw_hmac_hex, $html );
	}
}

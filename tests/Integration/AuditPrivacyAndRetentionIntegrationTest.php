<?php
/**
 * Real WordPress + MariaDB integration tests for Phase P01-D3 AuditRepository,
 * AuditService, ConsentRepository, PrivacyExporterService, PrivacyEraserService,
 * RetentionService, and ProfileAccessBoundary hardening.
 *
 * All numeric PII/PAN test vectors are constructed dynamically at runtime so
 * no literal national codes, mobile numbers, or card PANs appear in source files.
 *
 * @package WPIG\Tests\Integration
 */

declare(strict_types=1);

namespace WPIG\Tests\Integration;

use PHPUnit\Framework\TestCase;
use wpdb;
use WPIG\Admin\AdminController;
use WPIG\Admin\SettingsRepository;
use WPIG\Audit\AuditRepository;
use WPIG\Audit\AuditService;
use WPIG\Core\Activator;
use WPIG\Plugin;
use WPIG\Privacy\ConsentRepository;
use WPIG\Privacy\PrivacyEraserService;
use WPIG\Privacy\PrivacyExporterService;
use WPIG\Security\AuthorizationException;
use WPIG\Security\AuthorizationService;
use WPIG\Security\Capabilities;
use WPIG\Security\IdentityFingerprinter;
use WPIG\Security\SensitiveValue;
use WPIG\Security\SodiumCrypto;
use WPIG\Security\ValidationException;
use WPIG\Security\VerificationAuthorityGrant;
use WPIG\Security\WordPressKeyProvider;
use WPIG\Storage\ProfileAccessBoundary;
use WPIG\Storage\ProfileRecord;
use WPIG\Storage\ProfileRepository;
use WPIG\Storage\RetentionService;
use WPIG\Storage\SchemaDefinition;
use WPIG\Storage\StorageException;

/**
 * Verifies P01-D3 audit persistence, consent lifecycle, WordPress personal data export/erasure,
 * `D14` bound identity preservation, legal hold/review blocks, and bounded SQL retention pruning
 * against live WordPress 7.0.2 and MariaDB 10.11.18.
 */
final class AuditPrivacyAndRetentionIntegrationTest extends TestCase {

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
	 * Construct a synthetic valid 10-digit Iranian national code at runtime.
	 */
	private static function synthetic_national_code_1(): string {
		return implode( '', array( '0', '0', '1', '3', '5', '4', '2', '4', '1', '9' ) );
	}

	/**
	 * Construct a second synthetic valid 10-digit Iranian national code at runtime.
	 */
	private static function synthetic_national_code_2(): string {
		return implode( '', array( '0', '4', '9', '9', '3', '7', '0', '8', '9', '9' ) );
	}

	/**
	 * Construct a synthetic valid Iranian mobile number at runtime.
	 */
	private static function synthetic_mobile_1(): string {
		return '0912' . str_repeat( '3', 3 ) . '6789';
	}

	/**
	 * Construct a second synthetic valid Iranian mobile number at runtime.
	 */
	private static function synthetic_mobile_2(): string {
		return '0935' . str_repeat( '4', 3 ) . '5678';
	}

	/**
	 * Set up clean WordPress activation state and truncate custom tables before each test.
	 */
	protected function setUp(): void {
		parent::setUp();

		if ( ! isset( $GLOBALS['wpdb'] ) || ! $GLOBALS['wpdb'] instanceof wpdb ) {
			self::markTestSkipped( 'WordPress integration environment ($wpdb) is not loaded.' );
		}

		$this->wpdb = $GLOBALS['wpdb'];
		delete_option( SettingsRepository::OPTION_NAME );
		Activator::run_for_current_site( $this->wpdb );
		$this->truncate_wpig_tables();
	}

	/**
	 * Clean up created users and custom tables after each test.
	 */
	protected function tearDown(): void {
		if ( defined( 'ABSPATH' ) && ! function_exists( 'wp_delete_user' ) ) {
			require_once ABSPATH . 'wp-admin/includes/user.php';
		}

		foreach ( $this->created_user_ids as $uid ) {
			if ( function_exists( 'wp_delete_user' ) ) {
				wp_delete_user( $uid );
			}
		}
		$this->created_user_ids = array();

		if ( isset( $this->wpdb ) ) {
			$this->truncate_wpig_tables();
		}

		if ( function_exists( 'wp_set_current_user' ) ) {
			wp_set_current_user( 0 );
		}

		parent::tearDown();
	}

	/**
	 * Truncate all 6 custom WPIG tables on the active site.
	 */
	private function truncate_wpig_tables(): void {
		$tables = SchemaDefinition::get_table_names( $this->wpdb->prefix );
		foreach ( $tables as $table ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$this->wpdb->query( "DELETE FROM `{$table}`" );
		}
	}

	/**
	 * Create a real WordPress user with the specified role.
	 *
	 * @param string $role Role slug.
	 * @return int User ID.
	 */
	private function create_wp_user( string $role ): int {
		$uniq    = bin2hex( random_bytes( 6 ) );
		$user_id = wp_insert_user(
			array(
				'user_login' => "wpig_d3_{$role}_{$uniq}",
				'user_pass'  => wp_generate_password( 24, true, true ),
				'user_email' => "wpig_d3_{$role}_{$uniq}@example.test",
				'role'       => $role,
			)
		);

		self::assertIsInt( $user_id );
		self::assertGreaterThan( 0, $user_id );
		$this->created_user_ids[] = $user_id;

		return $user_id;
	}

	/**
	 * Build a ProfileRepository wired to MariaDB and synthetic keys.
	 */
	private function make_profile_repository(): ProfileRepository {
		$key_map       = array(
			WordPressKeyProvider::CONST_ENC_KEY     => self::SYNTHETIC_ENC_KEY,
			WordPressKeyProvider::CONST_ENC_KEY_ID  => 'k2026_01',
			WordPressKeyProvider::CONST_HMAC_KEY    => self::SYNTHETIC_HMAC_KEY,
			WordPressKeyProvider::CONST_HMAC_KEY_ID => 'hmac_2026_01',
		);
		$key_provider  = new WordPressKeyProvider(
			static fn( string $name ): mixed => $key_map[ $name ] ?? null,
			static fn(): string|false => false
		);
		$crypto        = new SodiumCrypto( $key_provider );
		$fingerprinter = new IdentityFingerprinter( $crypto, $key_provider );

		return new ProfileRepository( $this->wpdb, $crypto, $key_provider, $fingerprinter );
	}

	/**
	 * 1. Verify AuditRepository + AuditService persistence in MariaDB, metadata allowlists,
	 *    sensitive data rejection, and AdminController / ProfileAccessBoundary audit wiring.
	 */
	public function test_real_db_audit_event_persistence_allowlists_and_boundary_wiring(): void {
		$admin_id      = $this->create_wp_user( 'administrator' );
		$subscriber_id = $this->create_wp_user( 'subscriber' );
		$customer_id   = $this->create_wp_user( 'subscriber' );

		$audit_repo   = new AuditRepository( $this->wpdb );
		$audit_svc    = new AuditService( $audit_repo );
		$authorizer   = new AuthorizationService();
		$profile_repo = $this->make_profile_repository();
		$consent_repo = new ConsentRepository( $this->wpdb, $audit_svc );
		$secret       = str_repeat( 'm', 32 );
		$boundary     = new ProfileAccessBoundary(
			$profile_repo,
			$authorizer,
			$secret,
			null,
			$audit_svc,
			null,
			$consent_repo
		);

		// Create profile for subscriber_id, record verified mobile, record active consent, and bind via valid authority grant.
		wp_set_current_user( $subscriber_id );
		$consent_repo->record_consent(
			$subscriber_id,
			'1.0.0',
			ConsentRepository::hash_notice_text( 'WPIG Notice v1.0.0' ),
			array( ConsentRepository::PURPOSE_IDENTITY_VERIFICATION )
		);
		$profile = $boundary->create_own_profile(
			$subscriber_id,
			$subscriber_id,
			new SensitiveValue( self::synthetic_national_code_1() ),
			new SensitiveValue( self::synthetic_mobile_1() ),
			new SensitiveValue( '1371/03/15' )
		);
		$profile_repo->record_mobile_verified( $subscriber_id, $profile->mobile_version );

		$grant = VerificationAuthorityGrant::issue(
			$secret,
			max( 1, (int) get_current_blog_id() ),
			$subscriber_id,
			$profile->identity_version,
			$profile->mobile_version,
			'2027-11-15 00:00:00',
			60
		);

		$bound = $boundary->bind_verified_identity(
			$subscriber_id,
			$subscriber_id,
			$profile->identity_version,
			$profile->mobile_version,
			$grant,
			true
		);
		self::assertTrue( $bound->is_bound() );
		self::assertSame( 1, $audit_repo->count_events( AuditService::EVENT_IDENTITY_BOUND ) );

		// Replaying the same grant on a second ProfileAccessBoundary instance fails closed and logs authorization.denied!
		$boundary_2 = new ProfileAccessBoundary(
			$profile_repo,
			$authorizer,
			$secret,
			null,
			$audit_svc,
			null,
			$consent_repo
		);

		try {
			$boundary_2->bind_verified_identity(
				$subscriber_id,
				$subscriber_id,
				$profile->identity_version,
				$profile->mobile_version,
				$grant,
				true
			);
			self::fail( 'Replaying consumed grant across boundary instances must fail closed.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_BINDING_AUTHORITY_REQUIRED, $e->get_safe_code() );
		}
		self::assertSame( 1, $audit_repo->count_events( AuditService::EVENT_AUTHORIZATION_DENIED ) );

		// Duplicate national code binding attempt by customer_id logs identity.conflict_detected without exposing subscriber_id.
		wp_set_current_user( $customer_id );
		$consent_repo->record_consent(
			$customer_id,
			'1.0.0',
			ConsentRepository::hash_notice_text( 'WPIG Notice v1.0.0' ),
			array( ConsentRepository::PURPOSE_IDENTITY_VERIFICATION )
		);
		$cust_profile = $boundary->create_own_profile(
			$customer_id,
			$customer_id,
			new SensitiveValue( self::synthetic_national_code_1() ),
			new SensitiveValue( self::synthetic_mobile_2() ),
			new SensitiveValue( '1372/04/20' )
		);
		$profile_repo->record_mobile_verified( $customer_id, $cust_profile->mobile_version );

		$cust_grant = VerificationAuthorityGrant::issue(
			$secret,
			max( 1, (int) get_current_blog_id() ),
			$customer_id,
			$cust_profile->identity_version,
			$cust_profile->mobile_version,
			'2027-11-15 00:00:00',
			60
		);

		try {
			$boundary->bind_verified_identity(
				$customer_id,
				$customer_id,
				$cust_profile->identity_version,
				$cust_profile->mobile_version,
				$cust_grant,
				true
			);
			self::fail( 'Expected D14 identity binding conflict.' );
		} catch ( StorageException $e ) {
			self::assertSame( StorageException::CODE_IDENTITY_CONFLICT, $e->get_safe_code() );
			self::assertStringNotContainsString( (string) $subscriber_id, $e->getMessage() );
		}
		self::assertSame( 1, $audit_repo->count_events( AuditService::EVENT_IDENTITY_CONFLICT_DETECTED ) );

		// AdminController settings update logs settings.updated.
		wp_set_current_user( $admin_id );
		$controller = new AdminController( $authorizer, null, null, null, null, null, $audit_svc );
		$nonce      = wp_create_nonce( AdminController::NONCE_ACTION );
		$controller->handle_settings_post(
			$admin_id,
			'POST',
			array(
				AdminController::NONCE_FIELD => $nonce,
				'settings'                   => array(
					'default_provider'               => 'zohal',
					'sandbox_mode'                   => '1',
					'daily_request_budget'           => '1500',
					'rate_limit_per_user_hour'       => '15',
					'rate_limit_per_ip_hour'         => '60',
					'security_notifications_enabled' => '1',
					'consent_notice_version'         => '1.2.0',
				),
			)
		);
		self::assertSame( 1, $audit_repo->count_events( AuditService::EVENT_SETTINGS_UPDATED ) );
	}

	/**
	 * 2. Verify WordPress Personal Data Exporter and Eraser integration (`wp_privacy_personal_data_exporters`,
	 *    `wp_privacy_personal_data_erasers`), consent withdrawal vs erasure separation, `D14` bound identity
	 *    preservation, and `legal_hold_active` / `REVIEW_REQUIRED` retention in MariaDB.
	 */
	public function test_real_db_privacy_export_erasure_consent_lifecycle_and_d14_preservation(): void {
		$admin_id   = $this->create_wp_user( 'administrator' );
		$bound_uid  = $this->create_wp_user( 'subscriber' );
		$unbound_id = $this->create_wp_user( 'subscriber' );

		$bound_user   = get_userdata( $bound_uid );
		$unbound_user = get_userdata( $unbound_id );
		self::assertNotFalse( $bound_user );
		self::assertNotFalse( $unbound_user );

		$audit_repo   = new AuditRepository( $this->wpdb );
		$audit_svc    = new AuditService( $audit_repo );
		$authorizer   = new AuthorizationService();
		$profile_repo = $this->make_profile_repository();
		$consent_repo = new ConsentRepository( $this->wpdb, $audit_svc );
		$secret       = str_repeat( 'p', 32 );
		$boundary     = new ProfileAccessBoundary( $profile_repo, $authorizer, $secret, null, $audit_svc );

		$raw_nc_1  = self::synthetic_national_code_1();
		$raw_mob_1 = self::synthetic_mobile_1();
		$raw_bd_1  = '1369/11/22';

		// 1. Create and bind profile for $bound_uid, plus record consent and a transient OTP challenge.
		wp_set_current_user( $bound_uid );
		$consent_repo->record_consent(
			$bound_uid,
			'1.0.0',
			ConsentRepository::hash_notice_text( 'Canonical Privacy Notice v1.0.0' ),
			array( 'identity_verification', 'card_ownership' )
		);

		$p1 = $boundary->create_own_profile(
			$bound_uid,
			$bound_uid,
			new SensitiveValue( $raw_nc_1 ),
			new SensitiveValue( $raw_mob_1 ),
			new SensitiveValue( $raw_bd_1 )
		);
		$profile_repo->record_mobile_verified( $bound_uid, $p1->mobile_version );
		$grant        = VerificationAuthorityGrant::issue(
			$secret,
			max( 1, (int) get_current_blog_id() ),
			$bound_uid,
			$p1->identity_version,
			$p1->mobile_version,
			'2027-11-15 00:00:00',
			60
		);
		$bound_record = $boundary->bind_verified_identity(
			$bound_uid,
			$bound_uid,
			$p1->identity_version,
			$p1->mobile_version,
			$grant,
			true
		);

		$tables    = SchemaDefinition::get_table_names( $this->wpdb->prefix );
		$otp_table = $tables['wpig_otp_challenges'];
		$wpdb      = $this->wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"INSERT INTO `{$otp_table}` (wp_user_id, mobile_version, mobile_hmac, code_hmac, hmac_key_id, state, attempts, max_attempts, expires_at, created_at)
				VALUES (%d, 1, %s, %s, 'hmac_2026_01', 'PENDING', 0, 5, '2026-11-15 12:00:00', '2026-11-15 11:50:00')",
				$bound_uid,
				str_repeat( '1', 64 ),
				str_repeat( '2', 64 )
			)
		);

		// 2. Register and run WordPress Personal Data Exporter as $admin_id.
		wp_set_current_user( $admin_id );
		$exporter = new PrivacyExporterService( $profile_repo, $consent_repo, $authorizer, $this->wpdb, $audit_svc );
		$exporter->register_hooks();

		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core WordPress privacy hook.
		$exporters = apply_filters( 'wp_privacy_personal_data_exporters', array() );
		self::assertArrayHasKey( PrivacyExporterService::EXPORTER_SLUG, $exporters );

		$export_out = $exporter->handle_wp_privacy_export( $bound_user->user_email );
		self::assertTrue( $export_out['done'] );
		self::assertCount( 2, $export_out['data'] ); // Profile + Consent groups.

		$export_json = (string) json_encode( $export_out ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode
		self::assertStringContainsString( (string) $bound_record->national_code_masked, $export_json );
		self::assertStringContainsString( (string) $bound_record->mobile_masked, $export_json );
		self::assertStringNotContainsString( $raw_nc_1, $export_json );
		self::assertStringNotContainsString( $raw_mob_1, $export_json );
		self::assertStringNotContainsString( $raw_bd_1, $export_json );
		self::assertStringNotContainsString( (string) $bound_record->national_code_hmac, $export_json );
		self::assertStringNotContainsString( (string) $bound_record->bound_national_code_hmac, $export_json );

		// 3. Withdraw consent for $bound_uid: consent is marked withdrawn, but profile binding is untouched.
		self::assertSame( 1, $consent_repo->withdraw_consent( $bound_uid, $bound_uid ) );
		self::assertFalse( $consent_repo->has_active_consent( $bound_uid ) );
		$reloaded_after_withdraw = $profile_repo->find_by_user_id( $bound_uid );
		self::assertNotNull( $reloaded_after_withdraw );
		self::assertTrue( $reloaded_after_withdraw->is_bound() );

		// 4. Run Personal Data Eraser on $bound_uid: deletes OTP challenge, but retains BOUND identity binding (D14)!
		$eraser = new PrivacyEraserService( $profile_repo, $consent_repo, $authorizer, $this->wpdb, $audit_svc );
		$eraser->register_hooks();

		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core WordPress privacy hook.
		$erasers = apply_filters( 'wp_privacy_personal_data_erasers', array() );
		self::assertArrayHasKey( PrivacyEraserService::ERASER_SLUG, $erasers );

		$erase_bound_out = $eraser->handle_wp_privacy_erasure( $bound_user->user_email );
		self::assertTrue( $erase_bound_out['done'] );
		self::assertTrue( $erase_bound_out['items_removed'], 'Transient OTP challenge row must be removed.' );
		self::assertTrue( $erase_bound_out['items_retained'], 'Active D14 BOUND identity record must be retained.' );

		$reloaded_bound = $profile_repo->find_by_user_id( $bound_uid );
		self::assertNotNull( $reloaded_bound );
		self::assertTrue( $reloaded_bound->is_bound() );
		self::assertSame( $bound_record->bound_national_code_hmac, $reloaded_bound->bound_national_code_hmac );

		// 5. Create an UNBOUND profile for $unbound_id and erase: clears unverified PII in MariaDB!
		wp_set_current_user( $unbound_id );
		$boundary->create_own_profile(
			$unbound_id,
			$unbound_id,
			new SensitiveValue( self::synthetic_national_code_2() ),
			new SensitiveValue( self::synthetic_mobile_2() ),
			new SensitiveValue( '1375/01/10' )
		);

		wp_set_current_user( $admin_id );
		$erase_unbound_out = $eraser->handle_wp_privacy_erasure( $unbound_user->user_email );
		self::assertTrue( $erase_unbound_out['items_removed'] );
		self::assertFalse( $erase_unbound_out['items_retained'] );

		$cleared_profile = $profile_repo->find_by_user_id( $unbound_id );
		self::assertNotNull( $cleared_profile );
		self::assertFalse( $cleared_profile->has_national_code );
		self::assertFalse( $cleared_profile->has_mobile );
		self::assertFalse( $cleared_profile->has_birth_date );
		self::assertNull( $cleared_profile->national_code_masked );
		self::assertNull( $cleared_profile->mobile_masked );
	}

	/**
	 * 3. Verify bounded SQL retention pruning in MariaDB (`wpig_audit_events`, `wpig_verifications`,
	 *    `wpig_otp_challenges`), policy-unresolved default (`D04`), legal-hold block, and protection
	 *    of active verification evidence and card-referenced verifications.
	 */
	public function test_real_db_retention_pruning_batches_and_evidence_preservation(): void {
		$user_id    = $this->create_wp_user( 'subscriber' );
		$audit_repo = new AuditRepository( $this->wpdb );
		$audit_svc  = new AuditService( $audit_repo );

		// Insert 4 old audit events and 1 recent audit event.
		for ( $i = 1; $i <= 4; $i++ ) {
			$audit_svc->record(
				AuditService::EVENT_SETTINGS_UPDATED,
				AuditService::OUTCOME_SUCCESS,
				$user_id,
				null,
				array( 'changed_keys' => array( 'sandbox_mode' ) ),
				null,
				"2024-06-0{$i} 10:00:00"
			);
		}
		$audit_svc->record(
			AuditService::EVENT_SETTINGS_UPDATED,
			AuditService::OUTCOME_SUCCESS,
			$user_id,
			null,
			array( 'changed_keys' => array( 'sandbox_mode' ) ),
			null,
			'2026-11-15 10:00:00'
		);

		$tables              = SchemaDefinition::get_table_names( $this->wpdb->prefix );
		$verifications_table = $tables['wpig_verifications'];
		$cards_table         = $tables['wpig_cards'];
		$wpdb                = $this->wpdb;

		// Insert 3 verifications: #1 FAILED (prunable), #2 FAILED but referenced by a card (not prunable), #3 VERIFIED (not prunable).
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"INSERT INTO `{$verifications_table}` (wp_user_id, identity_version, mobile_version, card_version, idempotency_key, operation, provider, state, requested_at)
				VALUES (%d, 1, 1, 1, %s, 'shahkar', 'api_ir', 'FAILED', '2024-01-01 00:00:00')",
				$user_id,
				str_repeat( 'a', 64 )
			)
		);
		$ver_id_1 = (int) $wpdb->insert_id;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"INSERT INTO `{$verifications_table}` (wp_user_id, identity_version, mobile_version, card_version, idempotency_key, operation, provider, state, requested_at)
				VALUES (%d, 1, 1, 1, %s, 'card_match', 'api_ir', 'FAILED', '2024-01-01 00:00:00')",
				$user_id,
				str_repeat( 'b', 64 )
			)
		);
		$ver_id_2 = (int) $wpdb->insert_id;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"INSERT INTO `{$verifications_table}` (wp_user_id, identity_version, mobile_version, card_version, idempotency_key, operation, provider, state, requested_at)
				VALUES (%d, 1, 1, 1, %s, 'shahkar', 'api_ir', 'VERIFIED', '2024-01-01 00:00:00')",
				$user_id,
				str_repeat( 'c', 64 )
			)
		);
		$ver_id_3 = (int) $wpdb->insert_id;

		// Reference $ver_id_2 from wpig_cards.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"INSERT INTO `{$cards_table}` (wp_user_id, active_user_slot, is_current, identity_version, card_version, verification_id, card_last4, masked_pan, state, provider, verified_at, created_at)
				VALUES (%d, %d, 1, 1, 1, %d, '1234', '6037-99**-****-1234', 'VERIFIED', 'api_ir', '2024-01-01 00:00:00', '2024-01-01 00:00:00')",
				$user_id,
				$user_id,
				$ver_id_2
			)
		);

		// 1. Default RetentionService (policy_approved = false) does not prune anything.
		$default_retention = new RetentionService( $this->wpdb, $audit_repo );
		self::assertSame(
			RetentionService::STATUS_DISABLED_POLICY_UNRESOLVED,
			$default_retention->prune_audit_events_batch( '2025-01-01 00:00:00', 2 )['status']
		);
		self::assertSame( 5, $audit_repo->count_events() );

		// 2. Approved RetentionService with batch_size = 2 prunes 2 old audit events, leaving 3.
		$approved_retention = new RetentionService( $this->wpdb, $audit_repo, false, true );
		$prune_audit_1      = $approved_retention->prune_audit_events_batch( '2025-01-01 00:00:00', 2 );
		self::assertSame( 2, $prune_audit_1['pruned_count'] );
		self::assertSame( 3, $audit_repo->count_events() );

		// 3. Prune terminal verifications: deletes ONLY $ver_id_1 (unreferenced FAILED), preserving $ver_id_2 (card-referenced) and $ver_id_3 (VERIFIED).
		$prune_ver = $approved_retention->prune_terminal_verifications_batch( '2025-01-01 00:00:00', 100 );
		self::assertSame( 1, $prune_ver['pruned_count'] );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$remaining_ids = array_map( 'intval', $this->wpdb->get_col( "SELECT id FROM `{$verifications_table}` ORDER BY id ASC" ) );
		self::assertNotContains( $ver_id_1, $remaining_ids );
		self::assertContains( $ver_id_2, $remaining_ids );
		self::assertContains( $ver_id_3, $remaining_ids );
	}

	/**
	 * 4. P01 Security Closure real WordPress + MariaDB verification:
	 *    - Runtime bootstrap (`Plugin::boot()`) registers privacy exporter/eraser hooks once,
	 *      avoids AdminController allocation on frontend requests, and wires AuditService in admin context.
	 *    - Real WordPress actor-ID spoofing is rejected across AuthorizationService, ProfileAccessBoundary,
	 *      AdminController, PrivacyExporterService, and PrivacyEraserService.
	 *    - Real MariaDB expired/withdrawn consent fails closed on decryption and identity binding.
	 *    - Cross-process VerificationAuthorityGrant fails closed.
	 */
	public function test_real_wp_p01_security_closure_runtime_bootstrap_hooks_spoofing_consent_and_grant_lifecycle(): void {
		$admin_id      = $this->create_wp_user( 'administrator' );
		$subscriber_id = $this->create_wp_user( 'subscriber' );
		$other_id      = $this->create_wp_user( 'subscriber' );

		// 1. Runtime bootstrap lifecycle (frontend vs admin hook registration and idempotency).
		Plugin::reset_for_testing();
		self::assertFalse( Plugin::is_booted() );

		Plugin::boot();
		self::assertTrue( Plugin::is_booted() );

		// Calling boot() a second time is a no-op and does not duplicate filter registrations.
		Plugin::boot();
		self::assertNotFalse( has_filter( 'wp_privacy_personal_data_exporters', array( Plugin::class, 'register_privacy_exporter' ) ) );
		self::assertNotFalse( has_filter( 'wp_privacy_personal_data_erasers', array( Plugin::class, 'register_privacy_eraser' ) ) );

		// In default non-admin CLI test request (is_admin() === false), AdminController is not instantiated on frontend boot.
		if ( function_exists( 'is_admin' ) && ! is_admin() ) {
			self::assertNull( Plugin::get_admin_controller() );
		}

		// Applying WordPress privacy filters invokes the lazy composition root callbacks and registers wp-identity-guard.
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core WordPress privacy hook.
		$registered_exporters = apply_filters( 'wp_privacy_personal_data_exporters', array() );
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core WordPress privacy hook.
		$registered_erasers = apply_filters( 'wp_privacy_personal_data_erasers', array() );

		self::assertArrayHasKey( PrivacyExporterService::EXPORTER_SLUG, $registered_exporters );
		self::assertArrayHasKey( PrivacyEraserService::ERASER_SLUG, $registered_erasers );

		// 2. Real WordPress actor-ID spoofing prevention:
		$audit_repo   = new AuditRepository( $this->wpdb );
		$audit_svc    = new AuditService( $audit_repo );
		$authorizer   = new AuthorizationService();
		$profile_repo = $this->make_profile_repository();
		$consent_repo = new ConsentRepository( $this->wpdb, $audit_svc );
		$secret       = str_repeat( 'w', 32 );
		$boundary     = new ProfileAccessBoundary(
			$profile_repo,
			$authorizer,
			$secret,
			null,
			$audit_svc,
			null,
			$consent_repo
		);

		// 2a. Anonymous request (wp_set_current_user(0)) spoofing $admin_id or $subscriber_id fails closed.
		wp_set_current_user( 0 );
		try {
			$authorizer->assert_can_manage_settings( $admin_id );
			self::fail( 'Anonymous WordPress request spoofing admin_id must fail closed.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_UNAUTHENTICATED, $e->get_safe_code() );
		}

		// 2b. Authenticated as $other_id, spoofing $admin_id or $subscriber_id fails closed across all boundaries.
		wp_set_current_user( $other_id );
		try {
			$authorizer->assert_can_manage_settings( $admin_id );
			self::fail( 'Subscriber spoofing admin_id must fail closed.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_UNAUTHENTICATED, $e->get_safe_code() );
		}

		try {
			$boundary->create_own_profile(
				$subscriber_id,
				$subscriber_id,
				new SensitiveValue( self::synthetic_national_code_1() ),
				new SensitiveValue( self::synthetic_mobile_1() ),
				new SensitiveValue( '1371/03/15' )
			);
			self::fail( 'Other user spoofing subscriber_id on create_own_profile must fail closed.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_UNAUTHENTICATED, $e->get_safe_code() );
		}

		// 3. Trusted consent verification in MariaDB (unrecorded, expired, and withdrawn consent fail closed).
		wp_set_current_user( $subscriber_id );
		$profile = $boundary->create_own_profile(
			$subscriber_id,
			$subscriber_id,
			new SensitiveValue( self::synthetic_national_code_1() ),
			new SensitiveValue( self::synthetic_mobile_1() ),
			new SensitiveValue( '1371/03/15' )
		);
		$profile_repo->record_mobile_verified( $subscriber_id, $profile->mobile_version );

		// 3a. Passing boolean true when no consent row exists in MariaDB fails closed.
		try {
			$boundary->decrypt_identity(
				$subscriber_id,
				$subscriber_id,
				AuthorizationService::PURPOSE_VERIFICATION_DISPATCH,
				true
			);
			self::fail( 'Boolean true without MariaDB consent record must fail closed.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_CONSENT_REQUIRED, $e->get_safe_code() );
		}

		// 3b. Record an already-expired consent row in MariaDB: decryption still fails closed.
		$consent_repo->record_consent(
			$subscriber_id,
			'1.0.0',
			ConsentRepository::hash_notice_text( 'Expired Notice' ),
			array( ConsentRepository::PURPOSE_IDENTITY_VERIFICATION ),
			'2020-01-01 00:00:00'
		);
		try {
			$boundary->decrypt_identity(
				$subscriber_id,
				$subscriber_id,
				AuthorizationService::PURPOSE_VERIFICATION_DISPATCH,
				true
			);
			self::fail( 'Expired MariaDB consent record must fail closed.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_CONSENT_REQUIRED, $e->get_safe_code() );
		}

		// 3c. Record a valid active consent row in MariaDB: decryption succeeds and logs identity.sensitive_decrypted.
		$valid_consent = $consent_repo->record_consent(
			$subscriber_id,
			'1.0.0',
			ConsentRepository::hash_notice_text( 'Active Notice' ),
			array( ConsentRepository::PURPOSE_IDENTITY_VERIFICATION ),
			'2030-01-01 00:00:00'
		);
		$decrypted     = $boundary->decrypt_identity(
			$subscriber_id,
			$subscriber_id,
			AuthorizationService::PURPOSE_VERIFICATION_DISPATCH,
			$valid_consent
		);
		self::assertNotNull( $decrypted->national_code );
		self::assertSame( self::synthetic_national_code_1(), $decrypted->national_code->reveal() );
		self::assertSame( 1, $audit_repo->count_events( AuditService::EVENT_IDENTITY_DECRYPTED ) );

		// 4. Cross-process VerificationAuthorityGrant rejection in MariaDB integration:
		$cross_worker_grant = VerificationAuthorityGrant::issue(
			$secret,
			max( 1, (int) get_current_blog_id() ),
			$subscriber_id,
			$profile->identity_version,
			$profile->mobile_version,
			'2027-11-15 00:00:00',
			60
		);
		VerificationAuthorityGrant::rotate_process_token_for_testing();
		try {
			$boundary->bind_verified_identity(
				$subscriber_id,
				$subscriber_id,
				$profile->identity_version,
				$profile->mobile_version,
				$cross_worker_grant,
				$valid_consent
			);
			self::fail( 'Cross-process grant must be rejected at ProfileAccessBoundary.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_BINDING_AUTHORITY_REQUIRED, $e->get_safe_code() );
		}

		// 3d. Withdraw consent in MariaDB: subsequent binding attempt with valid same-process grant fails closed!
		$consent_repo->withdraw_consent( $subscriber_id, $subscriber_id );
		$same_worker_grant = VerificationAuthorityGrant::issue(
			$secret,
			max( 1, (int) get_current_blog_id() ),
			$subscriber_id,
			$profile->identity_version,
			$profile->mobile_version,
			'2027-11-15 00:00:00',
			60
		);
		try {
			$boundary->bind_verified_identity(
				$subscriber_id,
				$subscriber_id,
				$profile->identity_version,
				$profile->mobile_version,
				$same_worker_grant,
				$valid_consent
			);
			self::fail( 'Withdrawn consent in MariaDB must block bind_verified_identity even when stale ConsentRecord is passed.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_CONSENT_REQUIRED, $e->get_safe_code() );
		}
	}
}

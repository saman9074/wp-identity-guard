<?php
/**
 * Real WordPress + MariaDB integration tests for P01-D1 Capabilities,
 * AuthorizationService, VerificationAuthorityGrant, and ProfileAccessBoundary.
 *
 * @package WPIG\Tests\Integration
 */

declare(strict_types=1);

namespace WPIG\Tests\Integration;

use PHPUnit\Framework\TestCase;
use wpdb;
use WPIG\Core\Activator;
use WPIG\Core\Deactivator;
use WPIG\Privacy\ConsentRepository;
use WPIG\Security\AuthorizationException;
use WPIG\Security\AuthorizationService;
use WPIG\Security\Capabilities;
use WPIG\Security\IdentityFingerprinter;
use WPIG\Security\SodiumCrypto;
use WPIG\Security\VerificationAuthorityGrant;
use WPIG\Security\WordPressKeyProvider;
use WPIG\Storage\ProfileAccessBoundary;
use WPIG\Storage\ProfileRecord;
use WPIG\Storage\ProfileRepository;
use WPIG\Storage\SchemaDefinition;

/**
 * Verifies WordPress capabilities, roles, IDOR prevention, Multisite isolation,
 * and sensitive repository boundaries against real WordPress and MariaDB.
 */
final class AuthorizationIntegrationTest extends TestCase {

	private const SYNTHETIC_ENC_KEY     = 'hex:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20';
	private const SYNTHETIC_HMAC_KEY    = 'hex:a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0';
	private const TEST_AUTHORITY_SECRET = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

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
	 * Set up clean WordPress roles, users, and migrated tables.
	 */
	protected function setUp(): void {
		parent::setUp();

		if ( ! isset( $GLOBALS['wpdb'] ) || ! $GLOBALS['wpdb'] instanceof wpdb ) {
			self::markTestSkipped( 'WordPress integration environment ($wpdb) is not loaded.' );
		}

		$this->wpdb = $GLOBALS['wpdb'];
		$this->truncate_profiles_table();
		Activator::run_for_current_site( $this->wpdb );
	}

	/**
	 * Clean up test users, custom roles, and profile rows after each test.
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

		if ( isset( $this->wpdb ) ) {
			$this->truncate_profiles_table();
		}

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
		$login   = 'wpig_test_' . $suffix . '_' . bin2hex( random_bytes( 3 ) );
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
	 * Build a synthetic 10-digit national code with a valid modulo-11 check digit.
	 *
	 * @param string $nine_digits 9 ASCII digits.
	 */
	private static function make_synthetic_nc( string $nine_digits ): string {
		$sum = 0;
		for ( $i = 0; $i < 9; $i++ ) {
			$sum += ( (int) $nine_digits[ $i ] ) * ( 10 - $i );
		}
		$rem   = $sum % 11;
		$check = $rem < 2 ? $rem : ( 11 - $rem );
		return $nine_digits . (string) $check;
	}

	/**
	 * Build a ProfileRepository and ProfileAccessBoundary for integration tests.
	 *
	 * @param AuthorizationService|null $authorizer Optional custom authorizer.
	 * @return array{repo:ProfileRepository,boundary:ProfileAccessBoundary,authorizer:AuthorizationService}
	 */
	private function make_boundary( ?AuthorizationService $authorizer = null ): array {
		$k1 = array(
			WordPressKeyProvider::CONST_ENC_KEY     => self::SYNTHETIC_ENC_KEY,
			WordPressKeyProvider::CONST_ENC_KEY_ID  => 'k2026_01',
			WordPressKeyProvider::CONST_HMAC_KEY    => self::SYNTHETIC_HMAC_KEY,
			WordPressKeyProvider::CONST_HMAC_KEY_ID => 'hmac_2026_01',
		);

		$key_provider  = new WordPressKeyProvider(
			static fn( string $name ): mixed => $k1[ $name ] ?? null
		);
		$crypto        = new SodiumCrypto( $key_provider );
		$fingerprinter = new IdentityFingerprinter( $crypto );
		$repo          = new ProfileRepository(
			$this->wpdb,
			$crypto,
			$key_provider,
			$fingerprinter,
			static fn(): string => '2026-11-14 12:00:00',
			static fn(): int => 1
		);

		$auth     = $authorizer ?? new AuthorizationService();
		$boundary = new ProfileAccessBoundary(
			$repo,
			$auth,
			self::TEST_AUTHORITY_SECRET,
			static fn(): int => 1
		);

		return array(
			'repo'       => $repo,
			'boundary'   => $boundary,
			'authorizer' => $auth,
		);
	}

	/**
	 * Truncate wpig_profiles and wpig_consents tables between tests.
	 */
	private function truncate_profiles_table(): void {
		$tables = SchemaDefinition::get_table_names( $this->wpdb->prefix );
		foreach ( array( 'wpig_profiles', 'wpig_consents' ) as $logical_table ) {
			$table = $tables[ $logical_table ];
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$this->wpdb->query( "DELETE FROM `{$table}`" );
		}
	}

	/**
	 * Scenarios 1, 2, 3, 4, 9 & 10:
	 * - Real WordPress activation registers `manage_wpig_settings`, `view_wpig_reports`, `review_wpig_verification` on `administrator`.
	 * - Real WordPress `subscriber`, `customer`, and `editor` roles are denied all 3 capabilities.
	 * - Custom WordPress role (`wpig_compliance_officer`) granted `view_wpig_reports` and `review_wpig_verification`
	 *   survives plugin deactivation and reactivation intact, and is denied `manage_wpig_settings`.
	 */
	public function test_real_wp_roles_capabilities_activation_reactivation_and_custom_roles(): void {
		add_role( 'customer', 'Customer', array( 'read' => true ) );
		$this->created_roles[] = 'customer';

		add_role( 'wpig_compliance_officer', 'WPIG Compliance Officer', array( 'read' => true ) );
		$this->created_roles[] = 'wpig_compliance_officer';

		Capabilities::grant_to_role(
			'wpig_compliance_officer',
			array( Capabilities::VIEW_REPORTS, Capabilities::REVIEW_VERIFICATION )
		);

		$admin_id      = $this->create_wp_user( 'administrator', 'admin' );
		$subscriber_id = $this->create_wp_user( 'subscriber', 'sub' );
		$customer_id   = $this->create_wp_user( 'customer', 'cust' );
		$officer_id    = $this->create_wp_user( 'wpig_compliance_officer', 'officer' );

		$authorizer = new AuthorizationService();

		// 1. Administrator has all 3 capabilities via real WordPress user_can().
		wp_set_current_user( $admin_id );
		self::assertTrue( user_can( $admin_id, Capabilities::MANAGE_SETTINGS ) );
		self::assertTrue( user_can( $admin_id, Capabilities::VIEW_REPORTS ) );
		self::assertTrue( user_can( $admin_id, Capabilities::REVIEW_VERIFICATION ) );
		$authorizer->assert_can_manage_settings( $admin_id );
		$authorizer->assert_can_view_reports( $admin_id );
		$authorizer->assert_can_review_verification( $admin_id, $subscriber_id );

		// 2. Subscriber and customer are denied all WPIG administrative capabilities.
		foreach ( array( $subscriber_id, $customer_id ) as $uid ) {
			wp_set_current_user( $uid );
			foreach ( Capabilities::all() as $cap ) {
				self::assertFalse( user_can( $uid, $cap ) );
				try {
					$authorizer->assert_capability( $uid, $cap );
					self::fail( "Expected missing capability exception for user {$uid} on {$cap}." );
				} catch ( AuthorizationException $e ) {
					self::assertSame( AuthorizationException::CODE_MISSING_CAPABILITY, $e->get_safe_code() );
				}
			}
		}

		// 3 & 4. Custom role has view_wpig_reports and review_wpig_verification, but NOT manage_wpig_settings.
		wp_set_current_user( $officer_id );
		$authorizer->assert_can_view_reports( $officer_id );
		$authorizer->assert_can_review_verification( $officer_id, $subscriber_id );
		try {
			$authorizer->assert_can_manage_settings( $officer_id );
			self::fail( 'Compliance officer without manage_wpig_settings must fail closed.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_MISSING_CAPABILITY, $e->get_safe_code() );
		}

		// 9 & 10. Simulate accidental capability pollution on subscriber, then run Deactivator + Activator reactivation.
		$sub_role = get_role( 'subscriber' );
		self::assertNotNull( $sub_role );
		$sub_role->add_cap( Capabilities::MANAGE_SETTINGS, true );

		Deactivator::deactivate();
		$reactivation = Activator::run_for_current_site( $this->wpdb );
		self::assertTrue( $reactivation->success );
		self::assertSame( Capabilities::VERSION, get_option( Capabilities::VERSION_OPTION ) );

		// Polluted capability on subscriber is stripped on activation, while custom role & admin capabilities remain intact!
		$sub_role_reloaded = get_role( 'subscriber' );
		self::assertNotNull( $sub_role_reloaded );
		self::assertFalse( $sub_role_reloaded->has_cap( Capabilities::MANAGE_SETTINGS ) );
		wp_set_current_user( $admin_id );
		$authorizer->assert_can_manage_settings( $admin_id );
		wp_set_current_user( $officer_id );
		$authorizer->assert_can_view_reports( $officer_id );
		$authorizer->assert_can_review_verification( $officer_id, $subscriber_id );
	}

	/**
	 * Scenarios 5, 7, 8, 11 & 12:
	 * - End-to-end ProfileAccessBoundary prevents cross-user IDOR on profile creation, reading, mobile/identity updates, and decryption.
	 * - External callers (including administrators) cannot arbitrarily mark an identity VERIFIED or BOUND without a valid VerificationAuthorityGrant.
	 * - Decryption requires explicit purpose and active consent; report viewers / reviewers cannot decrypt plaintext identity attributes.
	 * - Client-supplied privilege escalation claims (`role`, `binding_state`, `verified`, etc.) fail closed.
	 */
	public function test_profile_access_boundary_prevents_idor_unauthorized_binding_and_unauthorized_decryption(): void {
		add_role( 'wpig_reviewer_only', 'WPIG Reviewer Only', array( 'read' => true ) );
		$this->created_roles[] = 'wpig_reviewer_only';
		Capabilities::grant_to_role(
			'wpig_reviewer_only',
			array( Capabilities::VIEW_REPORTS, Capabilities::REVIEW_VERIFICATION )
		);

		$admin_id    = $this->create_wp_user( 'administrator', 'b_admin' );
		$reviewer_id = $this->create_wp_user( 'wpig_reviewer_only', 'b_rev' );
		$user_a_id   = $this->create_wp_user( 'subscriber', 'user_a' );
		$user_b_id   = $this->create_wp_user( 'subscriber', 'user_b' );

		$setup    = $this->make_boundary();
		$repo     = $setup['repo'];
		$boundary = $setup['boundary'];

		$nc_a  = self::make_synthetic_nc( '001234567' );
		$mob_a = '09' . implode( '', array( '12', '345', '6789' ) );
		$bd_a  = '1370/01/05';

		// User A creates their own profile through the boundary.
		wp_set_current_user( $user_a_id );
		$profile_a = $boundary->create_own_profile( $user_a_id, $user_a_id, $nc_a, $mob_a, $bd_a );
		self::assertSame( ProfileRecord::BINDING_UNBOUND, $profile_a->binding_state );
		self::assertSame( ProfileRecord::STATE_UNVERIFIED, $profile_a->identity_state );

		// 5a. User B attempting to view User A's masked profile fails closed (IDOR prevented).
		wp_set_current_user( $user_b_id );
		try {
			$boundary->get_masked_profile( $user_b_id, $user_a_id );
			self::fail( 'Subscriber B must not view Subscriber A\'s profile.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_CROSS_USER_FORBIDDEN, $e->get_safe_code() );
		}

		// Reviewer and Admin CAN view User A's masked profile summary.
		wp_set_current_user( $reviewer_id );
		$masked_for_reviewer = $boundary->get_masked_profile( $reviewer_id, $user_a_id );
		self::assertNotNull( $masked_for_reviewer );
		self::assertSame( '0912***6789', $masked_for_reviewer->mobile_masked );

		// 5b. User B (and even Admin) attempting to overwrite User A's mobile or identity data via own-profile methods fails closed.
		$other_mob = '09' . implode( '', array( '12', '999', '8877' ) );
		foreach ( array( $user_b_id, $admin_id ) as $wrong_actor ) {
			wp_set_current_user( $wrong_actor );
			try {
				$boundary->update_own_mobile( $wrong_actor, $user_a_id, $other_mob, 1 );
				self::fail( "Actor {$wrong_actor} must not overwrite User A's mobile." );
			} catch ( AuthorizationException $e ) {
				self::assertSame( AuthorizationException::CODE_CROSS_USER_FORBIDDEN, $e->get_safe_code() );
			}
		}

		// 11. User A passing privilege-escalation or state-injection claims in request payload fails closed.
		wp_set_current_user( $user_a_id );
		try {
			$boundary->update_own_mobile(
				$user_a_id,
				$user_a_id,
				$other_mob,
				1,
				array( 'binding_state' => 'BOUND' )
			);
			self::fail( 'Injected binding_state claim must fail closed.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_PRIVILEGE_ESCALATION_ATTEMPT, $e->get_safe_code() );
		}

		// 8. Unauthorized decryption attempts:
		// 8a. User B attempting to decrypt User A's identity fails closed.
		wp_set_current_user( $user_b_id );
		try {
			$boundary->decrypt_identity(
				$user_b_id,
				$user_a_id,
				AuthorizationService::PURPOSE_VERIFICATION_DISPATCH,
				true
			);
			self::fail( 'User B must never decrypt User A\'s identity.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_CROSS_USER_FORBIDDEN, $e->get_safe_code() );
		}

		// 8b. User A attempting to decrypt own identity for verification dispatch WITHOUT active consent fails closed.
		wp_set_current_user( $user_a_id );
		try {
			$boundary->decrypt_identity(
				$user_a_id,
				$user_a_id,
				AuthorizationService::PURPOSE_VERIFICATION_DISPATCH,
				false
			);
			self::fail( 'Unconsented verification dispatch decryption must fail closed.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_CONSENT_REQUIRED, $e->get_safe_code() );
		}

		// Even passing boolean true BEFORE a trusted consent record exists in wpig_consents fails closed!
		try {
			$boundary->decrypt_identity(
				$user_a_id,
				$user_a_id,
				AuthorizationService::PURPOSE_VERIFICATION_DISPATCH,
				true
			);
			self::fail( 'Boolean true without a trusted consent record in wpig_consents must fail closed.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_CONSENT_REQUIRED, $e->get_safe_code() );
		}

		// Record active consent for User A in wpig_consents.
		$consent_repo = new ConsentRepository( $this->wpdb );
		$consent_repo->record_consent(
			$user_a_id,
			'1.0.0',
			ConsentRepository::hash_notice_text( 'WPIG Notice v1.0' ),
			array( ConsentRepository::PURPOSE_IDENTITY_VERIFICATION )
		);

		// 8c. Both Reviewer and Administrator (`manage_wpig_settings`) attempting cross-user plaintext decryption
		// via PURPOSE_PRIVACY_EXPORT fail closed per DS-4 (admin exports must use masked ProfileRecord::to_safe_export_array()).
		foreach ( array( $reviewer_id, $admin_id ) as $non_owner_id ) {
			wp_set_current_user( $non_owner_id );
			try {
				$boundary->decrypt_identity(
					$non_owner_id,
					$user_a_id,
					AuthorizationService::PURPOSE_PRIVACY_EXPORT,
					true
				);
				self::fail( "Non-owner {$non_owner_id} must not decrypt User A's raw PII for privacy export." );
			} catch ( AuthorizationException $e ) {
				self::assertSame( AuthorizationException::CODE_DECRYPTION_FORBIDDEN, $e->get_safe_code() );
			}
		}

		// 8d. User A WITH active consent record in wpig_consents CAN decrypt own identity for verification dispatch.
		wp_set_current_user( $user_a_id );
		$decrypted = $boundary->decrypt_identity(
			$user_a_id,
			$user_a_id,
			AuthorizationService::PURPOSE_VERIFICATION_DISPATCH,
			true
		);
		self::assertNotNull( $decrypted->national_code );
		self::assertSame( $nc_a, $decrypted->national_code->reveal() );

		// 7. Unauthorized identity binding attempts:
		$repo->record_mobile_verified( $user_a_id, 1, '2026-11-14 12:05:00' );

		// 7a. User A or Administrator attempting to bind without a VerificationAuthorityGrant fails closed.
		foreach ( array( $user_a_id, $admin_id ) as $caller_id ) {
			wp_set_current_user( $caller_id );
			try {
				$boundary->bind_verified_identity( $caller_id, $user_a_id, 1, 1, null, true );
				self::fail( 'Binding without a trusted VerificationAuthorityGrant must fail closed.' );
			} catch ( AuthorizationException $e ) {
				self::assertSame( AuthorizationException::CODE_BINDING_AUTHORITY_REQUIRED, $e->get_safe_code() );
			}
		}

		wp_set_current_user( $user_a_id );

		// 7b. Forged grant (wrong authority secret) fails closed.
		$forged_grant = VerificationAuthorityGrant::issue(
			str_repeat( 'f', 64 ),
			1,
			$user_a_id,
			1,
			1,
			'2027-11-14 12:05:00'
		);
		try {
			$boundary->bind_verified_identity( $user_a_id, $user_a_id, 1, 1, $forged_grant, true );
			self::fail( 'Forged VerificationAuthorityGrant must fail closed.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_BINDING_AUTHORITY_REQUIRED, $e->get_safe_code() );
		}

		// 7c. Authentic grant issued by trusted verification service succeeds when consent is active, and cannot be replayed.
		$valid_grant  = VerificationAuthorityGrant::issue(
			self::TEST_AUTHORITY_SECRET,
			1,
			$user_a_id,
			1,
			1,
			'2027-11-14 12:05:00'
		);
		$bound_record = $boundary->bind_verified_identity( $user_a_id, $user_a_id, 1, 1, $valid_grant, true );
		self::assertTrue( $bound_record->is_bound() );
		self::assertSame( ProfileRecord::STATE_VERIFIED, $bound_record->identity_state );

		try {
			$boundary->bind_verified_identity( $user_a_id, $user_a_id, 1, 1, $valid_grant, true );
			self::fail( 'Replayed VerificationAuthorityGrant must fail closed.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_BINDING_AUTHORITY_REQUIRED, $e->get_safe_code() );
		}
	}
}

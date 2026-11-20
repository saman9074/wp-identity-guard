<?php
/**
 * Unit tests for P01-D1 Capabilities, AuthorizationService, VerificationAuthorityGrant,
 * and sensitive repository boundaries.
 *
 * @package WPIG\Tests\Unit
 */

declare(strict_types=1);

namespace WPIG\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPIG\Privacy\ConsentRecord;
use WPIG\Privacy\ConsentRepository;
use WPIG\Security\AuthenticationContext;
use WPIG\Security\AuthorizationException;
use WPIG\Security\AuthorizationService;
use WPIG\Security\Capabilities;
use WPIG\Security\SensitiveValue;
use WPIG\Security\VerificationAuthorityGrant;

/**
 * Verifies all 12 P01-D1 authorization and capability requirements in pure unit tests.
 */
final class AuthorizationAndCapabilitiesTest extends TestCase {

	/**
	 * Active server-authenticated principal ID in unit tests.
	 *
	 * @var int
	 */
	private int $current_user_id = 1;

	/**
	 * Build an in-memory WP_Roles-compatible stub for testing capability registration and custom roles.
	 *
	 * @param array<string,array<string,bool>> $initial_roles Map of role_slug => capabilities.
	 * @return object
	 */
	private function make_roles_stub( array $initial_roles ): object {
		return new class( $initial_roles ) {
			/**
			 * Role objects keyed by slug.
			 *
			 * @var array<string,object>
			 */
			public array $roles = array();

			/**
			 * Constructor.
			 *
			 * @param array<string,array<string,bool>> $initial_roles Initial role map.
			 */
			public function __construct( array $initial_roles ) {
				foreach ( $initial_roles as $slug => $caps ) {
					$this->roles[ $slug ] = new class( $slug, $caps ) {
						/**
						 * Role slug.
						 *
						 * @var string
						 */
						public string $name;

						/**
						 * Capabilities map.
						 *
						 * @var array<string,bool>
						 */
						public array $capabilities;

						/**
						 * Count of add_cap invocations.
						 *
						 * @var int
						 */
						public int $add_cap_calls = 0;

						/**
						 * Count of remove_cap invocations.
						 *
						 * @var int
						 */
						public int $remove_cap_calls = 0;

						/**
						 * Constructor.
						 *
						 * @param string             $name Role slug.
						 * @param array<string,bool> $caps Capabilities map.
						 */
						public function __construct( string $name, array $caps ) {
							$this->name         = $name;
							$this->capabilities = $caps;
						}

						/**
						 * Grant a capability to this role.
						 *
						 * @param string $cap   Capability slug.
						 * @param bool   $grant Grant flag.
						 */
						public function add_cap( string $cap, bool $grant = true ): void {
							++$this->add_cap_calls;
							$this->capabilities[ $cap ] = $grant;
						}

						/**
						 * Remove a capability from this role.
						 *
						 * @param string $cap Capability slug.
						 */
						public function remove_cap( string $cap ): void {
							++$this->remove_cap_calls;
							unset( $this->capabilities[ $cap ] );
						}

						/**
						 * Check whether this role holds a capability.
						 *
						 * @param string $cap Capability slug.
						 */
						public function has_cap( string $cap ): bool {
							return isset( $this->capabilities[ $cap ] ) && true === $this->capabilities[ $cap ];
						}
					};
				}
			}

			/**
			 * Retrieve a role object by slug.
			 *
			 * @param string $slug Role slug.
			 */
			public function get_role( string $slug ): ?object {
				return $this->roles[ $slug ] ?? null;
			}
		};
	}

	/**
	 * Build a configured AuthorizationService over an in-memory user directory.
	 *
	 * @param array<int,array{roles:list<string>,caps:list<string>,blogs?:list<int>}> $users        User map.
	 * @param int                                                                     $blog_id      Active blog ID.
	 * @param bool                                                                    $is_multisite Whether Multisite is enabled.
	 * @param array<string,list<string>>|null                                         $role_caps    Optional map of role_slug => granted capabilities.
	 */
	private function make_authorizer(
		array $users,
		int $blog_id = 1,
		bool $is_multisite = false,
		?array $role_caps = null
	): AuthorizationService {
		return new AuthorizationService(
			static fn( int $uid ): bool => isset( $users[ $uid ] ),
			static fn( int $uid, string $cap ): bool => isset( $users[ $uid ] )
				&& in_array( $cap, $users[ $uid ]['caps'], true ),
			static fn( int $uid ): array => $users[ $uid ]['roles'] ?? array(),
			static fn(): int => $blog_id,
			static fn(): bool => $is_multisite,
			static function ( int $uid, int $b_id ) use ( $users ): bool {
				if ( ! isset( $users[ $uid ] ) ) {
					return false;
				}
				$blogs = $users[ $uid ]['blogs'] ?? array( 1 );
				return in_array( $b_id, $blogs, true );
			},
			static function ( string $role_slug, string $cap ) use ( $role_caps ): bool {
				if ( null === $role_caps ) {
					return ! Capabilities::is_disallowed_role( $role_slug );
				}
				return isset( $role_caps[ $role_slug ] ) && in_array( $cap, $role_caps[ $role_slug ], true );
			},
			AuthenticationContext::wordpress_request( fn(): int => $this->current_user_id )
		);
	}

	/**
	 * Scenarios 1, 2, 3, 9 & 10:
	 * - Administrator receives all 3 capabilities (`manage_wpig_settings`, `view_wpig_reports`, `review_wpig_verification`).
	 * - Subscriber, customer, contributor, author, editor do not receive WPIG capabilities and have any accidental grants stripped.
	 * - Custom roles can be granted specific subset capabilities and survive repeated registration (activation/reactivation idempotency).
	 */
	public function test_capability_registration_idempotency_custom_roles_and_least_privilege(): void {
		$roles_stub = $this->make_roles_stub(
			array(
				'administrator'            => array( 'manage_options' => true ),
				'subscriber'               => array(
					'read'                        => true,
					Capabilities::MANAGE_SETTINGS => true, // Polluted capability that must be stripped.
				),
				'customer'                 => array(
					'read'                     => true,
					Capabilities::VIEW_REPORTS => true, // Polluted capability that must be stripped.
				),
				'editor'                   => array( 'edit_posts' => true ),
				'wpig_compliance_reviewer' => array( 'read' => true ),
			)
		);

		// First registration (activation).
		self::assertTrue( Capabilities::register_for_current_site( $roles_stub ) );

		$admin_role      = $roles_stub->get_role( 'administrator' );
		$subscriber_role = $roles_stub->get_role( 'subscriber' );
		$customer_role   = $roles_stub->get_role( 'customer' );
		$editor_role     = $roles_stub->get_role( 'editor' );

		self::assertNotNull( $admin_role );
		self::assertNotNull( $subscriber_role );
		self::assertNotNull( $customer_role );
		self::assertNotNull( $editor_role );

		foreach ( Capabilities::all() as $cap ) {
			self::assertTrue( $admin_role->has_cap( $cap ), "Administrator must hold {$cap}." );
			self::assertFalse( $subscriber_role->has_cap( $cap ), "Subscriber must never hold {$cap}." );
			self::assertFalse( $customer_role->has_cap( $cap ), "Customer must never hold {$cap}." );
			self::assertFalse( $editor_role->has_cap( $cap ), "Editor must not hold {$cap} by default." );
		}

		$first_admin_add_count = $admin_role->add_cap_calls;
		self::assertSame( 3, $first_admin_add_count );

		// Grant subset capabilities to a custom role.
		Capabilities::grant_to_role(
			'wpig_compliance_reviewer',
			array( Capabilities::VIEW_REPORTS, Capabilities::REVIEW_VERIFICATION ),
			$roles_stub
		);

		$custom_role = $roles_stub->get_role( 'wpig_compliance_reviewer' );
		self::assertNotNull( $custom_role );
		self::assertTrue( $custom_role->has_cap( Capabilities::VIEW_REPORTS ) );
		self::assertTrue( $custom_role->has_cap( Capabilities::REVIEW_VERIFICATION ) );
		self::assertFalse( $custom_role->has_cap( Capabilities::MANAGE_SETTINGS ) );

		// Second registration (reactivation / upgrade idempotency):
		// Must not re-add existing capabilities on administrator and must preserve custom role capabilities!
		self::assertTrue( Capabilities::register_for_current_site( $roles_stub ) );
		self::assertSame( $first_admin_add_count, $admin_role->add_cap_calls, 'Idempotent registration must not duplicate add_cap calls.' );
		self::assertTrue( $custom_role->has_cap( Capabilities::VIEW_REPORTS ) );
		self::assertTrue( $custom_role->has_cap( Capabilities::REVIEW_VERIFICATION ) );

		// Attempting to grant WPIG capabilities to subscriber or customer must fail closed.
		foreach ( array( 'subscriber', 'customer', 'contributor', 'author', 'editor', 'shop_manager' ) as $disallowed ) {
			try {
				Capabilities::grant_to_role( $disallowed, array( Capabilities::VIEW_REPORTS ), $roles_stub );
				self::fail( "Expected AuthorizationException when granting capability to {$disallowed}." );
			} catch ( AuthorizationException $e ) {
				self::assertSame( AuthorizationException::CODE_INVALID_ROLE_ASSIGNMENT, $e->get_safe_code() );
			}
		}

		// Attempting to revoke capabilities from administrator must fail closed.
		try {
			Capabilities::revoke_from_role( 'administrator', null, $roles_stub );
			self::fail( 'Expected AuthorizationException when attempting to revoke capabilities from administrator.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_INVALID_ROLE_ASSIGNMENT, $e->get_safe_code() );
		}
	}

	/**
	 * Scenarios 1, 2, 3 & 4:
	 * - Administrator passes all capability assertions.
	 * - Subscriber and customer are denied all administrative capabilities (even if capability flag is present on user).
	 * - Custom role is allowed only for its granted capabilities and denied for missing capabilities.
	 */
	public function test_administrator_custom_role_and_subscriber_customer_capability_checks(): void {
		$authorizer = $this->make_authorizer(
			array(
				1 => array(
					'roles' => array( 'administrator' ),
					'caps'  => Capabilities::all(),
				),
				2 => array(
					'roles' => array( 'subscriber' ),
					'caps'  => array( 'read', Capabilities::MANAGE_SETTINGS ), // Simulated polluted cap on subscriber.
				),
				3 => array(
					'roles' => array( 'customer' ),
					'caps'  => array( 'read' ),
				),
				4 => array(
					'roles' => array( 'wpig_auditor' ),
					'caps'  => array( Capabilities::VIEW_REPORTS ),
				),
			)
		);

		// 1. Administrator has all 3 capabilities.
		$this->current_user_id = 1;
		$authorizer->assert_can_manage_settings( 1 );
		$authorizer->assert_can_view_reports( 1 );
		$authorizer->assert_can_review_verification( 1, 3 );

		// 2. Subscriber and customer are denied (even if subscriber has polluted cap).
		foreach ( array( 2, 3 ) as $unprivileged_id ) {
			$this->current_user_id = $unprivileged_id;
			foreach ( Capabilities::all() as $cap ) {
				try {
					$authorizer->assert_capability( $unprivileged_id, $cap );
					self::fail( "User {$unprivileged_id} must be denied {$cap}." );
				} catch ( AuthorizationException $e ) {
					self::assertSame( AuthorizationException::CODE_MISSING_CAPABILITY, $e->get_safe_code() );
				}
			}
		}

		// 3 & 4. Custom role 'wpig_auditor' can view reports, but fails closed for manage_settings and review_verification.
		$this->current_user_id = 4;
		$authorizer->assert_can_view_reports( 4 );
		$authorizer->assert_can_view_masked_profile( 4, 3 );

		try {
			$authorizer->assert_can_manage_settings( 4 );
			self::fail( 'Auditor without manage_wpig_settings must be denied.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_MISSING_CAPABILITY, $e->get_safe_code() );
		}

		try {
			$authorizer->assert_can_review_verification( 4, 3 );
			self::fail( 'Auditor without review_wpig_verification must be denied.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_MISSING_CAPABILITY, $e->get_safe_code() );
		}
	}

	/**
	 * Scenarios 5, 6 & 12:
	 * - Horizontal privilege escalation (IDOR) between subscribers/customers is denied.
	 * - Even an administrator cannot modify another user's raw profile attributes as if they were that user.
	 * - Multisite isolation prevents cross-blog access even for administrators of another blog.
	 * - Unauthenticated or non-existent actors fail closed.
	 */
	public function test_idor_prevention_multisite_isolation_and_fail_closed_defaults(): void {
		$authorizer = $this->make_authorizer(
			array(
				10 => array(
					'roles' => array( 'administrator' ),
					'caps'  => Capabilities::all(),
					'blogs' => array( 1 ),
				),
				11 => array(
					'roles' => array( 'subscriber' ),
					'caps'  => array( 'read' ),
					'blogs' => array( 1 ),
				),
				12 => array(
					'roles' => array( 'customer' ),
					'caps'  => array( 'read' ),
					'blogs' => array( 1 ),
				),
				20 => array(
					'roles' => array( 'administrator' ),
					'caps'  => Capabilities::all(),
					'blogs' => array( 2 ), // Admin of blog 2 ONLY, not blog 1!
				),
			),
			1,
			true
		);

		// Self-access on blog 1 succeeds.
		$this->current_user_id = 11;
		$authorizer->assert_can_view_masked_profile( 11, 11, 1 );
		$authorizer->assert_can_modify_own_profile( 11, 11, 1 );

		// 5. Subscriber 11 attempting to view or modify Customer 12 fails closed with CODE_CROSS_USER_FORBIDDEN.
		try {
			$authorizer->assert_can_view_masked_profile( 11, 12, 1 );
			self::fail( 'Expected IDOR view rejection.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_CROSS_USER_FORBIDDEN, $e->get_safe_code() );
		}

		try {
			$authorizer->assert_can_modify_own_profile( 11, 12, 1 );
			self::fail( 'Expected IDOR modify rejection.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_CROSS_USER_FORBIDDEN, $e->get_safe_code() );
		}

		// Admin 10 can view masked profile of User 11, but CANNOT call assert_can_modify_own_profile for User 11.
		$this->current_user_id = 10;
		$authorizer->assert_can_view_masked_profile( 10, 11, 1 );
		try {
			$authorizer->assert_can_modify_own_profile( 10, 11, 1 );
			self::fail( 'Admin must not modify another user\'s own-profile attributes directly.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_CROSS_USER_FORBIDDEN, $e->get_safe_code() );
		}

		// 6. Multisite isolation: Admin 20 (member of blog 2 only) is denied on blog 1.
		$this->current_user_id = 20;
		try {
			$authorizer->assert_can_manage_settings( 20, 1 );
			self::fail( 'Admin of blog 2 must be denied on blog 1.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_MULTISITE_FORBIDDEN, $e->get_safe_code() );
		}

		// Admin 10 (blog 1) attempting to review User 20 (who is on blog 2 only) is denied on blog 1.
		$this->current_user_id = 10;
		try {
			$authorizer->assert_can_review_verification( 10, 20, 1 );
			self::fail( 'Cross-blog target user review must be denied.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_MULTISITE_FORBIDDEN, $e->get_safe_code() );
		}

		// Requesting blog_id = 2 when active blog is 1 fails closed.
		try {
			$authorizer->assert_can_manage_settings( 10, 2 );
			self::fail( 'Mismatched blog_id must fail closed.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_MULTISITE_FORBIDDEN, $e->get_safe_code() );
		}

		// 12. Unauthenticated (0, -5) and non-existent (999) actors fail closed.
		foreach ( array( 0, -5, 999 ) as $invalid_actor ) {
			$this->current_user_id = $invalid_actor;
			try {
				$authorizer->assert_authenticated_actor( $invalid_actor );
				self::fail( "Invalid actor {$invalid_actor} must fail closed." );
			} catch ( AuthorizationException $e ) {
				self::assertSame( AuthorizationException::CODE_UNAUTHENTICATED, $e->get_safe_code() );
			}
		}
	}

	/**
	 * Scenarios 7, 8 & 11:
	 * - Decryption requires explicit purpose and active user consent for verification dispatch.
	 * - Report viewers and verification reviewers are denied raw plaintext decryption.
	 * - VerificationAuthorityGrant prevents forged, cross-user, cross-blog, or replayed binding attempts.
	 * - Client-provided role/capability/verification-state claims fail closed.
	 */
	public function test_decryption_policy_authority_grant_and_privilege_escalation_input_rejection(): void {
		$authorizer = $this->make_authorizer(
			array(
				1  => array(
					'roles' => array( 'administrator' ),
					'caps'  => Capabilities::all(),
				),
				2  => array(
					'roles' => array( 'wpig_reviewer' ),
					'caps'  => array( Capabilities::VIEW_REPORTS, Capabilities::REVIEW_VERIFICATION ),
				),
				11 => array(
					'roles' => array( 'subscriber' ),
					'caps'  => array( 'read' ),
				),
				12 => array(
					'roles' => array( 'customer' ),
					'caps'  => array( 'read' ),
				),
			)
		);

		$active_consent_11 = new ConsentRecord(
			1,
			11,
			'1.0',
			ConsentRepository::hash_notice_text( 'WPIG Notice v1.0' ),
			array( ConsentRepository::PURPOSE_IDENTITY_VERIFICATION ),
			'2026-01-01 00:00:00',
			null,
			null,
			1
		);

		// 8a. Profile owner (11) can decrypt for verification dispatch ONLY when a valid ConsentRecord is verified.
		$this->current_user_id = 11;
		$authorizer->assert_can_decrypt_identity(
			11,
			11,
			AuthorizationService::PURPOSE_VERIFICATION_DISPATCH,
			$active_consent_11
		);

		// Untrusted bare boolean true without a verified ConsentRecord or consent_verifier fails closed.
		try {
			$authorizer->assert_can_decrypt_identity(
				11,
				11,
				AuthorizationService::PURPOSE_VERIFICATION_DISPATCH,
				true
			);
			self::fail( 'Expected CODE_CONSENT_REQUIRED when only an unverified boolean true is supplied.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_CONSENT_REQUIRED, $e->get_safe_code() );
		}

		// Without active consent, decryption for verification dispatch fails closed with CODE_CONSENT_REQUIRED.
		try {
			$authorizer->assert_can_decrypt_identity(
				11,
				11,
				AuthorizationService::PURPOSE_VERIFICATION_DISPATCH,
				false
			);
			self::fail( 'Expected CODE_CONSENT_REQUIRED when consent is false.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_CONSENT_REQUIRED, $e->get_safe_code() );
		}

		// 8b. Cross-user verification dispatch decryption is denied (even for administrator 1!).
		foreach ( array( 1, 2, 12 ) as $other_actor ) {
			$this->current_user_id = $other_actor;
			try {
				$authorizer->assert_can_decrypt_identity(
					$other_actor,
					11,
					AuthorizationService::PURPOSE_VERIFICATION_DISPATCH,
					$active_consent_11
				);
				self::fail( "Actor {$other_actor} must not decrypt user 11 for verification dispatch." );
			} catch ( AuthorizationException $e ) {
				self::assertSame( AuthorizationException::CODE_CROSS_USER_FORBIDDEN, $e->get_safe_code() );
			}
		}

		// 8c. Cross-user privacy export decryption is denied even for administrator (1) and reviewer (2) per DS-4;
		// only the profile owner (11) can decrypt their own raw PII for privacy export.
		$this->current_user_id = 11;
		$authorizer->assert_can_decrypt_identity(
			11,
			11,
			AuthorizationService::PURPOSE_PRIVACY_EXPORT,
			false
		);

		foreach ( array( 1, 2, 12 ) as $other_actor ) {
			$this->current_user_id = $other_actor;
			try {
				$authorizer->assert_can_decrypt_identity(
					$other_actor,
					11,
					AuthorizationService::PURPOSE_PRIVACY_EXPORT,
					$active_consent_11
				);
				self::fail( "Actor {$other_actor} must not decrypt user 11's raw PII for privacy export." );
			} catch ( AuthorizationException $e ) {
				self::assertSame( AuthorizationException::CODE_DECRYPTION_FORBIDDEN, $e->get_safe_code() );
			}
		}

		// Unknown purpose is denied by default even for profile owner or administrator.
		$this->current_user_id = 1;
		try {
			$authorizer->assert_can_decrypt_identity( 1, 1, 'admin_dashboard_preview', $active_consent_11 );
			self::fail( 'Unknown decryption purpose must be denied.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_DECRYPTION_FORBIDDEN, $e->get_safe_code() );
		}

		// 7. VerificationAuthorityGrant: single-use, scope-bound, non-cloneable, and unforgeable.
		$secret = str_repeat( 'a', 32 );
		$grant  = VerificationAuthorityGrant::issue( $secret, 1, 11, 2, 1, '2027-11-14 00:00:00' );

		self::assertSame( 32, strlen( $grant->grant_id ) );
		self::assertSame( SensitiveValue::REDACTED, (string) $grant );
		self::assertSame( SensitiveValue::REDACTED, $grant->__debugInfo()['seal'] );

		// Cloning a single-use grant is prohibited.
		try {
			$cloned = clone $grant;
			unset( $cloned );
			self::fail( 'Cloning VerificationAuthorityGrant must fail closed.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_FORBIDDEN, $e->get_safe_code() );
		}

		// Multi-role / direct user-capability bypass prevention (Task 8 item 3).
		$multi_role_auth = $this->make_authorizer(
			array(
				50 => array(
					'roles' => array( 'subscriber', 'wpig_auditor' ),
					// Direct user-meta cap injection of MANAGE_SETTINGS.
					'caps'  => array( Capabilities::VIEW_REPORTS, Capabilities::MANAGE_SETTINGS ),
				),
			),
			1,
			false,
			array(
				'subscriber'   => array(),
				'wpig_auditor' => array( Capabilities::VIEW_REPORTS ),
			)
		);
		$this->current_user_id = 50;
		$multi_role_auth->assert_can_view_reports( 50 );
		try {
			$multi_role_auth->assert_can_manage_settings( 50 );
			self::fail( 'Direct user-capability injection on a user whose role only grants view_wpig_reports must be denied.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_MISSING_CAPABILITY, $e->get_safe_code() );
		}

		// Wrong secret or wrong user ID fails closed without consuming valid state for wrong call.
		try {
			$grant->verify_and_consume( str_repeat( 'b', 32 ), 1, 11, 2, 1 );
			self::fail( 'Forged authority secret must fail.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_BINDING_AUTHORITY_REQUIRED, $e->get_safe_code() );
		}

		try {
			$grant->verify_and_consume( $secret, 1, 12, 2, 1 );
			self::fail( 'Mismatched user ID on grant must fail.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_BINDING_AUTHORITY_REQUIRED, $e->get_safe_code() );
		}

		// Valid verification consumes the grant.
		$grant->verify_and_consume( $secret, 1, 11, 2, 1 );

		// Replaying the same grant a second time fails closed.
		try {
			$grant->verify_and_consume( $secret, 1, 11, 2, 1 );
			self::fail( 'Replayed authority grant must fail.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_BINDING_AUTHORITY_REQUIRED, $e->get_safe_code() );
		}

		// 11. Client-provided privilege escalation inputs fail closed.
		foreach ( AuthorizationService::FORBIDDEN_INPUT_KEYS as $forbidden_key ) {
			try {
				$authorizer->assert_no_privilege_escalation_input(
					array( $forbidden_key => 'injected' ),
					11
				);
				self::fail( "Forbidden input key {$forbidden_key} must be rejected." );
			} catch ( AuthorizationException $e ) {
				self::assertSame( AuthorizationException::CODE_PRIVILEGE_ESCALATION_ATTEMPT, $e->get_safe_code() );
			}
		}

		// Mismatched user_id in request input fails closed with CODE_CROSS_USER_FORBIDDEN.
		try {
			$authorizer->assert_no_privilege_escalation_input(
				array( 'user_id' => 12 ),
				11
			);
			self::fail( 'Mismatched user_id in input must be rejected.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_CROSS_USER_FORBIDDEN, $e->get_safe_code() );
		}
	}

	/**
	 * P01 Security Closure — Task 1:
	 * - Never trust caller-supplied actor_user_id when it mismatches the authenticated server principal.
	 * - Anonymous principal (0) spoofing an existing administrator (1) fails closed.
	 * - Authenticated subscriber (11) spoofing administrator (1) or another subscriber (12) fails closed.
	 * - Explicit WP-CLI, WP-Cron, and Internal Service contexts enforce their runtime environment guards.
	 */
	public function test_authentication_context_prevents_actor_id_spoofing_and_enforces_cli_cron_guards(): void {
		$authorizer = $this->make_authorizer(
			array(
				1  => array(
					'roles' => array( 'administrator' ),
					'caps'  => Capabilities::all(),
				),
				11 => array(
					'roles' => array( 'subscriber' ),
					'caps'  => array( 'read' ),
				),
				12 => array(
					'roles' => array( 'customer' ),
					'caps'  => array( 'read' ),
				),
			)
		);

		// 1. Anonymous HTTP request (current_user_id = 0) spoofing administrator (actor_user_id = 1).
		$this->current_user_id = 0;
		try {
			$authorizer->assert_can_manage_settings( 1 );
			self::fail( 'Anonymous caller spoofing administrator actor_user_id must fail closed.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_UNAUTHENTICATED, $e->get_safe_code() );
		}

		// 2. Logged-in subscriber (current_user_id = 11) spoofing administrator (actor_user_id = 1).
		$this->current_user_id = 11;
		try {
			$authorizer->assert_can_manage_settings( 1 );
			self::fail( 'Subscriber spoofing administrator actor_user_id must fail closed.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_UNAUTHENTICATED, $e->get_safe_code() );
		}

		// 3. Logged-in subscriber (current_user_id = 11) spoofing customer (actor_user_id = 12) for self-access.
		try {
			$authorizer->assert_can_view_masked_profile( 12, 12 );
			self::fail( 'Subscriber 11 spoofing actor_user_id = 12 must fail closed.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_UNAUTHENTICATED, $e->get_safe_code() );
		}

		// 4. WP-CLI context fails closed when WP-CLI runtime is not active.
		$cli_denied_ctx = AuthenticationContext::wp_cli( 1, static fn(): bool => false );
		try {
			$cli_denied_ctx->assert_principal_matches( 1 );
			self::fail( 'WP-CLI context outside WP-CLI runtime must fail closed.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_UNAUTHENTICATED, $e->get_safe_code() );
		}

		// WP-CLI context succeeds when WP-CLI runtime is active and actor matches designated principal.
		$cli_allowed_ctx = AuthenticationContext::wp_cli( 1, static fn(): bool => true );
		self::assertSame( AuthenticationContext::CONTEXT_WP_CLI, $cli_allowed_ctx->get_context_type() );
		self::assertSame( 1, $cli_allowed_ctx->assert_principal_matches( 1 ) );
		try {
			$cli_allowed_ctx->assert_principal_matches( 11 );
			self::fail( 'WP-CLI context must reject mismatched actor_user_id.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_UNAUTHENTICATED, $e->get_safe_code() );
		}

		// 5. WP-Cron context fails closed when wp_doing_cron() is false, and default system cron (0) denies user actions.
		$cron_denied_ctx = AuthenticationContext::wp_cron( 1, static fn(): bool => false );
		try {
			$cron_denied_ctx->assert_principal_matches( 1 );
			self::fail( 'WP-Cron context outside cron runtime must fail closed.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_UNAUTHENTICATED, $e->get_safe_code() );
		}

		$system_cron_ctx = AuthenticationContext::wp_cron( 0, static fn(): bool => true );
		self::assertSame( AuthenticationContext::CONTEXT_WP_CRON, $system_cron_ctx->get_context_type() );
		try {
			$system_cron_ctx->assert_principal_matches( 1 );
			self::fail( 'System WP-Cron context (principal 0) must deny user-impersonating actor_user_id.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_UNAUTHENTICATED, $e->get_safe_code() );
		}

		// 6. Internal service context binds strictly to the designated server principal.
		$internal_ctx = AuthenticationContext::internal_service( 11 );
		self::assertSame( AuthenticationContext::CONTEXT_INTERNAL_SERVICE, $internal_ctx->get_context_type() );
		self::assertSame( 11, $internal_ctx->assert_principal_matches( 11 ) );
		try {
			$internal_ctx->assert_principal_matches( 1 );
			self::fail( 'Internal service context bound to user 11 must reject actor_user_id = 1.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_UNAUTHENTICATED, $e->get_safe_code() );
		}
	}

	/**
	 * P01 Security Closure — Task 2 & Task 3:
	 * - Trusted consent verification rejects unverified boolean flags, revoked consent, expired consent,
	 *   wrong user ID, wrong Multisite blog ID, and wrong operation purpose.
	 * - VerificationAuthorityGrant rejects cross-process / cross-worker replay.
	 */
	public function test_trusted_consent_verification_and_cross_process_grant_rejection(): void {
		$this->current_user_id = 11;
		$authorizer            = $this->make_authorizer(
			array(
				11 => array(
					'roles' => array( 'subscriber' ),
					'caps'  => array( 'read' ),
					'blogs' => array( 1 ),
				),
			),
			1,
			true
		);

		$now_utc     = '2026-11-20 12:00:00';
		$notice_hash = ConsentRepository::hash_notice_text( 'WPIG Privacy Notice v1.0' );

		// 1. Revoked consent record fails closed.
		$revoked_consent = new ConsentRecord(
			10,
			11,
			'1.0',
			$notice_hash,
			array( ConsentRepository::PURPOSE_IDENTITY_VERIFICATION ),
			'2026-11-01 00:00:00',
			'2026-11-10 00:00:00',
			null,
			1
		);
		try {
			$authorizer->assert_can_decrypt_identity(
				11,
				11,
				AuthorizationService::PURPOSE_VERIFICATION_DISPATCH,
				$revoked_consent,
				1,
				$now_utc
			);
			self::fail( 'Revoked ConsentRecord must fail closed.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_CONSENT_REQUIRED, $e->get_safe_code() );
		}

		// 2. Expired consent record fails closed.
		$expired_consent = new ConsentRecord(
			11,
			11,
			'1.0',
			$notice_hash,
			array( ConsentRepository::PURPOSE_IDENTITY_VERIFICATION ),
			'2026-11-01 00:00:00',
			null,
			'2026-11-20 11:59:59',
			1
		);
		try {
			$authorizer->assert_can_decrypt_identity(
				11,
				11,
				AuthorizationService::PURPOSE_VERIFICATION_DISPATCH,
				$expired_consent,
				1,
				$now_utc
			);
			self::fail( 'Expired ConsentRecord must fail closed.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_CONSENT_REQUIRED, $e->get_safe_code() );
		}

		// 3. Consent record for wrong user ID (user 12 instead of 11) fails closed.
		$wrong_user_consent = new ConsentRecord(
			12,
			12,
			'1.0',
			$notice_hash,
			array( ConsentRepository::PURPOSE_IDENTITY_VERIFICATION ),
			'2026-11-01 00:00:00',
			null,
			null,
			1
		);
		try {
			$authorizer->assert_can_decrypt_identity(
				11,
				11,
				AuthorizationService::PURPOSE_VERIFICATION_DISPATCH,
				$wrong_user_consent,
				1,
				$now_utc
			);
			self::fail( 'ConsentRecord belonging to user 12 must be rejected for user 11.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_CONSENT_REQUIRED, $e->get_safe_code() );
		}

		// 4. Consent record for wrong Multisite blog ID (blog 2 instead of active blog 1) fails closed.
		$wrong_blog_consent = new ConsentRecord(
			13,
			11,
			'1.0',
			$notice_hash,
			array( ConsentRepository::PURPOSE_IDENTITY_VERIFICATION ),
			'2026-11-01 00:00:00',
			null,
			null,
			2
		);
		try {
			$authorizer->assert_can_decrypt_identity(
				11,
				11,
				AuthorizationService::PURPOSE_VERIFICATION_DISPATCH,
				$wrong_blog_consent,
				1,
				$now_utc
			);
			self::fail( 'ConsentRecord granted on blog 2 must be rejected on blog 1.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_CONSENT_REQUIRED, $e->get_safe_code() );
		}

		// 5. Consent record for wrong operation purpose ('mobile_otp' only, missing 'identity_verification') fails closed.
		$wrong_purpose_consent = new ConsentRecord(
			14,
			11,
			'1.0',
			$notice_hash,
			array( ConsentRepository::PURPOSE_MOBILE_OTP ),
			'2026-11-01 00:00:00',
			null,
			null,
			1
		);
		try {
			$authorizer->assert_can_decrypt_identity(
				11,
				11,
				AuthorizationService::PURPOSE_VERIFICATION_DISPATCH,
				$wrong_purpose_consent,
				1,
				$now_utc
			);
			self::fail( 'ConsentRecord without identity_verification purpose must fail closed.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_CONSENT_REQUIRED, $e->get_safe_code() );
		}

		// 6. Cross-process / cross-worker VerificationAuthorityGrant rejection:
		$secret = str_repeat( 'z', 32 );
		$grant  = VerificationAuthorityGrant::issue( $secret, 1, 11, 1, 1, '2027-11-20 00:00:00', 60, 1795000000 );
		self::assertFalse( $grant->is_consumed() );

		// Simulate crossing into a different HTTP request / PHP-FPM worker process.
		VerificationAuthorityGrant::rotate_process_token_for_testing();
		try {
			$grant->verify_and_consume( $secret, 1, 11, 1, 1, 1795000010 );
			self::fail( 'Grant issued in a different worker process must fail closed.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_BINDING_AUTHORITY_REQUIRED, $e->get_safe_code() );
		}
	}
}

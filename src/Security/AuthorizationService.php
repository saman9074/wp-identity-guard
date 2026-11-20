<?php
/**
 * WordPress authorization service enforcing capabilities, object-level access,
 * Multisite isolation, consent separation, and anti-IDOR / anti-escalation policies.
 *
 * @package WPIG\Security
 */

declare(strict_types=1);

namespace WPIG\Security;

use WP_User;
use WPIG\Privacy\ConsentRecord;
use WPIG\Privacy\ConsentRepository;

/**
 * Evaluates actor authentication, site membership, role/capability permissions,
 * cross-user (IDOR) boundaries, and sensitive-data decryption policies.
 *
 * Security Invariants:
 * - Deny by default: any unauthenticated actor, spoofed actor_user_id, unknown capability,
 *   unknown decryption purpose, or cross-site mismatch fails closed with `AuthorizationException`.
 * - Verifies that `$actor_user_id` matches the server-authenticated principal via `AuthenticationContext`.
 * - Separates actor (`$actor_user_id`) and target user (`$target_user_id`) checks.
 * - Prevents horizontal privilege escalation (User A cannot view, edit, or decrypt User B).
 * - Never trusts client-supplied role, capability, consent, authority-grant, or verification-state claims.
 * - Restricts decrypted identity access (`DecryptedIdentityData`) to explicit,
 *   narrow purposes (`PURPOSE_VERIFICATION_DISPATCH` with verified active consent record, or
 *   `PURPOSE_PRIVACY_EXPORT`); general reporting/review roles never receive
 *   unrestricted plaintext decryption.
 * - Enforces Multisite per-blog membership boundaries.
 */
final class AuthorizationService {

	/**
	 * Decryption purpose: self-initiated verification dispatch to an external provider (requires active consent).
	 */
	public const PURPOSE_VERIFICATION_DISPATCH = 'verification_dispatch';

	/**
	 * Decryption purpose: formal personal data export for the user or site privacy administrator.
	 */
	public const PURPOSE_PRIVACY_EXPORT = 'privacy_export';

	/**
	 * Client-controlled input keys that must never be accepted in user/profile request payloads.
	 *
	 * @var list<string>
	 */
	public const FORBIDDEN_INPUT_KEYS = array(
		'role',
		'roles',
		'capability',
		'capabilities',
		'caps',
		'allcaps',
		'is_admin',
		'is_super_admin',
		'binding_state',
		'identity_state',
		'bound_national_code_hmac',
		'verified',
		'is_verified',
		'verified_at',
		'shahkar_verified_at',
		'mobile_verified_at',
		'bound_at',
		'released_at',
		'enc_key_id',
		'hmac_key_id',
		'blog_id',
		'has_active_consent',
		'consent',
		'consent_accepted',
		'consented',
		'consent_status',
		'authority_grant',
		'grant_id',
		'verification_grant',
		'seal',
	);

	/**
	 * Callback checking whether a user ID exists (`fn(int $user_id): bool`).
	 *
	 * @var callable
	 * @phpstan-var callable(int):bool
	 */
	private $user_exists_resolver;

	/**
	 * Callback checking whether a user has a capability on the current site (`fn(int $user_id, string $cap): bool`).
	 *
	 * @var callable
	 * @phpstan-var callable(int, string):bool
	 */
	private $user_can_resolver;

	/**
	 * Callback returning a user's role slugs on the current site (`fn(int $user_id): list<string>`).
	 *
	 * @var callable
	 * @phpstan-var callable(int):list<string>
	 */
	private $user_roles_resolver;

	/**
	 * Callback returning the current active blog ID (`fn(): int`).
	 *
	 * @var callable
	 * @phpstan-var callable():int
	 */
	private $blog_id_resolver;

	/**
	 * Callback returning whether WordPress Multisite is active (`fn(): bool`).
	 *
	 * @var callable
	 * @phpstan-var callable():bool
	 */
	private $is_multisite_resolver;

	/**
	 * Callback checking whether a user is a member of a specific blog (`fn(int $user_id, int $blog_id): bool`).
	 *
	 * @var callable
	 * @phpstan-var callable(int, int):bool
	 */
	private $blog_member_resolver;

	/**
	 * Callback checking whether a specific role grants a capability (`fn(string $role_slug, string $cap): bool`).
	 *
	 * @var callable
	 * @phpstan-var callable(string, string):bool
	 */
	private $role_has_cap_resolver;

	/**
	 * Server-side authentication context establishing the acting principal.
	 *
	 * @var AuthenticationContext
	 */
	private AuthenticationContext $auth_context;

	/**
	 * Optional trusted consent verifier (`fn(int $user_id, int $blog_id, string $purpose, string $now_utc): ?ConsentRecord`).
	 *
	 * @var callable|null
	 * @phpstan-var (callable(int, int, string, string):(?ConsentRecord))|null
	 */
	private $consent_verifier;

	/**
	 * Constructor.
	 *
	 * Defaults to native WordPress user, capability, role, Multisite, and request principal functions when omitted.
	 *
	 * @param callable|null              $user_exists_resolver  Optional `(fn(int $user_id): bool)`.
	 * @param callable|null              $user_can_resolver     Optional `(fn(int $user_id, string $cap): bool)`.
	 * @param callable|null              $user_roles_resolver   Optional `(fn(int $user_id): list<string>)`.
	 * @param callable|null              $blog_id_resolver      Optional `(fn(): int)`.
	 * @param callable|null              $is_multisite_resolver Optional `(fn(): bool)`.
	 * @param callable|null              $blog_member_resolver  Optional `(fn(int $user_id, int $blog_id): bool)`.
	 * @param callable|null              $role_has_cap_resolver Optional `(fn(string $role_slug, string $cap): bool)`.
	 * @param AuthenticationContext|null $auth_context          Optional server-side authentication context.
	 * @param callable|null              $consent_verifier      Optional trusted consent verifier returning `?ConsentRecord`.
	 * @phpstan-param (callable(int):bool)|null                                   $user_exists_resolver
	 * @phpstan-param (callable(int, string):bool)|null                           $user_can_resolver
	 * @phpstan-param (callable(int):list<string>)|null                           $user_roles_resolver
	 * @phpstan-param (callable():int)|null                                       $blog_id_resolver
	 * @phpstan-param (callable():bool)|null                                      $is_multisite_resolver
	 * @phpstan-param (callable(int, int):bool)|null                              $blog_member_resolver
	 * @phpstan-param (callable(string, string):bool)|null                         $role_has_cap_resolver
	 * @phpstan-param (callable(int, int, string, string):(?ConsentRecord))|null  $consent_verifier
	 */
	public function __construct(
		?callable $user_exists_resolver = null,
		?callable $user_can_resolver = null,
		?callable $user_roles_resolver = null,
		?callable $blog_id_resolver = null,
		?callable $is_multisite_resolver = null,
		?callable $blog_member_resolver = null,
		?callable $role_has_cap_resolver = null,
		?AuthenticationContext $auth_context = null,
		?callable $consent_verifier = null
	) {
		$this->user_exists_resolver = $user_exists_resolver ?? static function ( int $user_id ): bool {
			if ( $user_id < 1 || ! function_exists( 'get_userdata' ) ) {
				return false;
			}
			$user = get_userdata( $user_id );
			return $user instanceof WP_User && $user->exists();
		};

		$this->user_can_resolver = $user_can_resolver ?? static function ( int $user_id, string $cap ): bool {
			if ( $user_id < 1 || ! function_exists( 'user_can' ) ) {
				return false;
			}
			return user_can( $user_id, $cap );
		};

		$this->user_roles_resolver = $user_roles_resolver ?? static function ( int $user_id ): array {
			if ( $user_id < 1 || ! function_exists( 'get_userdata' ) ) {
				return array();
			}
			$user = get_userdata( $user_id );
			if ( ! $user instanceof WP_User ) {
				return array();
			}
			return array_values( array_map( 'strval', $user->roles ) );
		};

		$this->blog_id_resolver = $blog_id_resolver ?? static function (): int {
			if ( function_exists( 'get_current_blog_id' ) ) {
				return max( 1, (int) get_current_blog_id() );
			}
			return 1;
		};

		$this->is_multisite_resolver = $is_multisite_resolver ?? static function (): bool {
			if ( function_exists( 'is_multisite' ) ) {
				return (bool) is_multisite();
			}
			return false;
		};

		$this->blog_member_resolver = $blog_member_resolver ?? static function ( int $user_id, int $blog_id ): bool {
			if ( $user_id < 1 || $blog_id < 1 ) {
				return false;
			}
			if ( function_exists( 'is_user_member_of_blog' ) ) {
				return (bool) is_user_member_of_blog( $user_id, $blog_id );
			}
			return true;
		};

		$this->role_has_cap_resolver = $role_has_cap_resolver ?? static function ( string $role_slug, string $cap ): bool {
			if ( ! function_exists( 'wp_roles' ) ) {
				return true;
			}
			$roles = wp_roles();
			$role  = $roles->get_role( $role_slug );
			if ( null === $role ) {
				return false;
			}
			return $role->has_cap( $cap );
		};

		$this->auth_context     = $auth_context ?? AuthenticationContext::wordpress_request();
		$this->consent_verifier = $consent_verifier;
	}

	/**
	 * Return the active server-side authentication context.
	 */
	public function get_authentication_context(): AuthenticationContext {
		return $this->auth_context;
	}

	/**
	 * Resolve the current authenticated server-side principal user ID (`0` if unauthenticated).
	 */
	public function get_authenticated_principal_id(): int {
		return $this->auth_context->resolve_principal_id();
	}

	/**
	 * Verify that the actor matches the authenticated server-side principal, exists in WordPress,
	 * and belongs to the active Multisite site.
	 *
	 * @param int      $actor_user_id Acting WordPress user ID.
	 * @param int|null $blog_id       Optional expected site blog ID.
	 * @throws AuthorizationException If unauthenticated, spoofed, non-existent, or outside the current Multisite blog.
	 */
	public function assert_authenticated_actor( int $actor_user_id, ?int $blog_id = null ): void {
		$principal_id   = $this->auth_context->assert_principal_matches( $actor_user_id );
		$active_blog_id = $this->resolve_and_verify_blog_id( $blog_id );

		if ( ! (bool) ( $this->user_exists_resolver )( $principal_id ) ) {
			AuthorizationException::raise(
				AuthorizationException::CODE_UNAUTHENTICATED,
				'Authenticated WordPress user account does not exist.'
			);
		}

		if ( (bool) ( $this->is_multisite_resolver )() ) {
			if ( ! (bool) ( $this->blog_member_resolver )( $principal_id, $active_blog_id ) ) {
				AuthorizationException::raise(
					AuthorizationException::CODE_MULTISITE_FORBIDDEN,
					'Actor is not a member of the target Multisite site.'
				);
			}
		}
	}

	/**
	 * Verify that the actor holds a specific WP Identity Guard capability on the current site.
	 *
	 * Enforces least privilege: even if a capability flag were somehow injected onto a
	 * user who holds only disallowed roles (`subscriber`, `customer`, etc.), access is denied.
	 *
	 * @param int      $actor_user_id Acting WordPress user ID.
	 * @param string   $capability    Required WPIG capability constant.
	 * @param int|null $blog_id       Optional expected site blog ID.
	 * @throws AuthorizationException If unauthenticated, on wrong blog, or missing capability.
	 */
	public function assert_capability( int $actor_user_id, string $capability, ?int $blog_id = null ): void {
		if ( ! Capabilities::is_valid_capability( $capability ) ) {
			AuthorizationException::raise(
				AuthorizationException::CODE_MISSING_CAPABILITY,
				'Unknown or unsupported capability requested.'
			);
		}

		$this->assert_authenticated_actor( $actor_user_id, $blog_id );

		if ( ! $this->actor_has_authorized_capability( $actor_user_id, $capability ) ) {
			AuthorizationException::raise(
				AuthorizationException::CODE_MISSING_CAPABILITY,
				'Actor does not have the required capability for this operation.'
			);
		}
	}

	/**
	 * Require `manage_wpig_settings` capability on the current site.
	 *
	 * @param int      $actor_user_id Acting WordPress user ID.
	 * @param int|null $blog_id       Optional expected site blog ID.
	 * @throws AuthorizationException If actor is not authorized to manage settings.
	 */
	public function assert_can_manage_settings( int $actor_user_id, ?int $blog_id = null ): void {
		$this->assert_capability( $actor_user_id, Capabilities::MANAGE_SETTINGS, $blog_id );
	}

	/**
	 * Require `view_wpig_reports` capability on the current site.
	 *
	 * @param int      $actor_user_id Acting WordPress user ID.
	 * @param int|null $blog_id       Optional expected site blog ID.
	 * @throws AuthorizationException If actor is not authorized to view reports.
	 */
	public function assert_can_view_reports( int $actor_user_id, ?int $blog_id = null ): void {
		$this->assert_capability( $actor_user_id, Capabilities::VIEW_REPORTS, $blog_id );
	}

	/**
	 * Require `review_wpig_verification` capability on the current site, and optionally
	 * verify that the target user belongs to the same Multisite site.
	 *
	 * @param int      $actor_user_id  Acting WordPress user ID.
	 * @param int|null $target_user_id Optional target WordPress user ID being reviewed.
	 * @param int|null $blog_id        Optional expected site blog ID.
	 * @throws AuthorizationException If actor lacks `review_wpig_verification` or target is invalid/cross-site.
	 */
	public function assert_can_review_verification(
		int $actor_user_id,
		?int $target_user_id = null,
		?int $blog_id = null
	): void {
		$this->assert_capability( $actor_user_id, Capabilities::REVIEW_VERIFICATION, $blog_id );

		if ( null !== $target_user_id ) {
			$this->assert_valid_target_user_on_blog( $target_user_id, $blog_id );
		}
	}

	/**
	 * Verify whether the actor can view a target user's masked profile summary (`ProfileRecord`).
	 *
	 * Allowed when:
	 * 1. `$actor_user_id === $target_user_id` (authenticated user viewing own masked profile), OR
	 * 2. `$actor_user_id` holds `view_wpig_reports` or `review_wpig_verification` on the current site.
	 *
	 * @param int      $actor_user_id  Acting WordPress user ID.
	 * @param int      $target_user_id Target WordPress user ID.
	 * @param int|null $blog_id        Optional expected site blog ID.
	 * @throws AuthorizationException On unauthenticated access, cross-user IDOR, or Multisite violation.
	 */
	public function assert_can_view_masked_profile(
		int $actor_user_id,
		int $target_user_id,
		?int $blog_id = null
	): void {
		$this->assert_authenticated_actor( $actor_user_id, $blog_id );
		$this->assert_valid_target_user_on_blog( $target_user_id, $blog_id );

		if ( $actor_user_id === $target_user_id ) {
			return;
		}

		if (
			$this->actor_has_authorized_capability( $actor_user_id, Capabilities::VIEW_REPORTS )
			|| $this->actor_has_authorized_capability( $actor_user_id, Capabilities::REVIEW_VERIFICATION )
		) {
			return;
		}

		AuthorizationException::raise(
			AuthorizationException::CODE_CROSS_USER_FORBIDDEN,
			'Actor is not authorized to view another user\'s identity profile.'
		);
	}

	/**
	 * Verify that the actor is modifying only their own profile (`$actor_user_id === $target_user_id`).
	 *
	 * Prevents horizontal privilege escalation (IDOR) and prevents administrators from
	 * silently overwriting another user's identity attributes as if they were that user.
	 *
	 * @param int      $actor_user_id  Acting WordPress user ID.
	 * @param int      $target_user_id Target WordPress user ID.
	 * @param int|null $blog_id        Optional expected site blog ID.
	 * @throws AuthorizationException If unauthenticated or `$actor_user_id !== $target_user_id`.
	 */
	public function assert_can_modify_own_profile(
		int $actor_user_id,
		int $target_user_id,
		?int $blog_id = null
	): void {
		$this->assert_authenticated_actor( $actor_user_id, $blog_id );
		$this->assert_valid_target_user_on_blog( $target_user_id, $blog_id );

		if ( $actor_user_id !== $target_user_id ) {
			AuthorizationException::raise(
				AuthorizationException::CODE_CROSS_USER_FORBIDDEN,
				'Actor cannot modify another user\'s identity profile attributes.'
			);
		}
	}

	/**
	 * Verify explicit user consent separately from authentication and capability authorization.
	 *
	 * Security Invariants (Task 2 — Trusted Consent Verification):
	 * - Never accepts a raw boolean `true` as sufficient proof on its own; when a boolean `true`
	 *   is supplied, a server-side `$this->consent_verifier` (`ConsentRepository`) MUST resolve
	 *   an active, unrevoked, unexpired `ConsentRecord` for `($expected_user_id, $active_blog_id, $required_purpose)`.
	 * - When a `ConsentRecord` is supplied, validates that the record is active, unrevoked, unexpired,
	 *   and strictly bound to `($expected_user_id, $active_blog_id, $required_purpose)`, and also cross-checks
	 *   against `$this->consent_verifier` when configured so stale pre-revocation records fail closed.
	 *
	 * @param ConsentRecord|bool $consent_evidence Trusted `ConsentRecord` or flag requiring server-side verification.
	 * @param int|null           $expected_user_id Expected target WordPress user ID (`>= 1`).
	 * @param int|null           $expected_blog_id Optional expected site blog ID.
	 * @param string             $required_purpose Required consent purpose (`ConsentRepository::PURPOSE_*`).
	 * @param string|null        $now_utc          Optional UTC timestamp override (`Y-m-d H:i:s`).
	 * @throws AuthorizationException If consent is missing, untrusted, revoked, expired, or mismatched.
	 */
	public function assert_active_consent(
		ConsentRecord|bool $consent_evidence,
		?int $expected_user_id = null,
		?int $expected_blog_id = null,
		string $required_purpose = ConsentRepository::PURPOSE_IDENTITY_VERIFICATION,
		?string $now_utc = null
	): void {
		if ( false === $consent_evidence ) {
			AuthorizationException::raise(
				AuthorizationException::CODE_CONSENT_REQUIRED,
				'Explicit user consent is required before processing or dispatching identity data.'
			);
		}

		$active_blog_id = $this->resolve_and_verify_blog_id( $expected_blog_id );
		$now            = $now_utc ?? gmdate( 'Y-m-d H:i:s' );

		if ( true === $consent_evidence ) {
			if ( null === $this->consent_verifier || null === $expected_user_id || $expected_user_id < 1 ) {
				AuthorizationException::raise(
					AuthorizationException::CODE_CONSENT_REQUIRED,
					'Untrusted boolean consent flag rejected: active consent must be proven by a trusted ConsentRecord.'
				);
			}

			$persisted = ( $this->consent_verifier )( $expected_user_id, $active_blog_id, $required_purpose, $now );
			if (
				! $persisted instanceof ConsentRecord
				|| ! $persisted->is_valid_for( $expected_user_id, $active_blog_id, $required_purpose, $now )
			) {
				AuthorizationException::raise(
					AuthorizationException::CODE_CONSENT_REQUIRED,
					'No active, unrevoked user consent record exists for this user, site, and operation.'
				);
			}

			return;
		}

		$target_user_id = $expected_user_id ?? $consent_evidence->wp_user_id;
		if ( ! $consent_evidence->is_valid_for( $target_user_id, $active_blog_id, $required_purpose, $now ) ) {
			AuthorizationException::raise(
				AuthorizationException::CODE_CONSENT_REQUIRED,
				'User consent record is revoked, expired, or does not match the target user, site, or operation.'
			);
		}

		if ( null !== $this->consent_verifier ) {
			$persisted = ( $this->consent_verifier )( $target_user_id, $active_blog_id, $required_purpose, $now );
			if (
				! $persisted instanceof ConsentRecord
				|| ! $persisted->is_valid_for( $target_user_id, $active_blog_id, $required_purpose, $now )
			) {
				AuthorizationException::raise(
					AuthorizationException::CODE_CONSENT_REQUIRED,
					'Persisted user consent has been withdrawn or expired.'
				);
			}
		}
	}

	/**
	 * Enforce strict access control for decrypting sensitive identity fields (`DecryptedIdentityData`).
	 *
	 * Policy:
	 * - Deny by default for any unknown or general UI/reporting/review purpose.
	 * - `PURPOSE_VERIFICATION_DISPATCH`:
	 *   - Allowed ONLY when `$actor_user_id === $target_user_id` (self-initiated verification)
	 *     AND trusted active consent is verified for `($target_user_id, $blog_id, 'identity_verification')`.
	 * - `PURPOSE_PRIVACY_EXPORT`:
	 *   - Allowed ONLY when `$actor_user_id === $target_user_id` (self-initiated personal data export).
	 *   - Site administrators (`manage_wpig_settings`) and compliance roles (`view_wpig_reports`,
	 *     `review_wpig_verification`) cannot decrypt another user's raw PII (`DecryptedIdentityData`);
	 *     administrative privacy exports must use masked `ProfileRecord::to_safe_export_array()` (`DS-4`).
	 *
	 * @param int                $actor_user_id      Acting WordPress user ID.
	 * @param int                $target_user_id     Target WordPress user ID whose ciphertext would be decrypted.
	 * @param string             $purpose            Explicit decryption purpose constant.
	 * @param ConsentRecord|bool $has_active_consent Trusted `ConsentRecord` or flag verified against `ConsentRepository`.
	 * @param int|null           $blog_id            Optional expected site blog ID.
	 * @param string|null        $now_utc            Optional UTC timestamp override (`Y-m-d H:i:s`).
	 * @throws AuthorizationException If decryption is not permitted for the actor, target, purpose, or consent state.
	 */
	public function assert_can_decrypt_identity(
		int $actor_user_id,
		int $target_user_id,
		string $purpose,
		ConsentRecord|bool $has_active_consent = false,
		?int $blog_id = null,
		?string $now_utc = null
	): void {
		$this->assert_authenticated_actor( $actor_user_id, $blog_id );
		$this->assert_valid_target_user_on_blog( $target_user_id, $blog_id );

		if ( self::PURPOSE_VERIFICATION_DISPATCH === $purpose ) {
			if ( $actor_user_id !== $target_user_id ) {
				AuthorizationException::raise(
					AuthorizationException::CODE_CROSS_USER_FORBIDDEN,
					'Verification dispatch decryption is restricted to the authenticated profile owner.'
				);
			}

			$this->assert_active_consent(
				$has_active_consent,
				$target_user_id,
				$blog_id,
				ConsentRepository::PURPOSE_IDENTITY_VERIFICATION,
				$now_utc
			);
			return;
		}

		if ( self::PURPOSE_PRIVACY_EXPORT === $purpose ) {
			if ( $actor_user_id === $target_user_id ) {
				return;
			}

			AuthorizationException::raise(
				AuthorizationException::CODE_DECRYPTION_FORBIDDEN,
				'Actor is not authorized to decrypt another user\'s raw identity data for privacy export; use masked export records (DS-4).'
			);
		}

		AuthorizationException::raise(
			AuthorizationException::CODE_DECRYPTION_FORBIDDEN,
			'Unrestricted or unrecognized decryption purpose is forbidden.'
		);
	}

	/**
	 * Reject user-controlled request arrays that attempt privilege escalation, role/capability
	 * injection, cross-user actor spoofing, or direct verification/binding state manipulation.
	 *
	 * @param array<string,mixed> $input                  User-supplied request parameters.
	 * @param int|null            $authenticated_actor_id Optional server-authenticated actor user ID.
	 * @throws AuthorizationException If any forbidden claim or mismatched user ID is present.
	 */
	public function assert_no_privilege_escalation_input(
		array $input,
		?int $authenticated_actor_id = null
	): void {
		foreach ( $input as $key => $value ) {
			$normalized_key = strtolower( trim( (string) $key ) );

			if ( in_array( $normalized_key, self::FORBIDDEN_INPUT_KEYS, true ) ) {
				AuthorizationException::raise(
					AuthorizationException::CODE_PRIVILEGE_ESCALATION_ATTEMPT,
					'Request contains forbidden privilege, role, capability, or verification-state claims.'
				);
			}

			if (
				null !== $authenticated_actor_id
				&& in_array( $normalized_key, array( 'user_id', 'wp_user_id', 'actor_user_id', 'target_user_id' ), true )
			) {
				if ( ! is_int( $value ) && ! ( is_string( $value ) && ctype_digit( $value ) ) ) {
					AuthorizationException::raise(
						AuthorizationException::CODE_PRIVILEGE_ESCALATION_ATTEMPT,
						'Invalid user identifier in request input.'
					);
				}
				if ( (int) $value !== $authenticated_actor_id ) {
					AuthorizationException::raise(
						AuthorizationException::CODE_CROSS_USER_FORBIDDEN,
						'Request user identifier does not match the authenticated actor.'
					);
				}
			}
		}
	}

	/**
	 * Check whether an authenticated user holds a valid WPIG capability through an allowed role.
	 *
	 * Prevents direct user-capability injection (`wp_usermeta`) and multi-role bypasses by verifying
	 * that at least one non-disallowed role held by the user grants the capability at the role level.
	 *
	 * @param int    $actor_user_id Acting WordPress user ID.
	 * @param string $capability    WPIG capability slug.
	 */
	private function actor_has_authorized_capability( int $actor_user_id, string $capability ): bool {
		$roles = ( $this->user_roles_resolver )( $actor_user_id );
		if ( array() === $roles ) {
			return false;
		}

		// At least one non-disallowed role held by the user must grant the requested capability.
		$has_authorizing_role = false;
		foreach ( $roles as $role_slug ) {
			if ( Capabilities::is_disallowed_role( $role_slug ) ) {
				continue;
			}
			if ( (bool) ( $this->role_has_cap_resolver )( $role_slug, $capability ) ) {
				$has_authorizing_role = true;
				break;
			}
		}

		if ( ! $has_authorizing_role ) {
			return false;
		}

		return (bool) ( $this->user_can_resolver )( $actor_user_id, $capability );
	}

	/**
	 * Validate target user ID (`>= 1`) and verify Multisite blog membership when applicable.
	 *
	 * @param int      $target_user_id Target WordPress user ID.
	 * @param int|null $blog_id        Optional expected site blog ID.
	 * @throws AuthorizationException If target user ID is invalid, does not exist, or is outside the blog.
	 */
	public function assert_valid_target_user_on_blog( int $target_user_id, ?int $blog_id = null ): void {
		if ( $target_user_id < 1 ) {
			AuthorizationException::raise(
				AuthorizationException::CODE_FORBIDDEN,
				'Target WordPress user ID must be a positive integer.'
			);
		}

		$active_blog_id = $this->resolve_and_verify_blog_id( $blog_id );

		if ( ! (bool) ( $this->user_exists_resolver )( $target_user_id ) ) {
			AuthorizationException::raise(
				AuthorizationException::CODE_FORBIDDEN,
				'Target WordPress user account does not exist.'
			);
		}

		if ( (bool) ( $this->is_multisite_resolver )() ) {
			if ( ! (bool) ( $this->blog_member_resolver )( $target_user_id, $active_blog_id ) ) {
				AuthorizationException::raise(
					AuthorizationException::CODE_MULTISITE_FORBIDDEN,
					'Target user is not a member of the current Multisite site.'
				);
			}
		}
	}

	/**
	 * Resolve current site blog ID and reject any cross-blog mismatch.
	 *
	 * @param int|null $expected_blog_id Optional blog ID claimed by caller.
	 * @return int Active blog ID (`>= 1`).
	 * @throws AuthorizationException If blog ID is `< 1` or mismatches the active site.
	 */
	private function resolve_and_verify_blog_id( ?int $expected_blog_id ): int {
		$active_blog_id = (int) ( $this->blog_id_resolver )();
		if ( $active_blog_id < 1 ) {
			AuthorizationException::raise(
				AuthorizationException::CODE_MULTISITE_FORBIDDEN,
				'Active site blog_id must be a positive integer (>= 1).'
			);
		}

		if ( null !== $expected_blog_id && $expected_blog_id !== $active_blog_id ) {
			AuthorizationException::raise(
				AuthorizationException::CODE_MULTISITE_FORBIDDEN,
				'Cross-site authorization mismatch: requested blog_id does not match active site.'
			);
		}

		return $active_blog_id;
	}
}

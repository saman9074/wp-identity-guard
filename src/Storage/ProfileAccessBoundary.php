<?php
/**
 * Authorized application-service boundary guarding `ProfileRepository`.
 *
 * @package WPIG\Storage
 */

declare(strict_types=1);

namespace WPIG\Storage;

use SensitiveParameter;
use WPIG\Audit\AuditService;
use WPIG\Privacy\ConsentRecord;
use WPIG\Privacy\ConsentRepository;
use WPIG\Security\AuthorizationException;
use WPIG\Security\AuthorizationService;
use WPIG\Security\CryptoException;
use WPIG\Security\SensitiveValue;
use WPIG\Security\ValidationException;
use WPIG\Security\VerificationAuthorityGrant;

// phpcs:disable Squiz.Commenting.FunctionCommentThrowTag.WrongNumber -- Boundary methods document both rethrown AuthorizationException and propagated repository/crypto exceptions.

/**
 * Enforces authentication, capability, cross-user (IDOR), Multisite, consent,
 * and trusted-verification-authority boundaries in front of `ProfileRepository`.
 *
 * Security Invariants (Task 5 & P01 Security Closure):
 * - `ProfileRepository` remains an internal persistence component (`@internal`).
 * - External callers (including administrators) cannot arbitrarily mark identities `VERIFIED` or `BOUND`.
 * - Authoritative identity binding requires an unforgeable single-use, same-process `VerificationAuthorityGrant`
 *   from a trusted verification workflow plus an active, unrevoked `ConsentRecord` verified in `ConsentRepository`.
 * - Sensitive identity decryption requires explicit authorization, principal matching, and purpose validation
 *   at this boundary (`PURPOSE_VERIFICATION_DISPATCH` with verified `ConsentRecord`, or `PURPOSE_PRIVACY_EXPORT`).
 * - Cryptographic decryptability and user authorization are never treated as equivalent.
 */
final class ProfileAccessBoundary {

	/**
	 * Same-process replay ledger (`grant_id => expires_at_unix`) preventing a consumed
	 * grant ID from being replayed across multiple `ProfileAccessBoundary` instances
	 * within the same PHP worker process during the grant's validity window.
	 *
	 * Note: In Free v1.0, `VerificationAuthorityGrant` is strictly same-process (bound to
	 * `VerificationAuthorityGrant`'s per-process execution token). If future asynchronous
	 * workflows require cross-process grants, durable atomic database replay protection is required.
	 *
	 * @var array<string,int>
	 */
	private static array $global_consumed_grants = array();

	/**
	 * Internal profile persistence repository.
	 *
	 * @var ProfileRepository
	 */
	private ProfileRepository $repository;

	/**
	 * Authorization service.
	 *
	 * @var AuthorizationService
	 */
	private AuthorizationService $authorizer;

	/**
	 * Internal per-instance secret used to verify `VerificationAuthorityGrant` seals.
	 *
	 * @var string
	 */
	private string $authority_secret;

	/**
	 * Consumed grant IDs recorded at the boundary (`grant_id => expires_at_unix`) to prevent replay.
	 *
	 * @var array<string,int>
	 */
	private array $consumed_grants = array();

	/**
	 * Callback returning the active blog ID (`fn(): int`).
	 *
	 * @var callable
	 * @phpstan-var callable():int
	 */
	private $blog_id_resolver;

	/**
	 * Optional security audit service.
	 *
	 * @var AuditService|null
	 */
	private ?AuditService $audit_service;

	/**
	 * Callback returning the current Unix timestamp (`fn(): int`).
	 *
	 * @var callable
	 * @phpstan-var callable():int
	 */
	private $clock;

	/**
	 * Trusted consent repository verifying persisted `wpig_consents` records.
	 *
	 * @var ConsentRepository
	 */
	private ConsentRepository $consent_repository;

	/**
	 * Constructor.
	 *
	 * @param ProfileRepository      $repository         Internal profile repository.
	 * @param AuthorizationService   $authorizer         Authorization policy service.
	 * @param string|null            $authority_secret   Optional 32+ byte secret shared only with the trusted verification service.
	 * @param callable|null          $blog_id_resolver   Optional blog ID resolver (`fn(): int`).
	 * @param AuditService|null      $audit_service      Optional security audit service.
	 * @param callable|null          $clock              Optional Unix timestamp clock (`fn(): int`).
	 * @param ConsentRepository|null $consent_repository Optional consent repository override.
	 * @phpstan-param (callable():int)|null $blog_id_resolver
	 * @phpstan-param (callable():int)|null $clock
	 */
	public function __construct(
		ProfileRepository $repository,
		AuthorizationService $authorizer,
		#[SensitiveParameter] ?string $authority_secret = null,
		?callable $blog_id_resolver = null,
		?AuditService $audit_service = null,
		?callable $clock = null,
		?ConsentRepository $consent_repository = null
	) {
		$this->repository         = $repository;
		$this->authorizer         = $authorizer;
		$this->authority_secret   = null !== $authority_secret && strlen( $authority_secret ) >= 32
			? $authority_secret
			: random_bytes( 32 );
		$this->blog_id_resolver   = $blog_id_resolver ?? static function (): int {
			if ( function_exists( 'get_current_blog_id' ) ) {
				return max( 1, (int) get_current_blog_id() );
			}
			return 1;
		};
		$this->audit_service      = $audit_service;
		$this->clock              = $clock ?? static function (): int {
			return time();
		};
		$clock_fn                 = $this->clock;
		$utc_clock                = static fn(): string => gmdate( 'Y-m-d H:i:s', (int) ( $clock_fn )() );
		$this->consent_repository = $consent_repository ?? new ConsentRepository(
			$this->repository->get_wpdb(),
			$this->audit_service,
			$utc_clock,
			$this->blog_id_resolver
		);
	}

	/**
	 * Read a masked profile summary (`ProfileRecord`) for an authorized actor.
	 *
	 * Allowed for the profile owner (`$actor_user_id === $target_user_id`) or an
	 * authorized site role holding `view_wpig_reports` or `review_wpig_verification`.
	 * Never returns plaintext or raw ciphertexts.
	 *
	 * @param int      $actor_user_id  Acting WordPress user ID.
	 * @param int      $target_user_id Target WordPress user ID.
	 * @param int|null $blog_id        Optional expected site blog ID.
	 * @return ProfileRecord|null
	 * @throws AuthorizationException On unauthenticated access, cross-user IDOR, or Multisite violation.
	 * @throws StorageException       On storage error.
	 */
	public function get_masked_profile(
		int $actor_user_id,
		int $target_user_id,
		?int $blog_id = null
	): ?ProfileRecord {
		try {
			$this->authorizer->assert_can_view_masked_profile( $actor_user_id, $target_user_id, $blog_id );
		} catch ( AuthorizationException $e ) {
			$this->record_denied_audit( $actor_user_id, $target_user_id, 'get_masked_profile', $e->get_safe_code() );
			throw $e;
		}

		return $this->repository->find_by_user_id( $target_user_id );
	}

	/**
	 * Create a new `UNBOUND` / `UNVERIFIED` profile for the authenticated actor.
	 *
	 * @param int                        $actor_user_id  Acting WordPress user ID.
	 * @param int                        $target_user_id Target WordPress user ID (must match `$actor_user_id`).
	 * @param SensitiveValue|string|null $national_code  Optional 10-digit national code.
	 * @param SensitiveValue|string|null $mobile         Optional Iranian mobile number.
	 * @param SensitiveValue|string|null $birth_date     Optional Jalali birth date (`YYYY/MM/DD`).
	 * @param array<string,mixed>        $request_claims Optional user-supplied request payload to inspect for privilege escalation.
	 * @param int|null                   $blog_id        Optional expected site blog ID.
	 * @return ProfileRecord
	 * @throws AuthorizationException On unauthenticated access, cross-user IDOR, or privilege escalation claims.
	 * @throws ValidationException    On invalid identity attributes.
	 * @throws CryptoException        On missing/invalid keys.
	 * @throws StorageException       On duplicate profile or database failure.
	 */
	public function create_own_profile(
		int $actor_user_id,
		int $target_user_id,
		#[SensitiveParameter] SensitiveValue|string|null $national_code = null,
		#[SensitiveParameter] SensitiveValue|string|null $mobile = null,
		#[SensitiveParameter] SensitiveValue|string|null $birth_date = null,
		array $request_claims = array(),
		?int $blog_id = null
	): ProfileRecord {
		try {
			$this->authorizer->assert_no_privilege_escalation_input( $request_claims, $actor_user_id );
			$this->authorizer->assert_can_modify_own_profile( $actor_user_id, $target_user_id, $blog_id );
		} catch ( AuthorizationException $e ) {
			$this->record_denied_audit( $actor_user_id, $target_user_id, 'create_own_profile', $e->get_safe_code() );
			throw $e;
		}

		return $this->repository->create_profile(
			$target_user_id,
			$national_code,
			$mobile,
			$birth_date
		);
	}

	/**
	 * Update the authenticated actor's own mobile number.
	 *
	 * @param int                   $actor_user_id           Acting WordPress user ID.
	 * @param int                   $target_user_id          Target WordPress user ID (must match `$actor_user_id`).
	 * @param SensitiveValue|string $mobile                  Raw or normalized Iranian mobile number.
	 * @param int                   $expected_mobile_version Expected current `mobile_version`.
	 * @param array<string,mixed>   $request_claims          Optional user-supplied request payload to inspect.
	 * @param int|null              $blog_id                 Optional expected site blog ID.
	 * @return ProfileRecord
	 * @throws AuthorizationException On unauthenticated access, cross-user IDOR, or privilege escalation claims.
	 * @throws ValidationException    If mobile number is invalid.
	 * @throws CryptoException        On missing/invalid keys.
	 * @throws StorageException       On version conflict or database error.
	 */
	public function update_own_mobile(
		int $actor_user_id,
		int $target_user_id,
		#[SensitiveParameter] SensitiveValue|string $mobile,
		int $expected_mobile_version,
		array $request_claims = array(),
		?int $blog_id = null
	): ProfileRecord {
		try {
			$this->authorizer->assert_no_privilege_escalation_input( $request_claims, $actor_user_id );
			$this->authorizer->assert_can_modify_own_profile( $actor_user_id, $target_user_id, $blog_id );
		} catch ( AuthorizationException $e ) {
			$this->record_denied_audit( $actor_user_id, $target_user_id, 'update_own_mobile', $e->get_safe_code() );
			throw $e;
		}

		return $this->repository->update_mobile(
			$target_user_id,
			$mobile,
			$expected_mobile_version
		);
	}

	/**
	 * Update the authenticated actor's own unbound identity attributes (national code and birth date).
	 *
	 * @param int                   $actor_user_id             Acting WordPress user ID.
	 * @param int                   $target_user_id            Target WordPress user ID (must match `$actor_user_id`).
	 * @param SensitiveValue|string $national_code             Raw or normalized 10-digit national code.
	 * @param SensitiveValue|string $birth_date                Raw or normalized Jalali birth date (`YYYY/MM/DD`).
	 * @param int                   $expected_identity_version Expected current `identity_version`.
	 * @param array<string,mixed>   $request_claims            Optional user-supplied request payload to inspect.
	 * @param int|null              $blog_id                   Optional expected site blog ID.
	 * @return ProfileRecord
	 * @throws AuthorizationException On unauthenticated access, cross-user IDOR, or privilege escalation claims.
	 * @throws ValidationException    If national code or birth date is invalid.
	 * @throws CryptoException        On missing/invalid keys.
	 * @throws StorageException       If profile is already `BOUND` or version conflicts.
	 */
	public function update_own_identity_data(
		int $actor_user_id,
		int $target_user_id,
		#[SensitiveParameter] SensitiveValue|string $national_code,
		#[SensitiveParameter] SensitiveValue|string $birth_date,
		int $expected_identity_version,
		array $request_claims = array(),
		?int $blog_id = null
	): ProfileRecord {
		try {
			$this->authorizer->assert_no_privilege_escalation_input( $request_claims, $actor_user_id );
			$this->authorizer->assert_can_modify_own_profile( $actor_user_id, $target_user_id, $blog_id );
		} catch ( AuthorizationException $e ) {
			$this->record_denied_audit( $actor_user_id, $target_user_id, 'update_own_identity_data', $e->get_safe_code() );
			throw $e;
		}

		return $this->repository->update_identity_data(
			$target_user_id,
			$national_code,
			$birth_date,
			$expected_identity_version
		);
	}

	/**
	 * Authorize and decrypt a user's stored identity fields for a strictly validated purpose.
	 *
	 * Enforces authorization and trusted consent verification (`wpig_consents`) BEFORE invoking
	 * `ProfileRepository::decrypt_identity_for_user()` so cryptographic decryptability is never
	 * treated as user authorization.
	 *
	 * @param int                $actor_user_id      Acting WordPress user ID.
	 * @param int                $target_user_id     Target WordPress user ID.
	 * @param string             $purpose            Explicit decryption purpose (`AuthorizationService::PURPOSE_*`).
	 * @param ConsentRecord|bool $has_active_consent Trusted `ConsentRecord` or flag verified against `ConsentRepository`.
	 * @param int|null           $blog_id            Optional expected site blog ID.
	 * @return DecryptedIdentityData
	 * @throws AuthorizationException If decryption is forbidden for the actor, target, purpose, or consent state.
	 * @throws CryptoException        If keys are missing/invalid or AEAD authentication fails.
	 */
	public function decrypt_identity(
		int $actor_user_id,
		int $target_user_id,
		string $purpose,
		ConsentRecord|bool $has_active_consent = false,
		?int $blog_id = null
	): DecryptedIdentityData {
		$now_unix       = (int) ( $this->clock )();
		$now_utc        = gmdate( 'Y-m-d H:i:s', $now_unix );
		$active_blog_id = null !== $blog_id ? $blog_id : max( 1, (int) ( $this->blog_id_resolver )() );

		try {
			$consent_proof = $has_active_consent;
			if ( AuthorizationService::PURPOSE_VERIFICATION_DISPATCH === $purpose && $actor_user_id === $target_user_id ) {
				$consent_proof = $this->resolve_verified_consent_record(
					$has_active_consent,
					$target_user_id,
					$active_blog_id,
					ConsentRepository::PURPOSE_IDENTITY_VERIFICATION,
					$now_utc
				);
			}

			$this->authorizer->assert_can_decrypt_identity(
				$actor_user_id,
				$target_user_id,
				$purpose,
				$consent_proof,
				$blog_id,
				$now_utc
			);
		} catch ( AuthorizationException $e ) {
			$this->record_denied_audit( $actor_user_id, $target_user_id, 'decrypt_identity', $e->get_safe_code(), $purpose );
			throw $e;
		}

		$decrypted = $this->repository->decrypt_identity_for_user( $target_user_id );

		if ( null !== $this->audit_service ) {
			$this->audit_service->log_identity_decrypted( $actor_user_id, $target_user_id, $purpose );
		}

		return $decrypted;
	}

	/**
	 * Establish an authoritative `BOUND` & `VERIFIED` identity binding at the application boundary.
	 *
	 * Verification and Consumption Order (P01 Security Closure — Task 3):
	 * 1. Prune expired entries from instance and same-process consumed grant ledgers.
	 * 2. Verify `$actor_user_id` against the server-side `AuthenticationContext` (`assert_authenticated_actor`).
	 * 3. Require a non-null `VerificationAuthorityGrant` instance.
	 * 4. Verify self-ownership (`$actor_user_id === $target_user_id` on the active blog).
	 * 5. Verify an active, unrevoked, unexpired `ConsentRecord` in `wpig_consents` bound to
	 *    `($target_user_id, $active_blog_id, 'identity_verification')`.
	 * 6. Verify `$authority_grant->grant_id` has not already been consumed in `$this->consumed_grants`
	 *    or `self::$global_consumed_grants`.
	 * 7. Invoke `$authority_grant->verify_and_consume()` (which checks consumed flag, same-process
	 *    execution token, scope binding, TTL window, and HMAC-SHA-256 seal, then marks the grant consumed).
	 * 8. Record `$authority_grant->grant_id` in both `$this->consumed_grants` and
	 *    `self::$global_consumed_grants` BEFORE calling `ProfileRepository::bind_verified_identity()`.
	 * 9. Execute `ProfileRepository::bind_verified_identity()`.
	 *
	 * @param int                             $actor_user_id             Acting WordPress user ID.
	 * @param int                             $target_user_id            Target WordPress user ID.
	 * @param int                             $expected_identity_version Captured `identity_version`.
	 * @param int                             $expected_mobile_version   Captured `mobile_version`.
	 * @param VerificationAuthorityGrant|null $authority_grant           Unforgeable grant from trusted verification service.
	 * @param ConsentRecord|bool              $has_active_consent        Trusted `ConsentRecord` or flag verified against `ConsentRepository`.
	 * @param int|null                        $blog_id                   Optional expected site blog ID.
	 * @return ProfileRecord
	 * @throws AuthorizationException If authority grant is missing/invalid/replayed/expired, actor is unauthorized, or consent is missing.
	 * @throws CryptoException        If stored HMAC/ciphertext integrity check fails.
	 * @throws StorageException       On version conflict, missing prerequisites, or duplicate identity conflict (`D14`).
	 */
	public function bind_verified_identity(
		int $actor_user_id,
		int $target_user_id,
		int $expected_identity_version,
		int $expected_mobile_version,
		?VerificationAuthorityGrant $authority_grant = null,
		ConsentRecord|bool $has_active_consent = false,
		?int $blog_id = null
	): ProfileRecord {
		$now_unix = (int) ( $this->clock )();
		$now_utc  = gmdate( 'Y-m-d H:i:s', $now_unix );
		$this->prune_expired_consumed_grants( $now_unix );

		try {
			$this->authorizer->assert_authenticated_actor( $actor_user_id, $blog_id );

			if ( null === $authority_grant ) {
				AuthorizationException::raise(
					AuthorizationException::CODE_BINDING_AUTHORITY_REQUIRED,
					'Authoritative identity binding requires a trusted verification service grant; arbitrary binding is forbidden.'
				);
			}

			$this->authorizer->assert_can_modify_own_profile( $actor_user_id, $target_user_id, $blog_id );

			$active_blog_id   = null !== $blog_id ? $blog_id : max( 1, (int) ( $this->blog_id_resolver )() );
			$verified_consent = $this->resolve_verified_consent_record(
				$has_active_consent,
				$target_user_id,
				$active_blog_id,
				ConsentRepository::PURPOSE_IDENTITY_VERIFICATION,
				$now_utc
			);
			$this->authorizer->assert_active_consent(
				$verified_consent,
				$target_user_id,
				$blog_id,
				ConsentRepository::PURPOSE_IDENTITY_VERIFICATION,
				$now_utc
			);

			if (
				isset( $this->consumed_grants[ $authority_grant->grant_id ] )
				|| isset( self::$global_consumed_grants[ $authority_grant->grant_id ] )
			) {
				AuthorizationException::raise(
					AuthorizationException::CODE_BINDING_AUTHORITY_REQUIRED,
					'Verification authority grant has already been consumed at this boundary.'
				);
			}

			$authority_grant->verify_and_consume(
				$this->authority_secret,
				$active_blog_id,
				$target_user_id,
				$expected_identity_version,
				$expected_mobile_version,
				$now_unix
			);

			// Record grant ID in both instance and same-process ledgers BEFORE mutating repository state.
			$expiry_marker                                       = max( $now_unix, $authority_grant->expires_at_unix );
			$this->consumed_grants[ $authority_grant->grant_id ] = $expiry_marker;
			self::$global_consumed_grants[ $authority_grant->grant_id ] = $expiry_marker;
		} catch ( AuthorizationException $e ) {
			$this->record_denied_audit( $actor_user_id, $target_user_id, 'bind_verified_identity', $e->get_safe_code() );
			throw $e;
		}

		try {
			$record = $this->repository->bind_verified_identity(
				$target_user_id,
				$expected_identity_version,
				$expected_mobile_version,
				$authority_grant->expires_at_utc
			);
		} catch ( StorageException $e ) {
			if ( StorageException::CODE_IDENTITY_CONFLICT === $e->get_safe_code() && null !== $this->audit_service ) {
				$this->audit_service->log_identity_conflict(
					$actor_user_id,
					$target_user_id,
					$expected_identity_version,
					$expected_mobile_version
				);
			}
			throw $e;
		}

		if ( null !== $this->audit_service ) {
			$this->audit_service->log_identity_bound(
				$actor_user_id,
				$target_user_id,
				$record->identity_version,
				$record->mobile_version
			);
		}

		return $record;
	}

	/**
	 * Resolve and verify an active, unrevoked, unexpired `ConsentRecord` from `ConsentRepository`
	 * bound to `($target_user_id, $active_blog_id, $required_purpose)`.
	 *
	 * Never trusts a caller-supplied boolean `true` unless backed by a valid persisted `ConsentRecord`.
	 *
	 * @param ConsentRecord|bool $consent_evidence Caller-supplied consent evidence.
	 * @param int                $target_user_id   Target WordPress user ID.
	 * @param int                $active_blog_id   Active site blog ID.
	 * @param string             $required_purpose Required consent purpose (`ConsentRepository::PURPOSE_*`).
	 * @param string             $now_utc          Current UTC timestamp (`Y-m-d H:i:s`).
	 * @return ConsentRecord
	 * @throws AuthorizationException If consent is false, missing, revoked, expired, or mismatched.
	 */
	private function resolve_verified_consent_record(
		ConsentRecord|bool $consent_evidence,
		int $target_user_id,
		int $active_blog_id,
		string $required_purpose,
		string $now_utc
	): ConsentRecord {
		if ( false === $consent_evidence ) {
			AuthorizationException::raise(
				AuthorizationException::CODE_CONSENT_REQUIRED,
				'Explicit user consent is required before processing or dispatching identity data.'
			);
		}

		if (
			$consent_evidence instanceof ConsentRecord
			&& ! $consent_evidence->is_valid_for( $target_user_id, $active_blog_id, $required_purpose, $now_utc )
		) {
			AuthorizationException::raise(
				AuthorizationException::CODE_CONSENT_REQUIRED,
				'Supplied consent record is revoked, expired, or does not match the user, site, or operation.'
			);
		}

		try {
			$persisted = $this->consent_repository->find_active_consent(
				$target_user_id,
				$required_purpose,
				$active_blog_id,
				$now_utc
			);
		} catch ( ValidationException $e ) {
			unset( $e );
			$persisted = null;
		}

		if ( null === $persisted ) {
			AuthorizationException::raise(
				AuthorizationException::CODE_CONSENT_REQUIRED,
				'No active, unrevoked user consent record exists in wpig_consents for this user, site, and operation.'
			);
		}

		return $persisted;
	}

	/**
	 * Prune expired entries from the instance and process-wide consumed grant ledgers.
	 *
	 * @param int $now_unix Current Unix timestamp.
	 */
	private function prune_expired_consumed_grants( int $now_unix ): void {
		foreach ( $this->consumed_grants as $grant_id => $expires_at_unix ) {
			if ( $expires_at_unix < $now_unix ) {
				unset( $this->consumed_grants[ $grant_id ] );
			}
		}

		foreach ( self::$global_consumed_grants as $grant_id => $expires_at_unix ) {
			if ( $expires_at_unix < $now_unix ) {
				unset( self::$global_consumed_grants[ $grant_id ] );
			}
		}
	}

	/**
	 * Record an authorization denial audit event when an `AuditService` is configured.
	 *
	 * @param int         $actor_user_id  Acting WordPress user ID.
	 * @param int         $target_user_id Target WordPress user ID.
	 * @param string      $operation      Normalized boundary operation name.
	 * @param string      $error_code     Safe error code from `AuthorizationException`.
	 * @param string|null $purpose        Optional decryption purpose.
	 */
	private function record_denied_audit(
		int $actor_user_id,
		int $target_user_id,
		string $operation,
		string $error_code,
		?string $purpose = null
	): void {
		if ( null === $this->audit_service ) {
			return;
		}

		$this->audit_service->log_authorization_denied(
			$actor_user_id > 0 ? $actor_user_id : null,
			$target_user_id > 0 ? $target_user_id : null,
			$operation,
			$error_code,
			null,
			$purpose
		);
	}

	/**
	 * Redact authority secret from debug output.
	 *
	 * @return array<string,int|string>
	 */
	public function __debugInfo(): array {
		return array(
			'authority_secret' => SensitiveValue::REDACTED,
			'consumed_grants'  => count( $this->consumed_grants ),
		);
	}

	/**
	 * Forbid PHP serialization of the boundary and its authority secret.
	 *
	 * @throws AuthorizationException Always thrown.
	 */
	public function __serialize(): array {
		AuthorizationException::raise(
			AuthorizationException::CODE_FORBIDDEN,
			'Serialization of ProfileAccessBoundary is prohibited.'
		);
	}

	/**
	 * Forbid PHP unserialization of the boundary.
	 *
	 * @param array<string,mixed> $data Serialized payload.
	 * @throws AuthorizationException Always thrown.
	 */
	public function __unserialize( array $data ): void {
		unset( $data );
		AuthorizationException::raise(
			AuthorizationException::CODE_FORBIDDEN,
			'Unserialization of ProfileAccessBoundary is prohibited.'
		);
	}
}

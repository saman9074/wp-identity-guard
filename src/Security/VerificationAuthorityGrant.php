<?php
/**
 * Single-use, scoped authority grant required for authoritative identity binding.
 *
 * @package WPIG\Security
 */

declare(strict_types=1);

namespace WPIG\Security;

use JsonSerializable;
use SensitiveParameter;

/**
 * Unforgeable internal proof that a trusted verification service (future P02 Shahkar workflow)
 * has completed authoritative identity verification for a specific `(blog_id, wp_user_id, identity_version, mobile_version)`.
 *
 * Security & Lifecycle Invariants (P01 Security Closure — Task 3):
 * - External callers, users, and even site administrators cannot arbitrarily mark an identity
 *   `VERIFIED` or `BOUND` without a valid `VerificationAuthorityGrant` issued by the trusted
 *   verification authority bound to the active `ProfileAccessBoundary`.
 * - Free v1.0 Same-Process Lifecycle: Grants are strictly same-process, single-request tokens
 *   issued and consumed synchronously within the same PHP worker execution. Every grant is
 *   bound to a per-process 128-bit execution token (`self::get_process_token()`) sealed inside
 *   its HMAC-SHA-256 signature and cannot cross HTTP requests, PHP-FPM workers, or queues.
 * - Cross-Process Requirement Note: In-memory replay ledgers (`ProfileAccessBoundary`) protect
 *   only within a single PHP worker process. If a future phase ever requires cross-request or
 *   cross-worker grants, durable atomic database replay protection is required rather than
 *   static PHP arrays.
 * - Single-use (`verify_and_consume()` marks `$this->consumed = true` immediately upon valid
 *   verification, and `ProfileAccessBoundary` records `grant_id` in its replay ledger before
 *   invoking repository persistence).
 * - Redacts debug/string representations and forbids cloning and serialization.
 *
 * @internal Reserved for trusted verification workflow integration in P02.
 */
final class VerificationAuthorityGrant implements JsonSerializable {

	/**
	 * Default short lifetime (in seconds) for a single-use authority grant.
	 */
	public const DEFAULT_TTL_SECONDS = 60;

	/**
	 * Maximum allowed lifetime (in seconds) for a single-use authority grant.
	 */
	public const MAX_TTL_SECONDS = 300;

	/**
	 * Ephemeral 128-bit per-process execution token binding grants to the current PHP worker process.
	 *
	 * @var string|null
	 */
	private static ?string $process_token = null;

	/**
	 * Cryptographically random 128-bit grant identifier (32-char lowercase hex).
	 *
	 * @var string
	 */
	public readonly string $grant_id;

	/**
	 * Site blog ID (`>= 1`).
	 *
	 * @var int
	 */
	public readonly int $blog_id;

	/**
	 * Target WordPress user ID (`>= 1`).
	 *
	 * @var int
	 */
	public readonly int $wp_user_id;

	/**
	 * Verified `identity_version` (`>= 1`).
	 *
	 * @var int
	 */
	public readonly int $identity_version;

	/**
	 * Verified `mobile_version` (`>= 1`).
	 *
	 * @var int
	 */
	public readonly int $mobile_version;

	/**
	 * Optional UTC freshness expiration timestamp (`Y-m-d H:i:s`) for the resulting profile verification state.
	 *
	 * @var string|null
	 */
	public readonly ?string $expires_at_utc;

	/**
	 * Unix timestamp when this grant was issued.
	 *
	 * @var int
	 */
	public readonly int $issued_at_unix;

	/**
	 * Unix timestamp when this single-use grant expires and can no longer be consumed.
	 *
	 * @var int
	 */
	public readonly int $expires_at_unix;

	/**
	 * Process token active when this grant was issued.
	 *
	 * @var string
	 */
	private string $issued_process_token;

	/**
	 * Unforgeable HMAC-SHA-256 seal bound to the issuing authority secret and process token.
	 *
	 * @var string
	 */
	private string $seal;

	/**
	 * Whether this single-use grant has already been consumed.
	 *
	 * @var bool
	 */
	private bool $consumed = false;

	/**
	 * Private constructor; instantiated only via `issue()`.
	 *
	 * @param string      $grant_id             Unique 128-bit hex grant identifier.
	 * @param int         $blog_id              Site blog ID.
	 * @param int         $wp_user_id           WordPress user ID.
	 * @param int         $identity_version     Verified identity_version.
	 * @param int         $mobile_version       Verified mobile_version.
	 * @param string|null $expires_at_utc       Optional freshness expiry UTC timestamp.
	 * @param int         $issued_at_unix       Grant issuance Unix timestamp.
	 * @param int         $expires_at_unix      Grant TTL expiry Unix timestamp.
	 * @param string      $issued_process_token Per-process execution token.
	 * @param string      $seal                 HMAC-SHA-256 seal.
	 */
	private function __construct(
		string $grant_id,
		int $blog_id,
		int $wp_user_id,
		int $identity_version,
		int $mobile_version,
		?string $expires_at_utc,
		int $issued_at_unix,
		int $expires_at_unix,
		string $issued_process_token,
		#[SensitiveParameter] string $seal
	) {
		$this->grant_id             = $grant_id;
		$this->blog_id              = $blog_id;
		$this->wp_user_id           = $wp_user_id;
		$this->identity_version     = $identity_version;
		$this->mobile_version       = $mobile_version;
		$this->expires_at_utc       = $expires_at_utc;
		$this->issued_at_unix       = $issued_at_unix;
		$this->expires_at_unix      = $expires_at_unix;
		$this->issued_process_token = $issued_process_token;
		$this->seal                 = $seal;
	}

	/**
	 * Issue a scoped, same-process authority grant sealed with the trusted verification service secret.
	 *
	 * @param string      $authority_secret 32-byte internal authority secret held by the trusted verification service.
	 * @param int         $blog_id          Site blog ID (`>= 1`).
	 * @param int         $wp_user_id       Target WordPress user ID (`>= 1`).
	 * @param int         $identity_version Verified `identity_version` (`>= 1`).
	 * @param int         $mobile_version   Verified `mobile_version` (`>= 1`).
	 * @param string|null $expires_at_utc   Optional UTC freshness expiration timestamp.
	 * @param int         $ttl_seconds      Grant validity window in seconds (`1..300`, default `60`).
	 * @param int|null    $now_unix         Optional current Unix timestamp override for deterministic tests.
	 * @return self
	 * @throws AuthorizationException If parameters or secret are invalid.
	 */
	public static function issue(
		#[SensitiveParameter] string $authority_secret,
		int $blog_id,
		int $wp_user_id,
		int $identity_version,
		int $mobile_version,
		?string $expires_at_utc = null,
		int $ttl_seconds = self::DEFAULT_TTL_SECONDS,
		?int $now_unix = null
	): self {
		if (
			strlen( $authority_secret ) < 32
			|| $blog_id < 1
			|| $wp_user_id < 1
			|| $identity_version < 1
			|| $mobile_version < 1
			|| $ttl_seconds < 1
			|| $ttl_seconds > self::MAX_TTL_SECONDS
		) {
			AuthorizationException::raise(
				AuthorizationException::CODE_BINDING_AUTHORITY_REQUIRED,
				'Invalid parameters for issuing a verification authority grant.'
			);
		}

		$grant_id        = bin2hex( random_bytes( 16 ) );
		$issued_at_unix  = $now_unix ?? time();
		$expires_at_unix = $issued_at_unix + $ttl_seconds;
		$process_token   = self::get_process_token();

		$seal = self::compute_seal(
			$authority_secret,
			$process_token,
			$grant_id,
			$blog_id,
			$wp_user_id,
			$identity_version,
			$mobile_version,
			$expires_at_utc,
			$issued_at_unix,
			$expires_at_unix
		);

		return new self(
			$grant_id,
			$blog_id,
			$wp_user_id,
			$identity_version,
			$mobile_version,
			$expires_at_utc,
			$issued_at_unix,
			$expires_at_unix,
			$process_token,
			$seal
		);
	}

	/**
	 * Verify and consume this single-use grant against the expected target and authority secret.
	 *
	 * Verification and Consumption Order (P01 Security Closure — Task 3):
	 * 1. Check `$this->consumed`: fails closed immediately if this grant instance was already consumed.
	 * 2. Check same-process execution token (`$this->issued_process_token === self::get_process_token()`):
	 *    fails closed if the grant crossed an HTTP request or worker-process boundary.
	 * 3. Validate authority secret length (`>= 32`), `grant_id` format (`32` hex chars), and exact
	 *    scope binding (`blog_id`, `wp_user_id`, `identity_version`, `mobile_version`).
	 * 4. Validate the sealed TTL validity window (`issued_at_unix - 5 <= now_unix <= expires_at_unix`).
	 * 5. Recompute the expected HMAC-SHA-256 seal over the canonical payload (including the active
	 *    process token) and verify constant-time equality via `hash_equals()`.
	 * 6. Mark `$this->consumed = true` so the grant object can never be reused.
	 *
	 * Note: `ProfileAccessBoundary::bind_verified_identity()` also records `$this->grant_id` in its
	 * instance and same-process consumed ledgers immediately after `verify_and_consume()` returns
	 * and BEFORE invoking `ProfileRepository::bind_verified_identity()`.
	 *
	 * @param string   $authority_secret          Expected 32-byte internal authority secret.
	 * @param int      $expected_blog_id          Expected active site blog ID.
	 * @param int      $expected_wp_user_id       Expected target WordPress user ID.
	 * @param int      $expected_identity_version Expected `identity_version`.
	 * @param int      $expected_mobile_version   Expected `mobile_version`.
	 * @param int|null $now_unix                  Optional current Unix timestamp override for deterministic tests.
	 * @throws AuthorizationException If the grant was already consumed, crossed processes, expired, forged, or mismatched.
	 */
	public function verify_and_consume(
		#[SensitiveParameter] string $authority_secret,
		int $expected_blog_id,
		int $expected_wp_user_id,
		int $expected_identity_version,
		int $expected_mobile_version,
		?int $now_unix = null
	): void {
		if ( $this->consumed ) {
			AuthorizationException::raise(
				AuthorizationException::CODE_BINDING_AUTHORITY_REQUIRED,
				'Verification authority grant has already been consumed.'
			);
		}

		$active_process_token = self::get_process_token();
		if ( ! hash_equals( $active_process_token, $this->issued_process_token ) ) {
			AuthorizationException::raise(
				AuthorizationException::CODE_BINDING_AUTHORITY_REQUIRED,
				'Verification authority grant cannot cross HTTP requests or worker processes in Free v1.0.'
			);
		}

		if (
			strlen( $authority_secret ) < 32
			|| 32 !== strlen( $this->grant_id )
			|| $this->blog_id !== $expected_blog_id
			|| $this->wp_user_id !== $expected_wp_user_id
			|| $this->identity_version !== $expected_identity_version
			|| $this->mobile_version !== $expected_mobile_version
		) {
			AuthorizationException::raise(
				AuthorizationException::CODE_BINDING_AUTHORITY_REQUIRED,
				'Verification authority grant scope does not match target profile or site.'
			);
		}

		$current_unix = $now_unix ?? time();
		if ( $current_unix > $this->expires_at_unix || $current_unix < ( $this->issued_at_unix - 5 ) ) {
			AuthorizationException::raise(
				AuthorizationException::CODE_BINDING_AUTHORITY_REQUIRED,
				'Verification authority grant has expired or is outside its validity window.'
			);
		}

		$expected_seal = self::compute_seal(
			$authority_secret,
			$active_process_token,
			$this->grant_id,
			$expected_blog_id,
			$expected_wp_user_id,
			$expected_identity_version,
			$expected_mobile_version,
			$this->expires_at_utc,
			$this->issued_at_unix,
			$this->expires_at_unix
		);

		if ( ! hash_equals( $expected_seal, $this->seal ) ) {
			AuthorizationException::raise(
				AuthorizationException::CODE_BINDING_AUTHORITY_REQUIRED,
				'Verification authority grant signature is invalid.'
			);
		}

		$this->consumed = true;
	}

	/**
	 * Check whether this grant instance has been consumed.
	 */
	public function is_consumed(): bool {
		return $this->consumed;
	}

	/**
	 * Rotate the per-process execution token to simulate a new HTTP request or PHP-FPM worker boundary in tests.
	 *
	 * @internal Reserved for unit and integration testing of cross-request/cross-worker grant rejection.
	 */
	public static function rotate_process_token_for_testing(): string {
		self::$process_token = bin2hex( random_bytes( 16 ) );
		return self::$process_token;
	}

	/**
	 * Forbid cloning of a single-use authority grant.
	 *
	 * @throws AuthorizationException Always thrown.
	 */
	public function __clone(): void {
		AuthorizationException::raise(
			AuthorizationException::CODE_FORBIDDEN,
			'Cloning of VerificationAuthorityGrant is prohibited.'
		);
	}

	/**
	 * Redact accidental string casts.
	 */
	public function __toString(): string {
		return SensitiveValue::REDACTED;
	}

	/**
	 * Redact debug output.
	 *
	 * @return array<string,int|bool|string>
	 */
	public function __debugInfo(): array {
		return array(
			'grant_id'         => $this->grant_id,
			'blog_id'          => $this->blog_id,
			'wp_user_id'       => $this->wp_user_id,
			'identity_version' => $this->identity_version,
			'mobile_version'   => $this->mobile_version,
			'issued_at_unix'   => $this->issued_at_unix,
			'expires_at_unix'  => $this->expires_at_unix,
			'consumed'         => $this->consumed,
			'seal'             => SensitiveValue::REDACTED,
		);
	}

	/**
	 * Forbid PHP serialization.
	 *
	 * @throws AuthorizationException Always thrown.
	 */
	public function __serialize(): array {
		AuthorizationException::raise(
			AuthorizationException::CODE_FORBIDDEN,
			'Serialization of VerificationAuthorityGrant is prohibited.'
		);
	}

	/**
	 * Forbid PHP unserialization.
	 *
	 * @param array<string,mixed> $data Serialized payload.
	 * @throws AuthorizationException Always thrown.
	 */
	public function __unserialize( array $data ): void {
		unset( $data );
		AuthorizationException::raise(
			AuthorizationException::CODE_FORBIDDEN,
			'Unserialization of VerificationAuthorityGrant is prohibited.'
		);
	}

	/**
	 * Forbid JSON serialization.
	 *
	 * @throws AuthorizationException Always thrown.
	 */
	public function jsonSerialize(): mixed {
		AuthorizationException::raise(
			AuthorizationException::CODE_FORBIDDEN,
			'JSON serialization of VerificationAuthorityGrant is prohibited.'
		);
	}

	/**
	 * Resolve the current PHP worker process execution token (lazily generated once per process).
	 */
	private static function get_process_token(): string {
		if ( null === self::$process_token ) {
			self::$process_token = bin2hex( random_bytes( 16 ) );
		}

		return self::$process_token;
	}

	/**
	 * Compute HMAC-SHA-256 seal over the process token, grant parameters, and lifetime window.
	 *
	 * @param string      $authority_secret Authority secret.
	 * @param string      $process_token    Per-process execution token.
	 * @param string      $grant_id         Unique 128-bit hex grant identifier.
	 * @param int         $blog_id          Blog ID.
	 * @param int         $wp_user_id       User ID.
	 * @param int         $identity_version Identity version.
	 * @param int         $mobile_version   Mobile version.
	 * @param string|null $expires_at_utc   Optional freshness expiry timestamp.
	 * @param int         $issued_at_unix   Grant issuance Unix timestamp.
	 * @param int         $expires_at_unix  Grant TTL expiry Unix timestamp.
	 */
	private static function compute_seal(
		#[SensitiveParameter] string $authority_secret,
		string $process_token,
		string $grant_id,
		int $blog_id,
		int $wp_user_id,
		int $identity_version,
		int $mobile_version,
		?string $expires_at_utc,
		int $issued_at_unix,
		int $expires_at_unix
	): string {
		$payload = sprintf(
			'wpig:v1:binding_grant|%s|%s|%d|%d|%d|%d|%s|%d|%d',
			$process_token,
			$grant_id,
			$blog_id,
			$wp_user_id,
			$identity_version,
			$mobile_version,
			$expires_at_utc ?? 'none',
			$issued_at_unix,
			$expires_at_unix
		);

		return hash_hmac( 'sha256', $payload, $authority_secret, false );
	}
}

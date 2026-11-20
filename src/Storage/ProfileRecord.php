<?php
/**
 * Immutable typed DTO representing a safe, non-plaintext identity profile record.
 *
 * @package WPIG\Storage
 */

declare(strict_types=1);

namespace WPIG\Storage;

/**
 * Represents a persisted `wpig_profiles` record without exposing raw database
 * rows, raw ciphertexts, or plaintext identity attributes (DS-3, DS-4).
 */
final class ProfileRecord {

	public const BINDING_UNBOUND  = 'UNBOUND';
	public const BINDING_BOUND    = 'BOUND';
	public const BINDING_RELEASED = 'RELEASED';

	public const STATE_UNVERIFIED      = 'UNVERIFIED';
	public const STATE_PENDING         = 'PENDING';
	public const STATE_VERIFIED        = 'VERIFIED';
	public const STATE_REJECTED        = 'REJECTED';
	public const STATE_UNAVAILABLE     = 'UNAVAILABLE';
	public const STATE_INVALID_INPUT   = 'INVALID_INPUT';
	public const STATE_EXPIRED         = 'EXPIRED';
	public const STATE_REVIEW_REQUIRED = 'REVIEW_REQUIRED';

	/**
	 * Primary key ID.
	 *
	 * @var int
	 */
	public readonly int $id;

	/**
	 * WordPress user ID (`wp_users.ID`).
	 *
	 * @var int
	 */
	public readonly int $wp_user_id;

	/**
	 * Two-letter country code (e.g. 'IR').
	 *
	 * @var string
	 */
	public readonly string $country_code;

	/**
	 * Subject type ('natural' in Free v1.0).
	 *
	 * @var string
	 */
	public readonly string $subject_type;

	/**
	 * Permanent/active binding state ('UNBOUND', 'BOUND', 'RELEASED').
	 *
	 * @var string
	 */
	public readonly string $binding_state;

	/**
	 * Verification freshness state ('UNVERIFIED', 'PENDING', 'VERIFIED', 'REJECTED', 'EXPIRED', 'REVIEW_REQUIRED').
	 *
	 * @var string
	 */
	public readonly string $identity_state;

	/**
	 * Monotonic identity version counter (national code + birth date).
	 *
	 * @var int
	 */
	public readonly int $identity_version;

	/**
	 * Monotonic mobile version counter.
	 *
	 * @var int
	 */
	public readonly int $mobile_version;

	/**
	 * Monotonic card version counter (decoupled from identity & mobile evidence).
	 *
	 * @var int
	 */
	public readonly int $card_version;

	/**
	 * Purpose-separated HMAC-SHA-256 fingerprint of canonical mobile (`wpig:v1:mobile`).
	 *
	 * @var string|null
	 */
	public readonly ?string $mobile_hmac;

	/**
	 * Safe display mask for mobile (`0912***4567`).
	 *
	 * @var string|null
	 */
	public readonly ?string $mobile_masked;

	/**
	 * UTC timestamp of mobile OTP possession proof for current `mobile_version`.
	 *
	 * @var string|null
	 */
	public readonly ?string $mobile_verified_at;

	/**
	 * Purpose-separated HMAC-SHA-256 fingerprint of canonical national code (`wpig:v1:national_code`).
	 *
	 * @var string|null
	 */
	public readonly ?string $national_code_hmac;

	/**
	 * Active bound national code HMAC (non-null when `binding_state = 'BOUND'`, persists across expiry).
	 *
	 * @var string|null
	 */
	public readonly ?string $bound_national_code_hmac;

	/**
	 * Safe display mask for national code (`******1234`).
	 *
	 * @var string|null
	 */
	public readonly ?string $national_code_masked;

	/**
	 * Whether an encrypted mobile number is stored.
	 *
	 * @var bool
	 */
	public readonly bool $has_mobile;

	/**
	 * Whether an encrypted national code is stored.
	 *
	 * @var bool
	 */
	public readonly bool $has_national_code;

	/**
	 * Whether an encrypted Jalali birth date is stored.
	 *
	 * @var bool
	 */
	public readonly bool $has_birth_date;

	/**
	 * UTC timestamp of authoritative Shahkar match for `(identity_version, mobile_version)`.
	 *
	 * @var string|null
	 */
	public readonly ?string $shahkar_verified_at;

	/**
	 * Encryption key ID recorded on the profile.
	 *
	 * @var string|null
	 */
	public readonly ?string $enc_key_id;

	/**
	 * HMAC key ID recorded on the profile.
	 *
	 * @var string|null
	 */
	public readonly ?string $hmac_key_id;

	/**
	 * UTC timestamp when identity binding became 'BOUND'.
	 *
	 * @var string|null
	 */
	public readonly ?string $bound_at;

	/**
	 * UTC timestamp when identity binding was explicitly released.
	 *
	 * @var string|null
	 */
	public readonly ?string $released_at;

	/**
	 * UTC timestamp when identity state last became 'VERIFIED'.
	 *
	 * @var string|null
	 */
	public readonly ?string $verified_at;

	/**
	 * Optional UTC freshness expiration timestamp.
	 *
	 * @var string|null
	 */
	public readonly ?string $expires_at;

	/**
	 * UTC creation timestamp.
	 *
	 * @var string
	 */
	public readonly string $created_at;

	/**
	 * UTC last update timestamp.
	 *
	 * @var string
	 */
	public readonly string $updated_at;

	/**
	 * Constructor.
	 *
	 * @param int         $id                       Primary key ID.
	 * @param int         $wp_user_id               WordPress user ID.
	 * @param string      $country_code             ISO country code.
	 * @param string      $subject_type             Subject type.
	 * @param string      $binding_state            Binding state ('UNBOUND', 'BOUND', 'RELEASED').
	 * @param string      $identity_state           Freshness state.
	 * @param int         $identity_version         Identity version counter.
	 * @param int         $mobile_version           Mobile version counter.
	 * @param int         $card_version             Card version counter.
	 * @param string|null $mobile_hmac              Mobile HMAC-SHA-256 hex.
	 * @param string|null $mobile_masked            Masked mobile (`0912***4567`).
	 * @param string|null $mobile_verified_at       Mobile verified UTC timestamp.
	 * @param string|null $national_code_hmac       National code HMAC-SHA-256 hex.
	 * @param string|null $bound_national_code_hmac Bound national code HMAC-SHA-256 hex.
	 * @param string|null $national_code_masked     Masked national code (`******1234`).
	 * @param bool        $has_mobile               Whether mobile ciphertext is present.
	 * @param bool        $has_national_code        Whether national code ciphertext is present.
	 * @param bool        $has_birth_date           Whether birth date ciphertext is present.
	 * @param string|null $shahkar_verified_at      Shahkar verified UTC timestamp.
	 * @param string|null $enc_key_id               Encryption key ID.
	 * @param string|null $hmac_key_id              HMAC key ID.
	 * @param string|null $bound_at                 Bound UTC timestamp.
	 * @param string|null $released_at              Released UTC timestamp.
	 * @param string|null $verified_at              Verified UTC timestamp.
	 * @param string|null $expires_at               Freshness expiry UTC timestamp.
	 * @param string      $created_at               Created UTC timestamp.
	 * @param string      $updated_at               Updated UTC timestamp.
	 */
	public function __construct(
		int $id,
		int $wp_user_id,
		string $country_code,
		string $subject_type,
		string $binding_state,
		string $identity_state,
		int $identity_version,
		int $mobile_version,
		int $card_version,
		?string $mobile_hmac,
		?string $mobile_masked,
		?string $mobile_verified_at,
		?string $national_code_hmac,
		?string $bound_national_code_hmac,
		?string $national_code_masked,
		bool $has_mobile,
		bool $has_national_code,
		bool $has_birth_date,
		?string $shahkar_verified_at,
		?string $enc_key_id,
		?string $hmac_key_id,
		?string $bound_at,
		?string $released_at,
		?string $verified_at,
		?string $expires_at,
		string $created_at,
		string $updated_at
	) {
		$this->id                       = $id;
		$this->wp_user_id               = $wp_user_id;
		$this->country_code             = $country_code;
		$this->subject_type             = $subject_type;
		$this->binding_state            = $binding_state;
		$this->identity_state           = $identity_state;
		$this->identity_version         = $identity_version;
		$this->mobile_version           = $mobile_version;
		$this->card_version             = $card_version;
		$this->mobile_hmac              = $mobile_hmac;
		$this->mobile_masked            = $mobile_masked;
		$this->mobile_verified_at       = $mobile_verified_at;
		$this->national_code_hmac       = $national_code_hmac;
		$this->bound_national_code_hmac = $bound_national_code_hmac;
		$this->national_code_masked     = $national_code_masked;
		$this->has_mobile               = $has_mobile;
		$this->has_national_code        = $has_national_code;
		$this->has_birth_date           = $has_birth_date;
		$this->shahkar_verified_at      = $shahkar_verified_at;
		$this->enc_key_id               = $enc_key_id;
		$this->hmac_key_id              = $hmac_key_id;
		$this->bound_at                 = $bound_at;
		$this->released_at              = $released_at;
		$this->verified_at              = $verified_at;
		$this->expires_at               = $expires_at;
		$this->created_at               = $created_at;
		$this->updated_at               = $updated_at;
	}

	/**
	 * Whether this profile holds an active identity binding (`binding_state = 'BOUND'`).
	 */
	public function is_bound(): bool {
		return self::BINDING_BOUND === $this->binding_state
			&& null !== $this->bound_national_code_hmac
			&& '' !== $this->bound_national_code_hmac;
	}

	/**
	 * Whether the verification evidence is currently fresh at the given UTC timestamp.
	 *
	 * @param string $now_utc Current UTC timestamp in `Y-m-d H:i:s` format.
	 */
	public function is_freshly_verified( string $now_utc ): bool {
		if ( self::STATE_VERIFIED !== $this->identity_state ) {
			return false;
		}
		if ( null !== $this->expires_at && $this->expires_at <= $now_utc ) {
			return false;
		}
		return true;
	}

	/**
	 * Return a safe, non-sensitive summary suitable for export, diagnostics, or UI rendering.
	 *
	 * Never includes plaintext identity values, ciphertexts, or HMAC digests (DS-4).
	 *
	 * @return array<string,int|string|bool|null>
	 */
	public function to_safe_export_array(): array {
		return array(
			'id'                   => $this->id,
			'wp_user_id'           => $this->wp_user_id,
			'country_code'         => $this->country_code,
			'subject_type'         => $this->subject_type,
			'binding_state'        => $this->binding_state,
			'identity_state'       => $this->identity_state,
			'identity_version'     => $this->identity_version,
			'mobile_version'       => $this->mobile_version,
			'card_version'         => $this->card_version,
			'mobile_masked'        => $this->mobile_masked,
			'national_code_masked' => $this->national_code_masked,
			'has_mobile'           => $this->has_mobile,
			'has_national_code'    => $this->has_national_code,
			'has_birth_date'       => $this->has_birth_date,
			'mobile_verified_at'   => $this->mobile_verified_at,
			'shahkar_verified_at'  => $this->shahkar_verified_at,
			'bound_at'             => $this->bound_at,
			'released_at'          => $this->released_at,
			'verified_at'          => $this->verified_at,
			'expires_at'           => $this->expires_at,
			'created_at'           => $this->created_at,
			'updated_at'           => $this->updated_at,
		);
	}
}

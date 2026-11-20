<?php
/**
 * Redacted container for decrypted user identity attributes wrapped in SensitiveValue.
 *
 * @package WPIG\Storage
 */

declare(strict_types=1);

namespace WPIG\Storage;

use JsonSerializable;
use WPIG\Security\CryptoException;
use WPIG\Security\SensitiveValue;

/**
 * Holds decrypted identity fields (`national_code`, `mobile`, `birth_date`) wrapped
 * in `SensitiveValue` alongside the non-sensitive `ProfileRecord`.
 *
 * Security invariants (DS-3, DS-4):
 * - Wipes all decrypted SensitiveValue instances on `wipe()` and `__destruct()`.
 * - Redacts string casts and `var_dump()` / `print_r()` output.
 * - Prohibits PHP and JSON serialization.
 */
final class DecryptedIdentityData implements JsonSerializable {

	/**
	 * Safe profile metadata record.
	 *
	 * @var ProfileRecord
	 */
	public readonly ProfileRecord $profile;

	/**
	 * Decrypted 10-digit canonical national code (if present).
	 *
	 * @var SensitiveValue|null
	 */
	public readonly ?SensitiveValue $national_code;

	/**
	 * Decrypted 11-digit canonical mobile number (if present).
	 *
	 * @var SensitiveValue|null
	 */
	public readonly ?SensitiveValue $mobile;

	/**
	 * Decrypted canonical Jalali birth date `YYYY/MM/DD` (if present).
	 *
	 * @var SensitiveValue|null
	 */
	public readonly ?SensitiveValue $birth_date;

	/**
	 * Constructor.
	 *
	 * @param ProfileRecord       $profile       Safe profile metadata record.
	 * @param SensitiveValue|null $national_code Decrypted national code.
	 * @param SensitiveValue|null $mobile        Decrypted mobile number.
	 * @param SensitiveValue|null $birth_date    Decrypted Jalali birth date.
	 */
	public function __construct(
		ProfileRecord $profile,
		?SensitiveValue $national_code,
		?SensitiveValue $mobile,
		?SensitiveValue $birth_date
	) {
		$this->profile       = $profile;
		$this->national_code = $national_code;
		$this->mobile        = $mobile;
		$this->birth_date    = $birth_date;
	}

	/**
	 * Destructor wipes all decrypted SensitiveValue buffers.
	 */
	public function __destruct() {
		$this->wipe();
	}

	/**
	 * Wipe all decrypted SensitiveValue buffers held by this container.
	 */
	public function wipe(): void {
		if ( null !== $this->national_code ) {
			$this->national_code->wipe();
		}
		if ( null !== $this->mobile ) {
			$this->mobile->wipe();
		}
		if ( null !== $this->birth_date ) {
			$this->birth_date->wipe();
		}
	}

	/**
	 * Redact accidental string casts.
	 */
	public function __toString(): string {
		return SensitiveValue::REDACTED;
	}

	/**
	 * Redact var_dump() and print_r() output.
	 *
	 * @return array<string,mixed>
	 */
	public function __debugInfo(): array {
		return array(
			'profile'       => $this->profile->to_safe_export_array(),
			'national_code' => SensitiveValue::REDACTED,
			'mobile'        => SensitiveValue::REDACTED,
			'birth_date'    => SensitiveValue::REDACTED,
		);
	}

	/**
	 * Prevent PHP serialize().
	 *
	 * @throws CryptoException Always thrown.
	 */
	public function __serialize(): array {
		CryptoException::raise(
			CryptoException::CODE_SERIALIZATION_FORBIDDEN,
			'Serialization of DecryptedIdentityData is prohibited.'
		);
	}

	/**
	 * Prevent PHP unserialize().
	 *
	 * @param array<string,mixed> $data Serialized payload.
	 * @throws CryptoException Always thrown.
	 */
	public function __unserialize( array $data ): void {
		unset( $data );
		CryptoException::raise(
			CryptoException::CODE_SERIALIZATION_FORBIDDEN,
			'Unserialization of DecryptedIdentityData is prohibited.'
		);
	}

	/**
	 * Prevent json_encode() from serializing decrypted identity data.
	 *
	 * @throws CryptoException Always thrown.
	 */
	public function jsonSerialize(): mixed {
		CryptoException::raise(
			CryptoException::CODE_SERIALIZATION_FORBIDDEN,
			'JSON serialization of DecryptedIdentityData is prohibited.'
		);
	}
}

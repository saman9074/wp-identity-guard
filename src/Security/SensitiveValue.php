<?php
/**
 * Redacted wrapper for in-memory secrets and sensitive identity attributes.
 *
 * @package WPIG\Security
 */

declare(strict_types=1);

namespace WPIG\Security;

use JsonSerializable;
use SensitiveParameter;

/**
 * Encapsulates a sensitive plaintext or key string to prevent accidental
 * exposure in logs, string interpolation, var_dump/print_r, stack traces,
 * or PHP/JSON serialization (DS-4).
 *
 * PHP Memory Limitation Note:
 * This class zeroes its internal buffer via `sodium_memzero()` on `wipe()`
 * and `__destruct()`. However, because PHP strings use copy-on-write and may
 * be interned or duplicated by the Zend Engine or I/O layers before wrapping
 * or after `reveal()`, userland PHP cannot guarantee complete physical RAM
 * erasure across all engine copies.
 */
final class SensitiveValue implements JsonSerializable {

	/**
	 * Redaction placeholder returned by string and debug representations.
	 */
	public const REDACTED = '[REDACTED]';

	/**
	 * Underlying sensitive bytes (null after wipe).
	 *
	 * @var string|null
	 */
	private ?string $value;

	/**
	 * Whether wipe() has been called on this instance.
	 *
	 * @var bool
	 */
	private bool $wiped = false;

	/**
	 * Constructor.
	 *
	 * @param string $value Sensitive plaintext or binary key material.
	 */
	public function __construct( #[SensitiveParameter] string $value ) {
		// Copy into a dedicated non-interned buffer (refcount = 1) so sodium_memzero can zero it in place.
		$this->value = str_repeat( $value, 1 );
	}

	/**
	 * Destructor performs best-effort memory wiping.
	 */
	public function __destruct() {
		$this->wipe();
	}

	/**
	 * Explicitly access the underlying value.
	 *
	 * @throws CryptoException If the value has already been wiped.
	 */
	public function reveal(): string {
		if ( $this->wiped || null === $this->value ) {
			CryptoException::raise(
				CryptoException::CODE_SENSITIVE_VALUE_WIPED,
				'Cannot reveal a SensitiveValue that has already been wiped.'
			);
		}

		return $this->value;
	}

	/**
	 * Whether the value has already been wiped.
	 */
	public function is_wiped(): bool {
		return $this->wiped;
	}

	/**
	 * Return byte length of the underlying value (0 if wiped).
	 */
	public function length(): int {
		if ( $this->wiped || null === $this->value ) {
			return 0;
		}

		return strlen( $this->value );
	}

	/**
	 * Constant-time equality comparison against another SensitiveValue or raw string.
	 *
	 * @param self|string $other Value to compare against.
	 * @throws CryptoException If either SensitiveValue has been wiped.
	 */
	public function equals( #[SensitiveParameter] self|string $other ): bool {
		$candidate = $other instanceof self ? $other->reveal() : $other;
		return hash_equals( $this->reveal(), $candidate );
	}

	/**
	 * Best-effort zeroing of the underlying string buffer and clearing of internal references.
	 *
	 * Note: Zeroes this instance's buffer via sodium_memzero() and sets the internal
	 * property reference to null, but userland PHP cannot guarantee complete physical
	 * RAM erasure of pre-existing Zend Engine copies.
	 */
	public function wipe(): void {
		if ( $this->wiped || null === $this->value ) {
			$this->wiped = true;
			$this->value = null;
			return;
		}

		$this->wiped = true;

		if ( '' === $this->value ) {
			$this->value = null;
			return;
		}

		try {
			if ( function_exists( 'sodium_memzero' ) ) {
				try {
					sodium_memzero( $this->value );
					return;
				} catch ( \Throwable ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch -- Fallback to manual overwrite below.
				}
			}

			if ( is_string( $this->value ) ) {
				$len = strlen( $this->value );
				for ( $i = 0; $i < $len; $i++ ) {
					$this->value[ $i ] = "\0";
				}
			}
		} finally {
			$this->value = null;
		}
	}

	/**
	 * Redact accidental string casts or interpolation.
	 */
	public function __toString(): string {
		return self::REDACTED;
	}

	/**
	 * Redact var_dump() and print_r() output.
	 *
	 * @return array<string,string>
	 */
	public function __debugInfo(): array {
		return array(
			'value' => self::REDACTED,
		);
	}

	/**
	 * Prevent PHP serialize().
	 *
	 * @throws CryptoException Always thrown to prevent serialization of secrets.
	 */
	public function __serialize(): array {
		CryptoException::raise(
			CryptoException::CODE_SERIALIZATION_FORBIDDEN,
			'Serialization of SensitiveValue is prohibited.'
		);
	}

	/**
	 * Prevent PHP unserialize().
	 *
	 * @param array<string,mixed> $data Serialized payload.
	 * @throws CryptoException Always thrown to prevent unserialization of secrets.
	 */
	public function __unserialize( array $data ): void {
		unset( $data );
		CryptoException::raise(
			CryptoException::CODE_SERIALIZATION_FORBIDDEN,
			'Unserialization of SensitiveValue is prohibited.'
		);
	}

	/**
	 * Prevent legacy __sleep() serialization.
	 *
	 * @throws CryptoException Always thrown.
	 */
	public function __sleep(): array {
		CryptoException::raise(
			CryptoException::CODE_SERIALIZATION_FORBIDDEN,
			'Serialization of SensitiveValue is prohibited.'
		);
	}

	/**
	 * Prevent legacy __wakeup() unserialization.
	 *
	 * @throws CryptoException Always thrown.
	 */
	public function __wakeup(): void {
		CryptoException::raise(
			CryptoException::CODE_SERIALIZATION_FORBIDDEN,
			'Unserialization of SensitiveValue is prohibited.'
		);
	}

	/**
	 * Prevent json_encode() from serializing sensitive values.
	 *
	 * @throws CryptoException Always thrown to prevent accidental JSON leakage.
	 */
	public function jsonSerialize(): mixed {
		CryptoException::raise(
			CryptoException::CODE_SERIALIZATION_FORBIDDEN,
			'JSON serialization of SensitiveValue is prohibited.'
		);
	}
}

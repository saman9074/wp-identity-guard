<?php
/**
 * Libsodium XChaCha20-Poly1305-IETF authenticated encryption and HMAC-SHA-256 implementation.
 *
 * @package WPIG\Security
 */

declare(strict_types=1);

namespace WPIG\Security;

use SensitiveParameter;
use WPIG\Contracts\CryptoInterface;
use WPIG\Contracts\KeyProviderInterface;

/**
 * Implements AEAD encryption (`sodium_crypto_aead_xchacha20poly1305_ietf_*`)
 * bound to canonical 6-segment AAD and purpose-separated HMAC-SHA-256 digests.
 *
 * Envelope format (v1): `v1:<key_id>:<base64_urlsafe_unpadded(nonce_24B || ciphertext_and_16B_tag)>`
 */
final class SodiumCrypto implements CryptoInterface {

	/**
	 * Supported ciphertext envelope version.
	 */
	public const ENVELOPE_VERSION = 'v1';

	/**
	 * XChaCha20-Poly1305-IETF nonce length in bytes (192 bits).
	 */
	public const NONCE_BYTES = 24;

	/**
	 * Poly1305 authentication tag length in bytes (128 bits).
	 */
	public const TAG_BYTES = 16;

	/**
	 * Key length in bytes (256 bits).
	 */
	public const KEY_BYTES = 32;

	/**
	 * Key provider instance.
	 *
	 * @var KeyProviderInterface
	 */
	private KeyProviderInterface $key_provider;

	/**
	 * Optional sodium availability check callback for testing missing extension handling.
	 *
	 * @var callable
	 * @phpstan-var callable():bool
	 */
	private $sodium_checker;

	/**
	 * Constructor.
	 *
	 * @param KeyProviderInterface $key_provider   Key provider instance.
	 * @param callable|null        $sodium_checker Optional sodium availability check override for tests.
	 * @phpstan-param (callable():bool)|null $sodium_checker
	 */
	public function __construct(
		KeyProviderInterface $key_provider,
		?callable $sodium_checker = null
	) {
		$this->key_provider   = $key_provider;
		$this->sodium_checker = $sodium_checker ?? static function (): bool {
			return extension_loaded( 'sodium' )
				&& function_exists( 'sodium_crypto_aead_xchacha20poly1305_ietf_encrypt' )
				&& function_exists( 'sodium_crypto_aead_xchacha20poly1305_ietf_decrypt' );
		};
	}

	/**
	 * Encrypt plaintext using the active encryption key and canonical AAD.
	 *
	 * @param SensitiveValue|string $plaintext Non-empty plaintext to encrypt.
	 * @param string                $aad       Canonical 6-segment AAD matching the active key ID.
	 * @return string Versioned ciphertext envelope.
	 * @throws CryptoException If sodium is unavailable, input/AAD/key is invalid, or encryption fails.
	 */
	public function encrypt(
		#[SensitiveParameter] SensitiveValue|string $plaintext,
		string $aad
	): string {
		$this->assert_sodium_available();

		$raw_plaintext = null;
		$key_obj       = null;
		$raw_key       = null;

		try {
			$raw_plaintext = $plaintext instanceof SensitiveValue
				? str_repeat( $plaintext->reveal(), 1 )
				: str_repeat( $plaintext, 1 );

			if ( '' === $raw_plaintext ) {
				CryptoException::raise(
					CryptoException::CODE_PLAINTEXT_INVALID,
					'Plaintext for AEAD encryption must not be empty.'
				);
			}

			$active_key_id = $this->key_provider->get_active_encryption_key_id();
			CanonicalAad::validate( $aad, $active_key_id );

			$key_obj = $this->key_provider->get_active_encryption_key();
			$raw_key = str_repeat( $key_obj->reveal(), 1 );
			$key_obj->wipe();

			if ( self::KEY_BYTES !== strlen( $raw_key ) ) {
				CryptoException::raise(
					CryptoException::CODE_KEY_INVALID,
					'Active encryption key must be exactly 32 bytes.'
				);
			}

			$nonce      = random_bytes( self::NONCE_BYTES );
			$ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
				$raw_plaintext,
				$aad,
				$nonce,
				$raw_key
			);

			$encoded = sodium_bin2base64(
				$nonce . $ciphertext,
				SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING
			);

			return sprintf( '%s:%s:%s', self::ENVELOPE_VERSION, $active_key_id, $encoded );
		} finally {
			if ( $key_obj instanceof SensitiveValue && ! $key_obj->is_wiped() ) {
				$key_obj->wipe();
			}
			if ( is_string( $raw_plaintext ) ) {
				sodium_memzero( $raw_plaintext );
			}
			if ( is_string( $raw_key ) ) {
				sodium_memzero( $raw_key );
			}
		}
	}

	/**
	 * Authenticate and decrypt a versioned ciphertext envelope using canonical AAD.
	 *
	 * @param string $envelope Versioned ciphertext envelope (`v1:<key_id>:<payload>`).
	 * @param string $aad      Canonical 6-segment AAD matching the envelope's `<key_id>`.
	 * @return SensitiveValue Decrypted plaintext wrapped in SensitiveValue.
	 * @throws CryptoException On invalid envelope, AAD mismatch, unknown key ID, or authentication failure.
	 */
	public function decrypt( string $envelope, string $aad ): SensitiveValue {
		$this->assert_sodium_available();

		$key_obj   = null;
		$raw_key   = null;
		$decrypted = null;

		try {
			list( $key_id, $payload_b64 ) = $this->parse_envelope( $envelope );
			CanonicalAad::validate( $aad, $key_id );

			try {
				$binary = sodium_base642bin(
					$payload_b64,
					SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING
				);
			} catch ( \Throwable ) {
				CryptoException::raise(
					CryptoException::CODE_ENVELOPE_INVALID,
					'Ciphertext envelope contains invalid base64 payload.'
				);
			}

			// Re-encode to enforce strict canonical unpadded base64 representation.
			$reencoded = sodium_bin2base64( $binary, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING );
			if ( ! hash_equals( $reencoded, $payload_b64 ) ) {
				CryptoException::raise(
					CryptoException::CODE_ENVELOPE_INVALID,
					'Ciphertext envelope base64 encoding is non-canonical.'
				);
			}

			if ( strlen( $binary ) <= ( self::NONCE_BYTES + self::TAG_BYTES ) ) {
				CryptoException::raise(
					CryptoException::CODE_ENVELOPE_INVALID,
					'Ciphertext payload is shorter than minimum nonce + authentication tag length.'
				);
			}

			$nonce              = substr( $binary, 0, self::NONCE_BYTES );
			$ciphertext_and_tag = substr( $binary, self::NONCE_BYTES );

			$key_obj = $this->key_provider->get_encryption_key( $key_id );
			$raw_key = str_repeat( $key_obj->reveal(), 1 );
			$key_obj->wipe();

			if ( self::KEY_BYTES !== strlen( $raw_key ) ) {
				CryptoException::raise(
					CryptoException::CODE_KEY_INVALID,
					'Resolved encryption key must be exactly 32 bytes.'
				);
			}

			$decrypted = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
				$ciphertext_and_tag,
				$aad,
				$nonce,
				$raw_key
			);

			if ( ! is_string( $decrypted ) ) {
				CryptoException::raise(
					CryptoException::CODE_AUTH_FAILED,
					'AEAD authentication and decryption failed (fail-closed).'
				);
			}

			return new SensitiveValue( $decrypted );
		} finally {
			if ( $key_obj instanceof SensitiveValue && ! $key_obj->is_wiped() ) {
				$key_obj->wipe();
			}
			if ( is_string( $decrypted ) ) {
				sodium_memzero( $decrypted );
			}
			if ( is_string( $raw_key ) ) {
				sodium_memzero( $raw_key );
			}
		}
	}

	/**
	 * Extract and validate the encryption `<key_id>` from a versioned envelope header.
	 *
	 * @param string $envelope Versioned ciphertext envelope (`v1:<key_id>:<payload>`).
	 * @return string Validated key identifier.
	 * @throws CryptoException If the envelope header or version is invalid.
	 */
	public function extract_key_id( string $envelope ): string {
		list( $key_id ) = $this->parse_envelope( $envelope );
		return $key_id;
	}

	/**
	 * Compute a purpose-separated HMAC-SHA-256 fingerprint (`64`-char lowercase hex).
	 *
	 * @param string                $purpose         Domain-separation tag matching `^wpig:v1:[a-z0-9_]+$`.
	 * @param SensitiveValue|string $canonical_value Non-empty canonical ASCII value.
	 * @param string|null           $key_id          Optional HMAC key ID (defaults to active HMAC key).
	 * @return string 64-character lowercase hexadecimal digest.
	 * @throws CryptoException If purpose, value, or key is invalid.
	 */
	public function hmac(
		string $purpose,
		#[SensitiveParameter] SensitiveValue|string $canonical_value,
		?string $key_id = null
	): string {
		$this->assert_sodium_available();

		$raw_value = null;
		$key_obj   = null;
		$raw_key   = null;
		$message   = null;

		try {
			if ( 1 !== preg_match( '/^wpig:v1:[a-z0-9_]+$/', $purpose ) ) {
				CryptoException::raise(
					CryptoException::CODE_PURPOSE_INVALID,
					'HMAC purpose tag must match wpig:v1:<purpose_name>.'
				);
			}

			$raw_value = $canonical_value instanceof SensitiveValue
				? str_repeat( $canonical_value->reveal(), 1 )
				: str_repeat( $canonical_value, 1 );

			if ( '' === $raw_value ) {
				CryptoException::raise(
					CryptoException::CODE_PLAINTEXT_INVALID,
					'HMAC canonical input value must not be empty.'
				);
			}

			$key_obj = null === $key_id
				? $this->key_provider->get_active_hmac_key()
				: $this->key_provider->get_hmac_key( $key_id );

			$raw_key = str_repeat( $key_obj->reveal(), 1 );
			$key_obj->wipe();

			if ( self::KEY_BYTES !== strlen( $raw_key ) ) {
				CryptoException::raise(
					CryptoException::CODE_KEY_INVALID,
					'HMAC key must be exactly 32 bytes.'
				);
			}

			$message = $purpose . '|' . $raw_value;
			return hash_hmac( 'sha256', $message, $raw_key, false );
		} finally {
			if ( $key_obj instanceof SensitiveValue && ! $key_obj->is_wiped() ) {
				$key_obj->wipe();
			}
			if ( is_string( $message ) ) {
				sodium_memzero( $message );
			}
			if ( is_string( $raw_value ) ) {
				sodium_memzero( $raw_value );
			}
			if ( is_string( $raw_key ) ) {
				sodium_memzero( $raw_key );
			}
		}
	}

	/**
	 * Verify a purpose-separated HMAC-SHA-256 fingerprint in constant time.
	 *
	 * @param string                $expected_hex    Expected 64-char hex digest.
	 * @param string                $purpose         Domain-separation tag matching `^wpig:v1:[a-z0-9_]+$`.
	 * @param SensitiveValue|string $canonical_value Non-empty canonical ASCII value.
	 * @param string|null           $key_id          Optional HMAC key ID (defaults to active HMAC key).
	 * @return bool True if digest matches in constant time, false otherwise.
	 * @throws CryptoException If purpose, value, or key is invalid.
	 */
	public function verify_hmac(
		string $expected_hex,
		string $purpose,
		#[SensitiveParameter] SensitiveValue|string $canonical_value,
		?string $key_id = null
	): bool {
		if ( 1 !== preg_match( '/^[0-9a-f]{64}$/', $expected_hex ) ) {
			return false;
		}

		$computed = $this->hmac( $purpose, $canonical_value, $key_id );
		return hash_equals( $expected_hex, $computed );
	}

	/**
	 * Parse and validate the `v1:<key_id>:<payload_b64>` envelope structure.
	 *
	 * @param string $envelope Raw envelope string.
	 * @return array{0:string,1:string} Tuple of `[ $key_id, $payload_b64 ]`.
	 * @throws CryptoException If the envelope structure or version is invalid.
	 */
	private function parse_envelope( string $envelope ): array {
		$parts = explode( ':', $envelope );
		if ( 3 !== count( $parts ) ) {
			CryptoException::raise(
				CryptoException::CODE_ENVELOPE_INVALID,
				'Ciphertext envelope must consist of 3 colon-separated segments (version:key_id:payload).'
			);
		}

		list( $version, $key_id, $payload_b64 ) = $parts;

		if ( self::ENVELOPE_VERSION !== $version ) {
			CryptoException::raise(
				CryptoException::CODE_ENVELOPE_VERSION,
				sprintf( 'Unsupported ciphertext envelope version "%s".', $version )
			);
		}

		CanonicalAad::assert_valid_key_id( $key_id );

		if ( '' === $payload_b64 || 1 !== preg_match( '/^[A-Za-z0-9_-]+$/', $payload_b64 ) ) {
			CryptoException::raise(
				CryptoException::CODE_ENVELOPE_INVALID,
				'Ciphertext envelope payload must be non-empty URL-safe unpadded base64.'
			);
		}

		return array( $key_id, $payload_b64 );
	}

	/**
	 * Ensure the PHP sodium extension and XChaCha20-Poly1305-IETF functions are available.
	 *
	 * @throws CryptoException If sodium is unavailable.
	 */
	private function assert_sodium_available(): void {
		if ( ! (bool) ( $this->sodium_checker )() ) {
			CryptoException::raise(
				CryptoException::CODE_SODIUM_UNAVAILABLE,
				'The PHP libsodium extension (xchacha20poly1305_ietf) is required for cryptographic operations.'
			);
		}
	}
}

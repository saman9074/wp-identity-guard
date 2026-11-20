<?php
/**
 * Contract for authenticated encryption (AEAD) and purpose-separated HMAC fingerprints.
 *
 * @package WPIG\Contracts
 */

declare(strict_types=1);

namespace WPIG\Contracts;

use SensitiveParameter;
use WPIG\Security\CryptoException;
use WPIG\Security\SensitiveValue;

/**
 * Provides authenticated encryption (`xchacha20poly1305_ietf`) bound to canonical
 * Associated Data (AAD) and purpose-separated HMAC-SHA-256 fingerprinting.
 */
interface CryptoInterface {

	/**
	 * Encrypt plaintext using the active encryption key and canonical AAD.
	 *
	 * Returns a versioned ASCII envelope:
	 * `v1:<key_id>:<base64_urlsafe_unpadded(nonce_24B || ciphertext_and_16B_tag)>`
	 *
	 * @param SensitiveValue|string $plaintext Non-empty plaintext to encrypt.
	 * @param string                $aad       Canonical 6-segment AAD matching the active key ID.
	 * @return string Versioned ciphertext envelope.
	 * @throws CryptoException If key validation, AAD validation, or encryption fails.
	 */
	public function encrypt(
		#[SensitiveParameter] SensitiveValue|string $plaintext,
		string $aad
	): string;

	/**
	 * Authenticate and decrypt a versioned ciphertext envelope using canonical AAD.
	 *
	 * Supports decrypting envelopes produced under either the active encryption
	 * key or any configured previous encryption key in the keyring.
	 *
	 * @param string $envelope Versioned ciphertext envelope (`v1:<key_id>:<payload>`).
	 * @param string $aad      Canonical 6-segment AAD matching the envelope's `<key_id>`.
	 * @return SensitiveValue Decrypted plaintext wrapped in SensitiveValue.
	 * @throws CryptoException On invalid envelope, AAD mismatch, unknown key ID, or authentication failure.
	 */
	public function decrypt( string $envelope, string $aad ): SensitiveValue;

	/**
	 * Extract and validate the encryption `<key_id>` from a versioned envelope header.
	 *
	 * @param string $envelope Versioned ciphertext envelope (`v1:<key_id>:<payload>`).
	 * @return string Validated key identifier.
	 * @throws CryptoException If the envelope header or version is invalid.
	 */
	public function extract_key_id( string $envelope ): string;

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
	): string;

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
	): bool;
}

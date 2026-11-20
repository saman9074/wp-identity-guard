<?php
/**
 * Contract for cryptographic key resolution and keyring inspection.
 *
 * @package WPIG\Contracts
 */

declare(strict_types=1);

namespace WPIG\Contracts;

use WPIG\Security\CryptoException;
use WPIG\Security\SensitiveValue;

/**
 * Provides validated 256-bit encryption and HMAC keys from external site
 * configuration (K1 wp-config.php constants or K2 environment variables),
 * including read-only access to previous keys for key-rotation compatibility.
 */
interface KeyProviderInterface {

	/**
	 * Return the active encryption key identifier (e.g. 'k2026_01').
	 *
	 * @throws CryptoException If keys are missing or invalid.
	 */
	public function get_active_encryption_key_id(): string;

	/**
	 * Return the active 32-byte raw encryption key wrapped in SensitiveValue.
	 *
	 * @throws CryptoException If keys are missing or invalid.
	 */
	public function get_active_encryption_key(): SensitiveValue;

	/**
	 * Resolve a 32-byte raw encryption key by key ID from the active or previous keyring.
	 *
	 * @param string $key_id Key identifier (`[A-Za-z0-9._-]{1,32}`).
	 * @return SensitiveValue 32-byte raw encryption key.
	 * @throws CryptoException If the key ID is invalid, unknown, or keys are unconfigured.
	 */
	public function get_encryption_key( string $key_id ): SensitiveValue;

	/**
	 * Return the list of configured encryption key IDs (active + previous keyring).
	 *
	 * @return string[]
	 * @phpstan-return list<string>
	 * @throws CryptoException If keys are missing or invalid.
	 */
	public function get_encryption_key_ids(): array;

	/**
	 * Return the active HMAC key identifier (e.g. 'hmac_v1').
	 *
	 * @throws CryptoException If keys are missing or invalid.
	 */
	public function get_active_hmac_key_id(): string;

	/**
	 * Return the active 32-byte raw HMAC key wrapped in SensitiveValue.
	 *
	 * @throws CryptoException If keys are missing or invalid.
	 */
	public function get_active_hmac_key(): SensitiveValue;

	/**
	 * Resolve a 32-byte raw HMAC key by key ID from the active or previous keyring.
	 *
	 * @param string $key_id Key identifier (`[A-Za-z0-9._-]{1,32}`).
	 * @return SensitiveValue 32-byte raw HMAC key.
	 * @throws CryptoException If the key ID is invalid, unknown, or keys are unconfigured.
	 */
	public function get_hmac_key( string $key_id ): SensitiveValue;

	/**
	 * Return true if both encryption and HMAC keys are present, valid, and distinct.
	 */
	public function is_configured(): bool;
}

<?php
/**
 * Safe exception for cryptographic and key-management failures.
 *
 * @package WPIG\Security
 */

declare(strict_types=1);

namespace WPIG\Security;

use RuntimeException;

/**
 * Thrown when a cryptographic operation, AAD check, or key validation fails
 * closed. Never includes plaintext, key material, or raw ciphertexts in messages.
 */
final class CryptoException extends RuntimeException {

	public const CODE_SODIUM_UNAVAILABLE      = 'SODIUM_UNAVAILABLE';
	public const CODE_KEY_MISSING             = 'KEY_MISSING';
	public const CODE_KEY_ID_INVALID          = 'KEY_ID_INVALID';
	public const CODE_KEY_INVALID             = 'KEY_INVALID';
	public const CODE_KEY_SEPARATION          = 'KEY_SEPARATION_VIOLATION';
	public const CODE_KEY_UNKNOWN             = 'KEY_UNKNOWN';
	public const CODE_AAD_INVALID             = 'AAD_INVALID';
	public const CODE_AAD_KEY_MISMATCH        = 'AAD_KEY_MISMATCH';
	public const CODE_PLAINTEXT_INVALID       = 'PLAINTEXT_INVALID';
	public const CODE_ENVELOPE_INVALID        = 'ENVELOPE_INVALID';
	public const CODE_ENVELOPE_VERSION        = 'INVALID_ENVELOPE_VERSION';
	public const CODE_AUTH_FAILED             = 'AUTHENTICATION_FAILED';
	public const CODE_PURPOSE_INVALID         = 'PURPOSE_INVALID';
	public const CODE_SENSITIVE_VALUE_WIPED   = 'SENSITIVE_VALUE_WIPED';
	public const CODE_SERIALIZATION_FORBIDDEN = 'SERIALIZATION_FORBIDDEN';

	/**
	 * Machine-readable safe error code.
	 *
	 * @var string
	 */
	private string $safe_code;

	/**
	 * Constructor.
	 *
	 * @param string $safe_code Machine-readable safe error code constant.
	 * @param string $message   Safe, non-sensitive diagnostic description.
	 */
	public function __construct( string $safe_code, string $message ) {
		parent::__construct( $message, 0 );
		$this->safe_code = $safe_code;
	}

	/**
	 * Create a safe CryptoException instance.
	 *
	 * @param string $safe_code Machine-readable safe error code constant.
	 * @param string $message   Safe, non-sensitive diagnostic description.
	 */
	public static function create( string $safe_code, string $message ): self {
		return new self( $safe_code, $message );
	}

	/**
	 * Throw a safe CryptoException with a machine-readable safe code.
	 *
	 * @param string $safe_code Machine-readable safe error code constant.
	 * @param string $message   Safe, non-sensitive diagnostic description.
	 * @throws self Always thrown.
	 */
	public static function raise( string $safe_code, string $message ): never {
		// phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Safe internal exception message; never rendered unescaped to HTML.
		throw new self( $safe_code, $message );
	}

	/**
	 * Return the machine-readable safe error code.
	 */
	public function get_safe_code(): string {
		return $this->safe_code;
	}
}

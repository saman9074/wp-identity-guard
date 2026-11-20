<?php
/**
 * Safe exception for identity normalization, card validation, and masking errors.
 *
 * @package WPIG\Security
 */

declare(strict_types=1);

namespace WPIG\Security;

use InvalidArgumentException;

/**
 * Thrown when an identity attribute, birth date, card number, OTP code, or IP
 * address fails canonicalization or structural validation.
 *
 * Security invariant (DS-4): Never embeds raw user input, PII, or PAN in messages.
 */
final class ValidationException extends InvalidArgumentException {

	public const CODE_INVALID_NATIONAL_CODE     = 'INVALID_NATIONAL_CODE';
	public const CODE_INVALID_MOBILE            = 'INVALID_MOBILE';
	public const CODE_INVALID_BIRTH_DATE        = 'INVALID_BIRTH_DATE';
	public const CODE_INVALID_CARD_PAN          = 'INVALID_CARD_PAN';
	public const CODE_INVALID_CARD_LAST4        = 'INVALID_CARD_LAST4';
	public const CODE_INVALID_OTP_CODE          = 'INVALID_OTP_CODE';
	public const CODE_INVALID_CHALLENGE_CONTEXT = 'INVALID_CHALLENGE_CONTEXT';
	public const CODE_INVALID_IP_ADDRESS        = 'INVALID_IP_ADDRESS';
	public const CODE_INVALID_SETTING           = 'INVALID_SETTING';
	public const CODE_INVALID_AUDIT_EVENT       = 'INVALID_AUDIT_EVENT';
	public const CODE_INVALID_AUDIT_OUTCOME     = 'INVALID_AUDIT_OUTCOME';
	public const CODE_INVALID_AUDIT_METADATA    = 'INVALID_AUDIT_METADATA';
	public const CODE_SENSITIVE_AUDIT_METADATA  = 'SENSITIVE_AUDIT_METADATA';
	public const CODE_INVALID_CONSENT           = 'INVALID_CONSENT';

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
	 * Throw a safe ValidationException with a machine-readable safe code.
	 *
	 * @param string $safe_code Machine-readable safe error code constant.
	 * @param string $message   Safe, non-sensitive diagnostic description.
	 * @throws self Always thrown.
	 */
	public static function raise( string $safe_code, string $message ): never {
		// phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Safe static exception message; never contains user input or unescaped HTML.
		throw new self( $safe_code, $message );
	}

	/**
	 * Return the machine-readable safe error code.
	 */
	public function get_safe_code(): string {
		return $this->safe_code;
	}
}

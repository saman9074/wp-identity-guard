<?php
/**
 * Safe exception for authorization, capability, cross-user IDOR, Multisite, and consent errors.
 *
 * @package WPIG\Security
 */

declare(strict_types=1);

namespace WPIG\Security;

use RuntimeException;

/**
 * Thrown when an actor fails authentication, lacks a required WordPress capability,
 * attempts horizontal/vertical privilege escalation (IDOR), violates Multisite
 * site boundaries, lacks active user consent, or attempts unauthorized identity
 * binding or decryption.
 *
 * Security invariant (DS-4): Never embeds sensitive PII, ciphertexts, tokens,
 * or target user details in exception messages.
 */
final class AuthorizationException extends RuntimeException {

	public const CODE_UNAUTHENTICATED              = 'UNAUTHENTICATED';
	public const CODE_FORBIDDEN                    = 'FORBIDDEN';
	public const CODE_MISSING_CAPABILITY           = 'MISSING_CAPABILITY';
	public const CODE_CROSS_USER_FORBIDDEN         = 'CROSS_USER_FORBIDDEN';
	public const CODE_MULTISITE_FORBIDDEN          = 'MULTISITE_FORBIDDEN';
	public const CODE_DECRYPTION_FORBIDDEN         = 'DECRYPTION_FORBIDDEN';
	public const CODE_CONSENT_REQUIRED             = 'CONSENT_REQUIRED';
	public const CODE_BINDING_AUTHORITY_REQUIRED   = 'BINDING_AUTHORITY_REQUIRED';
	public const CODE_PRIVILEGE_ESCALATION_ATTEMPT = 'PRIVILEGE_ESCALATION_ATTEMPT';
	public const CODE_INVALID_ROLE_ASSIGNMENT      = 'INVALID_ROLE_ASSIGNMENT';

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
	 * Throw a safe AuthorizationException with a machine-readable safe code.
	 *
	 * @param string $safe_code Machine-readable safe error code constant.
	 * @param string $message   Safe, non-sensitive diagnostic description.
	 * @throws self Always thrown.
	 */
	public static function raise( string $safe_code, string $message ): never {
		// phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Safe static internal exception message; never contains user input or unescaped HTML.
		throw new self( $safe_code, $message );
	}

	/**
	 * Return the machine-readable safe error code.
	 */
	public function get_safe_code(): string {
		return $this->safe_code;
	}
}

<?php
/**
 * Safe exception for profile persistence, concurrency, and binding invariant errors.
 *
 * @package WPIG\Storage
 */

declare(strict_types=1);

namespace WPIG\Storage;

use RuntimeException;

/**
 * Thrown when a repository operation fails due to missing records, optimistic/pessimistic
 * version conflicts, identity binding invariants (D14), or database write errors.
 *
 * Security invariant (DS-4, D14): Never embeds raw SQL queries, PII, ciphertexts,
 * or conflicting user identifiers in exception messages.
 */
final class StorageException extends RuntimeException {

	public const CODE_INVALID_USER_ID                 = 'INVALID_USER_ID';
	public const CODE_INVALID_BLOG_ID                 = 'INVALID_BLOG_ID';
	public const CODE_PROFILE_NOT_FOUND               = 'PROFILE_NOT_FOUND';
	public const CODE_PROFILE_ALREADY_EXISTS          = 'PROFILE_ALREADY_EXISTS';
	public const CODE_VERSION_CONFLICT                = 'VERSION_CONFLICT';
	public const CODE_BOUND_IDENTITY_IMMUTABLE        = 'BOUND_IDENTITY_IMMUTABLE';
	public const CODE_UNAUTHORIZED_BINDING_TRANSITION = 'UNAUTHORIZED_BINDING_TRANSITION';
	public const CODE_IDENTITY_CONFLICT               = 'IDENTITY_CONFLICT';
	public const CODE_DATABASE_ERROR                  = 'DATABASE_ERROR';

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
	 * Throw a safe StorageException with a machine-readable safe code.
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

<?php
/**
 * Outcome DTO for schema migration execution.
 *
 * @package WPIG\Storage
 */

declare(strict_types=1);

namespace WPIG\Storage;

/**
 * Immutable value object describing the result of a migration run.
 */
final class MigrationResult {

	/**
	 * Whether the migration succeeded and all tables/indexes verified cleanly.
	 *
	 * @var bool
	 */
	public readonly bool $success;

	/**
	 * Installed schema version after the run (empty string if none installed).
	 *
	 * @var string
	 */
	public readonly string $schema_version;

	/**
	 * Safe error code if $success is false, or null on success.
	 *
	 * @var string|null
	 */
	public readonly ?string $error_code;

	/**
	 * Non-sensitive diagnostic details (e.g. missing index names).
	 *
	 * @var string[]
	 * @phpstan-var list<string>
	 */
	public readonly array $errors;

	/**
	 * Constructor.
	 *
	 * @param bool        $success        Whether migration succeeded.
	 * @param string      $schema_version Installed schema version.
	 * @param string|null $error_code     Safe error code on failure.
	 * @param string[]    $errors         Non-sensitive diagnostic messages.
	 * @phpstan-param list<string> $errors
	 */
	public function __construct(
		bool $success,
		string $schema_version,
		?string $error_code = null,
		array $errors = array()
	) {
		$this->success        = $success;
		$this->schema_version = $schema_version;
		$this->error_code     = $error_code;
		$this->errors         = $errors;
	}
}

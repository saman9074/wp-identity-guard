<?php
/**
 * Immutable DTO representing a persisted security audit event record.
 *
 * @package WPIG\Audit
 */

declare(strict_types=1);

namespace WPIG\Audit;

/**
 * Represents a safe, non-sensitive row from `wpig_audit_events` (Tasks 2 & 3).
 */
final class AuditEventRecord {

	/**
	 * Primary key ID.
	 *
	 * @var int
	 */
	public readonly int $id;

	/**
	 * Request/operation correlation UUID v4 (`CHAR(36)`).
	 *
	 * @var string
	 */
	public readonly string $correlation_id;

	/**
	 * Acting WordPress user ID (`null` for system/unauthenticated/cron events).
	 *
	 * @var int|null
	 */
	public readonly ?int $actor_user_id;

	/**
	 * Target WordPress user ID (`null` for site-wide events).
	 *
	 * @var int|null
	 */
	public readonly ?int $target_user_id;

	/**
	 * Canonical allowlisted event type.
	 *
	 * @var string
	 */
	public readonly string $event_type;

	/**
	 * Canonical allowlisted outcome (`SUCCESS`, `FAILURE`, `DENIED`, `UNAVAILABLE`, `RATE_LIMITED`).
	 *
	 * @var string
	 */
	public readonly string $outcome;

	/**
	 * Strictly allowlisted, redacted non-PII metadata map.
	 *
	 * @var array<string,scalar|list<string>|null>
	 */
	public readonly array $safe_metadata;

	/**
	 * UTC timestamp (`Y-m-d H:i:s`) when the event occurred.
	 *
	 * @var string
	 */
	public readonly string $occurred_at;

	/**
	 * Constructor.
	 *
	 * @param int                                    $id             Primary key ID.
	 * @param string                                 $correlation_id UUID v4 correlation identifier.
	 * @param int|null                               $actor_user_id  Optional acting WP user ID.
	 * @param int|null                               $target_user_id Optional target WP user ID.
	 * @param string                                 $event_type     Event type slug.
	 * @param string                                 $outcome        Outcome code.
	 * @param array<string,scalar|list<string>|null> $safe_metadata  Validated metadata map.
	 * @param string                                 $occurred_at    UTC timestamp (`Y-m-d H:i:s`).
	 */
	public function __construct(
		int $id,
		string $correlation_id,
		?int $actor_user_id,
		?int $target_user_id,
		string $event_type,
		string $outcome,
		array $safe_metadata,
		string $occurred_at
	) {
		$this->id             = $id;
		$this->correlation_id = $correlation_id;
		$this->actor_user_id  = $actor_user_id;
		$this->target_user_id = $target_user_id;
		$this->event_type     = $event_type;
		$this->outcome        = $outcome;
		$this->safe_metadata  = $safe_metadata;
		$this->occurred_at    = $occurred_at;
	}
}

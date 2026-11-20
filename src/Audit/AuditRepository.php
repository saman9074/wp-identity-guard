<?php
/**
 * Append-only persistence repository for `wpig_audit_events`.
 *
 * @package WPIG\Audit
 */

declare(strict_types=1);

namespace WPIG\Audit;

use wpdb;
use WPIG\Storage\SchemaDefinition;
use WPIG\Storage\StorageException;

/**
 * Provides append-only (`INSERT`), read, and bounded retention-pruning (`DELETE`)
 * access to `{$wpdb->prefix}wpig_audit_events` using prepared SQL statements (Task 2).
 *
 * Security & Integrity Note:
 * - Application code exposes NO `UPDATE` operations on `wpig_audit_events`.
 * - Application-level append-only behavior enforces immutability within the WordPress
 *   application layer, but does NOT provide cryptographic tamper-evidence (such as
 *   external WORM storage or hardware-anchored hash chains) and cannot prevent a
 *   privileged database administrator (`DBA` / direct SQL root user) from modifying
 *   or deleting records directly in MariaDB/MySQL.
 *
 * @internal Callers should record events via `AuditService` to enforce allowlists.
 */
final class AuditRepository {

	/**
	 * Unprefixed logical table name.
	 */
	public const LOGICAL_TABLE = 'wpig_audit_events';

	/**
	 * WordPress database instance.
	 *
	 * @var wpdb
	 */
	private wpdb $wpdb;

	/**
	 * UTC clock callback (`fn(): string`).
	 *
	 * @var callable
	 * @phpstan-var callable():string
	 */
	private $clock;

	/**
	 * Constructor.
	 *
	 * @param wpdb          $wpdb  WordPress database object.
	 * @param callable|null $clock Optional UTC clock override (`fn(): string`).
	 * @phpstan-param (callable():string)|null $clock
	 */
	public function __construct( wpdb $wpdb, ?callable $clock = null ) {
		$this->wpdb  = $wpdb;
		$this->clock = $clock ?? static fn(): string => gmdate( 'Y-m-d H:i:s' );
	}

	/**
	 * Append a validated security audit event row to `wpig_audit_events`.
	 *
	 * @param string                                 $correlation_id UUID v4 correlation identifier.
	 * @param string                                 $event_type     Validated event type.
	 * @param string                                 $outcome        Validated outcome.
	 * @param int|null                               $actor_user_id  Optional acting WP user ID (`>= 1` or `null`).
	 * @param int|null                               $target_user_id Optional target WP user ID (`>= 1` or `null`).
	 * @param array<string,scalar|list<string>|null> $safe_metadata  Validated non-sensitive metadata map.
	 * @param string|null                            $occurred_at    Optional UTC timestamp (`Y-m-d H:i:s`).
	 * @return AuditEventRecord Newly inserted audit event DTO.
	 * @throws StorageException On database insert failure.
	 */
	public function append(
		string $correlation_id,
		string $event_type,
		string $outcome,
		?int $actor_user_id = null,
		?int $target_user_id = null,
		array $safe_metadata = array(),
		?string $occurred_at = null
	): AuditEventRecord {
		$now_utc = $occurred_at ?? (string) ( $this->clock )();
		$table   = $this->get_table_name();

		$actor_db  = null !== $actor_user_id && $actor_user_id >= 1 ? $actor_user_id : null;
		$target_db = null !== $target_user_id && $target_user_id >= 1 ? $target_user_id : null;

		$metadata_json = null;
		if ( array() !== $safe_metadata ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Deterministic JSON serialization for DB column.
			$encoded       = json_encode( $safe_metadata, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
			$metadata_json = is_string( $encoded ) ? $encoded : null;
		}

		$wpdb = $this->wpdb;

		if ( null === $actor_db && null === $target_db ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$inserted = $wpdb->query(
				$wpdb->prepare(
					// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					"INSERT INTO `{$table}` (correlation_id, actor_user_id, target_user_id, event_type, outcome, safe_metadata_json, occurred_at)
					VALUES (%s, NULL, NULL, %s, %s, %s, %s)",
					$correlation_id,
					$event_type,
					$outcome,
					$metadata_json,
					$now_utc
				)
			);
		} elseif ( null !== $actor_db && null === $target_db ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$inserted = $wpdb->query(
				$wpdb->prepare(
					// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					"INSERT INTO `{$table}` (correlation_id, actor_user_id, target_user_id, event_type, outcome, safe_metadata_json, occurred_at)
					VALUES (%s, %d, NULL, %s, %s, %s, %s)",
					$correlation_id,
					$actor_db,
					$event_type,
					$outcome,
					$metadata_json,
					$now_utc
				)
			);
		} elseif ( null === $actor_db ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$inserted = $wpdb->query(
				$wpdb->prepare(
					// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					"INSERT INTO `{$table}` (correlation_id, actor_user_id, target_user_id, event_type, outcome, safe_metadata_json, occurred_at)
					VALUES (%s, NULL, %d, %s, %s, %s, %s)",
					$correlation_id,
					$target_db,
					$event_type,
					$outcome,
					$metadata_json,
					$now_utc
				)
			);
		} else {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$inserted = $wpdb->query(
				$wpdb->prepare(
					// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					"INSERT INTO `{$table}` (correlation_id, actor_user_id, target_user_id, event_type, outcome, safe_metadata_json, occurred_at)
					VALUES (%s, %d, %d, %s, %s, %s, %s)",
					$correlation_id,
					$actor_db,
					$target_db,
					$event_type,
					$outcome,
					$metadata_json,
					$now_utc
				)
			);
		}

		if ( 1 !== $inserted ) {
			StorageException::raise(
				StorageException::CODE_DATABASE_ERROR,
				'Failed to append audit event record.'
			);
		}

		$insert_id = (int) $wpdb->insert_id;

		return new AuditEventRecord(
			$insert_id,
			$correlation_id,
			$actor_db,
			$target_db,
			$event_type,
			$outcome,
			$safe_metadata,
			$now_utc
		);
	}

	/**
	 * Find an audit event by primary key ID.
	 *
	 * @param int $id Primary key ID (`>= 1`).
	 * @return AuditEventRecord|null
	 */
	public function find_by_id( int $id ): ?AuditEventRecord {
		if ( $id < 1 ) {
			return null;
		}

		$table = $this->get_table_name();
		$wpdb  = $this->wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$row = $wpdb->get_row(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT * FROM `{$table}` WHERE id = %d LIMIT 1",
				$id
			),
			ARRAY_A
		);

		return is_array( $row ) ? $this->map_row_to_record( $row ) : null;
	}

	/**
	 * Retrieve recent audit events targeting a specific WordPress user.
	 *
	 * @param int $target_user_id Target WordPress user ID (`>= 1`).
	 * @param int $limit          Bounded limit (`1..200`, default `50`).
	 * @return AuditEventRecord[]
	 * @phpstan-return list<AuditEventRecord>
	 */
	public function find_for_target_user( int $target_user_id, int $limit = 50 ): array {
		if ( $target_user_id < 1 ) {
			return array();
		}

		$bounded_limit = max( 1, min( 200, $limit ) );
		$table         = $this->get_table_name();
		$wpdb          = $this->wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT * FROM `{$table}` WHERE target_user_id = %d ORDER BY occurred_at DESC, id DESC LIMIT %d",
				$target_user_id,
				$bounded_limit
			),
			ARRAY_A
		);

		if ( ! is_array( $rows ) ) {
			return array();
		}

		$records = array();
		foreach ( $rows as $row ) {
			/**
			 * Raw audit row.
			 *
			 * @var array<string,mixed> $row
			 */
			$records[] = $this->map_row_to_record( $row );
		}

		return $records;
	}

	/**
	 * Count audit events, optionally filtered by `event_type`.
	 *
	 * @param string|null $event_type Optional event type filter.
	 */
	public function count_events( ?string $event_type = null ): int {
		$table = $this->get_table_name();
		$wpdb  = $this->wpdb;

		if ( null === $event_type ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$count = $wpdb->get_var( "SELECT COUNT(*) FROM `{$table}`" );
			return (int) $count;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$count = $wpdb->get_var(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT COUNT(*) FROM `{$table}` WHERE event_type = %s",
				$event_type
			)
		);

		return (int) $count;
	}

	/**
	 * Prune a bounded batch of expired audit events older than `$cutoff_utc` (`occurred_at < $cutoff_utc`).
	 *
	 * Reserved strictly for `RetentionService` when retention policy (`D04`) is enabled
	 * and `legal_hold_active` is false.
	 *
	 * @param string $cutoff_utc UTC timestamp (`Y-m-d H:i:s`) before which events may be pruned.
	 * @param int    $batch_size Bounded batch size (`1..500`, default `100`).
	 * @return int Number of deleted rows.
	 */
	public function prune_expired_batch( string $cutoff_utc, int $batch_size = 100 ): int {
		$bounded_batch = max( 1, min( 500, $batch_size ) );
		$table         = $this->get_table_name();
		$wpdb          = $this->wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$deleted = $wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"DELETE FROM `{$table}` WHERE occurred_at < %s ORDER BY occurred_at ASC, id ASC LIMIT %d",
				$cutoff_utc,
				$bounded_batch
			)
		);

		return is_int( $deleted ) && $deleted > 0 ? $deleted : 0;
	}

	/**
	 * Map a raw database associative array to an `AuditEventRecord` DTO.
	 *
	 * @param array<string,mixed> $row Raw database row.
	 */
	private function map_row_to_record( array $row ): AuditEventRecord {
		$metadata = array();
		if ( isset( $row['safe_metadata_json'] ) && is_string( $row['safe_metadata_json'] ) && '' !== $row['safe_metadata_json'] ) {
			$decoded = json_decode( $row['safe_metadata_json'], true );
			if ( is_array( $decoded ) ) {
				foreach ( $decoded as $k => $v ) {
					if ( is_string( $k ) && ( is_scalar( $v ) || null === $v || is_array( $v ) ) ) {
						/**
						 * Validated metadata value.
						 *
						 * @var scalar|list<string>|null $v
						 */
						$metadata[ $k ] = $v;
					}
				}
			}
		}

		return new AuditEventRecord(
			(int) $row['id'],
			(string) $row['correlation_id'],
			isset( $row['actor_user_id'] ) ? (int) $row['actor_user_id'] : null,
			isset( $row['target_user_id'] ) ? (int) $row['target_user_id'] : null,
			(string) $row['event_type'],
			(string) $row['outcome'],
			$metadata,
			(string) $row['occurred_at']
		);
	}

	/**
	 * Return the prefixed `wpig_audit_events` table name.
	 */
	private function get_table_name(): string {
		$tables = SchemaDefinition::get_table_names( $this->wpdb->prefix );
		return $tables[ self::LOGICAL_TABLE ];
	}
}

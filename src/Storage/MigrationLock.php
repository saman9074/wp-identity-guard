<?php
/**
 * Owner-aware database migration lock using MySQL/MariaDB GET_LOCK.
 *
 * @package WPIG\Storage
 */

declare(strict_types=1);

namespace WPIG\Storage;

use wpdb;

/**
 * Acquires and verifies an exclusive, session-bound database migration lock.
 *
 * Design (per docs/p01/P01-B1-database-schema.md §6):
 * - Primary lock: MySQL/MariaDB session advisory lock `GET_LOCK(name, 0)`.
 *   Automatically released by the database server if the connection drops.
 * - Continuity check: `IS_USED_LOCK(name) = CONNECTION_ID()` verifies the
 *   current database connection still holds the lock between DDL steps.
 * - Secondary state: non-autoloaded `wpig_migration_lock` option storing an
 *   `owner_token` UUID and `heartbeat_at` timestamp (verified on every step).
 * - Fail-closed: if `GET_LOCK` is unsupported (`NULL`) or held by another
 *   connection (`0`), `acquire()` fails closed (`false`) and never steals locks.
 */
final class MigrationLock {

	/**
	 * Option name for secondary owner-token state.
	 */
	public const OPTION_NAME = 'wpig_migration_lock';

	/**
	 * WordPress database instance.
	 *
	 * @var wpdb
	 */
	private wpdb $wpdb;

	/**
	 * Computed advisory lock name (max 64 chars in MySQL/MariaDB).
	 *
	 * @var string
	 */
	private string $lock_name;

	/**
	 * Random owner token for this lock instance.
	 *
	 * @var string
	 */
	private string $owner_token;

	/**
	 * Database connection ID that acquired the lock.
	 *
	 * @var int|null
	 */
	private ?int $connection_id = null;

	/**
	 * Whether this instance currently holds the lock.
	 *
	 * @var bool
	 */
	private bool $held = false;

	/**
	 * Constructor.
	 *
	 * @param wpdb        $wpdb        WordPress database object.
	 * @param string|null $owner_token Optional deterministic token for testing.
	 */
	public function __construct( wpdb $wpdb, ?string $owner_token = null ) {
		$this->wpdb        = $wpdb;
		$db_name           = defined( 'DB_NAME' ) ? (string) DB_NAME : '';
		$hash              = substr( hash( 'sha256', $db_name . '|' . $wpdb->prefix ), 0, 24 );
		$this->lock_name   = 'wpig_mig_' . $hash;
		$this->owner_token = null !== $owner_token && '' !== $owner_token
			? $owner_token
			: bin2hex( random_bytes( 16 ) );
	}

	/**
	 * Return the advisory lock name.
	 */
	public function get_lock_name(): string {
		return $this->lock_name;
	}

	/**
	 * Return the owner token for this lock instance.
	 */
	public function get_owner_token(): string {
		return $this->owner_token;
	}

	/**
	 * Attempt to acquire the exclusive migration lock (non-blocking).
	 *
	 * @param string $target_version Target schema version being migrated to.
	 * @return bool True if acquired and verified, false otherwise (fail-closed).
	 */
	public function acquire( string $target_version ): bool {
		if ( $this->held ) {
			return $this->verify_continuity();
		}

		$wpdb = $this->wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Advisory lock check.
		$conn_id = $wpdb->get_var( 'SELECT CONNECTION_ID()' );
		if ( null === $conn_id || ! is_numeric( $conn_id ) ) {
			return false;
		}
		$this->connection_id = (int) $conn_id;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Advisory lock acquisition.
		$acquired = $wpdb->get_var(
			$wpdb->prepare( 'SELECT GET_LOCK(%s, 0)', $this->lock_name )
		);

		if ( '1' !== (string) $acquired ) {
			$this->connection_id = null;
			return false;
		}

		$now     = time();
		$payload = wp_json_encode(
			array(
				'owner_token'    => $this->owner_token,
				'connection_id'  => $this->connection_id,
				'target_version' => $target_version,
				'acquired_at'    => $now,
				'heartbeat_at'   => $now,
			)
		);

		if ( false === $payload ) {
			$this->release_db_lock();
			return false;
		}

		// Store non-autoloaded option state. Because GET_LOCK is exclusively held by this
		// DB session, any residual option row from a previously crashed session can be
		// safely replaced before we verify ownership continuity.
		delete_option( self::OPTION_NAME );
		if ( ! add_option( self::OPTION_NAME, $payload, '', false ) ) {
			$this->release_db_lock();
			return false;
		}

		$this->held = true;
		if ( ! $this->verify_continuity() ) {
			$this->release();
			return false;
		}

		return true;
	}

	/**
	 * Verify that this instance still owns both the DB session lock and the option token,
	 * and refresh the heartbeat timestamp.
	 *
	 * @return bool True if lock ownership and connection continuity are intact.
	 */
	public function verify_continuity(): bool {
		if ( ! $this->held || null === $this->connection_id ) {
			return false;
		}

		$wpdb = $this->wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Verify session lock continuity.
		$row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT CONNECTION_ID() AS conn_id, IS_USED_LOCK(%s) AS lock_holder',
				$this->lock_name
			),
			ARRAY_A
		);

		if ( ! is_array( $row ) ) {
			return false;
		}

		$current_conn = isset( $row['conn_id'] ) ? (int) $row['conn_id'] : -1;
		$lock_holder  = isset( $row['lock_holder'] ) ? (int) $row['lock_holder'] : -2;

		if ( $current_conn !== $this->connection_id || $lock_holder !== $this->connection_id ) {
			return false;
		}

		$raw_option = get_option( self::OPTION_NAME, '' );
		if ( ! is_string( $raw_option ) || '' === $raw_option ) {
			return false;
		}

		$decoded = json_decode( $raw_option, true );
		if ( ! is_array( $decoded ) || ( $decoded['owner_token'] ?? '' ) !== $this->owner_token ) {
			return false;
		}

		$decoded['heartbeat_at'] = time();
		$encoded                 = wp_json_encode( $decoded );
		if ( is_string( $encoded ) ) {
			update_option( self::OPTION_NAME, $encoded, false );
		}

		return true;
	}

	/**
	 * Release the migration lock safely. Only deletes the option if owned by this instance.
	 */
	public function release(): void {
		if ( ! $this->held && null === $this->connection_id ) {
			return;
		}

		$raw_option = get_option( self::OPTION_NAME, '' );
		if ( is_string( $raw_option ) && '' !== $raw_option ) {
			$decoded = json_decode( $raw_option, true );
			if ( is_array( $decoded ) && ( $decoded['owner_token'] ?? '' ) === $this->owner_token ) {
				delete_option( self::OPTION_NAME );
			}
		}

		$this->release_db_lock();
		$this->held          = false;
		$this->connection_id = null;
	}

	/**
	 * Release the MySQL/MariaDB advisory lock if held by this connection.
	 */
	private function release_db_lock(): void {
		$wpdb = $this->wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Advisory lock release.
		$wpdb->get_var(
			$wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', $this->lock_name )
		);
	}
}

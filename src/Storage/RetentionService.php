<?php
/**
 * Bounded batch retention pruning and diagnostics service (`RetentionService`).
 *
 * @package WPIG\Storage
 */

declare(strict_types=1);

namespace WPIG\Storage;

use wpdb;
use WPIG\Audit\AuditRepository;
use WPIG\Security\ValidationException;

/**
 * Implements safe, bounded batch retention pruning for `wpig_audit_events`,
 * terminal/expired `wpig_verifications`, and expired `wpig_otp_challenges` (Task 7).
 *
 * Security & Compliance Invariants:
 * - While legal retention windows (`D04`) remain unresolved in `docs/p00/decision-status.md`,
 *   this service NEVER invents a legal retention period: destructive pruning of
 *   `wpig_audit_events` and `wpig_verifications` is disabled by default (`$policy_approved = false`).
 * - Destructive pruning is strictly blocked whenever `$legal_hold_active === true`.
 * - Bounded batch size (`1..500`, default `100`) prevents table locks on shared WordPress hosts.
 * - NEVER deletes active verification evidence (`PENDING`, `VERIFIED`, `REVIEW_REQUIRED`, or any
 *   `wpig_verifications` record referenced by `wpig_cards.verification_id`).
 * - NEVER deletes or modifies `wpig_profiles` identity bindings (`D14`).
 */
final class RetentionService {

	/**
	 * Default batch size for retention pruning (`Schema §5.3`).
	 */
	public const DEFAULT_BATCH_SIZE = 100;

	/**
	 * Maximum batch size for retention pruning (`Schema §5.3`).
	 */
	public const MAX_BATCH_SIZE = 500;

	/**
	 * Diagnostic and execution status constants.
	 */
	public const STATUS_DISABLED_POLICY_UNRESOLVED = 'DISABLED_POLICY_UNRESOLVED';
	public const STATUS_BLOCKED_LEGAL_HOLD         = 'BLOCKED_LEGAL_HOLD';
	public const STATUS_READY_FOR_BOUNDED_PRUNE    = 'READY_FOR_BOUNDED_PRUNE';
	public const STATUS_PRUNED                     = 'PRUNED';

	/**
	 * UTC datetime validation pattern (`YYYY-MM-DD HH:MM:SS`).
	 */
	private const UTC_DATETIME_PATTERN = '/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/';

	/**
	 * WordPress database abstraction instance.
	 *
	 * @var wpdb
	 */
	private wpdb $wpdb;

	/**
	 * Audit repository for bounded `wpig_audit_events` batch pruning.
	 *
	 * @var AuditRepository
	 */
	private AuditRepository $audit_repository;

	/**
	 * Whether a legal hold is active on the current site.
	 *
	 * @var bool
	 */
	private bool $legal_hold_active;

	/**
	 * Whether a formal legal retention policy (`D04`) has been approved and configured.
	 *
	 * Defaults to `false` because `D04` is unresolved in Phase P01.
	 *
	 * @var bool
	 */
	private bool $policy_approved;

	/**
	 * Constructor.
	 *
	 * @param wpdb            $wpdb              WordPress database connection.
	 * @param AuditRepository $audit_repository  Audit repository.
	 * @param bool            $legal_hold_active Whether a legal hold is active (default false).
	 * @param bool            $policy_approved   Whether legal retention policy `D04` is approved (default false).
	 */
	public function __construct(
		wpdb $wpdb,
		AuditRepository $audit_repository,
		bool $legal_hold_active = false,
		bool $policy_approved = false
	) {
		$this->wpdb              = $wpdb;
		$this->audit_repository  = $audit_repository;
		$this->legal_hold_active = $legal_hold_active;
		$this->policy_approved   = $policy_approved;
	}

	/**
	 * Return safe operational diagnostics for the retention subsystem (Task 7).
	 *
	 * @return array{
	 *     status:string,
	 *     policy_approved:bool,
	 *     legal_hold_active:bool,
	 *     default_batch_size:int,
	 *     max_batch_size:int,
	 *     summary:string
	 * }
	 */
	public function get_diagnostics(): array {
		if ( $this->legal_hold_active ) {
			return array(
				'status'             => self::STATUS_BLOCKED_LEGAL_HOLD,
				'policy_approved'    => $this->policy_approved,
				'legal_hold_active'  => true,
				'default_batch_size' => self::DEFAULT_BATCH_SIZE,
				'max_batch_size'     => self::MAX_BATCH_SIZE,
				'summary'            => 'Destructive retention pruning is blocked because a legal hold is active.',
			);
		}

		if ( ! $this->policy_approved ) {
			return array(
				'status'             => self::STATUS_DISABLED_POLICY_UNRESOLVED,
				'policy_approved'    => false,
				'legal_hold_active'  => false,
				'default_batch_size' => self::DEFAULT_BATCH_SIZE,
				'max_batch_size'     => self::MAX_BATCH_SIZE,
				'summary'            => 'Automatic pruning of audit and verification records is disabled until legal retention decision D04 is finalized.',
			);
		}

		return array(
			'status'             => self::STATUS_READY_FOR_BOUNDED_PRUNE,
			'policy_approved'    => true,
			'legal_hold_active'  => false,
			'default_batch_size' => self::DEFAULT_BATCH_SIZE,
			'max_batch_size'     => self::MAX_BATCH_SIZE,
			'summary'            => 'Bounded batch retention pruning is enabled under an approved retention policy.',
		);
	}

	/**
	 * Prune a bounded batch of expired `wpig_audit_events` rows (`occurred_at < $cutoff_utc`).
	 *
	 * Remains a safe no-op (`pruned_count = 0`) when `$this->legal_hold_active` is true or
	 * `$this->policy_approved` is false (`D04` unresolved).
	 *
	 * @param string $cutoff_utc Explicit UTC cutoff timestamp (`Y-m-d H:i:s`).
	 * @param int    $batch_size Bounded batch size (`1..500`, default `100`).
	 * @return array{status:string,pruned_count:int}
	 * @throws ValidationException On malformed `$cutoff_utc`.
	 * @throws StorageException    On database error.
	 */
	public function prune_audit_events_batch(
		string $cutoff_utc,
		int $batch_size = self::DEFAULT_BATCH_SIZE
	): array {
		$this->assert_valid_cutoff( $cutoff_utc );
		$clamped_batch = max( 1, min( self::MAX_BATCH_SIZE, $batch_size ) );

		if ( $this->legal_hold_active ) {
			return array(
				'status'       => self::STATUS_BLOCKED_LEGAL_HOLD,
				'pruned_count' => 0,
			);
		}

		if ( ! $this->policy_approved ) {
			return array(
				'status'       => self::STATUS_DISABLED_POLICY_UNRESOLVED,
				'pruned_count' => 0,
			);
		}

		$pruned = $this->audit_repository->prune_expired_batch( $cutoff_utc, $clamped_batch );

		return array(
			'status'       => self::STATUS_PRUNED,
			'pruned_count' => $pruned,
		);
	}

	/**
	 * Prune a bounded batch of expired, non-active `wpig_verifications` rows.
	 *
	 * Security & Evidence Invariants:
	 * - Blocked when `$this->legal_hold_active` is true or `$this->policy_approved` is false (`D04`).
	 * - NEVER deletes rows with `state IN ('PENDING', 'VERIFIED', 'REVIEW_REQUIRED')`.
	 * - NEVER deletes rows referenced by `wpig_cards.verification_id`.
	 * - Only deletes terminal rows (`state IN ('REJECTED', 'EXPIRED', 'FAILED')`) where
	 *   `requested_at < $cutoff_utc`.
	 *
	 * @param string $cutoff_utc Explicit UTC cutoff timestamp (`Y-m-d H:i:s`).
	 * @param int    $batch_size Bounded batch size (`1..500`, default `100`).
	 * @return array{status:string,pruned_count:int}
	 * @throws ValidationException On malformed `$cutoff_utc`.
	 * @throws StorageException    On database error.
	 */
	public function prune_terminal_verifications_batch(
		string $cutoff_utc,
		int $batch_size = self::DEFAULT_BATCH_SIZE
	): array {
		$this->assert_valid_cutoff( $cutoff_utc );
		$clamped_batch = max( 1, min( self::MAX_BATCH_SIZE, $batch_size ) );

		if ( $this->legal_hold_active ) {
			return array(
				'status'       => self::STATUS_BLOCKED_LEGAL_HOLD,
				'pruned_count' => 0,
			);
		}

		if ( ! $this->policy_approved ) {
			return array(
				'status'       => self::STATUS_DISABLED_POLICY_UNRESOLVED,
				'pruned_count' => 0,
			);
		}

		$tables              = SchemaDefinition::get_table_names( $this->wpdb->prefix );
		$verifications_table = $tables['wpig_verifications'];
		$cards_table         = $tables['wpig_cards'];
		$wpdb                = $this->wpdb;

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table names are strictly constructed from $wpdb->prefix + constant logical tables.
		$deleted = $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM `{$verifications_table}`
				WHERE state IN ('REJECTED', 'EXPIRED', 'FAILED')
				  AND requested_at < %s
				  AND id NOT IN (SELECT verification_id FROM `{$cards_table}`)
				ORDER BY requested_at ASC, id ASC
				LIMIT %d",
				$cutoff_utc,
				$clamped_batch
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		if ( false === $deleted ) {
			StorageException::raise(
				StorageException::CODE_DATABASE_ERROR,
				'Failed to prune terminal verification records batch.'
			);
		}

		return array(
			'status'       => self::STATUS_PRUNED,
			'pruned_count' => (int) $deleted,
		);
	}

	/**
	 * Prune a bounded batch of expired or consumed `wpig_otp_challenges` rows (`expires_at < $cutoff_utc`).
	 *
	 * Blocked when `$this->legal_hold_active` is true.
	 *
	 * @param string $cutoff_utc Explicit UTC cutoff timestamp (`Y-m-d H:i:s`).
	 * @param int    $batch_size Bounded batch size (`1..500`, default `100`).
	 * @return array{status:string,pruned_count:int}
	 * @throws ValidationException On malformed `$cutoff_utc`.
	 * @throws StorageException    On database error.
	 */
	public function prune_expired_otp_challenges_batch(
		string $cutoff_utc,
		int $batch_size = self::DEFAULT_BATCH_SIZE
	): array {
		$this->assert_valid_cutoff( $cutoff_utc );
		$clamped_batch = max( 1, min( self::MAX_BATCH_SIZE, $batch_size ) );

		if ( $this->legal_hold_active ) {
			return array(
				'status'       => self::STATUS_BLOCKED_LEGAL_HOLD,
				'pruned_count' => 0,
			);
		}

		$tables    = SchemaDefinition::get_table_names( $this->wpdb->prefix );
		$otp_table = $tables['wpig_otp_challenges'];
		$wpdb      = $this->wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Bounded batch prune of expired OTP challenges.
		$deleted = $wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is strictly constructed from $wpdb->prefix + constant logical table.
				"DELETE FROM `{$otp_table}` WHERE expires_at < %s ORDER BY expires_at ASC LIMIT %d",
				$cutoff_utc,
				$clamped_batch
			)
		);

		if ( false === $deleted ) {
			StorageException::raise(
				StorageException::CODE_DATABASE_ERROR,
				'Failed to prune expired OTP challenges batch.'
			);
		}

		return array(
			'status'       => self::STATUS_PRUNED,
			'pruned_count' => (int) $deleted,
		);
	}

	/**
	 * Assert that `$cutoff_utc` is a valid `Y-m-d H:i:s` timestamp.
	 *
	 * @param string $cutoff_utc UTC timestamp string.
	 * @throws ValidationException On invalid format.
	 */
	private function assert_valid_cutoff( string $cutoff_utc ): void {
		if ( 1 !== preg_match( self::UTC_DATETIME_PATTERN, $cutoff_utc ) ) {
			ValidationException::raise(
				ValidationException::CODE_INVALID_AUDIT_METADATA,
				'Retention cutoff_utc must be formatted as Y-m-d H:i:s.'
			);
		}
	}
}

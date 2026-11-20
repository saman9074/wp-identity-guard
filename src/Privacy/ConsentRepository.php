<?php
/**
 * Repository for `wpig_consents` records (`ConsentRepository`).
 *
 * @package WPIG\Privacy
 */

declare(strict_types=1);

namespace WPIG\Privacy;

use wpdb;
use WPIG\Audit\AuditService;
use WPIG\Security\ValidationException;
use WPIG\Storage\SchemaDefinition;
use WPIG\Storage\StorageException;

/**
 * Manages user consent records in `wpig_consents` with prepared SQL queries
 * and strict separation between consent withdrawal and personal data erasure (Tasks 4 & 5).
 *
 * Security Invariants:
 * - Uses `$wpdb->prefix . 'wpig_consents'` and prepared SQL statements exclusively.
 * - Withdrawing consent sets `revoked_at` in UTC without deleting consent audit history
 *   and without automatically triggering personal data erasure or identity-binding release.
 */
final class ConsentRepository {

	/**
	 * Logical table name in `SchemaDefinition`.
	 */
	public const LOGICAL_TABLE = 'wpig_consents';

	/**
	 * Canonical consent purpose constants.
	 */
	public const PURPOSE_IDENTITY_VERIFICATION = 'identity_verification';
	public const PURPOSE_CARD_OWNERSHIP        = 'card_ownership';
	public const PURPOSE_MOBILE_OTP            = 'mobile_otp';

	/**
	 * Allowlisted consent purpose identifiers.
	 *
	 * @var list<string>
	 */
	public const ALLOWED_PURPOSES = array(
		self::PURPOSE_IDENTITY_VERIFICATION,
		self::PURPOSE_CARD_OWNERSHIP,
		self::PURPOSE_MOBILE_OTP,
	);

	/**
	 * Notice version validation pattern (`1..32` safe ASCII chars).
	 */
	private const NOTICE_VERSION_PATTERN = '/^[A-Za-z0-9._-]{1,32}$/';

	/**
	 * SHA-256 hex digest validation pattern (`64` lowercase hex chars).
	 */
	private const SHA256_HEX_PATTERN = '/^[0-9a-f]{64}$/';

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
	 * Optional security audit service.
	 *
	 * @var AuditService|null
	 */
	private ?AuditService $audit_service;

	/**
	 * Callback returning current UTC datetime (`Y-m-d H:i:s`).
	 *
	 * @var callable
	 * @phpstan-var callable():string
	 */
	private $clock;

	/**
	 * Callback returning the active site blog ID (`fn(): int`).
	 *
	 * @var callable
	 * @phpstan-var callable():int
	 */
	private $blog_id_resolver;

	/**
	 * Constructor.
	 *
	 * @param wpdb              $wpdb             WordPress database connection.
	 * @param AuditService|null $audit_service    Optional security audit service.
	 * @param callable|null     $clock            Optional UTC clock (`fn(): string`).
	 * @param callable|null     $blog_id_resolver Optional site blog ID resolver (`fn(): int`).
	 * @phpstan-param (callable():string)|null $clock
	 * @phpstan-param (callable():int)|null    $blog_id_resolver
	 */
	public function __construct(
		wpdb $wpdb,
		?AuditService $audit_service = null,
		?callable $clock = null,
		?callable $blog_id_resolver = null
	) {
		$this->wpdb             = $wpdb;
		$this->audit_service    = $audit_service;
		$this->clock            = $clock ?? static function (): string {
			return gmdate( 'Y-m-d H:i:s' );
		};
		$this->blog_id_resolver = $blog_id_resolver ?? static function (): int {
			if ( function_exists( 'get_current_blog_id' ) ) {
				return max( 1, (int) get_current_blog_id() );
			}
			return 1;
		};
	}

	/**
	 * Record an explicit user consent acceptance in `wpig_consents`.
	 *
	 * @param int         $wp_user_id     WordPress user ID (`>= 1`).
	 * @param string      $notice_version Notice version (`1..32` chars).
	 * @param string      $notice_hash    Lowercase SHA-256 hex digest (`64` chars) or raw text to hash via `hash_notice_text()`.
	 * @param string[]    $purposes       Non-empty list of allowlisted consent purposes.
	 * @param string|null $expires_at_utc Optional UTC expiry timestamp (`Y-m-d H:i:s`).
	 * @param int|null    $actor_user_id  Optional acting user ID (defaults to `$wp_user_id`).
	 * @return ConsentRecord
	 * @phpstan-param list<string> $purposes
	 * @throws ValidationException On invalid user ID, notice version, notice hash, or purposes.
	 * @throws StorageException    On database insert failure.
	 */
	public function record_consent(
		int $wp_user_id,
		string $notice_version,
		string $notice_hash,
		array $purposes = array( 'identity_verification' ),
		?string $expires_at_utc = null,
		?int $actor_user_id = null
	): ConsentRecord {
		$this->assert_valid_user_id( $wp_user_id );

		$trimmed_version = trim( $notice_version );
		if ( 1 !== preg_match( self::NOTICE_VERSION_PATTERN, $trimmed_version ) ) {
			ValidationException::raise(
				ValidationException::CODE_INVALID_CONSENT,
				'Consent notice_version must be 1 to 32 safe ASCII characters.'
			);
		}

		$normalized_hash = strtolower( trim( $notice_hash ) );
		if ( 1 !== preg_match( self::SHA256_HEX_PATTERN, $normalized_hash ) ) {
			ValidationException::raise(
				ValidationException::CODE_INVALID_CONSENT,
				'Consent notice_hash must be a 64-character lowercase hexadecimal SHA-256 digest.'
			);
		}

		if ( array() === $purposes ) {
			ValidationException::raise(
				ValidationException::CODE_INVALID_CONSENT,
				'At least one consent purpose must be specified.'
			);
		}

		$normalized_purposes = array();
		foreach ( $purposes as $purpose ) {
			if ( ! in_array( $purpose, self::ALLOWED_PURPOSES, true ) ) {
				ValidationException::raise(
					ValidationException::CODE_INVALID_CONSENT,
					'Invalid or unsupported consent purpose.'
				);
			}
			if ( ! in_array( $purpose, $normalized_purposes, true ) ) {
				$normalized_purposes[] = $purpose;
			}
		}

		if ( null !== $expires_at_utc && 1 !== preg_match( self::UTC_DATETIME_PATTERN, $expires_at_utc ) ) {
			ValidationException::raise(
				ValidationException::CODE_INVALID_CONSENT,
				'Consent expires_at_utc must be formatted as Y-m-d H:i:s.'
			);
		}

		$purposes_json = (string) json_encode( $normalized_purposes, JSON_UNESCAPED_SLASHES ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Deterministic JSON serialization for DB column.
		$accepted_at   = (string) ( $this->clock )();
		$tables        = SchemaDefinition::get_table_names( $this->wpdb->prefix );
		$table         = $tables[ self::LOGICAL_TABLE ];
		$wpdb          = $this->wpdb;

		if ( null === $expires_at_utc ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom consent table insert.
			$inserted = $wpdb->query(
				$wpdb->prepare(
					// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is strictly constructed from $wpdb->prefix + constant logical table.
					"INSERT INTO `{$table}` (wp_user_id, notice_version, notice_hash, purposes_json, accepted_at, revoked_at, expires_at)
					VALUES (%d, %s, %s, %s, %s, NULL, NULL)",
					$wp_user_id,
					$trimmed_version,
					$normalized_hash,
					$purposes_json,
					$accepted_at
				)
			);
		} else {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom consent table insert.
			$inserted = $wpdb->query(
				$wpdb->prepare(
					// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is strictly constructed from $wpdb->prefix + constant logical table.
					"INSERT INTO `{$table}` (wp_user_id, notice_version, notice_hash, purposes_json, accepted_at, revoked_at, expires_at)
					VALUES (%d, %s, %s, %s, %s, NULL, %s)",
					$wp_user_id,
					$trimmed_version,
					$normalized_hash,
					$purposes_json,
					$accepted_at,
					$expires_at_utc
				)
			);
		}

		if ( false === $inserted || 1 !== (int) $inserted ) {
			StorageException::raise(
				StorageException::CODE_DATABASE_ERROR,
				'Failed to persist consent record in wpig_consents.'
			);
		}

		$insert_id = (int) $wpdb->insert_id;

		if ( null !== $this->audit_service ) {
			$this->audit_service->log_consent_accepted(
				$actor_user_id ?? $wp_user_id,
				$wp_user_id,
				$trimmed_version
			);
		}

		$active_blog_id = max( 1, (int) ( $this->blog_id_resolver )() );

		return new ConsentRecord(
			$insert_id > 0 ? $insert_id : 1,
			$wp_user_id,
			$trimmed_version,
			$normalized_hash,
			$normalized_purposes,
			$accepted_at,
			null,
			$expires_at_utc,
			$active_blog_id
		);
	}

	/**
	 * Withdraw active user consent (`revoked_at = $now_utc`) without erasing personal data
	 * or releasing an active identity binding (Task 5).
	 *
	 * @param int      $wp_user_id    Target WordPress user ID (`>= 1`).
	 * @param int|null $actor_user_id Optional acting WordPress user ID (defaults to `$wp_user_id`).
	 * @return int Number of active consent records marked as withdrawn.
	 * @throws ValidationException On invalid user ID.
	 * @throws StorageException    On database error.
	 */
	public function withdraw_consent( int $wp_user_id, ?int $actor_user_id = null ): int {
		$this->assert_valid_user_id( $wp_user_id );

		$now    = (string) ( $this->clock )();
		$tables = SchemaDefinition::get_table_names( $this->wpdb->prefix );
		$table  = $tables[ self::LOGICAL_TABLE ];
		$wpdb   = $this->wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom consent revocation update.
		$updated = $wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is strictly constructed from $wpdb->prefix + constant logical table.
				"UPDATE `{$table}` SET revoked_at = %s WHERE wp_user_id = %d AND revoked_at IS NULL",
				$now,
				$wp_user_id
			)
		);

		if ( false === $updated ) {
			StorageException::raise(
				StorageException::CODE_DATABASE_ERROR,
				'Failed to withdraw active consent records.'
			);
		}

		$count = (int) $updated;
		if ( $count > 0 && null !== $this->audit_service ) {
			$this->audit_service->log_consent_withdrawn(
				$actor_user_id ?? $wp_user_id,
				$wp_user_id
			);
		}

		return $count;
	}

	/**
	 * Find the latest active, unrevoked, unexpired consent record bound to the user, blog, and required purpose.
	 *
	 * @param int         $wp_user_id       WordPress user ID (`>= 1`).
	 * @param string      $required_purpose Required consent purpose (`PURPOSE_*`).
	 * @param int|null    $expected_blog_id Optional expected site blog ID.
	 * @param string|null $now_utc          Optional UTC timestamp override (`Y-m-d H:i:s`).
	 * @return ConsentRecord|null
	 * @throws ValidationException On invalid user ID.
	 */
	public function find_active_consent(
		int $wp_user_id,
		string $required_purpose = self::PURPOSE_IDENTITY_VERIFICATION,
		?int $expected_blog_id = null,
		?string $now_utc = null
	): ?ConsentRecord {
		$this->assert_valid_user_id( $wp_user_id );

		if ( '' === $required_purpose || ! in_array( $required_purpose, self::ALLOWED_PURPOSES, true ) ) {
			return null;
		}

		$active_blog_id = max( 1, (int) ( $this->blog_id_resolver )() );
		if ( null !== $expected_blog_id && $expected_blog_id !== $active_blog_id ) {
			return null;
		}

		$now     = $now_utc ?? (string) ( $this->clock )();
		$records = $this->find_all_for_user( $wp_user_id );

		foreach ( $records as $record ) {
			if ( $record->is_valid_for( $wp_user_id, $active_blog_id, $required_purpose, $now ) ) {
				return $record;
			}
		}

		return null;
	}

	/**
	 * Check whether the user currently has at least one active (unrevoked, unexpired) consent record.
	 *
	 * @param int         $wp_user_id       WordPress user ID (`>= 1`).
	 * @param string|null $required_purpose Optional purpose that must be included in `purposes_json`.
	 * @param string|null $now_utc          Optional UTC timestamp override (`Y-m-d H:i:s`).
	 * @param int|null    $expected_blog_id Optional expected site blog ID.
	 * @return bool
	 * @throws ValidationException On invalid user ID.
	 */
	public function has_active_consent(
		int $wp_user_id,
		?string $required_purpose = null,
		?string $now_utc = null,
		?int $expected_blog_id = null
	): bool {
		$this->assert_valid_user_id( $wp_user_id );

		$active_blog_id = max( 1, (int) ( $this->blog_id_resolver )() );
		if ( null !== $expected_blog_id && $expected_blog_id !== $active_blog_id ) {
			return false;
		}

		if ( null !== $required_purpose && ! in_array( $required_purpose, self::ALLOWED_PURPOSES, true ) ) {
			return false;
		}

		$now     = $now_utc ?? (string) ( $this->clock )();
		$records = $this->find_all_for_user( $wp_user_id );

		foreach ( $records as $record ) {
			if ( $record->blog_id !== $active_blog_id || ! $record->is_active( $now ) ) {
				continue;
			}

			if ( null === $required_purpose || in_array( $required_purpose, $record->purposes, true ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Retrieve all consent records for a user ordered by `id DESC`.
	 *
	 * @param int $wp_user_id WordPress user ID (`>= 1`).
	 * @return list<ConsentRecord>
	 * @throws ValidationException On invalid user ID.
	 */
	public function find_all_for_user( int $wp_user_id ): array {
		$this->assert_valid_user_id( $wp_user_id );

		$tables = SchemaDefinition::get_table_names( $this->wpdb->prefix );
		$table  = $tables[ self::LOGICAL_TABLE ];
		$wpdb   = $this->wpdb;

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is strictly constructed from $wpdb->prefix + constant logical table.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT id, wp_user_id, notice_version, notice_hash, purposes_json, accepted_at, revoked_at, expires_at
				FROM `{$table}`
				WHERE wp_user_id = %d
				ORDER BY id DESC",
				$wp_user_id
			),
			ARRAY_A
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		if ( ! is_array( $rows ) ) {
			return array();
		}

		$records = array();
		foreach ( $rows as $row ) {
			/**
			 * Raw consent row.
			 *
			 * @var array<string,mixed> $row
			 */
			$records[] = $this->map_row_to_record( $row );
		}

		return $records;
	}

	/**
	 * Compute the canonical lowercase SHA-256 hex digest of a consent notice text.
	 *
	 * @param string $notice_text Canonical consent notice text.
	 */
	public static function hash_notice_text( string $notice_text ): string {
		return hash( 'sha256', trim( $notice_text ) );
	}

	/**
	 * Assert that `$wp_user_id` is a positive integer.
	 *
	 * @param int $wp_user_id WordPress user ID.
	 * @throws ValidationException If `$wp_user_id < 1`.
	 */
	private function assert_valid_user_id( int $wp_user_id ): void {
		if ( $wp_user_id < 1 ) {
			ValidationException::raise(
				ValidationException::CODE_INVALID_CONSENT,
				'Consent user ID must be a positive integer.'
			);
		}
	}

	/**
	 * Map a raw database associative array to an immutable `ConsentRecord`.
	 *
	 * @param array<string,mixed> $row Database row.
	 */
	private function map_row_to_record( array $row ): ConsentRecord {
		$decoded_purposes = array();
		if ( isset( $row['purposes_json'] ) && is_string( $row['purposes_json'] ) && '' !== $row['purposes_json'] ) {
			$decoded = json_decode( $row['purposes_json'], true );
			if ( is_array( $decoded ) ) {
				foreach ( $decoded as $item ) {
					if ( is_string( $item ) && '' !== $item ) {
						$decoded_purposes[] = $item;
					}
				}
			}
		}

		$active_blog_id = max( 1, (int) ( $this->blog_id_resolver )() );

		return new ConsentRecord(
			isset( $row['id'] ) ? (int) $row['id'] : 0,
			isset( $row['wp_user_id'] ) ? (int) $row['wp_user_id'] : 0,
			isset( $row['notice_version'] ) ? (string) $row['notice_version'] : '',
			isset( $row['notice_hash'] ) ? (string) $row['notice_hash'] : '',
			$decoded_purposes,
			isset( $row['accepted_at'] ) ? (string) $row['accepted_at'] : '',
			isset( $row['revoked_at'] ) && is_string( $row['revoked_at'] ) && '' !== $row['revoked_at'] ? $row['revoked_at'] : null,
			isset( $row['expires_at'] ) && is_string( $row['expires_at'] ) && '' !== $row['expires_at'] ? $row['expires_at'] : null,
			$active_blog_id
		);
	}
}

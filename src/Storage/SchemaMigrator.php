<?php
/**
 * Versioned, idempotent database schema migrator and verifier.
 *
 * @package WPIG\Storage
 */

declare(strict_types=1);

namespace WPIG\Storage;

use wpdb;

/**
 * Executes versioned schema migrations under an owner-aware lock and verifies
 * that all required tables, columns, and indexes exist before recording the
 * installed schema version in non-autoloaded wp_options.
 */
final class SchemaMigrator {

	/**
	 * Option name storing the installed schema version (non-autoloaded).
	 */
	public const VERSION_OPTION = 'wpig_schema_version';

	/**
	 * WordPress database instance.
	 *
	 * @var wpdb
	 */
	private wpdb $wpdb;

	/**
	 * Migration lock instance.
	 *
	 * @var MigrationLock
	 */
	private MigrationLock $lock;

	/**
	 * Optional DDL executor override for testing failure scenarios.
	 *
	 * @var callable|null
	 * @phpstan-var (callable(array<string,string>):void)|null
	 */
	private $ddl_runner;

	/**
	 * Constructor.
	 *
	 * @param wpdb               $wpdb       WordPress database object.
	 * @param MigrationLock|null $lock       Optional custom lock instance.
	 * @param callable|null      $ddl_runner Optional DDL runner override for tests.
	 * @phpstan-param (callable(array<string,string>):void)|null $ddl_runner
	 */
	public function __construct( wpdb $wpdb, ?MigrationLock $lock = null, ?callable $ddl_runner = null ) {
		$this->wpdb       = $wpdb;
		$this->lock       = $lock ?? new MigrationLock( $wpdb );
		$this->ddl_runner = $ddl_runner;
	}

	/**
	 * Return the currently recorded schema version from wp_options.
	 */
	public function get_installed_version(): string {
		$ver = get_option( self::VERSION_OPTION, '' );
		return is_string( $ver ) ? $ver : '';
	}

	/**
	 * Run pending schema migrations idempotently and verify schema integrity.
	 *
	 * Note: Even when get_installed_version() equals SchemaDefinition::SCHEMA_VERSION,
	 * migrate() runs under lock and verifies all 6 tables and indexes so activation
	 * or repair calls are strictly idempotent and self-verifying.
	 *
	 * @return MigrationResult
	 */
	public function migrate(): MigrationResult {
		$target_version  = SchemaDefinition::SCHEMA_VERSION;
		$current_version = $this->get_installed_version();

		if ( ! $this->lock->acquire( $target_version ) ) {
			return new MigrationResult(
				false,
				$current_version,
				'MIGRATION_LOCK_UNAVAILABLE',
				array( 'Could not acquire exclusive database migration lock.' )
			);
		}

		try {
			$charset_collate = $this->wpdb->get_charset_collate();
			$sql_map         = SchemaDefinition::get_create_table_sql( $this->wpdb->prefix, $charset_collate );

			if ( null !== $this->ddl_runner ) {
				( $this->ddl_runner )( $sql_map );
			} else {
				require_once ABSPATH . 'wp-admin/includes/upgrade.php';
				foreach ( $sql_map as $logical_table => $ddl ) {
					if ( ! $this->lock->verify_continuity() ) {
						return new MigrationResult(
							false,
							$current_version,
							'MIGRATION_LOCK_LOST',
							array( "Migration lock continuity lost before table {$logical_table}." )
						);
					}
					dbDelta( $ddl );
				}
			}

			if ( ! $this->lock->verify_continuity() ) {
				return new MigrationResult(
					false,
					$current_version,
					'MIGRATION_LOCK_LOST',
					array( 'Migration lock continuity lost before schema verification.' )
				);
			}

			$verification_errors = $this->verify_schema();
			if ( array() !== $verification_errors ) {
				return new MigrationResult(
					false,
					$current_version,
					'SCHEMA_VERIFICATION_FAILED',
					$verification_errors
				);
			}

			$this->set_installed_version( $target_version );

			return new MigrationResult( true, $target_version );
		} finally {
			$this->lock->release();
		}
	}

	/**
	 * Verify that all 6 custom tables, expected columns, and expected indexes
	 * (including uniqueness and column ordering) exist in the database.
	 *
	 * @return string[] Empty array if valid; list of diagnostic error messages otherwise.
	 * @phpstan-return list<string>
	 */
	public function verify_schema(): array {
		$wpdb             = $this->wpdb;
		$errors           = array();
		$tables           = SchemaDefinition::get_table_names( $wpdb->prefix );
		$expected_columns = SchemaDefinition::get_expected_columns();
		$expected_indexes = SchemaDefinition::get_expected_indexes();

		foreach ( $tables as $logical => $prefixed_table ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Schema verification.
			$found_table = $wpdb->get_var(
				$wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $prefixed_table ) )
			);

			if ( $found_table !== $prefixed_table ) {
				$errors[] = "Missing table: {$prefixed_table}";
				continue;
			}

			// Verify columns.
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is strictly constructed from $wpdb->prefix + constant logical table name.
			$col_rows = $wpdb->get_results( "SHOW COLUMNS FROM `{$prefixed_table}`", ARRAY_A );
			if ( array() === $col_rows ) {
				$errors[] = "Unable to inspect columns for table: {$prefixed_table}";
				continue;
			}

			$actual_cols = array();
			foreach ( $col_rows as $col_row ) {
				if ( isset( $col_row['Field'] ) && is_string( $col_row['Field'] ) ) {
					$actual_cols[] = $col_row['Field'];
				}
			}

			foreach ( $expected_columns[ $logical ] as $expected_col ) {
				if ( ! in_array( $expected_col, $actual_cols, true ) ) {
					$errors[] = "Missing column {$logical}.{$expected_col}";
				}
			}

			// Verify indexes.
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is strictly constructed from $wpdb->prefix + constant logical table name.
			$idx_rows = $wpdb->get_results( "SHOW INDEX FROM `{$prefixed_table}`", ARRAY_A );
			if ( array() === $idx_rows ) {
				$errors[] = "Unable to inspect indexes for table: {$prefixed_table}";
				continue;
			}

			$actual_indexes = array();
			foreach ( $idx_rows as $idx_row ) {
				if ( ! isset( $idx_row['Key_name'], $idx_row['Column_name'], $idx_row['Seq_in_index'], $idx_row['Non_unique'] ) ) {
					continue;
				}
				$key_name = (string) $idx_row['Key_name'];
				$seq      = (int) $idx_row['Seq_in_index'];
				$unique   = 0 === (int) $idx_row['Non_unique'];

				if ( ! isset( $actual_indexes[ $key_name ] ) ) {
					$actual_indexes[ $key_name ] = array(
						'unique'  => $unique,
						'columns' => array(),
					);
				}
				$actual_indexes[ $key_name ]['columns'][ $seq ] = (string) $idx_row['Column_name'];
			}

			foreach ( $expected_indexes[ $logical ] as $idx_name => $expected_meta ) {
				if ( ! isset( $actual_indexes[ $idx_name ] ) ) {
					$errors[] = "Missing index {$logical}.{$idx_name}";
					continue;
				}
				$actual_meta = $actual_indexes[ $idx_name ];
				ksort( $actual_meta['columns'] );
				$ordered_cols = array_values( $actual_meta['columns'] );

				if ( $actual_meta['unique'] !== $expected_meta['unique'] ) {
					$errors[] = "Index uniqueness mismatch on {$logical}.{$idx_name}";
				}
				if ( $ordered_cols !== $expected_meta['columns'] ) {
					$errors[] = "Index columns mismatch on {$logical}.{$idx_name}";
				}
			}
		}

		return $errors;
	}

	/**
	 * Persist the installed schema version in wp_options with autoload = 'no'.
	 *
	 * @param string $version Verified schema version.
	 */
	private function set_installed_version( string $version ): void {
		// Ensure autoload is explicitly false ('no') even if option did not exist.
		if ( false === get_option( self::VERSION_OPTION, false ) ) {
			add_option( self::VERSION_OPTION, $version, '', false );
			return;
		}
		update_option( self::VERSION_OPTION, $version, false );
	}
}

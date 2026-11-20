<?php
/**
 * Real WordPress + MariaDB integration tests for P01-B2 database schema,
 * migration locking, and plugin activation/deactivation lifecycle.
 *
 * @package WPIG\Tests\Integration
 */

declare(strict_types=1);

namespace WPIG\Tests\Integration;

use PHPUnit\Framework\TestCase;
use wpdb;
use WPIG\Core\Activator;
use WPIG\Core\Deactivator;
use WPIG\Storage\MigrationLock;
use WPIG\Storage\SchemaDefinition;
use WPIG\Storage\SchemaMigrator;

/**
 * Verifies the 6-table schema, dbDelta execution, unique/nullable constraints,
 * lock concurrency, Multisite prefix isolation, and lifecycle preservation
 * against a live WordPress + MariaDB instance.
 */
final class DatabaseMigrationIntegrationTest extends TestCase {

	/**
	 * Primary WordPress database instance.
	 *
	 * @var wpdb
	 */
	private wpdb $wpdb;

	/**
	 * Set up test environment before each test.
	 */
	protected function setUp(): void {
		parent::setUp();

		if ( ! isset( $GLOBALS['wpdb'] ) || ! $GLOBALS['wpdb'] instanceof wpdb ) {
			self::markTestSkipped( 'WordPress integration environment ($wpdb) is not loaded.' );
		}

		$this->wpdb = $GLOBALS['wpdb'];
		$this->drop_tables_for_prefix( $this->wpdb->prefix );
		$this->drop_tables_for_prefix( $this->wpdb->prefix . '2_' );

		delete_option( SchemaMigrator::VERSION_OPTION );
		delete_option( MigrationLock::OPTION_NAME );
		delete_option( Activator::SETTINGS_OPTION );
		delete_option( Activator::STATUS_OPTION );
	}

	/**
	 * Clean up secondary prefix tables and ensure primary site schema is restored after tests.
	 */
	protected function tearDown(): void {
		if ( isset( $this->wpdb ) ) {
			$this->drop_tables_for_prefix( $this->wpdb->prefix . '2_' );
			Activator::run_for_current_site( $this->wpdb );
		}
		parent::tearDown();
	}

	/**
	 * 1 & 2 & 8. Fresh activation creates all 6 tables, all required columns and
	 * indexes, and stores wpig_schema_version and wpig_settings as non-autoloaded options.
	 */
	public function test_fresh_activation_creates_all_tables_indexes_and_non_autoloaded_options(): void {
		$result = Activator::run_for_current_site( $this->wpdb );

		self::assertTrue( $result->success, 'Fresh activation migration must succeed.' );
		self::assertSame( SchemaDefinition::SCHEMA_VERSION, $result->schema_version );
		self::assertNull( $result->error_code );
		self::assertSame( array(), $result->errors );

		$migrator = new SchemaMigrator( $this->wpdb );
		self::assertSame( array(), $migrator->verify_schema() );
		self::assertSame( '1.0.0', get_option( SchemaMigrator::VERSION_OPTION ) );

		$settings = get_option( Activator::SETTINGS_OPTION );
		self::assertIsArray( $settings );
		self::assertFalse( $settings['erase_on_uninstall'] );
		self::assertFalse( $settings['legal_hold_active'] );

		// Verify autoload is disabled ('no' or 'off' in WP 6.6+) in wp_options.
		$wpdb = $this->wpdb;
		foreach ( array( SchemaMigrator::VERSION_OPTION, Activator::SETTINGS_OPTION, Activator::STATUS_OPTION ) as $opt_name ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Integration verification of wp_options autoload column.
			$autoload = $wpdb->get_var(
				$wpdb->prepare(
					"SELECT autoload FROM {$wpdb->options} WHERE option_name = %s",
					$opt_name
				)
			);
			self::assertContains(
				(string) $autoload,
				array( 'no', 'off' ),
				"Option {$opt_name} must not be autoloaded."
			);
		}
	}

	/**
	 * 3 & 4. Unique constraints reject duplicate non-null values while allowing
	 * multiple NULL values in nullable unique slots (D14 & single-active-card slot).
	 */
	public function test_unique_constraints_and_multiple_nulls_in_nullable_unique_slots(): void {
		Activator::run_for_current_site( $this->wpdb );
		$tables = SchemaDefinition::get_table_names( $this->wpdb->prefix );
		$now    = '2026-11-09 12:00:00';

		$nc_hmac_1 = str_repeat( 'a', 64 );
		$nc_hmac_2 = str_repeat( 'b', 64 );

		// Insert two unverified/unbound profiles with bound_national_code_hmac = NULL.
		// Both must succeed (D14: abandoned/unverified attempts do not reserve identity).
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$ins1 = $this->wpdb->insert(
			$tables['wpig_profiles'],
			array(
				'wp_user_id'               => 101,
				'binding_state'            => 'UNBOUND',
				'identity_state'           => 'PENDING',
				'national_code_hmac'       => $nc_hmac_1,
				'bound_national_code_hmac' => null,
				'created_at'               => $now,
				'updated_at'               => $now,
			)
		);
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$ins2 = $this->wpdb->insert(
			$tables['wpig_profiles'],
			array(
				'wp_user_id'               => 102,
				'binding_state'            => 'UNBOUND',
				'identity_state'           => 'PENDING',
				'national_code_hmac'       => $nc_hmac_1,
				'bound_national_code_hmac' => null,
				'created_at'               => $now,
				'updated_at'               => $now,
			)
		);
		self::assertSame( 1, $ins1, 'First NULL bound_national_code_hmac profile must insert.' );
		self::assertSame( 1, $ins2, 'Second NULL bound_national_code_hmac profile must also insert.' );

		// Duplicate wp_user_id must be rejected by uq_wpig_profiles_wp_user.
		$suppressed = $this->wpdb->suppress_errors( true );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$dup_user = $this->wpdb->insert(
			$tables['wpig_profiles'],
			array(
				'wp_user_id'               => 101,
				'binding_state'            => 'UNBOUND',
				'identity_state'           => 'UNVERIFIED',
				'bound_national_code_hmac' => null,
				'created_at'               => $now,
				'updated_at'               => $now,
			)
		);
		$this->wpdb->suppress_errors( $suppressed );
		self::assertFalse( $dup_user, 'Duplicate wp_user_id must be rejected.' );

		// Bind user 101 to $nc_hmac_1; then attempting to bind user 102 to the same
		// bound_national_code_hmac must be rejected by uq_wpig_profiles_bound_nc.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$upd1 = $this->wpdb->update(
			$tables['wpig_profiles'],
			array(
				'binding_state'            => 'BOUND',
				'identity_state'           => 'VERIFIED',
				'bound_national_code_hmac' => $nc_hmac_1,
			),
			array( 'wp_user_id' => 101 )
		);
		self::assertSame( 1, $upd1 );

		$suppressed = $this->wpdb->suppress_errors( true );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$dup_nc = $this->wpdb->update(
			$tables['wpig_profiles'],
			array(
				'binding_state'            => 'BOUND',
				'identity_state'           => 'VERIFIED',
				'bound_national_code_hmac' => $nc_hmac_1,
			),
			array( 'wp_user_id' => 102 )
		);
		$this->wpdb->suppress_errors( $suppressed );
		self::assertFalse( $dup_nc, 'Duplicate non-null bound_national_code_hmac must be rejected.' );

		// Binding user 102 to a distinct national code HMAC succeeds.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$upd2 = $this->wpdb->update(
			$tables['wpig_profiles'],
			array(
				'binding_state'            => 'BOUND',
				'identity_state'           => 'VERIFIED',
				'bound_national_code_hmac' => $nc_hmac_2,
			),
			array( 'wp_user_id' => 102 )
		);
		self::assertSame( 1, $upd2 );

		// Test wpig_verifications idempotency_key uniqueness.
		$idem_key = str_repeat( 'c', 64 );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$v_ins1 = $this->wpdb->insert(
			$tables['wpig_verifications'],
			array(
				'wp_user_id'       => 101,
				'identity_version' => 1,
				'mobile_version'   => 1,
				'card_version'     => 1,
				'idempotency_key'  => $idem_key,
				'operation'        => 'shahkar',
				'provider'         => 'zohal',
				'state'            => 'VERIFIED',
				'requested_at'     => $now,
			)
		);
		self::assertSame( 1, $v_ins1 );

		$suppressed = $this->wpdb->suppress_errors( true );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$v_dup = $this->wpdb->insert(
			$tables['wpig_verifications'],
			array(
				'wp_user_id'       => 101,
				'identity_version' => 1,
				'mobile_version'   => 1,
				'card_version'     => 1,
				'idempotency_key'  => $idem_key,
				'operation'        => 'shahkar',
				'provider'         => 'zohal',
				'state'            => 'VERIFIED',
				'requested_at'     => $now,
			)
		);
		$this->wpdb->suppress_errors( $suppressed );
		self::assertFalse( $v_dup, 'Duplicate idempotency_key must be rejected.' );

		// Test wpig_cards: multiple historical cards (active_user_slot = NULL) allowed,
		// but only one active card (active_user_slot = wp_user_id) per user.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$card_hist1 = $this->wpdb->insert(
			$tables['wpig_cards'],
			array(
				'wp_user_id'       => 101,
				'active_user_slot' => null,
				'is_current'       => 0,
				'identity_version' => 1,
				'card_version'     => 1,
				'verification_id'  => 1,
				'card_last4'       => '1111',
				'masked_pan'       => '621986******1111',
				'state'            => 'SUPERSEDED',
				'provider'         => 'zohal',
				'verified_at'      => $now,
				'superseded_at'    => $now,
				'created_at'       => $now,
			)
		);
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$card_hist2 = $this->wpdb->insert(
			$tables['wpig_cards'],
			array(
				'wp_user_id'       => 101,
				'active_user_slot' => null,
				'is_current'       => 0,
				'identity_version' => 1,
				'card_version'     => 2,
				'verification_id'  => 1,
				'card_last4'       => '2222',
				'masked_pan'       => '621986******2222',
				'state'            => 'SUPERSEDED',
				'provider'         => 'zohal',
				'verified_at'      => $now,
				'superseded_at'    => $now,
				'created_at'       => $now,
			)
		);
		self::assertSame( 1, $card_hist1 );
		self::assertSame( 1, $card_hist2 );

		// Active card for user 101.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$card_active1 = $this->wpdb->insert(
			$tables['wpig_cards'],
			array(
				'wp_user_id'       => 101,
				'active_user_slot' => 101,
				'is_current'       => 1,
				'identity_version' => 1,
				'card_version'     => 3,
				'verification_id'  => 1,
				'card_last4'       => '3333',
				'masked_pan'       => '621986******3333',
				'state'            => 'VERIFIED',
				'provider'         => 'zohal',
				'verified_at'      => $now,
				'created_at'       => $now,
			)
		);
		self::assertSame( 1, $card_active1 );

		// Second active card for user 101 must fail uq_wpig_cards_active_slot.
		$suppressed = $this->wpdb->suppress_errors( true );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$card_active_dup = $this->wpdb->insert(
			$tables['wpig_cards'],
			array(
				'wp_user_id'       => 101,
				'active_user_slot' => 101,
				'is_current'       => 1,
				'identity_version' => 1,
				'card_version'     => 4,
				'verification_id'  => 1,
				'card_last4'       => '4444',
				'masked_pan'       => '621986******4444',
				'state'            => 'VERIFIED',
				'provider'         => 'zohal',
				'verified_at'      => $now,
				'created_at'       => $now,
			)
		);
		$this->wpdb->suppress_errors( $suppressed );
		self::assertFalse( $card_active_dup, 'Second active card slot for the same user must be rejected.' );
	}

	/**
	 * 5, 6 & 7. Activation is idempotent, and deactivation followed by reactivation
	 * preserves all 6 tables, inserted rows, schema version, and settings.
	 */
	public function test_idempotent_activation_deactivation_and_reactivation_preserve_data(): void {
		$first = Activator::run_for_current_site( $this->wpdb );
		self::assertTrue( $first->success );

		$tables = SchemaDefinition::get_table_names( $this->wpdb->prefix );
		$now    = '2026-11-09 12:30:00';

		// Insert a row into each of the 6 tables.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$this->wpdb->insert(
			$tables['wpig_profiles'],
			array(
				'wp_user_id'               => 501,
				'binding_state'            => 'BOUND',
				'identity_state'           => 'VERIFIED',
				'bound_national_code_hmac' => str_repeat( 'd', 64 ),
				'created_at'               => $now,
				'updated_at'               => $now,
			)
		);
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$this->wpdb->insert(
			$tables['wpig_verifications'],
			array(
				'wp_user_id'       => 501,
				'identity_version' => 1,
				'mobile_version'   => 1,
				'card_version'     => 1,
				'idempotency_key'  => str_repeat( 'e', 64 ),
				'operation'        => 'card_match',
				'provider'         => 'api_ir',
				'state'            => 'VERIFIED',
				'requested_at'     => $now,
			)
		);
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$this->wpdb->insert(
			$tables['wpig_cards'],
			array(
				'wp_user_id'       => 501,
				'active_user_slot' => 501,
				'is_current'       => 1,
				'identity_version' => 1,
				'card_version'     => 1,
				'verification_id'  => 1,
				'card_last4'       => '9999',
				'masked_pan'       => '603799******9999',
				'state'            => 'VERIFIED',
				'provider'         => 'api_ir',
				'verified_at'      => $now,
				'created_at'       => $now,
			)
		);
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$this->wpdb->insert(
			$tables['wpig_otp_challenges'],
			array(
				'wp_user_id'     => 501,
				'mobile_version' => 1,
				'mobile_hmac'    => str_repeat( 'f', 64 ),
				'code_hmac'      => str_repeat( '0', 64 ),
				'hmac_key_id'    => 'v1',
				'state'          => 'CONSUMED',
				'expires_at'     => $now,
				'created_at'     => $now,
			)
		);
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$this->wpdb->insert(
			$tables['wpig_consents'],
			array(
				'wp_user_id'     => 501,
				'notice_version' => '1.0',
				'notice_hash'    => str_repeat( '1', 64 ),
				'purposes_json'  => '["identity_verification"]',
				'accepted_at'    => $now,
			)
		);
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$this->wpdb->insert(
			$tables['wpig_audit_events'],
			array(
				'correlation_id' => '00000000-0000-4000-8000-000000000001',
				'actor_user_id'  => 501,
				'target_user_id' => 501,
				'event_type'     => 'identity.verified',
				'outcome'        => 'SUCCESS',
				'occurred_at'    => $now,
			)
		);

		// Repeated activation (idempotency check).
		$second = Activator::run_for_current_site( $this->wpdb );
		self::assertTrue( $second->success );

		// Deactivate plugin.
		Deactivator::deactivate();
		$status_after_deactivation = get_option( Activator::STATUS_OPTION );
		self::assertIsArray( $status_after_deactivation );
		self::assertSame( 'deactivated', $status_after_deactivation['lifecycle'] );

		// Verify all 6 tables still have 1 row each during deactivation.
		foreach ( $tables as $logical => $prefixed ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$count = (int) $this->wpdb->get_var( "SELECT COUNT(*) FROM `{$prefixed}`" );
			self::assertSame( 1, $count, "Table {$logical} must preserve rows on deactivation." );
		}

		// Reactivate plugin.
		$third = Activator::run_for_current_site( $this->wpdb );
		self::assertTrue( $third->success );
		$status_after_reactivation = get_option( Activator::STATUS_OPTION );
		self::assertSame( 'active', $status_after_reactivation['lifecycle'] );

		// Verify all 6 tables still have 1 row each after reactivation.
		foreach ( $tables as $logical => $prefixed ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$count = (int) $this->wpdb->get_var( "SELECT COUNT(*) FROM `{$prefixed}`" );
			self::assertSame( 1, $count, "Table {$logical} must preserve rows on reactivation." );
		}
	}

	/**
	 * 9. Failed migration does not record wpig_schema_version and releases the lock.
	 */
	public function test_failed_migration_does_not_mark_version_complete_and_releases_lock(): void {
		// Simulate partial DDL execution that creates only 5 of the 6 tables.
		$migrator = new SchemaMigrator(
			$this->wpdb,
			null,
			function ( array $sql_map ): void {
				require_once ABSPATH . 'wp-admin/includes/upgrade.php';
				unset( $sql_map['wpig_audit_events'] );
				foreach ( $sql_map as $ddl ) {
					dbDelta( $ddl );
				}
			}
		);

		$result = $migrator->migrate();

		self::assertFalse( $result->success );
		self::assertSame( 'SCHEMA_VERIFICATION_FAILED', $result->error_code );
		self::assertNotEmpty( $result->errors );
		self::assertFalse(
			get_option( SchemaMigrator::VERSION_OPTION, false ),
			'wpig_schema_version must not be written when schema verification fails.'
		);
		self::assertFalse(
			get_option( MigrationLock::OPTION_NAME, false ),
			'Migration lock option must be cleaned up in finally block after failure.'
		);
	}

	/**
	 * 10. Concurrent migration attempts: a second database connection cannot
	 * acquire or steal an active MigrationLock and fails closed.
	 */
	public function test_concurrent_migration_attempt_is_blocked_safely(): void {
		$lock1 = new MigrationLock( $this->wpdb, 'owner-session-1' );
		self::assertTrue( $lock1->acquire( SchemaDefinition::SCHEMA_VERSION ) );
		self::assertTrue( $lock1->verify_continuity() );

		// Open a separate MySQL/MariaDB session to simulate a concurrent PHP worker.
		$second_wpdb = new wpdb( DB_USER, DB_PASSWORD, DB_NAME, DB_HOST );
		$second_wpdb->set_prefix( $this->wpdb->prefix );

		try {
			$concurrent_migrator = new SchemaMigrator( $second_wpdb );
			$concurrent_result   = $concurrent_migrator->migrate();

			self::assertFalse( $concurrent_result->success );
			self::assertSame( 'MIGRATION_LOCK_UNAVAILABLE', $concurrent_result->error_code );

			// Verify lock 1 is still intact and uncorrupted by connection 2.
			self::assertTrue( $lock1->verify_continuity() );
		} finally {
			$lock1->release();
			$second_wpdb->close();
		}
	}

	/**
	 * 11. Multisite table prefix isolation: migrating site 2 (prefix wp_2_)
	 * creates isolated tables without modifying site 1 tables or rows.
	 */
	public function test_multisite_table_prefix_isolation(): void {
		// Migrate primary site (wp_).
		$res1 = Activator::run_for_current_site( $this->wpdb );
		self::assertTrue( $res1->success );

		$site1_tables = SchemaDefinition::get_table_names( $this->wpdb->prefix );
		$now          = '2026-11-09 13:00:00';
		$shared_hmac  = str_repeat( '9', 64 );

		// Bind user 1 on site 1 to $shared_hmac.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$this->wpdb->insert(
			$site1_tables['wpig_profiles'],
			array(
				'wp_user_id'               => 1,
				'binding_state'            => 'BOUND',
				'identity_state'           => 'VERIFIED',
				'bound_national_code_hmac' => $shared_hmac,
				'created_at'               => $now,
				'updated_at'               => $now,
			)
		);

		// Simulate site 2 using prefix wp_2_.
		$original_prefix = $this->wpdb->prefix;
		// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- Simulating Multisite switch_to_blog prefix change.
		$this->wpdb->prefix = $original_prefix . '2_';

		try {
			$site2_migrator = new SchemaMigrator( $this->wpdb );
			$res2           = $site2_migrator->migrate();
			self::assertTrue( $res2->success );
			self::assertSame( array(), $site2_migrator->verify_schema() );

			$site2_tables = SchemaDefinition::get_table_names( $this->wpdb->prefix );

			// The same national code HMAC can be bound on site 2 because site tables are isolated (D14).
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$ins_site2 = $this->wpdb->insert(
				$site2_tables['wpig_profiles'],
				array(
					'wp_user_id'               => 2,
					'binding_state'            => 'BOUND',
					'identity_state'           => 'VERIFIED',
					'bound_national_code_hmac' => $shared_hmac,
					'created_at'               => $now,
					'updated_at'               => $now,
				)
			);
			self::assertSame( 1, $ins_site2 );

			// Verify site 1 still has exactly 1 row and site 2 has 1 row.
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$count1 = (int) $this->wpdb->get_var( "SELECT COUNT(*) FROM `{$site1_tables['wpig_profiles']}`" );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$count2 = (int) $this->wpdb->get_var( "SELECT COUNT(*) FROM `{$site2_tables['wpig_profiles']}`" );
			self::assertSame( 1, $count1 );
			self::assertSame( 1, $count2 );
		} finally {
			// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
			$this->wpdb->prefix = $original_prefix;
		}
	}

	/**
	 * 12. Registered WordPress activation and deactivation hooks execute cleanly.
	 */
	public function test_registered_wordpress_activation_and_deactivation_hooks(): void {
		$plugin_basename = plugin_basename( WPIG_PLUGIN_FILE );

		self::assertNotFalse(
			has_action( 'activate_' . $plugin_basename, array( Activator::class, 'activate' ) ),
			'Activation hook must be registered for wp-identity-guard.php.'
		);
		self::assertNotFalse(
			has_action( 'deactivate_' . $plugin_basename, array( Deactivator::class, 'deactivate' ) ),
			'Deactivation hook must be registered for wp-identity-guard.php.'
		);

		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Invoking core WordPress plugin activation hook in integration test.
		do_action( 'activate_' . $plugin_basename, false );
		self::assertSame( SchemaDefinition::SCHEMA_VERSION, get_option( SchemaMigrator::VERSION_OPTION ) );

		$migrator = new SchemaMigrator( $this->wpdb );
		self::assertSame( array(), $migrator->verify_schema() );

		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Invoking core WordPress plugin deactivation hook in integration test.
		do_action( 'deactivate_' . $plugin_basename, false );
		$status = get_option( Activator::STATUS_OPTION );
		self::assertIsArray( $status );
		self::assertSame( 'deactivated', $status['lifecycle'] );
		self::assertSame( array(), $migrator->verify_schema() );
	}

	/**
	 * Drop all 6 WPIG tables for a given prefix (test helper).
	 *
	 * @param string $prefix Table prefix.
	 */
	private function drop_tables_for_prefix( string $prefix ): void {
		foreach ( SchemaDefinition::get_table_names( $prefix ) as $table ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$this->wpdb->query( "DROP TABLE IF EXISTS `{$table}`" );
		}
	}
}

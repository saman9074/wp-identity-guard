<?php
/**
 * Unit tests for SchemaDefinition and MigrationResult.
 *
 * @package WPIG\Tests\Unit
 */

declare(strict_types=1);

namespace WPIG\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPIG\Storage\MigrationResult;
use WPIG\Storage\SchemaDefinition;

/**
 * Verifies table naming, dbDelta formatting invariants, and expected schema metadata.
 */
final class SchemaDefinitionTest extends TestCase {

	/**
	 * Ensure all 6 approved logical tables are prefixed accurately for single-site and Multisite.
	 */
	public function test_get_table_names_applies_site_prefix(): void {
		$single = SchemaDefinition::get_table_names( 'wp_' );
		self::assertCount( 6, $single );
		self::assertSame(
			array(
				'wpig_profiles'       => 'wp_wpig_profiles',
				'wpig_verifications'  => 'wp_wpig_verifications',
				'wpig_cards'          => 'wp_wpig_cards',
				'wpig_otp_challenges' => 'wp_wpig_otp_challenges',
				'wpig_consents'       => 'wp_wpig_consents',
				'wpig_audit_events'   => 'wp_wpig_audit_events',
			),
			$single
		);

		$multisite = SchemaDefinition::get_table_names( 'wp_2_' );
		self::assertSame( 'wp_2_wpig_profiles', $multisite['wpig_profiles'] );
		self::assertSame( 'wp_2_wpig_audit_events', $multisite['wpig_audit_events'] );
	}

	/**
	 * Ensure CREATE TABLE SQL obeys WordPress dbDelta() formatting requirements
	 * and matches expected column and index definitions.
	 */
	public function test_create_table_sql_conforms_to_dbdelta_and_metadata(): void {
		$sql_map          = SchemaDefinition::get_create_table_sql( 'wp_', 'DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci' );
		$expected_columns = SchemaDefinition::get_expected_columns();
		$expected_indexes = SchemaDefinition::get_expected_indexes();

		self::assertSame( SchemaDefinition::LOGICAL_TABLES, array_keys( $sql_map ) );
		self::assertSame( SchemaDefinition::LOGICAL_TABLES, array_keys( $expected_columns ) );
		self::assertSame( SchemaDefinition::LOGICAL_TABLES, array_keys( $expected_indexes ) );

		foreach ( SchemaDefinition::LOGICAL_TABLES as $logical ) {
			$ddl = $sql_map[ $logical ];

			// dbDelta requires exactly two spaces between PRIMARY KEY and (id).
			self::assertStringContainsString( 'PRIMARY KEY  (id)', $ddl, "Table {$logical} must have two spaces after PRIMARY KEY." );

			// dbDelta prohibits the INDEX keyword (must use KEY or UNIQUE KEY).
			self::assertDoesNotMatchRegularExpression( '/\bINDEX\b/i', $ddl, "Table {$logical} must not use INDEX keyword." );

			// Every expected column must appear in the DDL.
			foreach ( $expected_columns[ $logical ] as $col ) {
				self::assertMatchesRegularExpression(
					'/^\s+' . preg_quote( $col, '/' ) . '\s+/m',
					$ddl,
					"Column {$logical}.{$col} missing from CREATE TABLE SQL."
				);
			}

			// Every non-PRIMARY expected index name must appear in the DDL.
			foreach ( $expected_indexes[ $logical ] as $idx_name => $meta ) {
				if ( 'PRIMARY' === $idx_name ) {
					continue;
				}
				$prefix = $meta['unique'] ? 'UNIQUE KEY ' : 'KEY ';
				self::assertStringContainsString(
					$prefix . $idx_name . ' (' . implode( ',', $meta['columns'] ) . ')',
					$ddl,
					"Index {$logical}.{$idx_name} definition mismatch in CREATE TABLE SQL."
				);
			}
		}
	}

	/**
	 * Ensure wpig_cards never defines any column capable of holding a full PAN (D02 / DS-2).
	 */
	public function test_cards_table_contains_no_full_pan_columns(): void {
		$card_cols = SchemaDefinition::get_expected_columns()['wpig_cards'];
		self::assertContains( 'card_last4', $card_cols );
		self::assertContains( 'masked_pan', $card_cols );
		self::assertNotContains( 'pan', $card_cols );
		self::assertNotContains( 'card_number', $card_cols );
		self::assertNotContains( 'pan_ciphertext', $card_cols );
		self::assertNotContains( 'pan_hmac', $card_cols );
	}

	/**
	 * Verify MigrationResult value object properties.
	 */
	public function test_migration_result_value_object(): void {
		$ok = new MigrationResult( true, SchemaDefinition::SCHEMA_VERSION );
		self::assertTrue( $ok->success );
		self::assertSame( '1.0.0', $ok->schema_version );
		self::assertNull( $ok->error_code );
		self::assertSame( array(), $ok->errors );

		$fail = new MigrationResult( false, '', 'SCHEMA_VERIFICATION_FAILED', array( 'Missing table: wp_wpig_profiles' ) );
		self::assertFalse( $fail->success );
		self::assertSame( '', $fail->schema_version );
		self::assertSame( 'SCHEMA_VERIFICATION_FAILED', $fail->error_code );
		self::assertCount( 1, $fail->errors );
	}
}

<?php
/**
 * Real WordPress + MariaDB security integration tests for P01-C3 ProfileRepository,
 * AEAD encryption/decryption, canonical AAD isolation, HMAC fingerprinting,
 * version concurrency, transaction rollback, and D14 identity binding invariants.
 *
 * Uses strictly synthetic test vectors constructed at runtime.
 *
 * @package WPIG\Tests\Integration
 */

declare(strict_types=1);

namespace WPIG\Tests\Integration;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use wpdb;
use WPIG\Core\Activator;
use WPIG\Core\Deactivator;
use WPIG\Security\CryptoException;
use WPIG\Security\IdentityFingerprinter;
use WPIG\Security\SensitiveValue;
use WPIG\Security\SodiumCrypto;
use WPIG\Security\ValidationException;
use WPIG\Security\WordPressKeyProvider;
use WPIG\Storage\ProfileRecord;
use WPIG\Storage\ProfileRepository;
use WPIG\Storage\SchemaDefinition;
use WPIG\Storage\StorageException;

/**
 * Verifies ProfileRepository security and persistence invariants against live MariaDB.
 */
final class ProfileRepositoryIntegrationTest extends TestCase {

	/**
	 * Synthetic 256-bit encryption key #1 (hex).
	 */
	private const SYNTHETIC_ENC_KEY_1 = 'hex:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20';

	/**
	 * Synthetic 256-bit encryption key #2 for key-rotation preservation tests (hex).
	 */
	private const SYNTHETIC_ENC_KEY_2 = 'hex:2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40';

	/**
	 * Synthetic 256-bit HMAC key #1 (hex).
	 */
	private const SYNTHETIC_HMAC_KEY_1 = 'hex:a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0';

	/**
	 * Synthetic 256-bit HMAC key #2 (hex).
	 */
	private const SYNTHETIC_HMAC_KEY_2 = 'hex:c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0';

	/**
	 * WordPress database instance.
	 *
	 * @var wpdb
	 */
	private wpdb $wpdb;

	/**
	 * Set up a clean migrated schema before each test.
	 */
	protected function setUp(): void {
		parent::setUp();

		if ( ! isset( $GLOBALS['wpdb'] ) || ! $GLOBALS['wpdb'] instanceof wpdb ) {
			self::markTestSkipped( 'WordPress integration environment ($wpdb) is not loaded.' );
		}

		$this->wpdb = $GLOBALS['wpdb'];
		$this->truncate_profiles_table();
		Activator::run_for_current_site( $this->wpdb );
		$this->truncate_profiles_table();
	}

	/**
	 * Clean up test rows after each test.
	 */
	protected function tearDown(): void {
		if ( isset( $this->wpdb ) ) {
			$this->truncate_profiles_table();
		}
		parent::tearDown();
	}

	/**
	 * Build a synthetic 10-digit national code with a valid modulo-11 check digit.
	 *
	 * @param string $nine_digits 9 ASCII digits.
	 */
	private static function make_synthetic_nc( string $nine_digits ): string {
		$sum = 0;
		for ( $i = 0; $i < 9; $i++ ) {
			$sum += ( (int) $nine_digits[ $i ] ) * ( 10 - $i );
		}
		$rem   = $sum % 11;
		$check = $rem < 2 ? $rem : ( 11 - $rem );
		return $nine_digits . (string) $check;
	}

	/**
	 * Convert ASCII digits in a string to Persian digits ('۰'..'۹').
	 *
	 * @param string $ascii Input string.
	 */
	private static function to_persian_digits( string $ascii ): string {
		return strtr(
			$ascii,
			array(
				'0' => '۰',
				'1' => '۱',
				'2' => '۲',
				'3' => '۳',
				'4' => '۴',
				'5' => '۵',
				'6' => '۶',
				'7' => '۷',
				'8' => '۸',
				'9' => '۹',
			)
		);
	}

	/**
	 * Build a configured ProfileRepository instance for tests.
	 *
	 * @param array<string,mixed> $k1_overrides Optional K1 constant overrides.
	 * @param int                 $blog_id      Blog ID for canonical AAD.
	 * @param string              $now_utc      Fixed UTC clock timestamp.
	 */
	private function make_repository(
		array $k1_overrides = array(),
		int $blog_id = 1,
		string $now_utc = '2026-11-14 12:00:00'
	): ProfileRepository {
		$defaults = array(
			WordPressKeyProvider::CONST_ENC_KEY     => self::SYNTHETIC_ENC_KEY_1,
			WordPressKeyProvider::CONST_ENC_KEY_ID  => 'k2026_01',
			WordPressKeyProvider::CONST_HMAC_KEY    => self::SYNTHETIC_HMAC_KEY_1,
			WordPressKeyProvider::CONST_HMAC_KEY_ID => 'hmac_2026_01',
		);

		$merged = array_merge( $defaults, $k1_overrides );

		$key_provider  = new WordPressKeyProvider(
			static fn( string $name ): mixed => $merged[ $name ] ?? null
		);
		$crypto        = new SodiumCrypto( $key_provider );
		$fingerprinter = new IdentityFingerprinter( $crypto );

		return new ProfileRepository(
			$this->wpdb,
			$crypto,
			$key_provider,
			$fingerprinter,
			static fn(): string => $now_utc,
			static fn(): int => $blog_id
		);
	}

	/**
	 * Fetch the raw associative database row directly from MariaDB for low-level inspection.
	 *
	 * @param int $wp_user_id WordPress user ID.
	 * @return array<string,mixed>
	 */
	private function fetch_raw_db_row( int $wp_user_id ): array {
		$table = SchemaDefinition::get_table_names( $this->wpdb->prefix )['wpig_profiles'];
		$wpdb  = $this->wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Test helper reading raw DB state.
		$row = $wpdb->get_row(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is strictly constructed from $wpdb->prefix + constant logical table.
				"SELECT * FROM `{$table}` WHERE wp_user_id = %d",
				$wp_user_id
			),
			ARRAY_A
		);
		self::assertIsArray( $row );
		return $row;
	}

	/**
	 * Truncate wpig_profiles table between tests.
	 */
	private function truncate_profiles_table(): void {
		$table = SchemaDefinition::get_table_names( $this->wpdb->prefix )['wpig_profiles'];
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$this->wpdb->query( "DELETE FROM `{$table}`" );
	}

	/**
	 * Scenarios 1, 2, 3, 4, 14 & 15:
	 * - Create a secure profile with synthetic data (Persian digits & formatting).
	 * - Verify database contains no plaintext identity values.
	 * - Verify ciphertext differs from plaintext and uses versioned v1 envelope.
	 * - Verify correct-user decryption returns canonical normalized values.
	 * - Verify masked values contain no full identifiers.
	 * - Verify export/read DTOs never expose plaintext or ciphertexts.
	 */
	public function test_create_secure_profile_no_plaintext_in_db_and_correct_user_decryption(): void {
		$repo = $this->make_repository();

		$canonical_nc  = self::make_synthetic_nc( '001234567' );
		$mob_tail      = implode( '', array( '12', '345', '6789' ) );
		$canonical_mob = '09' . $mob_tail;
		$canonical_bd  = '1370/01/05';

		// Supply Persian numerals and unpadded Jalali date to verify pre-encryption normalization.
		$input_nc  = '  ' . self::to_persian_digits( $canonical_nc ) . '  ';
		$input_mob = '+98 9' . self::to_persian_digits( $mob_tail );
		$input_bd  = self::to_persian_digits( '1370-1-5' );

		$record = $repo->create_profile( 1001, $input_nc, $input_mob, $input_bd );

		// 1 & 14. Verify safe DTO properties and masked display formats.
		self::assertSame( 1001, $record->wp_user_id );
		self::assertSame( ProfileRecord::BINDING_UNBOUND, $record->binding_state );
		self::assertSame( ProfileRecord::STATE_UNVERIFIED, $record->identity_state );
		self::assertNull( $record->bound_national_code_hmac, 'UNBOUND profile must never reserve bound_national_code_hmac.' );
		self::assertSame( 1, $record->identity_version );
		self::assertSame( 1, $record->mobile_version );
		self::assertSame( 1, $record->card_version );
		self::assertSame( '******' . substr( $canonical_nc, 6, 4 ), $record->national_code_masked );
		self::assertSame( '0912***6789', $record->mobile_masked );
		self::assertStringNotContainsString( $canonical_nc, (string) $record->national_code_masked );
		self::assertStringNotContainsString( $canonical_mob, (string) $record->mobile_masked );
		self::assertTrue( $record->has_national_code );
		self::assertTrue( $record->has_mobile );
		self::assertTrue( $record->has_birth_date );
		self::assertSame( 'k2026_01', $record->enc_key_id );
		self::assertSame( 'hmac_2026_01', $record->hmac_key_id );

		// 2 & 3. Inspect raw MariaDB row: verify zero plaintext values and valid v1 AEAD envelopes.
		$raw_row        = $this->fetch_raw_db_row( 1001 );
		$serialized_row = json_encode( $raw_row ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode
		self::assertIsString( $serialized_row );
		self::assertStringNotContainsString( $canonical_nc, $serialized_row, 'Database row must never contain plaintext national code.' );
		self::assertStringNotContainsString( $canonical_mob, $serialized_row, 'Database row must never contain plaintext mobile.' );
		self::assertStringNotContainsString( $canonical_bd, $serialized_row, 'Database row must never contain plaintext birth date.' );
		self::assertStringNotContainsString( '1370-1-5', $serialized_row );

		self::assertStringStartsWith( 'v1:k2026_01:', (string) $raw_row['national_code_ciphertext'] );
		self::assertStringStartsWith( 'v1:k2026_01:', (string) $raw_row['mobile_ciphertext'] );
		self::assertStringStartsWith( 'v1:k2026_01:', (string) $raw_row['birth_date_ciphertext'] );
		self::assertNotSame( $canonical_nc, $raw_row['national_code_ciphertext'] );
		self::assertNotSame( $canonical_mob, $raw_row['mobile_ciphertext'] );
		self::assertNotSame( $canonical_bd, $raw_row['birth_date_ciphertext'] );
		self::assertMatchesRegularExpression( '/^[0-9a-f]{64}$/', (string) $raw_row['national_code_hmac'] );
		self::assertMatchesRegularExpression( '/^[0-9a-f]{64}$/', (string) $raw_row['mobile_hmac'] );

		// 4. Verify correct-user decryption returns exact canonical values.
		$decrypted = $repo->decrypt_identity_for_user( 1001 );
		self::assertNotNull( $decrypted->national_code );
		self::assertNotNull( $decrypted->mobile );
		self::assertNotNull( $decrypted->birth_date );
		self::assertSame( $canonical_nc, $decrypted->national_code->reveal() );
		self::assertSame( $canonical_mob, $decrypted->mobile->reveal() );
		self::assertSame( $canonical_bd, $decrypted->birth_date->reveal() );

		// 15. Verify export/read DTOs never expose plaintext or ciphertexts.
		$safe_export     = $record->to_safe_export_array();
		$safe_export_str = json_encode( $safe_export ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode
		self::assertIsString( $safe_export_str );
		self::assertStringNotContainsString( $canonical_nc, $safe_export_str );
		self::assertStringNotContainsString( $canonical_mob, $safe_export_str );
		self::assertStringNotContainsString( $canonical_bd, $safe_export_str );
		self::assertStringNotContainsString( 'v1:k2026_01:', $safe_export_str );
	}

	/**
	 * Scenarios 5, 6 & 7:
	 * - Wrong-user decryption fails closed (AAD wp_user_id mismatch).
	 * - Wrong-blog decryption fails closed (AAD blog_id mismatch).
	 * - Wrong-column decryption fails closed (AAD column_name mismatch).
	 */
	public function test_wrong_user_wrong_blog_and_wrong_column_decryption_fail_closed(): void {
		$repo_blog1 = $this->make_repository( array(), 1 );

		$nc1  = self::make_synthetic_nc( '001234567' );
		$nc2  = self::make_synthetic_nc( '009876543' );
		$mob1 = '09' . implode( '', array( '12', '111', '2233' ) );
		$mob2 = '09' . implode( '', array( '12', '444', '5566' ) );

		$repo_blog1->create_profile( 2001, $nc1, $mob1, '1370/01/05' );
		$repo_blog1->create_profile( 2002, $nc2, $mob2, '1375/12/30' );

		$row_2001 = $this->fetch_raw_db_row( 2001 );
		$table    = SchemaDefinition::get_table_names( $this->wpdb->prefix )['wpig_profiles'];

		// 6. Wrong-blog decryption: attempting to decrypt user 2001's profile from blog_id = 2 fails closed.
		$repo_blog2 = $this->make_repository( array(), 2 );
		try {
			$repo_blog2->decrypt_identity_for_user( 2001 );
			self::fail( 'Expected CryptoException when decrypting blog:1 ciphertext under blog:2.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_AUTH_FAILED, $e->get_safe_code() );
		}

		// 5. Wrong-user decryption: transplant user 2001's national_code_ciphertext onto user 2002's row.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$this->wpdb->update(
			$table,
			array( 'national_code_ciphertext' => $row_2001['national_code_ciphertext'] ),
			array( 'wp_user_id' => 2002 )
		);

		try {
			$repo_blog1->decrypt_identity_for_user( 2002 );
			self::fail( 'Expected CryptoException when ciphertext is transplanted to another wp_user_id.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_AUTH_FAILED, $e->get_safe_code() );
		}

		// 7. Wrong-column decryption: transplant user 2001's mobile_ciphertext into user 2001's birth_date_ciphertext.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$this->wpdb->update(
			$table,
			array( 'birth_date_ciphertext' => $row_2001['mobile_ciphertext'] ),
			array( 'wp_user_id' => 2001 )
		);

		try {
			$repo_blog1->decrypt_identity_for_user( 2001 );
			self::fail( 'Expected CryptoException when mobile_ciphertext is transplanted into birth_date_ciphertext.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_AUTH_FAILED, $e->get_safe_code() );
		}
	}

	/**
	 * Scenarios 8 & 9:
	 * - Missing encryption keys fail closed without overwriting valid persisted ciphertext.
	 * - Invalid HMAC keys fail closed without writing partial or corrupted data.
	 */
	public function test_missing_encryption_keys_and_invalid_hmac_keys_fail_closed_without_data_corruption(): void {
		$valid_repo = $this->make_repository();
		$nc         = self::make_synthetic_nc( '001234567' );
		$mob        = '09' . implode( '', array( '12', '345', '6789' ) );

		$valid_repo->create_profile( 3001, $nc, $mob, '1370/01/05' );
		$original_row = $this->fetch_raw_db_row( 3001 );

		// 8a. Missing encryption key on update_mobile must fail closed BEFORE touching the database row.
		$missing_enc_repo = $this->make_repository(
			array( WordPressKeyProvider::CONST_ENC_KEY => '' )
		);

		$new_mob = '09' . implode( '', array( '12', '999', '8877' ) );
		try {
			$missing_enc_repo->update_mobile( 3001, $new_mob, 1 );
			self::fail( 'Expected CryptoException when WPIG_ENC_KEY is missing.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_KEY_MISSING, $e->get_safe_code() );
		}

		// Verify original ciphertext and version in MariaDB are 100% preserved.
		$after_failed_update = $this->fetch_raw_db_row( 3001 );
		self::assertSame( $original_row['mobile_ciphertext'], $after_failed_update['mobile_ciphertext'] );
		self::assertSame( $original_row['mobile_hmac'], $after_failed_update['mobile_hmac'] );
		self::assertSame( '1', (string) $after_failed_update['mobile_version'] );

		// 8b. Missing encryption key on decrypt_identity_for_user fails closed without mutating stored data.
		try {
			$missing_enc_repo->decrypt_identity_for_user( 3001 );
			self::fail( 'Expected CryptoException when decrypting with missing WPIG_ENC_KEY.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_KEY_MISSING, $e->get_safe_code() );
		}

		// Original ciphertext still decrypts cleanly with the valid repository.
		$decrypted = $valid_repo->decrypt_identity_for_user( 3001 );
		self::assertNotNull( $decrypted->mobile );
		self::assertSame( $mob, $decrypted->mobile->reveal() );

		// 9. Invalid HMAC key (too short / malformed) fails closed on create_profile and update_identity_data.
		$invalid_hmac_repo = $this->make_repository(
			array( WordPressKeyProvider::CONST_HMAC_KEY => 'hex:1234' )
		);

		try {
			$invalid_hmac_repo->create_profile( 3002, $nc, $mob, '1370/01/05' );
			self::fail( 'Expected CryptoException when WPIG_HMAC_KEY is invalid.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_KEY_INVALID, $e->get_safe_code() );
		}

		self::assertNull( $valid_repo->find_by_user_id( 3002 ), 'Failed create_profile must not insert a row.' );
	}

	/**
	 * Scenario 10:
	 * - Encrypted profile data survives plugin deactivation and reactivation intact.
	 */
	public function test_encrypted_profile_survives_plugin_deactivation_and_reactivation(): void {
		$repo = $this->make_repository();
		$nc   = self::make_synthetic_nc( '001234567' );
		$mob  = '09' . implode( '', array( '12', '345', '6789' ) );
		$bd   = '1375/12/30';

		$repo->create_profile( 4001, $nc, $mob, $bd );
		$repo->record_mobile_verified( 4001, 1, '2026-11-14 12:01:00' );
		$repo->bind_verified_identity( 4001, 1, 1, '2027-11-14 12:01:00' );

		Deactivator::deactivate();
		$reactivation = Activator::run_for_current_site( $this->wpdb );
		self::assertTrue( $reactivation->success );

		$loaded = $repo->get_by_user_id( 4001 );
		self::assertTrue( $loaded->is_bound() );
		self::assertSame( ProfileRecord::STATE_VERIFIED, $loaded->identity_state );

		$decrypted = $repo->decrypt_identity_for_user( 4001 );
		self::assertNotNull( $decrypted->national_code );
		self::assertNotNull( $decrypted->mobile );
		self::assertNotNull( $decrypted->birth_date );
		self::assertSame( $nc, $decrypted->national_code->reveal() );
		self::assertSame( $mob, $decrypted->mobile->reveal() );
		self::assertSame( $bd, $decrypted->birth_date->reveal() );
	}

	/**
	 * Scenario 11 & Task 6:
	 * - Stale version updates fail closed with CODE_VERSION_CONFLICT.
	 * - Mobile changes invalidate dependent mobile & Shahkar evidence while preserving identity_version, card_version, and binding_state.
	 * - Identity changes on an UNBOUND profile invalidate Shahkar evidence while preserving mobile_version, mobile_verified_at, and card_version.
	 * - Card-only changes increment card_version without invalidating identity or mobile evidence or altering key IDs.
	 */
	public function test_version_concurrency_and_granular_evidence_invalidation(): void {
		$repo = $this->make_repository();

		$nc1  = self::make_synthetic_nc( '001234567' );
		$nc2  = self::make_synthetic_nc( '009876543' );
		$mob1 = '09' . implode( '', array( '12', '111', '2233' ) );
		$mob2 = '09' . implode( '', array( '12', '444', '5566' ) );

		// Create unbound profile and verify mobile OTP possession.
		$created = $repo->create_profile( 5001, $nc1, $mob1, '1370/01/05' );
		self::assertSame( 1, $created->identity_version );
		self::assertSame( 1, $created->mobile_version );
		self::assertSame( 1, $created->card_version );

		$after_otp = $repo->record_mobile_verified( 5001, 1, '2026-11-14 12:05:00' );
		self::assertSame( '2026-11-14 12:05:00', $after_otp->mobile_verified_at );

		// Changing unbound identity data increments identity_version (1 -> 2),
		// but preserves mobile_version (1) and mobile_verified_at!
		$after_id_edit = $repo->update_identity_data( 5001, $nc2, '1372/06/31', 1 );
		self::assertSame( 2, $after_id_edit->identity_version );
		self::assertSame( 1, $after_id_edit->mobile_version );
		self::assertSame( 1, $after_id_edit->card_version );
		self::assertSame( '2026-11-14 12:05:00', $after_id_edit->mobile_verified_at );

		// Stale identity_version (passing 1 when current is 2) must fail closed.
		try {
			$repo->update_identity_data( 5001, $nc1, '1370/01/05', 1 );
			self::fail( 'Expected StorageException for stale identity_version.' );
		} catch ( StorageException $e ) {
			self::assertSame( StorageException::CODE_VERSION_CONFLICT, $e->get_safe_code() );
		}

		// Bind verified identity at (identity_version=2, mobile_version=1).
		$bound = $repo->bind_verified_identity( 5001, 2, 1, '2027-11-14 12:00:00' );
		self::assertSame( ProfileRecord::BINDING_BOUND, $bound->binding_state );
		self::assertSame( ProfileRecord::STATE_VERIFIED, $bound->identity_state );
		self::assertNotNull( $bound->shahkar_verified_at );

		// Card-only change increments card_version (1 -> 2) without invalidating mobile_verified_at,
		// shahkar_verified_at, identity_state, binding_state, or key IDs.
		$after_card = $repo->increment_card_version( 5001, 1 );
		self::assertSame( 2, $after_card->identity_version );
		self::assertSame( 1, $after_card->mobile_version );
		self::assertSame( 2, $after_card->card_version );
		self::assertSame( ProfileRecord::BINDING_BOUND, $after_card->binding_state );
		self::assertSame( ProfileRecord::STATE_VERIFIED, $after_card->identity_state );
		self::assertSame( '2026-11-14 12:05:00', $after_card->mobile_verified_at );
		self::assertNotNull( $after_card->shahkar_verified_at );
		self::assertSame( 'k2026_01', $after_card->enc_key_id );
		self::assertSame( 'hmac_2026_01', $after_card->hmac_key_id );

		// Stale card_version (passing 1 when current is 2) must fail closed.
		try {
			$repo->increment_card_version( 5001, 1 );
			self::fail( 'Expected StorageException for stale card_version.' );
		} catch ( StorageException $e ) {
			self::assertSame( StorageException::CODE_VERSION_CONFLICT, $e->get_safe_code() );
		}

		// Mobile change increments mobile_version (1 -> 2), clears mobile_verified_at and shahkar_verified_at,
		// transitions identity_state VERIFIED -> PENDING, while keeping binding_state = BOUND,
		// bound_national_code_hmac, identity_version (2), and card_version (2) intact!
		$after_mob_change = $repo->update_mobile( 5001, $mob2, 1 );
		self::assertSame( 2, $after_mob_change->identity_version );
		self::assertSame( 2, $after_mob_change->mobile_version );
		self::assertSame( 2, $after_mob_change->card_version );
		self::assertNull( $after_mob_change->mobile_verified_at );
		self::assertNull( $after_mob_change->shahkar_verified_at );
		self::assertSame( ProfileRecord::STATE_PENDING, $after_mob_change->identity_state );
		self::assertSame( ProfileRecord::BINDING_BOUND, $after_mob_change->binding_state );
		self::assertSame( $bound->bound_national_code_hmac, $after_mob_change->bound_national_code_hmac );

		// Stale mobile_version (passing 1 when current is 2) must fail closed.
		try {
			$repo->update_mobile( 5001, $mob1, 1 );
			self::fail( 'Expected StorageException for stale mobile_version.' );
		} catch ( StorageException $e ) {
			self::assertSame( StorageException::CODE_VERSION_CONFLICT, $e->get_safe_code() );
		}
	}

	/**
	 * Scenario 12:
	 * - Transaction rollback on error: failed validation or mid-transaction exception
	 *   leaves database state completely unchanged.
	 */
	public function test_transaction_rollback_on_error_prevents_partial_updates(): void {
		$repo = $this->make_repository();

		$nc1  = self::make_synthetic_nc( '001234567' );
		$mob1 = '09' . implode( '', array( '12', '111', '2233' ) );
		$mob2 = '09' . implode( '', array( '12', '444', '5566' ) );

		$repo->create_profile( 6001, $nc1, $mob1, '1370/01/05' );

		// 12a. Validation failure on update_identity_data (Gregorian year '1990/01/01') leaves row untouched.
		try {
			$repo->update_identity_data( 6001, $nc1, '1990/01/01', 1 );
			self::fail( 'Expected ValidationException for Gregorian birth year.' );
		} catch ( ValidationException $e ) {
			self::assertSame( ValidationException::CODE_INVALID_BIRTH_DATE, $e->get_safe_code() );
		}

		$unchanged = $repo->get_by_user_id( 6001 );
		self::assertSame( 1, $unchanged->identity_version );

		// 12b. Multi-step transactional operation where step 1 succeeds (update_mobile)
		// and step 2 throws an exception: MariaDB ROLLBACK undoes step 1 completely.
		try {
			$repo->run_in_transaction(
				function () use ( $repo, $mob2 ): void {
					$updated_mob = $repo->update_mobile( 6001, $mob2, 1 );
					self::assertSame( 2, $updated_mob->mobile_version );

					throw new RuntimeException( 'Simulated mid-transaction failure.' );
				}
			);
			self::fail( 'Expected RuntimeException from aborted transaction.' );
		} catch ( RuntimeException $e ) {
			self::assertSame( 'Simulated mid-transaction failure.', $e->getMessage() );
		}

		$after_rollback = $repo->get_by_user_id( 6001 );
		self::assertSame( 1, $after_rollback->mobile_version, 'Mobile version must roll back to 1.' );

		$decrypted = $repo->decrypt_identity_for_user( 6001 );
		self::assertNotNull( $decrypted->mobile );
		self::assertSame( $mob1, $decrypted->mobile->reveal(), 'Mobile ciphertext must roll back to original value.' );
	}

	/**
	 * Scenario 13 & Task 5 (D14 Identity Binding Safety):
	 * - Multiple UNBOUND profiles with the same national code do not block each other.
	 * - Once User A is BOUND, User B cannot bind the same national code (CODE_IDENTITY_CONFLICT, no user enumeration).
	 * - Bound user cannot overwrite their bound national code via update_identity_data.
	 * - Verification expiry (mark_expired_if_past) transitions identity_state to EXPIRED while keeping
	 *   binding_state = BOUND and bound_national_code_hmac reserved so User B STILL cannot claim it.
	 */
	public function test_d14_identity_binding_uniqueness_expiry_reservation_and_immutability(): void {
		$repo = $this->make_repository( array(), 1, '2026-11-14 12:00:00' );

		$shared_nc = self::make_synthetic_nc( '001234567' );
		$other_nc  = self::make_synthetic_nc( '009876543' );
		$mob_a     = '09' . implode( '', array( '12', '111', '2233' ) );
		$mob_b     = '09' . implode( '', array( '12', '444', '5566' ) );

		// Both User 7001 and User 7002 enter $shared_nc while UNBOUND -> both succeed (abandoned attempts never reserve).
		$prof_a = $repo->create_profile( 7001, $shared_nc, $mob_a, '1370/01/05' );
		$prof_b = $repo->create_profile( 7002, $shared_nc, $mob_b, '1370/01/05' );

		self::assertSame( ProfileRecord::BINDING_UNBOUND, $prof_a->binding_state );
		self::assertSame( ProfileRecord::BINDING_UNBOUND, $prof_b->binding_state );
		self::assertNull( $prof_a->bound_national_code_hmac );
		self::assertNull( $prof_b->bound_national_code_hmac );
		self::assertSame( $prof_a->national_code_hmac, $prof_b->national_code_hmac );

		// Both users verify their mobile numbers.
		$repo->record_mobile_verified( 7001, 1, '2026-11-14 12:01:00' );
		$repo->record_mobile_verified( 7002, 1, '2026-11-14 12:01:00' );

		// User 7001 completes authoritative binding with an expiry timestamp of 2026-12-01.
		$bound_a = $repo->bind_verified_identity( 7001, 1, 1, '2026-12-01 00:00:00' );
		self::assertTrue( $bound_a->is_bound() );
		self::assertSame( ProfileRecord::STATE_VERIFIED, $bound_a->identity_state );
		self::assertSame( $prof_a->national_code_hmac, $bound_a->bound_national_code_hmac );

		// User 7002 attempts to bind the same national code -> must fail closed with CODE_IDENTITY_CONFLICT
		// and must NOT leak User 7001's ID or details in the exception message.
		try {
			$repo->bind_verified_identity( 7002, 1, 1 );
			self::fail( 'Expected StorageException when second user attempts to bind an already bound national code.' );
		} catch ( StorageException $e ) {
			self::assertSame( StorageException::CODE_IDENTITY_CONFLICT, $e->get_safe_code() );
			self::assertStringNotContainsString( '7001', $e->getMessage() );
			self::assertStringNotContainsString( $shared_nc, $e->getMessage() );
		}

		// User 7001's verification expires after 2026-12-01.
		$expired_a = $repo->mark_expired_if_past( 7001, '2026-12-02 00:00:00' );
		self::assertSame( ProfileRecord::STATE_EXPIRED, $expired_a->identity_state );
		self::assertSame( ProfileRecord::BINDING_BOUND, $expired_a->binding_state, 'BOUND state must persist across verification expiry.' );
		self::assertSame( $bound_a->bound_national_code_hmac, $expired_a->bound_national_code_hmac );

		// Even while User 7001 is EXPIRED, User 7002 STILL cannot claim User 7001's bound national code!
		try {
			$repo->bind_verified_identity( 7002, 1, 1 );
			self::fail( 'Expired verification must never release bound_national_code_hmac to another user.' );
		} catch ( StorageException $e ) {
			self::assertSame( StorageException::CODE_IDENTITY_CONFLICT, $e->get_safe_code() );
		}

		// Bound User 7001 (even when EXPIRED) cannot self-edit their national code via update_identity_data.
		try {
			$repo->update_identity_data( 7001, $other_nc, '1375/01/01', 1 );
			self::fail( 'Expected StorageException when bound user attempts to modify identity attributes.' );
		} catch ( StorageException $e ) {
			self::assertSame( StorageException::CODE_BOUND_IDENTITY_IMMUTABLE, $e->get_safe_code() );
		}

		// However, bound User 7001 CAN refresh their own verification for the same bound national code.
		$refreshed_a = $repo->bind_verified_identity( 7001, 1, 1, '2027-12-01 00:00:00' );
		self::assertSame( ProfileRecord::STATE_VERIFIED, $refreshed_a->identity_state );
		self::assertSame( ProfileRecord::BINDING_BOUND, $refreshed_a->binding_state );
	}

	/**
	 * Task 4:
	 * - Key rotation compatibility and preservation of existing key IDs on partial updates.
	 */
	public function test_key_id_preservation_across_partial_updates_after_key_rotation(): void {
		// Step 1: Create profile under initial keys (k2025_01 / hmac_2025_01).
		$initial_repo = $this->make_repository(
			array(
				WordPressKeyProvider::CONST_ENC_KEY     => self::SYNTHETIC_ENC_KEY_1,
				WordPressKeyProvider::CONST_ENC_KEY_ID  => 'k2025_01',
				WordPressKeyProvider::CONST_HMAC_KEY    => self::SYNTHETIC_HMAC_KEY_1,
				WordPressKeyProvider::CONST_HMAC_KEY_ID => 'hmac_2025_01',
			)
		);

		$nc   = self::make_synthetic_nc( '001234567' );
		$mob1 = '09' . implode( '', array( '12', '111', '2233' ) );
		$mob2 = '09' . implode( '', array( '12', '444', '5566' ) );

		$created = $initial_repo->create_profile( 8001, $nc, $mob1, '1370/01/05' );
		self::assertSame( 'k2025_01', $created->enc_key_id );
		self::assertSame( 'hmac_2025_01', $created->hmac_key_id );

		// Step 2: Rotate active keys to k2026_02 / hmac_2026_02 while keeping k2025_01 / hmac_2025_01 in *_PREVIOUS.
		$rotated_repo = $this->make_repository(
			array(
				WordPressKeyProvider::CONST_ENC_KEY     => self::SYNTHETIC_ENC_KEY_2,
				WordPressKeyProvider::CONST_ENC_KEY_ID  => 'k2026_02',
				WordPressKeyProvider::CONST_ENC_KEYS_PREVIOUS => array( 'k2025_01' => self::SYNTHETIC_ENC_KEY_1 ),
				WordPressKeyProvider::CONST_HMAC_KEY    => self::SYNTHETIC_HMAC_KEY_2,
				WordPressKeyProvider::CONST_HMAC_KEY_ID => 'hmac_2026_02',
				WordPressKeyProvider::CONST_HMAC_KEYS_PREVIOUS => array( 'hmac_2025_01' => self::SYNTHETIC_HMAC_KEY_1 ),
			)
		);

		// Partial update: update mobile only under k2026_02 while national_code & birth_date remain encrypted under k2025_01.
		$updated = $rotated_repo->update_mobile( 8001, $mob2, 1 );

		// Row-level key IDs preserve 'k2025_01' / 'hmac_2025_01' because national_code & birth_date are still on the older key.
		self::assertSame( 'k2025_01', $updated->enc_key_id );
		self::assertSame( 'hmac_2025_01', $updated->hmac_key_id );

		// Both the newly encrypted mobile (k2026_02) and the existing national_code/birth_date (k2025_01) decrypt cleanly!
		$decrypted = $rotated_repo->decrypt_identity_for_user( 8001 );
		self::assertNotNull( $decrypted->national_code );
		self::assertNotNull( $decrypted->mobile );
		self::assertNotNull( $decrypted->birth_date );
		self::assertSame( $nc, $decrypted->national_code->reveal() );
		self::assertSame( $mob2, $decrypted->mobile->reveal() );
		self::assertSame( '1370/01/05', $decrypted->birth_date->reveal() );

		// Attempting to bind while national_code_hmac is still on pre-rotation key (hmac_2025_01) must fail closed.
		$rotated_repo->record_mobile_verified( 8001, 2, '2026-11-14 12:10:00' );
		try {
			$rotated_repo->bind_verified_identity( 8001, 1, 2 );
			self::fail( 'Expected StorageException when attempting to bind a profile with a stale hmac_key_id.' );
		} catch ( StorageException $e ) {
			self::assertSame( StorageException::CODE_UNAUTHORIZED_BINDING_TRANSITION, $e->get_safe_code() );
		}

		// Now update identity data under k2026_02 / hmac_2026_02 as well -> all columns on the row now use k2026_02 & hmac_2026_02!
		$fully_rotated = $rotated_repo->update_identity_data( 8001, $nc, '1370/01/05', 1 );
		self::assertSame( 'k2026_02', $fully_rotated->enc_key_id );
		self::assertSame( 'hmac_2026_02', $fully_rotated->hmac_key_id );
	}
}

<?php
/**
 * Unit tests for P01-C3 ProfileRecord, DecryptedIdentityData, and StorageException.
 *
 * All test vectors are constructed synthetically at runtime so no literal PII
 * or mobile strings appear in source files.
 *
 * @package WPIG\Tests\Unit
 */

declare(strict_types=1);

namespace WPIG\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPIG\Security\CryptoException;
use WPIG\Security\SensitiveValue;
use WPIG\Storage\DecryptedIdentityData;
use WPIG\Storage\ProfileRecord;
use WPIG\Storage\StorageException;

/**
 * Verifies DTO immutability, safe export formatting, debug/serialization redaction,
 * and StorageException safe error codes.
 */
final class ProfilePersistenceUnitTest extends TestCase {

	/**
	 * Build a synthetic ProfileRecord fixture.
	 *
	 * @param string      $binding_state  Binding state.
	 * @param string      $identity_state Identity freshness state.
	 * @param string|null $expires_at     Optional expiry timestamp.
	 */
	private static function make_record(
		string $binding_state = ProfileRecord::BINDING_BOUND,
		string $identity_state = ProfileRecord::STATE_VERIFIED,
		?string $expires_at = '2026-12-01 00:00:00'
	): ProfileRecord {
		$nc_hmac  = str_repeat( 'a', 64 );
		$mob_hmac = str_repeat( 'b', 64 );

		return new ProfileRecord(
			10,
			42,
			'IR',
			'natural',
			$binding_state,
			$identity_state,
			2,
			3,
			4,
			$mob_hmac,
			'0912***6789',
			'2026-11-10 10:00:00',
			$nc_hmac,
			ProfileRecord::BINDING_BOUND === $binding_state ? $nc_hmac : null,
			'******4567',
			true,
			true,
			true,
			'2026-11-10 10:05:00',
			'k2026_01',
			'hmac_2026_01',
			'2026-11-10 10:05:00',
			null,
			'2026-11-10 10:05:00',
			$expires_at,
			'2026-11-10 09:00:00',
			'2026-11-10 10:05:00'
		);
	}

	/**
	 * 1. ProfileRecord helper methods and safe export array never expose plaintext, ciphertexts, or HMACs.
	 */
	public function test_profile_record_helpers_and_safe_export_array(): void {
		$record = self::make_record();

		self::assertTrue( $record->is_bound() );
		self::assertTrue( $record->is_freshly_verified( '2026-11-15 00:00:00' ) );
		self::assertFalse( $record->is_freshly_verified( '2026-12-01 00:00:00' ) );

		$unbound = self::make_record( ProfileRecord::BINDING_UNBOUND, ProfileRecord::STATE_UNVERIFIED, null );
		self::assertFalse( $unbound->is_bound() );
		self::assertFalse( $unbound->is_freshly_verified( '2026-11-15 00:00:00' ) );

		$exported = $record->to_safe_export_array();
		self::assertSame( 10, $exported['id'] );
		self::assertSame( 42, $exported['wp_user_id'] );
		self::assertSame( '0912***6789', $exported['mobile_masked'] );
		self::assertSame( '******4567', $exported['national_code_masked'] );
		self::assertArrayNotHasKey( 'mobile_ciphertext', $exported );
		self::assertArrayNotHasKey( 'national_code_ciphertext', $exported );
		self::assertArrayNotHasKey( 'birth_date_ciphertext', $exported );
		self::assertArrayNotHasKey( 'mobile_hmac', $exported );
		self::assertArrayNotHasKey( 'national_code_hmac', $exported );
		self::assertArrayNotHasKey( 'bound_national_code_hmac', $exported );
	}

	/**
	 * 2. DecryptedIdentityData redaction, memory wiping, and serialization prevention.
	 */
	public function test_decrypted_identity_data_redaction_wiping_and_serialization_prevention(): void {
		$record    = self::make_record();
		$nc_plain  = 'SYNTHETIC_NC_VALUE';
		$mob_plain = 'SYNTHETIC_MOB_VALUE';
		$bd_plain  = '1370/01/05';

		$decrypted = new DecryptedIdentityData(
			$record,
			new SensitiveValue( $nc_plain ),
			new SensitiveValue( $mob_plain ),
			new SensitiveValue( $bd_plain )
		);

		self::assertSame( SensitiveValue::REDACTED, (string) $decrypted );

		$printed = print_r( $decrypted, true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_print_r -- Testing debug redaction.
		self::assertStringNotContainsString( $nc_plain, $printed );
		self::assertStringNotContainsString( $mob_plain, $printed );
		self::assertStringNotContainsString( $bd_plain, $printed );
		self::assertStringContainsString( SensitiveValue::REDACTED, $printed );

		// PHP serialize() and json_encode() must fail closed.
		try {
			serialize( $decrypted ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize -- Testing serialization prevention.
			self::fail( 'Expected CryptoException when serializing DecryptedIdentityData.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_SERIALIZATION_FORBIDDEN, $e->get_safe_code() );
		}

		try {
			json_encode( $decrypted, JSON_THROW_ON_ERROR ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Testing JsonSerializable prevention.
			self::fail( 'Expected CryptoException when JSON-encoding DecryptedIdentityData.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_SERIALIZATION_FORBIDDEN, $e->get_safe_code() );
		}

		// wipe() clears all three SensitiveValue buffers.
		$decrypted->wipe();
		self::assertNotNull( $decrypted->national_code );
		self::assertNotNull( $decrypted->mobile );
		self::assertNotNull( $decrypted->birth_date );
		self::assertTrue( $decrypted->national_code->is_wiped() );
		self::assertTrue( $decrypted->mobile->is_wiped() );
		self::assertTrue( $decrypted->birth_date->is_wiped() );
	}

	/**
	 * 3. StorageException carries machine-readable safe code.
	 */
	public function test_storage_exception_carries_safe_code(): void {
		try {
			StorageException::raise(
				StorageException::CODE_VERSION_CONFLICT,
				'Stale profile version detected.'
			);
		} catch ( StorageException $e ) {
			self::assertSame( StorageException::CODE_VERSION_CONFLICT, $e->get_safe_code() );
			self::assertSame( 'Stale profile version detected.', $e->getMessage() );
		}
	}
}

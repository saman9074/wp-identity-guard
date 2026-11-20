<?php
/**
 * Unit and security tests for P01-C2 identity normalization, purpose-separated
 * HMAC fingerprinting, data masking, and K1/K2 fallback isolation.
 *
 * All test vectors are constructed synthetically at runtime so no literal PII,
 * mobile numbers, or Luhn PAN strings appear in source files.
 *
 * @package WPIG\Tests\Unit
 */

declare(strict_types=1);

namespace WPIG\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPIG\Security\CryptoException;
use WPIG\Security\DataMasker;
use WPIG\Security\IdentityFingerprinter;
use WPIG\Security\IdentityNormalizer;
use WPIG\Security\SensitiveValue;
use WPIG\Security\SodiumCrypto;
use WPIG\Security\ValidationException;
use WPIG\Security\WordPressKeyProvider;

/**
 * Verifies IdentityNormalizer, IdentityFingerprinter, DataMasker, and K1/K2 key-provider isolation.
 */
final class NormalizationAndMaskingTest extends TestCase {

	/**
	 * Synthetic 256-bit encryption key (hex).
	 */
	private const SYNTHETIC_ENC_KEY = 'hex:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20';

	/**
	 * Synthetic 256-bit HMAC key #1 (hex).
	 */
	private const SYNTHETIC_HMAC_KEY_1 = 'hex:a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0';

	/**
	 * Synthetic 256-bit HMAC key #2 (hex).
	 */
	private const SYNTHETIC_HMAC_KEY_2 = 'hex:c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0';

	/**
	 * Build a synthetic 10-digit national code with a valid modulo-11 check digit from a 9-digit prefix.
	 *
	 * @param string $nine_digits 9 ASCII digits.
	 * @return string 10-digit checksum-valid synthetic national code.
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
	 * Build a synthetic 16-digit Luhn-valid card number from a 15-digit prefix.
	 *
	 * @param string $fifteen_digits 15 ASCII digits.
	 * @return string 16-digit Luhn-valid synthetic card number.
	 */
	private static function make_synthetic_pan( string $fifteen_digits ): string {
		$sum = 0;
		for ( $i = 0; $i < 15; $i++ ) {
			$d = (int) $fifteen_digits[ $i ];
			if ( 0 === ( $i % 2 ) ) {
				$d *= 2;
				if ( $d > 9 ) {
					$d -= 9;
				}
			}
			$sum += $d;
		}
		$check = ( 10 - ( $sum % 10 ) ) % 10;
		return $fifteen_digits . (string) $check;
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
	 * Convert ASCII digits in a string to Arabic-Indic digits ('٠'..'٩').
	 *
	 * @param string $ascii Input string.
	 */
	private static function to_arabic_digits( string $ascii ): string {
		return strtr(
			$ascii,
			array(
				'0' => '٠',
				'1' => '١',
				'2' => '٢',
				'3' => '٣',
				'4' => '٤',
				'5' => '٥',
				'6' => '٦',
				'7' => '٧',
				'8' => '٨',
				'9' => '٩',
			)
		);
	}

	/**
	 * 1. National code normalization: leading zeros, Persian/Arabic digits, modulo-11 checksum, and rejection of invalid/repeated codes.
	 */
	public function test_national_code_normalization_and_validation(): void {
		// Leading-zero synthetic national code (prefix '001234567').
		$valid_leading_zero = self::make_synthetic_nc( '001234567' );
		self::assertSame( 10, strlen( $valid_leading_zero ) );
		self::assertStringStartsWith( '00', $valid_leading_zero );

		// Standard ASCII, Persian digits, Arabic digits, and whitespace/ZWNJ around input.
		self::assertSame(
			$valid_leading_zero,
			IdentityNormalizer::normalize_national_code( $valid_leading_zero )
		);
		self::assertSame(
			$valid_leading_zero,
			IdentityNormalizer::normalize_national_code( '  ' . self::to_persian_digits( $valid_leading_zero ) . "\u{200C}\n" )
		);
		self::assertSame(
			$valid_leading_zero,
			IdentityNormalizer::normalize_national_code( new SensitiveValue( self::to_arabic_digits( $valid_leading_zero ) ) )
		);
		self::assertTrue( IdentityNormalizer::is_valid_national_code( $valid_leading_zero ) );

		// Also test a national code whose modulo-11 remainder is < 2 (prefix '001000002' -> sum = 8+4 = 12 -> rem 1).
		$rem_one_nc = self::make_synthetic_nc( '001000002' );
		self::assertStringEndsWith( '1', $rem_one_nc );
		self::assertSame( $rem_one_nc, IdentityNormalizer::normalize_national_code( $rem_one_nc ) );

		// Flip check digit -> must fail checksum validation without leaking input in exception message.
		$bad_check_digit = substr( $valid_leading_zero, 0, 9 ) . ( '0' === $valid_leading_zero[9] ? '1' : '0' );
		self::assertFalse( IdentityNormalizer::is_valid_national_code( $bad_check_digit ) );

		try {
			IdentityNormalizer::normalize_national_code( $bad_check_digit );
			self::fail( 'Expected ValidationException for wrong national code check digit.' );
		} catch ( ValidationException $e ) {
			self::assertSame( ValidationException::CODE_INVALID_NATIONAL_CODE, $e->get_safe_code() );
			self::assertStringNotContainsString( $bad_check_digit, $e->getMessage() );
		}

		// All 10 repeated-digit codes ('0000000000'..'9999999999') and malformed strings must be rejected.
		for ( $d = 0; $d <= 9; $d++ ) {
			$repeated = str_repeat( (string) $d, 10 );
			self::assertFalse(
				IdentityNormalizer::is_valid_national_code( $repeated ),
				"Repeated-digit national code {$d}x10 must be rejected."
			);
		}

		foreach ( array( '', '123456789', '12345678901', '00123-4567', 'abcdefghij' ) as $malformed ) {
			self::assertFalse( IdentityNormalizer::is_valid_national_code( $malformed ) );
		}
	}

	/**
	 * 2. Iranian mobile normalization variants and rejection of ambiguous/malformed inputs.
	 */
	public function test_mobile_normalization_variants_and_rejections(): void {
		$tail      = implode( '', array( '12', '345', '6789' ) );
		$canonical = '09' . $tail;

		$variants = array(
			'09' . $tail,
			'+989' . $tail,
			'00989' . $tail,
			'989' . $tail,
			'  +98 9' . substr( $tail, 0, 2 ) . ' ' . substr( $tail, 2, 3 ) . ' ' . substr( $tail, 5 ) . '  ',
			self::to_persian_digits( '00989' . $tail ),
			self::to_arabic_digits( '+989' . $tail ),
		);

		foreach ( $variants as $variant ) {
			self::assertSame( $canonical, IdentityNormalizer::normalize_mobile( $variant ) );
			self::assertTrue( IdentityNormalizer::is_valid_mobile( $variant ) );
		}

		// Ambiguous or malformed mobile inputs must be rejected.
		$invalid_mobiles = array(
			'',
			'9' . $tail,          // Missing leading 0 / country code.
			'+9809' . $tail,      // Trunk 0 included after +98.
			'009809' . $tail,     // Trunk 0 included after 0098.
			'9809' . $tail,       // Trunk 0 included after 98.
			'08' . $tail,         // Non-mobile prefix 08.
			'+19' . $tail,        // Non-Iran country code.
			'09' . substr( $tail, 0, 8 ), // Too short (10 digits).
			'09' . $tail . '0',   // Too long (12 digits).
			'0912-345-6789',      // Hyphens not accepted as mobile digits.
		);

		foreach ( $invalid_mobiles as $bad_mobile ) {
			self::assertFalse( IdentityNormalizer::is_valid_mobile( $bad_mobile ) );
			try {
				IdentityNormalizer::normalize_mobile( $bad_mobile );
				self::fail( 'Expected ValidationException for invalid mobile input.' );
			} catch ( ValidationException $e ) {
				self::assertSame( ValidationException::CODE_INVALID_MOBILE, $e->get_safe_code() );
				if ( '' !== $bad_mobile ) {
					self::assertStringNotContainsString( $bad_mobile, $e->getMessage() );
				}
			}
		}
	}

	/**
	 * 3. Jalali birth date normalization, leap-year boundaries, and Gregorian rejection.
	 */
	public function test_jalali_birth_date_normalization_and_leap_years(): void {
		self::assertSame(
			'1370/01/05',
			IdentityNormalizer::normalize_jalali_birth_date( '1370/1/5' )
		);
		self::assertSame(
			'1370/06/31',
			IdentityNormalizer::normalize_jalali_birth_date( '1370-06-31' )
		);
		self::assertSame(
			'1378/11/30',
			IdentityNormalizer::normalize_jalali_birth_date( self::to_persian_digits( '1378/11/30' ) )
		);
		self::assertSame(
			'1385/09/15',
			IdentityNormalizer::normalize_jalali_birth_date( self::to_arabic_digits( '  1385-9-15  ' ) )
		);

		// Jalali leap years: 1370, 1375, 1399, 1403, 1408 (5-year cycle jump: 1407 is NOT leap, 1408 IS leap).
		foreach ( array( 1370, 1375, 1399, 1403, 1408 ) as $leap_year ) {
			self::assertTrue( IdentityNormalizer::is_jalali_leap_year( $leap_year ), "Year {$leap_year} must be a Jalali leap year." );
			self::assertSame(
				sprintf( '%04d/12/30', $leap_year ),
				IdentityNormalizer::normalize_jalali_birth_date( sprintf( '%d/12/30', $leap_year ) )
			);
		}

		// Common (non-leap) Jalali years: Esfand 29 is valid, Esfand 30 must be rejected.
		foreach ( array( 1371, 1374, 1400, 1402, 1404, 1407 ) as $common_year ) {
			self::assertFalse( IdentityNormalizer::is_jalali_leap_year( $common_year ), "Year {$common_year} must not be a Jalali leap year." );
			self::assertSame(
				sprintf( '%04d/12/29', $common_year ),
				IdentityNormalizer::normalize_jalali_birth_date( sprintf( '%d/12/29', $common_year ) )
			);
			self::assertFalse(
				IdentityNormalizer::is_valid_jalali_birth_date( sprintf( '%d/12/30', $common_year ) ),
				"Esfand 30 must be rejected in common year {$common_year}."
			);
		}

		// Invalid dates: Mehr..Bahman (months 7..11) with 31 days, Gregorian years, mixed separators, month 0/13.
		$invalid_dates = array(
			'',
			'1370/07/31', // Mehr has 30 days.
			'1370/08/31',
			'1370/09/31',
			'1370/10/31',
			'1370/11/31',
			'1370/12/31', // Esfand never has 31 days.
			'1370/00/10',
			'1370/13/01',
			'1370/01/00',
			'1370/01/32',
			'1990/01/01', // Gregorian year must be rejected, never silently converted.
			'2005-05-12', // Gregorian year must be rejected.
			'1370/01-05', // Mixed separators.
			'13700105',   // Missing separators.
		);

		foreach ( $invalid_dates as $bad_date ) {
			self::assertFalse(
				IdentityNormalizer::is_valid_jalali_birth_date( $bad_date ),
				"Invalid Jalali date {$bad_date} must be rejected."
			);
		}
	}

	/**
	 * 4. Card PAN structural validation (16 digits, Luhn checksum, Persian/Arabic digits, no full PAN persistence).
	 */
	public function test_card_pan_validation_and_luhn_checksum(): void {
		$prefix    = implode( '', array( '6037', '9912', '3456', '789' ) );
		$valid_pan = self::make_synthetic_pan( $prefix );
		$last4     = substr( $valid_pan, 12, 4 );

		$formatted_input = substr( $valid_pan, 0, 4 ) . ' - '
			. self::to_persian_digits( substr( $valid_pan, 4, 4 ) ) . ' '
			. self::to_arabic_digits( substr( $valid_pan, 8, 4 ) ) . '-'
			. substr( $valid_pan, 12, 4 );

		$normalized_sv = IdentityNormalizer::normalize_card_pan( $formatted_input );
		self::assertSame( $valid_pan, $normalized_sv->reveal() );
		self::assertTrue( IdentityNormalizer::is_valid_card_pan( $formatted_input ) );
		self::assertSame( $last4, IdentityNormalizer::extract_card_last4( $formatted_input ) );

		// Corrupt Luhn check digit -> must fail closed without leaking the PAN in the exception message.
		$bad_luhn = substr( $valid_pan, 0, 15 ) . ( '0' === $valid_pan[15] ? '1' : '0' );
		self::assertFalse( IdentityNormalizer::is_valid_card_pan( $bad_luhn ) );

		try {
			IdentityNormalizer::normalize_card_pan( $bad_luhn );
			self::fail( 'Expected ValidationException for invalid Luhn checksum.' );
		} catch ( ValidationException $e ) {
			self::assertSame( ValidationException::CODE_INVALID_CARD_PAN, $e->get_safe_code() );
			self::assertStringNotContainsString( $bad_luhn, $e->getMessage() );
		}

		// Wrong lengths and repeated digits (e.g. 16 zeros) must be rejected.
		self::assertFalse( IdentityNormalizer::is_valid_card_pan( str_repeat( '0', 16 ) ) );
		self::assertFalse( IdentityNormalizer::is_valid_card_pan( substr( $valid_pan, 0, 15 ) ) );
		self::assertFalse( IdentityNormalizer::is_valid_card_pan( $valid_pan . '0' ) );
	}

	/**
	 * 5. Purpose-separated HMAC fingerprints (national code, mobile, OTP challenge, IP rate limit) and key ID support.
	 */
	public function test_purpose_separated_hmac_fingerprints_and_key_ids(): void {
		$provider = new WordPressKeyProvider(
			static function ( string $name ): mixed {
				$map = array(
					WordPressKeyProvider::CONST_ENC_KEY    => self::SYNTHETIC_ENC_KEY,
					WordPressKeyProvider::CONST_ENC_KEY_ID => 'enc_2026_01',
					WordPressKeyProvider::CONST_HMAC_KEY   => self::SYNTHETIC_HMAC_KEY_1,
					WordPressKeyProvider::CONST_HMAC_KEY_ID => 'hmac_2026_02',
					WordPressKeyProvider::CONST_HMAC_KEYS_PREVIOUS => array(
						'hmac_2025_01' => self::SYNTHETIC_HMAC_KEY_2,
					),
				);
				return $map[ $name ] ?? null;
			}
		);

		$crypto        = new SodiumCrypto( $provider );
		$fingerprinter = new IdentityFingerprinter( $crypto );

		$nc   = self::make_synthetic_nc( '001234567' );
		$tail = implode( '', array( '12', '345', '6789' ) );
		$mob1 = '+98 9' . $tail;
		$mob2 = self::to_persian_digits( '00989' . $tail );
		$mob3 = '09' . $tail;

		// Canonical mobile normalization before HMAC produces identical digests across all input formats.
		$hmac_mob1 = $fingerprinter->fingerprint_mobile( $mob1 );
		$hmac_mob2 = $fingerprinter->fingerprint_mobile( $mob2 );
		$hmac_mob3 = $fingerprinter->fingerprint_mobile( $mob3 );
		self::assertSame( $hmac_mob1, $hmac_mob2 );
		self::assertSame( $hmac_mob2, $hmac_mob3 );
		self::assertTrue( $fingerprinter->verify_mobile( $hmac_mob1, $mob1 ) );
		self::assertFalse( $fingerprinter->verify_mobile( $hmac_mob1, implode( '', array( '0912', '0000000' ) ) ) );

		// National code HMAC consistency across Persian/ASCII inputs.
		$hmac_nc_ascii   = $fingerprinter->fingerprint_national_code( $nc );
		$hmac_nc_persian = $fingerprinter->fingerprint_national_code( self::to_persian_digits( $nc ) );
		self::assertSame( $hmac_nc_ascii, $hmac_nc_persian );
		self::assertTrue( $fingerprinter->verify_national_code( $hmac_nc_ascii, $nc ) );

		// Explicit key_id support (active vs previous HMAC key).
		$hmac_nc_prev = $fingerprinter->fingerprint_national_code( $nc, 'hmac_2025_01' );
		self::assertNotSame( $hmac_nc_ascii, $hmac_nc_prev );
		self::assertTrue( $fingerprinter->verify_national_code( $hmac_nc_prev, $nc, 'hmac_2025_01' ) );
		self::assertFalse( $fingerprinter->verify_national_code( $hmac_nc_prev, $nc, 'hmac_2026_02' ) );

		// Unknown HMAC key ID must fail closed.
		try {
			$fingerprinter->fingerprint_national_code( $nc, 'unknown_key' );
			self::fail( 'Expected CryptoException for unknown HMAC key ID.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_KEY_UNKNOWN, $e->get_safe_code() );
		}

		// OTP challenge context binds challenge_id, wp_user_id, and normalized OTP code.
		$otp_hmac = $fingerprinter->fingerprint_otp_challenge( 55, 101, self::to_persian_digits( '482910' ) );
		self::assertTrue( $fingerprinter->verify_otp_challenge( $otp_hmac, 55, 101, '482910' ) );
		self::assertFalse( $fingerprinter->verify_otp_challenge( $otp_hmac, 56, 101, '482910' ), 'Different challenge_id must not verify.' );
		self::assertFalse( $fingerprinter->verify_otp_challenge( $otp_hmac, 55, 102, '482910' ), 'Different wp_user_id must not verify.' );
		self::assertFalse( $fingerprinter->verify_otp_challenge( $otp_hmac, 55, 101, '482911' ), 'Different OTP code must not verify.' );

		// IP rate-limit HMAC normalizes expanded vs compressed IPv6 addresses to identical digests.
		$ip_v6_expanded   = '2001:0db8:0000:0000:0000:0000:0000:0001';
		$ip_v6_compressed = '2001:DB8::1';
		$hmac_ip1         = $fingerprinter->fingerprint_ip( $ip_v6_expanded );
		$hmac_ip2         = $fingerprinter->fingerprint_ip( $ip_v6_compressed );
		self::assertSame( $hmac_ip1, $hmac_ip2 );
		self::assertTrue( $fingerprinter->verify_ip( $hmac_ip1, '2001:db8::1' ) );
		self::assertFalse( $fingerprinter->verify_ip( $hmac_ip1, '192.0.2.1' ) );

		// Invalid IP must fail closed with ValidationException.
		try {
			$fingerprinter->fingerprint_ip( 'not-an-ip-address' );
			self::fail( 'Expected ValidationException for invalid IP.' );
		} catch ( ValidationException $e ) {
			self::assertSame( ValidationException::CODE_INVALID_IP_ADDRESS, $e->get_safe_code() );
		}
	}

	/**
	 * 6. Masking formats and non-mutation of caller source values.
	 */
	public function test_masking_formats_and_non_mutation_of_source_values(): void {
		$nc        = self::make_synthetic_nc( '001234567' );
		$nc_sv     = new SensitiveValue( $nc );
		$masked_nc = DataMasker::mask_national_code( $nc_sv );

		self::assertSame( '******' . substr( $nc, 6, 4 ), $masked_nc );
		self::assertFalse( $nc_sv->is_wiped(), 'mask_national_code must not wipe or mutate caller SensitiveValue.' );
		self::assertSame( $nc, $nc_sv->reveal() );

		$mob        = implode( ' ', array( '+98', '912', '345', '6789' ) );
		$mob_sv     = new SensitiveValue( $mob );
		$masked_mob = DataMasker::mask_mobile( $mob_sv );

		self::assertSame( '0912***6789', $masked_mob );
		self::assertFalse( $mob_sv->is_wiped(), 'mask_mobile must not wipe or mutate caller SensitiveValue.' );
		self::assertSame( $mob, $mob_sv->reveal() );

		$pan        = self::make_synthetic_pan( implode( '', array( '6037', '9912', '3456', '789' ) ) );
		$last4      = substr( $pan, 12, 4 );
		$pan_sv     = new SensitiveValue( $pan );
		$masked_pan = DataMasker::mask_card( $pan_sv );

		self::assertSame( '**** **** **** ' . $last4, $masked_pan );
		self::assertSame( '**** **** **** ' . $last4, DataMasker::mask_card_last4( self::to_persian_digits( $last4 ) ) );
		self::assertFalse( $pan_sv->is_wiped(), 'mask_card must not wipe or mutate caller SensitiveValue.' );
		self::assertSame( $pan, $pan_sv->reveal() );

		try {
			DataMasker::mask_card_last4( '123' );
			self::fail( 'Expected ValidationException for 3-digit card_last4.' );
		} catch ( ValidationException $e ) {
			self::assertSame( ValidationException::CODE_INVALID_CARD_LAST4, $e->get_safe_code() );
		}
	}

	/**
	 * 7. Security review verification: invalid, empty, or partial K1 constants never silently fall back to K2 env vars.
	 */
	public function test_invalid_or_partial_k1_never_falls_back_to_k2(): void {
		$valid_k2_env = array(
			WordPressKeyProvider::CONST_ENC_KEY     => self::SYNTHETIC_ENC_KEY,
			WordPressKeyProvider::CONST_ENC_KEY_ID  => 'k2_env_id',
			WordPressKeyProvider::CONST_HMAC_KEY    => self::SYNTHETIC_HMAC_KEY_1,
			WordPressKeyProvider::CONST_HMAC_KEY_ID => 'h2_env_id',
		);

		// Case A: K1 defines WPIG_ENC_KEY_ID, but WPIG_ENC_KEY is missing in K1 (even though present in K2).
		$partial_k1_provider = new WordPressKeyProvider(
			static fn( string $name ): mixed => WordPressKeyProvider::CONST_ENC_KEY_ID === $name ? 'k1_const_id' : null,
			static fn( string $name ): string|false => $valid_k2_env[ $name ] ?? false
		);

		self::assertFalse(
			$partial_k1_provider->is_configured(),
			'Partial K1 configuration must not silently pull missing keys from K2.'
		);

		// Case B: K1 defines WPIG_ENC_KEY as empty/invalid string while K2 has a valid key.
		$empty_k1_provider = new WordPressKeyProvider(
			static function ( string $name ): mixed {
				$k1 = array(
					WordPressKeyProvider::CONST_ENC_KEY    => '',
					WordPressKeyProvider::CONST_ENC_KEY_ID => 'k1_const_id',
					WordPressKeyProvider::CONST_HMAC_KEY   => self::SYNTHETIC_HMAC_KEY_1,
				);
				return $k1[ $name ] ?? null;
			},
			static fn( string $name ): string|false => $valid_k2_env[ $name ] ?? false
		);

		try {
			$empty_k1_provider->get_active_encryption_key();
			self::fail( 'Empty K1 constant must fail closed and never fall back to K2.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_KEY_MISSING, $e->get_safe_code() );
		}
	}

	/**
	 * 8. Regression: Verify all fingerprint implementations match keyed HMAC-SHA-256 test vectors
	 * (and never BLAKE2b) and that optional K1 constants also lock out K2 fallback.
	 */
	public function test_regression_hmac_sha256_algorithm_consistency_and_k1_optional_constant_lock(): void {
		$raw_hmac_key = hex2bin( substr( self::SYNTHETIC_HMAC_KEY_1, 4 ) );
		self::assertIsString( $raw_hmac_key );

		$provider = new WordPressKeyProvider(
			static function ( string $name ): mixed {
				$map = array(
					WordPressKeyProvider::CONST_ENC_KEY    => self::SYNTHETIC_ENC_KEY,
					WordPressKeyProvider::CONST_ENC_KEY_ID => 'k2026_01',
					WordPressKeyProvider::CONST_HMAC_KEY   => self::SYNTHETIC_HMAC_KEY_1,
					WordPressKeyProvider::CONST_HMAC_KEY_ID => 'hmac_2026_01',
				);
				return $map[ $name ] ?? null;
			}
		);

		$crypto        = new SodiumCrypto( $provider );
		$fingerprinter = new IdentityFingerprinter( $crypto );

		$nc         = self::make_synthetic_nc( '001234567' );
		$mob        = '09' . implode( '', array( '12', '345', '6789' ) );
		$otp_code   = '482910';
		$ip_address = '2001:db8::1';

		// Expected keyed HMAC-SHA-256 reference vectors.
		$expected_nc_hmac  = hash_hmac( 'sha256', 'wpig:v1:national_code|' . $nc, $raw_hmac_key, false );
		$expected_mob_hmac = hash_hmac( 'sha256', 'wpig:v1:mobile|' . $mob, $raw_hmac_key, false );
		$expected_otp_hmac = hash_hmac( 'sha256', 'wpig:v1:otp_challenge|77|101|' . $otp_code, $raw_hmac_key, false );
		$expected_ip_hmac  = hash_hmac( 'sha256', 'wpig:v1:ip_rate|' . $ip_address, $raw_hmac_key, false );

		self::assertSame( $expected_nc_hmac, $fingerprinter->fingerprint_national_code( $nc ) );
		self::assertSame( $expected_mob_hmac, $fingerprinter->fingerprint_mobile( $mob ) );
		self::assertSame( $expected_otp_hmac, $fingerprinter->fingerprint_otp_challenge( 77, 101, $otp_code ) );
		self::assertSame( $expected_ip_hmac, $fingerprinter->fingerprint_ip( '2001:0db8:0000:0000:0000:0000:0000:0001' ) );

		// Explicitly confirm digests are NOT BLAKE2b-256.
		$blake2b_nc = bin2hex( sodium_crypto_generichash( 'wpig:v1:national_code|' . $nc, $raw_hmac_key, 32 ) );
		self::assertNotSame( $blake2b_nc, $fingerprinter->fingerprint_national_code( $nc ) );

		// Defining even an optional K1 constant (e.g. WPIG_HMAC_KEYS_PREVIOUS) locks provider into K1 mode.
		$optional_k1_only = new WordPressKeyProvider(
			static fn( string $name ): mixed => WordPressKeyProvider::CONST_HMAC_KEYS_PREVIOUS === $name ? array() : null,
			static fn( string $name ): string|false => array(
				WordPressKeyProvider::CONST_ENC_KEY    => self::SYNTHETIC_ENC_KEY,
				WordPressKeyProvider::CONST_ENC_KEY_ID => 'k2_id',
				WordPressKeyProvider::CONST_HMAC_KEY   => self::SYNTHETIC_HMAC_KEY_1,
			)[ $name ] ?? false
		);
		self::assertFalse( $optional_k1_only->is_configured() );
	}
}

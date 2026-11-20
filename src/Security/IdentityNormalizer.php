<?php
/**
 * Deterministic normalization and structural validation for Iranian identity attributes.
 *
 * @package WPIG\Security
 */

declare(strict_types=1);

namespace WPIG\Security;

use SensitiveParameter;

/**
 * Normalizes and validates Iranian national codes, mobile numbers, Jalali birth
 * dates, and 16-digit bank card numbers without mutating caller inputs.
 *
 * Note on Card Validation:
 * Structural 16-digit and Luhn checksum validation checks formatting only; it
 * never proves bank card authenticity, ownership, or active status. Full PAN
 * must never be persisted (DS-2 / C1).
 */
final class IdentityNormalizer {

	/**
	 * Minimum supported Jalali birth year (avoids silent Gregorian acceptance).
	 */
	public const MIN_JALALI_YEAR = 1250;

	/**
	 * Maximum supported Jalali birth year.
	 */
	public const MAX_JALALI_YEAR = 1499;

	/**
	 * Persian digits (U+06F0..U+06F9).
	 *
	 * @var string[]
	 */
	private const PERSIAN_DIGITS = array( '۰', '۱', '۲', '۳', '۴', '۵', '۶', '۷', '۸', '۹' );

	/**
	 * Arabic-Indic digits (U+0660..U+0669).
	 *
	 * @var string[]
	 */
	private const ARABIC_DIGITS = array( '٠', '١', '٢', '٣', '٤', '٥', '٦', '٧', '٨', '٩' );

	/**
	 * Canonical ASCII digits ('0'..'9').
	 *
	 * @var string[]
	 */
	private const ASCII_DIGITS = array( '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' );

	/**
	 * Convert Persian and Arabic-Indic digits to ASCII digits ('0'..'9').
	 *
	 * @param string $input Input string.
	 * @return string String with localized digits replaced by ASCII digits.
	 */
	public static function digits_to_ascii( #[SensitiveParameter] string $input ): string {
		$converted = str_replace( self::PERSIAN_DIGITS, self::ASCII_DIGITS, $input );
		return str_replace( self::ARABIC_DIGITS, self::ASCII_DIGITS, $converted );
	}

	/**
	 * Normalize and validate an Iranian 10-digit national code (Kode Melli).
	 *
	 * - Converts Persian/Arabic digits to ASCII.
	 * - Strips whitespace and invisible directional/zero-width characters.
	 * - Preserves leading zeros as a 10-character ASCII string.
	 * - Rejects repeated-digit sequences (0000000000..9999999999).
	 * - Validates the official Iranian modulo-11 check digit.
	 *
	 * @param SensitiveValue|string $input Raw national code input.
	 * @return string Canonical 10-digit ASCII national code.
	 * @throws ValidationException If the national code is malformed or fails checksum validation.
	 */
	public static function normalize_national_code(
		#[SensitiveParameter] SensitiveValue|string $input
	): string {
		$raw        = $input instanceof SensitiveValue ? $input->reveal() : $input;
		$ascii      = self::digits_to_ascii( $raw );
		$normalized = preg_replace( '/[\s\x{200B}\x{200C}\x{200D}\x{200E}\x{200F}\x{FEFF}]+/u', '', $ascii );

		if ( ! is_string( $normalized ) || 1 !== preg_match( '/^\d{10}$/', $normalized ) ) {
			ValidationException::raise(
				ValidationException::CODE_INVALID_NATIONAL_CODE,
				'National code must consist of exactly 10 digits.'
			);
		}

		// Reject all 10-identical-digit codes (0000000000 through 9999999999).
		if ( 1 === preg_match( '/^(\d)\1{9}$/', $normalized ) ) {
			ValidationException::raise(
				ValidationException::CODE_INVALID_NATIONAL_CODE,
				'National code with 10 identical digits is invalid.'
			);
		}

		$sum = 0;
		for ( $i = 0; $i < 9; $i++ ) {
			$sum += ( (int) $normalized[ $i ] ) * ( 10 - $i );
		}

		$remainder   = $sum % 11;
		$check_digit = (int) $normalized[9];
		$expected    = $remainder < 2 ? $remainder : ( 11 - $remainder );

		if ( $check_digit !== $expected ) {
			ValidationException::raise(
				ValidationException::CODE_INVALID_NATIONAL_CODE,
				'National code failed modulo-11 checksum validation.'
			);
		}

		return $normalized;
	}

	/**
	 * Return true if the input is a valid Iranian 10-digit national code.
	 *
	 * @param SensitiveValue|string $input Raw national code input.
	 */
	public static function is_valid_national_code(
		#[SensitiveParameter] SensitiveValue|string $input
	): bool {
		try {
			self::normalize_national_code( $input );
			return true;
		} catch ( ValidationException ) {
			return false;
		}
	}

	/**
	 * Normalize and validate an Iranian mobile number into canonical `09xxxxxxxxx` format.
	 *
	 * Supported input variants:
	 * - `09xxxxxxxxx`
	 * - `+989xxxxxxxxx`
	 * - `00989xxxxxxxxx`
	 * - `989xxxxxxxxx`
	 *
	 * @param SensitiveValue|string $input Raw mobile number input.
	 * @return string Canonical 11-digit ASCII mobile number (`09xxxxxxxxx`).
	 * @throws ValidationException If the mobile number is ambiguous or malformed.
	 */
	public static function normalize_mobile(
		#[SensitiveParameter] SensitiveValue|string $input
	): string {
		$raw        = $input instanceof SensitiveValue ? $input->reveal() : $input;
		$ascii      = self::digits_to_ascii( $raw );
		$normalized = preg_replace( '/[\s\x{200B}\x{200C}\x{200D}\x{200E}\x{200F}\x{FEFF}]+/u', '', $ascii );

		if ( ! is_string( $normalized ) || '' === $normalized ) {
			ValidationException::raise(
				ValidationException::CODE_INVALID_MOBILE,
				'Mobile number must not be empty.'
			);
		}

		if ( 1 === preg_match( '/^09(\d{9})$/', $normalized, $matches ) ) {
			return '09' . $matches[1];
		}

		if ( 1 === preg_match( '/^(?:\+989|00989|989)(\d{9})$/', $normalized, $matches ) ) {
			return '09' . $matches[1];
		}

		ValidationException::raise(
			ValidationException::CODE_INVALID_MOBILE,
			'Mobile number must match a supported Iranian mobile format (09xxxxxxxxx, +989xxxxxxxxx, 00989xxxxxxxxx, or 989xxxxxxxxx).'
		);
	}

	/**
	 * Return true if the input is a valid Iranian mobile number.
	 *
	 * @param SensitiveValue|string $input Raw mobile number input.
	 */
	public static function is_valid_mobile(
		#[SensitiveParameter] SensitiveValue|string $input
	): bool {
		try {
			self::normalize_mobile( $input );
			return true;
		} catch ( ValidationException ) {
			return false;
		}
	}

	/**
	 * Normalize and validate a Jalali (Solar Hijri) birth date into `YYYY/MM/DD`.
	 *
	 * - Converts Persian/Arabic digits to ASCII.
	 * - Accepts `/` or `-` separators with 1-or-2-digit month and day.
	 * - Rejects Gregorian years (enforces 1250 <= year <= 1499; never converts calendars).
	 * - Enforces month lengths (1..6 => 31 days, 7..11 => 30 days, 12 => 30 days in leap years, 29 in common years).
	 *
	 * @param SensitiveValue|string $input Raw Jalali birth date string.
	 * @return string Canonical 10-character ASCII Jalali date (`YYYY/MM/DD`).
	 * @throws ValidationException If the date is malformed, out of range, or calendar-invalid.
	 */
	public static function normalize_jalali_birth_date(
		#[SensitiveParameter] SensitiveValue|string $input
	): string {
		$raw     = $input instanceof SensitiveValue ? $input->reveal() : $input;
		$ascii   = self::digits_to_ascii( $raw );
		$trimmed = preg_replace( '/^[\s\x{200B}-\x{200F}\x{FEFF}]+|[\s\x{200B}-\x{200F}\x{FEFF}]+$/u', '', $ascii );

		if (
			! is_string( $trimmed )
			|| 1 !== preg_match( '/^(\d{4})([\/\-])(\d{1,2})\2(\d{1,2})$/', $trimmed, $matches )
		) {
			ValidationException::raise(
				ValidationException::CODE_INVALID_BIRTH_DATE,
				'Jalali birth date must match YYYY/MM/DD or YYYY-MM-DD.'
			);
		}

		$year  = (int) $matches[1];
		$month = (int) $matches[3];
		$day   = (int) $matches[4];

		if ( $year < self::MIN_JALALI_YEAR || $year > self::MAX_JALALI_YEAR ) {
			ValidationException::raise(
				ValidationException::CODE_INVALID_BIRTH_DATE,
				'Jalali birth year is outside the supported Solar Hijri range (1250..1499).'
			);
		}

		if ( $month < 1 || $month > 12 || $day < 1 ) {
			ValidationException::raise(
				ValidationException::CODE_INVALID_BIRTH_DATE,
				'Jalali birth month or day is out of range.'
			);
		}

		if ( $month <= 6 ) {
			$max_day = 31;
		} elseif ( $month <= 11 ) {
			$max_day = 30;
		} else {
			$max_day = self::is_jalali_leap_year( $year ) ? 30 : 29;
		}

		if ( $day > $max_day ) {
			ValidationException::raise(
				ValidationException::CODE_INVALID_BIRTH_DATE,
				'Jalali birth day exceeds the maximum days in the specified month/year.'
			);
		}

		return sprintf( '%04d/%02d/%02d', $year, $month, $day );
	}

	/**
	 * Determine whether a Jalali (Solar Hijri) year is a leap year using the
	 * standard 33-year astronomical break table (Borkowski / Jalaali algorithm).
	 *
	 * @param int $jalali_year 4-digit Jalali year.
	 * @return bool True if Esfand (month 12) has 30 days; false if 29 days.
	 */
	public static function is_jalali_leap_year( int $jalali_year ): bool {
		$breaks = array(
			-61,
			9,
			38,
			199,
			426,
			686,
			756,
			818,
			1111,
			1181,
			1210,
			1635,
			2060,
			2097,
			2192,
			2262,
			2324,
			2394,
			2456,
			3178,
		);

		$count = count( $breaks );
		$jp    = $breaks[0];
		$jump  = 0;

		for ( $i = 1; $i < $count; $i++ ) {
			$jm   = $breaks[ $i ];
			$jump = $jm - $jp;
			if ( $jalali_year < $jm ) {
				break;
			}
			$jp = $jm;
		}

		$n = $jalali_year - $jp;
		if ( ( $jump - $n ) < 6 ) {
			$n = $n - $jump + ( intdiv( $jump + 4, 33 ) * 33 );
		}

		$leap = ( ( ( $n + 1 ) % 33 ) - 1 ) % 4;
		if ( -1 === $leap ) {
			$leap = 4;
		}

		return 0 === $leap;
	}

	/**
	 * Return true if the input is a valid Jalali birth date.
	 *
	 * @param SensitiveValue|string $input Raw Jalali birth date string.
	 */
	public static function is_valid_jalali_birth_date(
		#[SensitiveParameter] SensitiveValue|string $input
	): bool {
		try {
			self::normalize_jalali_birth_date( $input );
			return true;
		} catch ( ValidationException ) {
			return false;
		}
	}

	/**
	 * Normalize and structurally validate a 16-digit bank card number (PAN).
	 *
	 * - Converts Persian/Arabic digits to ASCII.
	 * - Strips spaces and hyphens.
	 * - Enforces 16 ASCII digits, non-repeated digits, and Luhn modulo-10 checksum.
	 * - Returns the canonical 16-digit string wrapped in SensitiveValue and zeroes
	 *   temporary intermediate buffers.
	 *
	 * Note: Structural validation never claims bank ownership or card authenticity,
	 * and full PAN must never be persisted (DS-2 / C1).
	 *
	 * @param SensitiveValue|string $input Raw card number input.
	 * @return SensitiveValue Canonical 16-digit ASCII card number wrapped in SensitiveValue.
	 * @throws ValidationException If the card number is malformed or fails Luhn validation.
	 */
	public static function normalize_card_pan(
		#[SensitiveParameter] SensitiveValue|string $input
	): SensitiveValue {
		$raw        = $input instanceof SensitiveValue ? str_repeat( $input->reveal(), 1 ) : str_repeat( $input, 1 );
		$ascii      = self::digits_to_ascii( $raw );
		$normalized = preg_replace( '/[\s\-\x{200B}-\x{200F}\x{FEFF}]+/u', '', $ascii );

		if ( function_exists( 'sodium_memzero' ) ) {
			sodium_memzero( $raw );
			sodium_memzero( $ascii );
		}

		try {
			if ( ! is_string( $normalized ) || 1 !== preg_match( '/^\d{16}$/', $normalized ) ) {
				ValidationException::raise(
					ValidationException::CODE_INVALID_CARD_PAN,
					'Card number must consist of exactly 16 digits.'
				);
			}

			if ( 1 === preg_match( '/^(\d)\1{15}$/', $normalized ) ) {
				ValidationException::raise(
					ValidationException::CODE_INVALID_CARD_PAN,
					'Card number with 16 identical digits is invalid.'
				);
			}

			if ( ! self::passes_luhn( $normalized ) ) {
				ValidationException::raise(
					ValidationException::CODE_INVALID_CARD_PAN,
					'Card number failed Luhn modulo-10 checksum validation.'
				);
			}

			return new SensitiveValue( $normalized );
		} finally {
			if ( is_string( $normalized ) && function_exists( 'sodium_memzero' ) ) {
				sodium_memzero( $normalized );
			}
		}
	}

	/**
	 * Validate a 16-digit card PAN and return only its last 4 ASCII digits,
	 * immediately wiping the full 16-digit PAN from memory (DS-2 / C1).
	 *
	 * @param SensitiveValue|string $input Raw card number input.
	 * @return string 4-character ASCII `card_last4`.
	 * @throws ValidationException If the card number is invalid.
	 */
	public static function extract_card_last4(
		#[SensitiveParameter] SensitiveValue|string $input
	): string {
		$pan = self::normalize_card_pan( $input );
		try {
			return substr( $pan->reveal(), 12, 4 );
		} finally {
			$pan->wipe();
		}
	}

	/**
	 * Return true if the input is a structurally valid 16-digit Luhn card number.
	 *
	 * @param SensitiveValue|string $input Raw card number input.
	 */
	public static function is_valid_card_pan(
		#[SensitiveParameter] SensitiveValue|string $input
	): bool {
		try {
			$pan = self::normalize_card_pan( $input );
			$pan->wipe();
			return true;
		} catch ( ValidationException ) {
			return false;
		}
	}

	/**
	 * Evaluate Luhn modulo-10 checksum on a numeric ASCII string.
	 *
	 * @param string $digits Numeric ASCII string.
	 */
	private static function passes_luhn( #[SensitiveParameter] string $digits ): bool {
		$sum    = 0;
		$length = strlen( $digits );
		$parity = $length % 2;

		for ( $i = 0; $i < $length; $i++ ) {
			$digit = (int) $digits[ $i ];
			if ( $i % 2 === $parity ) {
				$digit *= 2;
				if ( $digit > 9 ) {
					$digit -= 9;
				}
			}
			$sum += $digit;
		}

		return 0 === ( $sum % 10 );
	}
}

<?php
/**
 * Consistent, non-mutating display masking for sensitive identity and card fields (DS-4).
 *
 * @package WPIG\Security
 */

declare(strict_types=1);

namespace WPIG\Security;

use SensitiveParameter;

/**
 * Formats canonical masked representations for safe UI/admin display and audit metadata:
 * - National code: `******1234`
 * - Mobile number: `0912***4567`
 * - Bank card:     `**** **** **** 1234`
 *
 * Never mutates the caller's source string or `SensitiveValue`.
 */
final class DataMasker {

	/**
	 * Mask a 10-digit Iranian national code as `******1234` (6 asterisks + last 4 digits).
	 *
	 * @param SensitiveValue|string $national_code Raw or normalized 10-digit national code.
	 * @return string Masked national code (`******1234`).
	 * @throws ValidationException If the national code is invalid.
	 */
	public static function mask_national_code(
		#[SensitiveParameter] SensitiveValue|string $national_code
	): string {
		$canonical = IdentityNormalizer::normalize_national_code( $national_code );
		try {
			return '******' . substr( $canonical, 6, 4 );
		} finally {
			if ( function_exists( 'sodium_memzero' ) ) {
				sodium_memzero( $canonical );
			}
		}
	}

	/**
	 * Mask an Iranian mobile number as `0912***4567` (first 4 digits + 3 asterisks + last 4 digits).
	 *
	 * @param SensitiveValue|string $mobile Raw or normalized Iranian mobile number.
	 * @return string Masked mobile number (`0912***4567`).
	 * @throws ValidationException If the mobile number is invalid.
	 */
	public static function mask_mobile(
		#[SensitiveParameter] SensitiveValue|string $mobile
	): string {
		$canonical = IdentityNormalizer::normalize_mobile( $mobile );
		try {
			return substr( $canonical, 0, 4 ) . '***' . substr( $canonical, 7, 4 );
		} finally {
			if ( function_exists( 'sodium_memzero' ) ) {
				sodium_memzero( $canonical );
			}
		}
	}

	/**
	 * Mask a 16-digit bank card PAN as `**** **** **** 1234` without mutating the source value.
	 *
	 * @param SensitiveValue|string $card_pan Raw or formatted 16-digit card PAN.
	 * @return string Masked card number (`**** **** **** 1234`).
	 * @throws ValidationException If the card PAN is invalid.
	 */
	public static function mask_card(
		#[SensitiveParameter] SensitiveValue|string $card_pan
	): string {
		$last4 = IdentityNormalizer::extract_card_last4( $card_pan );
		return '**** **** **** ' . $last4;
	}

	/**
	 * Format an already-extracted 4-digit card_last4 value as `**** **** **** 1234`.
	 *
	 * @param string $last4 4-digit card tail (Persian/Arabic/ASCII digits).
	 * @return string Masked card number (`**** **** **** 1234`).
	 * @throws ValidationException If $last4 is not exactly 4 digits.
	 */
	public static function mask_card_last4( string $last4 ): string {
		$ascii   = IdentityNormalizer::digits_to_ascii( $last4 );
		$trimmed = trim( $ascii );

		if ( 1 !== preg_match( '/^\d{4}$/', $trimmed ) ) {
			ValidationException::raise(
				ValidationException::CODE_INVALID_CARD_LAST4,
				'Card last4 must consist of exactly 4 digits.'
			);
		}

		return '**** **** **** ' . $trimmed;
	}
}

<?php
/**
 * Purpose-separated keyed HMAC-SHA-256 fingerprinter for normalized identity contexts.
 *
 * @package WPIG\Security
 */

declare(strict_types=1);

namespace WPIG\Security;

use SensitiveParameter;
use WPIG\Contracts\CryptoInterface;

/**
 * Produces and verifies domain-separated HMAC-SHA-256 fingerprints (`CHAR(64)` hex)
 * over canonically normalized inputs using `CryptoInterface`.
 *
 * Security invariants (DS-1, DS-2, DS-3):
 * - Always normalizes and validates inputs before computing HMAC digests.
 * - Enforces distinct purpose tags (`wpig:v1:national_code`, `wpig:v1:mobile`,
 *   `wpig:v1:otp_challenge`, `wpig:v1:ip_rate`).
 * - Supports explicit HMAC key IDs for keyring lookups.
 * - Never falls back to unkeyed SHA-256.
 * - Never fingerprints bank card PANs (prohibited in Free v1.0 per DS-2 / C1).
 */
final class IdentityFingerprinter {

	public const PURPOSE_NATIONAL_CODE = 'wpig:v1:national_code';
	public const PURPOSE_MOBILE        = 'wpig:v1:mobile';
	public const PURPOSE_OTP_CHALLENGE = 'wpig:v1:otp_challenge';
	public const PURPOSE_IP_RATE       = 'wpig:v1:ip_rate';

	/**
	 * Approved cryptographic service.
	 *
	 * @var CryptoInterface
	 */
	private CryptoInterface $crypto;

	/**
	 * Constructor.
	 *
	 * @param CryptoInterface $crypto Approved cryptographic service instance.
	 */
	public function __construct( CryptoInterface $crypto ) {
		$this->crypto = $crypto;
	}

	/**
	 * Compute the 64-char hex HMAC fingerprint of a normalized Iranian national code.
	 *
	 * @param SensitiveValue|string $national_code Raw or normalized 10-digit national code.
	 * @param string|null           $key_id        Optional HMAC key ID override.
	 * @return string 64-character lowercase hexadecimal digest.
	 * @throws ValidationException If the national code is invalid.
	 * @throws CryptoException     If the HMAC key is missing or invalid.
	 */
	public function fingerprint_national_code(
		#[SensitiveParameter] SensitiveValue|string $national_code,
		?string $key_id = null
	): string {
		$canonical = IdentityNormalizer::normalize_national_code( $national_code );
		try {
			return $this->crypto->hmac( self::PURPOSE_NATIONAL_CODE, $canonical, $key_id );
		} finally {
			if ( function_exists( 'sodium_memzero' ) ) {
				sodium_memzero( $canonical );
			}
		}
	}

	/**
	 * Verify a national code against an expected 64-char hex HMAC fingerprint in constant time.
	 *
	 * @param string                $expected_hex  Expected 64-char hex digest.
	 * @param SensitiveValue|string $national_code Raw or normalized 10-digit national code.
	 * @param string|null           $key_id        Optional HMAC key ID override.
	 * @return bool True if valid and matching in constant time.
	 * @throws ValidationException If the national code is invalid.
	 * @throws CryptoException     If the HMAC key is missing or invalid.
	 */
	public function verify_national_code(
		string $expected_hex,
		#[SensitiveParameter] SensitiveValue|string $national_code,
		?string $key_id = null
	): bool {
		$canonical = IdentityNormalizer::normalize_national_code( $national_code );
		try {
			return $this->crypto->verify_hmac( $expected_hex, self::PURPOSE_NATIONAL_CODE, $canonical, $key_id );
		} finally {
			if ( function_exists( 'sodium_memzero' ) ) {
				sodium_memzero( $canonical );
			}
		}
	}

	/**
	 * Compute the 64-char hex HMAC fingerprint of a normalized Iranian mobile number (`09xxxxxxxxx`).
	 *
	 * @param SensitiveValue|string $mobile Raw or normalized Iranian mobile number.
	 * @param string|null           $key_id Optional HMAC key ID override.
	 * @return string 64-character lowercase hexadecimal digest.
	 * @throws ValidationException If the mobile number is invalid.
	 * @throws CryptoException     If the HMAC key is missing or invalid.
	 */
	public function fingerprint_mobile(
		#[SensitiveParameter] SensitiveValue|string $mobile,
		?string $key_id = null
	): string {
		$canonical = IdentityNormalizer::normalize_mobile( $mobile );
		try {
			return $this->crypto->hmac( self::PURPOSE_MOBILE, $canonical, $key_id );
		} finally {
			if ( function_exists( 'sodium_memzero' ) ) {
				sodium_memzero( $canonical );
			}
		}
	}

	/**
	 * Verify a mobile number against an expected 64-char hex HMAC fingerprint in constant time.
	 *
	 * @param string                $expected_hex Expected 64-char hex digest.
	 * @param SensitiveValue|string $mobile       Raw or normalized Iranian mobile number.
	 * @param string|null           $key_id       Optional HMAC key ID override.
	 * @return bool True if valid and matching in constant time.
	 * @throws ValidationException If the mobile number is invalid.
	 * @throws CryptoException     If the HMAC key is missing or invalid.
	 */
	public function verify_mobile(
		string $expected_hex,
		#[SensitiveParameter] SensitiveValue|string $mobile,
		?string $key_id = null
	): bool {
		$canonical = IdentityNormalizer::normalize_mobile( $mobile );
		try {
			return $this->crypto->verify_hmac( $expected_hex, self::PURPOSE_MOBILE, $canonical, $key_id );
		} finally {
			if ( function_exists( 'sodium_memzero' ) ) {
				sodium_memzero( $canonical );
			}
		}
	}

	/**
	 * Compute the 64-char hex HMAC fingerprint for an OTP challenge context:
	 * `wpig:v1:otp_challenge|<challenge_context>|<wp_user_id>|<otp_code_ascii>`
	 *
	 * @param int|string            $challenge_context Positive integer challenge ID or canonical context token (`[A-Za-z0-9._-]{1,64}`).
	 * @param int                   $wp_user_id        WordPress user ID (`>= 1`).
	 * @param SensitiveValue|string $otp_code          4..10 digit OTP code (Persian/Arabic/ASCII digits).
	 * @param string|null           $key_id            Optional HMAC key ID override.
	 * @return string 64-character lowercase hexadecimal digest.
	 * @throws ValidationException If challenge context, user ID, or OTP code is invalid.
	 * @throws CryptoException     If the HMAC key is missing or invalid.
	 */
	public function fingerprint_otp_challenge(
		int|string $challenge_context,
		int $wp_user_id,
		#[SensitiveParameter] SensitiveValue|string $otp_code,
		?string $key_id = null
	): string {
		$canonical_payload = $this->build_otp_challenge_payload( $challenge_context, $wp_user_id, $otp_code );
		try {
			return $this->crypto->hmac( self::PURPOSE_OTP_CHALLENGE, $canonical_payload, $key_id );
		} finally {
			if ( function_exists( 'sodium_memzero' ) ) {
				sodium_memzero( $canonical_payload );
			}
		}
	}

	/**
	 * Verify an OTP challenge code in constant time against an expected 64-char hex HMAC digest.
	 *
	 * @param string                $expected_hex      Expected 64-char hex digest.
	 * @param int|string            $challenge_context Positive integer challenge ID or canonical context token.
	 * @param int                   $wp_user_id        WordPress user ID (`>= 1`).
	 * @param SensitiveValue|string $otp_code          4..10 digit OTP code.
	 * @param string|null           $key_id            Optional HMAC key ID override.
	 * @return bool True if matching in constant time.
	 * @throws ValidationException If challenge context, user ID, or OTP code is invalid.
	 * @throws CryptoException     If the HMAC key is missing or invalid.
	 */
	public function verify_otp_challenge(
		string $expected_hex,
		int|string $challenge_context,
		int $wp_user_id,
		#[SensitiveParameter] SensitiveValue|string $otp_code,
		?string $key_id = null
	): bool {
		$canonical_payload = $this->build_otp_challenge_payload( $challenge_context, $wp_user_id, $otp_code );
		try {
			return $this->crypto->verify_hmac(
				$expected_hex,
				self::PURPOSE_OTP_CHALLENGE,
				$canonical_payload,
				$key_id
			);
		} finally {
			if ( function_exists( 'sodium_memzero' ) ) {
				sodium_memzero( $canonical_payload );
			}
		}
	}

	/**
	 * Compute the 64-char hex HMAC fingerprint for a canonicalized IPv4/IPv6 rate-limit identity.
	 *
	 * Canonicalizes IPv4 and IPv6 addresses via `inet_pton()` + `inet_ntop()` so
	 * equivalent representations (e.g. expanded vs compressed IPv6) map to the
	 * exact same HMAC digest.
	 *
	 * @param SensitiveValue|string $ip_address Raw IPv4 or IPv6 address.
	 * @param string|null           $key_id     Optional HMAC key ID override.
	 * @return string 64-character lowercase hexadecimal digest.
	 * @throws ValidationException If the IP address is invalid.
	 * @throws CryptoException     If the HMAC key is missing or invalid.
	 */
	public function fingerprint_ip(
		#[SensitiveParameter] SensitiveValue|string $ip_address,
		?string $key_id = null
	): string {
		$canonical_ip = self::normalize_ip( $ip_address );
		return $this->crypto->hmac( self::PURPOSE_IP_RATE, $canonical_ip, $key_id );
	}

	/**
	 * Verify an IPv4/IPv6 address against an expected 64-char hex rate-limit HMAC digest.
	 *
	 * @param string                $expected_hex Expected 64-char hex digest.
	 * @param SensitiveValue|string $ip_address   Raw IPv4 or IPv6 address.
	 * @param string|null           $key_id       Optional HMAC key ID override.
	 * @return bool True if matching in constant time.
	 * @throws ValidationException If the IP address is invalid.
	 * @throws CryptoException     If the HMAC key is missing or invalid.
	 */
	public function verify_ip(
		string $expected_hex,
		#[SensitiveParameter] SensitiveValue|string $ip_address,
		?string $key_id = null
	): bool {
		$canonical_ip = self::normalize_ip( $ip_address );
		return $this->crypto->verify_hmac( $expected_hex, self::PURPOSE_IP_RATE, $canonical_ip, $key_id );
	}

	/**
	 * Normalize and validate an IPv4 or IPv6 address into canonical RFC representation.
	 *
	 * @param SensitiveValue|string $ip_address Raw IP address.
	 * @return string Canonical IP string.
	 * @throws ValidationException If the IP address is malformed.
	 */
	public static function normalize_ip(
		#[SensitiveParameter] SensitiveValue|string $ip_address
	): string {
		$raw     = $ip_address instanceof SensitiveValue ? $ip_address->reveal() : $ip_address;
		$trimmed = trim( $raw );

		if ( '' === $trimmed || false === filter_var( $trimmed, FILTER_VALIDATE_IP ) ) {
			ValidationException::raise(
				ValidationException::CODE_INVALID_IP_ADDRESS,
				'IP address must be a valid IPv4 or IPv6 literal.'
			);
		}

		$packed = @inet_pton( $trimmed ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Validated by filter_var above.
		if ( false === $packed ) {
			ValidationException::raise(
				ValidationException::CODE_INVALID_IP_ADDRESS,
				'Unable to canonicalize IP address.'
			);
		}

		$canonical = inet_ntop( $packed );
		if ( false === $canonical ) {
			ValidationException::raise(
				ValidationException::CODE_INVALID_IP_ADDRESS,
				'Unable to format canonical IP address.'
			);
		}

		return strtolower( $canonical );
	}

	/**
	 * Validate and assemble the canonical OTP challenge payload `<challenge_context>|<wp_user_id>|<otp_code_ascii>`.
	 *
	 * @param int|string            $challenge_context Challenge ID or token.
	 * @param int                   $wp_user_id        WP user ID (`>= 1`).
	 * @param SensitiveValue|string $otp_code          Raw OTP code.
	 * @return string Canonical payload string.
	 * @throws ValidationException If any component is invalid.
	 */
	private function build_otp_challenge_payload(
		int|string $challenge_context,
		int $wp_user_id,
		#[SensitiveParameter] SensitiveValue|string $otp_code
	): string {
		if ( is_int( $challenge_context ) ) {
			if ( $challenge_context < 1 ) {
				ValidationException::raise(
					ValidationException::CODE_INVALID_CHALLENGE_CONTEXT,
					'OTP challenge ID must be a positive integer.'
				);
			}
			$context_str = (string) $challenge_context;
		} else {
			$context_str = trim( $challenge_context );
			if ( 1 !== preg_match( '/^[A-Za-z0-9._-]{1,64}$/', $context_str ) ) {
				ValidationException::raise(
					ValidationException::CODE_INVALID_CHALLENGE_CONTEXT,
					'OTP challenge context must be 1..64 ASCII characters matching [A-Za-z0-9._-].'
				);
			}
		}

		if ( $wp_user_id < 1 ) {
			ValidationException::raise(
				ValidationException::CODE_INVALID_CHALLENGE_CONTEXT,
				'OTP challenge wp_user_id must be >= 1.'
			);
		}

		$raw_code        = $otp_code instanceof SensitiveValue ? $otp_code->reveal() : $otp_code;
		$ascii_code      = IdentityNormalizer::digits_to_ascii( $raw_code );
		$normalized_code = preg_replace( '/[\s\x{200B}-\x{200F}\x{FEFF}]+/u', '', $ascii_code );

		if ( ! is_string( $normalized_code ) || 1 !== preg_match( '/^\d{4,10}$/', $normalized_code ) ) {
			ValidationException::raise(
				ValidationException::CODE_INVALID_OTP_CODE,
				'OTP code must consist of 4 to 10 digits.'
			);
		}

		return sprintf( '%s|%d|%s', $context_str, $wp_user_id, $normalized_code );
	}
}

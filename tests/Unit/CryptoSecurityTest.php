<?php
/**
 * Comprehensive security unit tests for P01-C1 cryptographic primitives,
 * canonical AAD binding, K1/K2 key management, and SensitiveValue redaction.
 *
 * Uses strictly synthetic test vectors (no real PII, PAN, or credentials).
 *
 * @package WPIG\Tests\Unit
 */

declare(strict_types=1);

namespace WPIG\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPIG\Contracts\KeyProviderInterface;
use WPIG\Security\CanonicalAad;
use WPIG\Security\CryptoException;
use WPIG\Security\SensitiveValue;
use WPIG\Security\SodiumCrypto;
use WPIG\Security\WordPressKeyProvider;

/**
 * Verifies SodiumCrypto, WordPressKeyProvider, CanonicalAad, and SensitiveValue.
 */
final class CryptoSecurityTest extends TestCase {

	/**
	 * Synthetic 256-bit encryption key #1 (hex).
	 */
	private const SYNTHETIC_ENC_KEY_1 = 'hex:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20';

	/**
	 * Synthetic 256-bit encryption key #2 for rotation tests (hex).
	 */
	private const SYNTHETIC_ENC_KEY_2 = 'hex:2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40';

	/**
	 * Synthetic 256-bit HMAC key #1 (hex, distinct from encryption keys).
	 */
	private const SYNTHETIC_HMAC_KEY_1 = 'hex:a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0';

	/**
	 * Synthetic 256-bit HMAC key #2 (hex).
	 */
	private const SYNTHETIC_HMAC_KEY_2 = 'hex:c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0';

	/**
	 * Build a WordPressKeyProvider backed by an in-memory constant/env map.
	 *
	 * @param array<string,mixed>  $constants Simulated K1 wp-config.php constants.
	 * @param array<string,string> $env       Simulated K2 environment variables.
	 */
	private function make_provider( array $constants = array(), array $env = array() ): WordPressKeyProvider {
		$defaults = array(
			WordPressKeyProvider::CONST_ENC_KEY     => self::SYNTHETIC_ENC_KEY_1,
			WordPressKeyProvider::CONST_ENC_KEY_ID  => 'k2026_01',
			WordPressKeyProvider::CONST_HMAC_KEY    => self::SYNTHETIC_HMAC_KEY_1,
			WordPressKeyProvider::CONST_HMAC_KEY_ID => 'hmac_2026_01',
		);

		$merged_consts = array_merge( $defaults, $constants );

		return new WordPressKeyProvider(
			static fn( string $name ): mixed => $merged_consts[ $name ] ?? null,
			static fn( string $name ): string|false => $env[ $name ] ?? false
		);
	}

	/**
	 * 1. Successful encryption and decryption with randomized nonces and AAD binding.
	 */
	public function test_successful_encryption_and_decryption(): void {
		$provider = $this->make_provider();
		$crypto   = new SodiumCrypto( $provider );

		$aad = CanonicalAad::for_table_column(
			1,
			'wpig_profiles',
			'national_code_ciphertext',
			42,
			'k2026_01'
		);
		self::assertSame(
			'wpig|v1|blog:1|table:wpig_profiles.national_code_ciphertext|42|k2026_01',
			$aad
		);

		$synthetic_payload = new SensitiveValue( '0000000000' );
		$envelope1         = $crypto->encrypt( $synthetic_payload, $aad );
		$envelope2         = $crypto->encrypt( $synthetic_payload, $aad );

		self::assertStringStartsWith( 'v1:k2026_01:', $envelope1 );
		self::assertNotSame( $envelope1, $envelope2, 'Random 24-byte nonces must produce distinct ciphertexts.' );
		self::assertSame( 'k2026_01', $crypto->extract_key_id( $envelope1 ) );

		$decrypted = $crypto->decrypt( $envelope1, $aad );
		self::assertSame( '0000000000', $decrypted->reveal() );

		// Also verify site-option encryption & decryption.
		$option_aad      = CanonicalAad::for_option( 1, 'wpig_provider_credentials', 'k2026_01' );
		$option_envelope = $crypto->encrypt( '{"token":"synthetic_test_token"}', $option_aad );
		self::assertSame(
			'{"token":"synthetic_test_token"}',
			$crypto->decrypt( $option_envelope, $option_aad )->reveal()
		);
	}

	/**
	 * 2. Invalid encryption keys (wrong length, bad encoding, low entropy, salt reuse, key separation violation).
	 */
	public function test_invalid_encryption_key_fails_closed(): void {
		// Too short (16 bytes instead of 32).
		$short_provider = $this->make_provider(
			array( WordPressKeyProvider::CONST_ENC_KEY => 'hex:0102030405060708090a0b0c0d0e0f10' )
		);
		self::assertFalse( $short_provider->is_configured() );
		$this->expectException( CryptoException::class );
		$short_provider->get_active_encryption_key();
	}

	/**
	 * 2b. Degenerate all-zero 32-byte key is rejected.
	 */
	public function test_low_entropy_all_zero_key_is_rejected(): void {
		$zero_provider = $this->make_provider(
			array( WordPressKeyProvider::CONST_ENC_KEY => 'hex:' . str_repeat( '00', 32 ) )
		);

		try {
			$zero_provider->get_active_encryption_key();
			self::fail( 'Expected CryptoException for all-zero key.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_KEY_INVALID, $e->get_safe_code() );
		}
	}

	/**
	 * 2c. Reusing the same key for encryption and HMAC is rejected (DS-1 key separation).
	 */
	public function test_identical_encryption_and_hmac_key_fails_closed(): void {
		$same_key_provider = $this->make_provider(
			array(
				WordPressKeyProvider::CONST_ENC_KEY  => self::SYNTHETIC_ENC_KEY_1,
				WordPressKeyProvider::CONST_HMAC_KEY => self::SYNTHETIC_ENC_KEY_1,
			)
		);

		try {
			$same_key_provider->get_active_encryption_key();
			self::fail( 'Expected CryptoException when encryption and HMAC keys are identical.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_KEY_SEPARATION, $e->get_safe_code() );
		}
	}

	/**
	 * 2d. Reusing a WordPress salt (e.g. AUTH_KEY) as an encryption key is rejected (K3 rejection).
	 */
	public function test_wordpress_salt_reuse_is_rejected(): void {
		$salt_provider = $this->make_provider(
			array(
				'AUTH_KEY'                          => self::SYNTHETIC_ENC_KEY_1,
				WordPressKeyProvider::CONST_ENC_KEY => self::SYNTHETIC_ENC_KEY_1,
			)
		);

		try {
			$salt_provider->get_active_encryption_key();
			self::fail( 'Expected CryptoException when encryption key matches AUTH_KEY.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_KEY_INVALID, $e->get_safe_code() );
		}
	}

	/**
	 * 2e. SodiumCrypto validates raw key length even if a custom KeyProviderInterface returns wrong bytes.
	 */
	public function test_sodium_crypto_rejects_wrong_length_key_from_custom_provider(): void {
		$bad_provider = new class() implements KeyProviderInterface {
			/**
			 * Return bad key ID.
			 */
			public function get_active_encryption_key_id(): string {
				return 'k_bad';
			}

			/**
			 * Return invalid 16-byte key.
			 */
			public function get_active_encryption_key(): SensitiveValue {
				return new SensitiveValue( 'short_16byte_key' );
			}

			/**
			 * Return invalid 16-byte key for ID.
			 *
			 * @param string $key_id Key ID.
			 */
			public function get_encryption_key( string $key_id ): SensitiveValue {
				unset( $key_id );
				return new SensitiveValue( 'short_16byte_key' );
			}

			/**
			 * Return key IDs.
			 *
			 * @return string[]
			 */
			public function get_encryption_key_ids(): array {
				return array( 'k_bad' );
			}

			/**
			 * Return bad HMAC key ID.
			 */
			public function get_active_hmac_key_id(): string {
				return 'h_bad';
			}

			/**
			 * Return invalid 16-byte HMAC key.
			 */
			public function get_active_hmac_key(): SensitiveValue {
				return new SensitiveValue( 'short_16byte_key' );
			}

			/**
			 * Return invalid 16-byte HMAC key for ID.
			 *
			 * @param string $key_id Key ID.
			 */
			public function get_hmac_key( string $key_id ): SensitiveValue {
				unset( $key_id );
				return new SensitiveValue( 'short_16byte_key' );
			}

			/**
			 * Return configured state.
			 */
			public function is_configured(): bool {
				return true;
			}
		};

		$crypto = new SodiumCrypto( $bad_provider );
		$aad    = CanonicalAad::for_option( 1, 'wpig_provider_credentials', 'k_bad' );

		try {
			$crypto->encrypt( 'synthetic_secret', $aad );
			self::fail( 'Expected CryptoException for 16-byte raw key.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_KEY_INVALID, $e->get_safe_code() );
		}
	}

	/**
	 * 3. Missing encryption key or HMAC key fails closed.
	 */
	public function test_missing_encryption_or_hmac_key_fails_closed(): void {
		$missing_enc = $this->make_provider(
			array( WordPressKeyProvider::CONST_ENC_KEY => null )
		);
		self::assertFalse( $missing_enc->is_configured() );

		$crypto = new SodiumCrypto( $missing_enc );
		$aad    = CanonicalAad::for_option( 1, 'wpig_provider_credentials', 'k2026_01' );

		try {
			$crypto->encrypt( 'synthetic_secret', $aad );
			self::fail( 'Expected CryptoException when WPIG_ENC_KEY is missing.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_KEY_MISSING, $e->get_safe_code() );
		}

		$missing_hmac = $this->make_provider(
			array( WordPressKeyProvider::CONST_HMAC_KEY => null )
		);
		self::assertFalse( $missing_hmac->is_configured() );
	}

	/**
	 * 4. Missing sodium extension handling fails closed.
	 */
	public function test_missing_sodium_extension_fails_closed(): void {
		$provider = $this->make_provider();
		$crypto   = new SodiumCrypto( $provider, static fn(): bool => false );
		$aad      = CanonicalAad::for_option( 1, 'wpig_provider_credentials', 'k2026_01' );

		try {
			$crypto->encrypt( 'synthetic_secret', $aad );
			self::fail( 'Expected CryptoException when sodium is unavailable.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_SODIUM_UNAVAILABLE, $e->get_safe_code() );
		}
	}

	/**
	 * 5. Invalid ciphertext envelopes fail closed.
	 */
	public function test_invalid_ciphertext_envelopes_fail_closed(): void {
		$crypto = new SodiumCrypto( $this->make_provider() );
		$aad    = CanonicalAad::for_option( 1, 'wpig_provider_credentials', 'k2026_01' );

		$invalid_envelopes = array(
			'',
			'v1:k2026_01',
			'v1:k2026_01:a:b',
			'v1:k2026_01:!!!not_base64!!!',
			'v1:k2026_01:dG9vX3Nob3J0', // valid base64 ("too_short"), shorter than 40 bytes.
		);

		foreach ( $invalid_envelopes as $bad_envelope ) {
			try {
				$crypto->decrypt( $bad_envelope, $aad );
				self::fail( "Expected CryptoException for malformed envelope: {$bad_envelope}" );
			} catch ( CryptoException $e ) {
				self::assertSame( CryptoException::CODE_ENVELOPE_INVALID, $e->get_safe_code() );
			}
		}
	}

	/**
	 * 6, 7 & 8. Modified ciphertext, modified authentication tag, and modified nonce all fail closed.
	 */
	public function test_modified_ciphertext_tag_and_nonce_fail_closed(): void {
		$crypto   = new SodiumCrypto( $this->make_provider() );
		$aad      = CanonicalAad::for_table_column( 1, 'wpig_profiles', 'birth_date_ciphertext', 99, 'k2026_01' );
		$envelope = $crypto->encrypt( '1370/01/01', $aad );

		$parts  = explode( ':', $envelope );
		$binary = sodium_base642bin( $parts[2], SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING );

		// 6. Flip a bit in the ciphertext body (byte index 25, just after the 24-byte nonce).
		$corrupted_ct     = $binary;
		$corrupted_ct[25] = chr( ord( $corrupted_ct[25] ) ^ 0x01 );
		$tampered_ct_env  = 'v1:k2026_01:' . sodium_bin2base64( $corrupted_ct, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING );

		try {
			$crypto->decrypt( $tampered_ct_env, $aad );
			self::fail( 'Modified ciphertext body must fail authentication.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_AUTH_FAILED, $e->get_safe_code() );
		}

		// 7. Flip a bit in the last byte of the 16-byte Poly1305 authentication tag.
		$corrupted_tag              = $binary;
		$last_idx                   = strlen( $corrupted_tag ) - 1;
		$corrupted_tag[ $last_idx ] = chr( ord( $corrupted_tag[ $last_idx ] ) ^ 0x01 );
		$tampered_tag_env           = 'v1:k2026_01:' . sodium_bin2base64( $corrupted_tag, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING );

		try {
			$crypto->decrypt( $tampered_tag_env, $aad );
			self::fail( 'Modified authentication tag must fail authentication.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_AUTH_FAILED, $e->get_safe_code() );
		}

		// 8. Flip a bit in the first byte of the 24-byte XChaCha20 nonce.
		$corrupted_nonce    = $binary;
		$corrupted_nonce[0] = chr( ord( $corrupted_nonce[0] ) ^ 0x01 );
		$tampered_nonce_env = 'v1:k2026_01:' . sodium_bin2base64( $corrupted_nonce, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING );

		try {
			$crypto->decrypt( $tampered_nonce_env, $aad );
			self::fail( 'Modified nonce must fail authentication.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_AUTH_FAILED, $e->get_safe_code() );
		}
	}

	/**
	 * 9, 10, 11, 12 & 13. Canonical AAD validation and cross-user, cross-site,
	 * cross-column/entity, and wrong key_id isolation.
	 */
	public function test_aad_validation_and_cross_context_isolation(): void {
		$provider = $this->make_provider(
			array(
				WordPressKeyProvider::CONST_ENC_KEYS_PREVIOUS => array(
					'k2025_01' => self::SYNTHETIC_ENC_KEY_2,
				),
			)
		);
		$crypto   = new SodiumCrypto( $provider );

		$valid_aad = CanonicalAad::for_table_column(
			1,
			'wpig_profiles',
			'national_code_ciphertext',
			101,
			'k2026_01'
		);
		$envelope  = $crypto->encrypt( '0000000000', $valid_aad );

		// 9. Malformed AAD strings are rejected before decryption.
		$malformed_aads = array(
			'',
			'wpig|v1|blog:1|table:wpig_profiles.national_code_ciphertext|101',
			'wpig|v2|blog:1|table:wpig_profiles.national_code_ciphertext|101|k2026_01',
			'wpig|v1|blog:0|table:wpig_profiles.national_code_ciphertext|101|k2026_01',
			'wpig|v1|blog:1|table:wp_wpig_profiles|101|k2026_01',
			'wpig|v1|blog:1|table:wpig_profiles.national_code_ciphertext|0|k2026_01',
			'wpig|v1|blog:1|option:wpig_provider_credentials|101|k2026_01',
		);

		foreach ( $malformed_aads as $bad_aad ) {
			try {
				$crypto->decrypt( $envelope, $bad_aad );
				self::fail( "Expected CryptoException for malformed AAD: {$bad_aad}" );
			} catch ( CryptoException $e ) {
				self::assertSame( CryptoException::CODE_AAD_INVALID, $e->get_safe_code() );
			}
		}

		// 10. Wrong WordPress user ID (102 instead of 101).
		$wrong_user_aad = CanonicalAad::for_table_column(
			1,
			'wpig_profiles',
			'national_code_ciphertext',
			102,
			'k2026_01'
		);
		try {
			$crypto->decrypt( $envelope, $wrong_user_aad );
			self::fail( 'Ciphertext transplant across WordPress user IDs must fail.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_AUTH_FAILED, $e->get_safe_code() );
		}

		// 11. Wrong blog ID (blog:2 instead of blog:1).
		$wrong_blog_aad = CanonicalAad::for_table_column(
			2,
			'wpig_profiles',
			'national_code_ciphertext',
			101,
			'k2026_01'
		);
		try {
			$crypto->decrypt( $envelope, $wrong_blog_aad );
			self::fail( 'Ciphertext transplant across Multisite blog IDs must fail.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_AUTH_FAILED, $e->get_safe_code() );
		}

		// 12a. Wrong column (mobile_ciphertext instead of national_code_ciphertext).
		$wrong_col_aad = CanonicalAad::for_table_column(
			1,
			'wpig_profiles',
			'mobile_ciphertext',
			101,
			'k2026_01'
		);
		try {
			$crypto->decrypt( $envelope, $wrong_col_aad );
			self::fail( 'Ciphertext transplant across table columns must fail.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_AUTH_FAILED, $e->get_safe_code() );
		}

		// 12b. Wrong entity type (option instead of table).
		$wrong_entity_aad = CanonicalAad::for_option(
			1,
			'wpig_provider_credentials',
			'k2026_01'
		);
		try {
			$crypto->decrypt( $envelope, $wrong_entity_aad );
			self::fail( 'Ciphertext transplant from table column to option must fail.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_AUTH_FAILED, $e->get_safe_code() );
		}

		// 13a. Wrong encryption key ID in AAD vs envelope header.
		$wrong_key_aad = CanonicalAad::for_table_column(
			1,
			'wpig_profiles',
			'national_code_ciphertext',
			101,
			'k2025_01'
		);
		try {
			$crypto->decrypt( $envelope, $wrong_key_aad );
			self::fail( 'Mismatched AAD key_id and envelope key_id must fail.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_AAD_KEY_MISMATCH, $e->get_safe_code() );
		}

		// 13b. Tampered envelope header key_id (changing v1:k2026_01:... to v1:k2025_01:...).
		$tampered_header_env = preg_replace( '/^v1:k2026_01:/', 'v1:k2025_01:', $envelope );
		self::assertIsString( $tampered_header_env );
		try {
			$crypto->decrypt( $tampered_header_env, $wrong_key_aad );
			self::fail( 'Tampered envelope key_id must fail AEAD authentication.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_AUTH_FAILED, $e->get_safe_code() );
		}
	}

	/**
	 * 14 & 15. Previous-key decryption, key-rotation compatibility, and K1/K2 keyring formats.
	 */
	public function test_previous_key_decryption_and_key_rotation_compatibility(): void {
		// Step 1: Encrypt under initial active key k2025_01.
		$initial_provider = $this->make_provider(
			array(
				WordPressKeyProvider::CONST_ENC_KEY    => self::SYNTHETIC_ENC_KEY_1,
				WordPressKeyProvider::CONST_ENC_KEY_ID => 'k2025_01',
			)
		);
		$initial_crypto   = new SodiumCrypto( $initial_provider );
		$old_aad          = CanonicalAad::for_table_column( 1, 'wpig_profiles', 'mobile_ciphertext', 77, 'k2025_01' );
		$old_envelope     = $initial_crypto->encrypt( 'SYNTHETIC_MOBILE_TEST_PAYLOAD', $old_aad );

		self::assertStringStartsWith( 'v1:k2025_01:', $old_envelope );

		// Step 2: Rotate active key to k2026_02 and move k2025_01 into WPIG_ENC_KEYS_PREVIOUS (via K2 env string format).
		$rotated_provider = new WordPressKeyProvider(
			static fn( string $name ): mixed => '' !== $name ? null : null,
			static function ( string $name ): string|false {
				$map = array(
					WordPressKeyProvider::CONST_ENC_KEY    => self::SYNTHETIC_ENC_KEY_2,
					WordPressKeyProvider::CONST_ENC_KEY_ID => 'k2026_02',
					WordPressKeyProvider::CONST_ENC_KEYS_PREVIOUS => 'k2025_01=' . self::SYNTHETIC_ENC_KEY_1,
					WordPressKeyProvider::CONST_HMAC_KEY   => self::SYNTHETIC_HMAC_KEY_1,
					WordPressKeyProvider::CONST_HMAC_KEY_ID => 'hmac_2026_01',
				);
				return $map[ $name ] ?? false;
			}
		);

		self::assertTrue( $rotated_provider->is_configured() );
		self::assertSame( array( 'k2026_02', 'k2025_01' ), $rotated_provider->get_encryption_key_ids() );

		$rotated_crypto = new SodiumCrypto( $rotated_provider );

		// Step 3: Decrypt old envelope using rotated crypto instance (reads k2025_01 from previous keyring).
		$extracted_old_key_id = $rotated_crypto->extract_key_id( $old_envelope );
		self::assertSame( 'k2025_01', $extracted_old_key_id );

		$decrypted = $rotated_crypto->decrypt( $old_envelope, $old_aad );
		self::assertSame( 'SYNTHETIC_MOBILE_TEST_PAYLOAD', $decrypted->reveal() );

		// Step 4: Re-encrypt under the new active key k2026_02 with updated AAD.
		$new_key_id   = $rotated_provider->get_active_encryption_key_id();
		$new_aad      = CanonicalAad::for_table_column( 1, 'wpig_profiles', 'mobile_ciphertext', 77, $new_key_id );
		$new_envelope = $rotated_crypto->encrypt( $decrypted, $new_aad );

		self::assertStringStartsWith( 'v1:k2026_02:', $new_envelope );
		self::assertSame( 'SYNTHETIC_MOBILE_TEST_PAYLOAD', $rotated_crypto->decrypt( $new_envelope, $new_aad )->reveal() );
	}

	/**
	 * 16 & 17. SensitiveValue redaction, memory wiping, and serialization prevention.
	 */
	public function test_sensitive_value_redaction_wiping_and_serialization_prevention(): void {
		$raw_value = 'SYNTHETIC_SENSITIVE_VALUE_PAYLOAD';
		$sensitive = new SensitiveValue( $raw_value );

		// String cast and interpolation must be redacted.
		self::assertSame( SensitiveValue::REDACTED, (string) $sensitive );
		self::assertSame( 'value=' . SensitiveValue::REDACTED, "value={$sensitive}" );

		// Debug output (__debugInfo / print_r / var_export) must never contain the underlying value.
		$debug_info = $sensitive->__debugInfo();
		self::assertSame( array( 'value' => SensitiveValue::REDACTED ), $debug_info );
		$printed = print_r( $sensitive, true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_print_r -- Testing debug redaction.
		self::assertStringNotContainsString( $raw_value, $printed );
		self::assertStringContainsString( SensitiveValue::REDACTED, $printed );

		// Explicit reveal() and constant-time equals() work prior to wipe().
		self::assertSame( strlen( $raw_value ), $sensitive->length() );
		self::assertSame( $raw_value, $sensitive->reveal() );
		self::assertTrue( $sensitive->equals( $raw_value ) );
		self::assertTrue( $sensitive->equals( new SensitiveValue( $raw_value ) ) );
		self::assertFalse( $sensitive->equals( 'different_value' ) );

		// PHP serialize() must fail closed.
		try {
			serialize( $sensitive ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize -- Testing serialization prevention.
			self::fail( 'serialize(SensitiveValue) must throw CryptoException.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_SERIALIZATION_FORBIDDEN, $e->get_safe_code() );
			self::assertStringNotContainsString( $raw_value, $e->getMessage() );
		}

		// json_encode() must fail closed.
		try {
			json_encode( $sensitive, JSON_THROW_ON_ERROR ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Testing JsonSerializable prevention.
			self::fail( 'json_encode(SensitiveValue) must throw CryptoException.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_SERIALIZATION_FORBIDDEN, $e->get_safe_code() );
			self::assertStringNotContainsString( $raw_value, $e->getMessage() );
		}

		// wipe() zeroes the buffer and blocks subsequent reveal().
		$sensitive->wipe();
		self::assertTrue( $sensitive->is_wiped() );
		self::assertSame( 0, $sensitive->length() );

		try {
			$sensitive->reveal();
			self::fail( 'reveal() after wipe() must throw CryptoException.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_SENSITIVE_VALUE_WIPED, $e->get_safe_code() );
		}
	}

	/**
	 * 18. Invalid envelope version fails closed with INVALID_ENVELOPE_VERSION.
	 */
	public function test_invalid_envelope_version_fails_closed(): void {
		$crypto = new SodiumCrypto( $this->make_provider() );
		$aad    = CanonicalAad::for_option( 1, 'wpig_provider_credentials', 'k2026_01' );

		try {
			$crypto->decrypt( 'v2:k2026_01:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', $aad );
			self::fail( 'Envelope with version v2 must fail closed.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_ENVELOPE_VERSION, $e->get_safe_code() );
		}
	}

	/**
	 * 19. Purpose-separated HMAC-SHA-256 and secure key generation.
	 */
	public function test_purpose_separated_hmac_and_key_generation(): void {
		$generated_enc  = WordPressKeyProvider::generate_encoded_key();
		$generated_hmac = WordPressKeyProvider::generate_encoded_key();

		self::assertStringStartsWith( 'base64:', $generated_enc->reveal() );
		self::assertFalse( $generated_enc->equals( $generated_hmac ) );

		$provider = $this->make_provider(
			array(
				WordPressKeyProvider::CONST_ENC_KEY  => $generated_enc->reveal(),
				WordPressKeyProvider::CONST_HMAC_KEY => $generated_hmac->reveal(),
			)
		);
		$crypto   = new SodiumCrypto( $provider );

		$digest_nc  = $crypto->hmac( 'wpig:v1:national_code', '0000000000' );
		$digest_mob = $crypto->hmac( 'wpig:v1:mobile', '0000000000' );

		self::assertMatchesRegularExpression( '/^[0-9a-f]{64}$/', $digest_nc );
		self::assertMatchesRegularExpression( '/^[0-9a-f]{64}$/', $digest_mob );
		self::assertNotSame( $digest_nc, $digest_mob, 'Different purpose tags must produce distinct HMAC digests.' );

		self::assertTrue( $crypto->verify_hmac( $digest_nc, 'wpig:v1:national_code', '0000000000' ) );
		self::assertFalse( $crypto->verify_hmac( $digest_nc, 'wpig:v1:mobile', '0000000000' ) );
		self::assertFalse( $crypto->verify_hmac( 'invalid_hex', 'wpig:v1:national_code', '0000000000' ) );

		try {
			$crypto->hmac( 'invalid_purpose', '0000000000' );
			self::fail( 'Invalid HMAC purpose tag must fail closed.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_PURPOSE_INVALID, $e->get_safe_code() );
		}
	}

	/**
	 * 20. Regression: Verify canonical WordPressKeyProvider constant names, strict key decoding,
	 * extended WordPress salt-derivation rejection, and zero key leakage in exceptions.
	 */
	public function test_regression_canonical_key_constants_strict_decoding_and_salt_rejection(): void {
		self::assertSame( 'WPIG_ENC_KEY', WordPressKeyProvider::CONST_ENC_KEY );
		self::assertSame( 'WPIG_ENC_KEY_ID', WordPressKeyProvider::CONST_ENC_KEY_ID );
		self::assertSame( 'WPIG_ENC_KEYS_PREVIOUS', WordPressKeyProvider::CONST_ENC_KEYS_PREVIOUS );
		self::assertSame( 'WPIG_HMAC_KEY', WordPressKeyProvider::CONST_HMAC_KEY );
		self::assertSame( 'WPIG_HMAC_KEY_ID', WordPressKeyProvider::CONST_HMAC_KEY_ID );
		self::assertSame( 'WPIG_HMAC_KEYS_PREVIOUS', WordPressKeyProvider::CONST_HMAC_KEYS_PREVIOUS );

		// Unencoded 32-character ASCII passphrases must be rejected by strict key decoding.
		$ascii_passphrase = 'ChangeMe_WordPress_Secret_Key_01';
		self::assertSame( 32, strlen( $ascii_passphrase ) );
		$passphrase_provider = $this->make_provider(
			array( WordPressKeyProvider::CONST_ENC_KEY => $ascii_passphrase )
		);
		try {
			$passphrase_provider->get_active_encryption_key();
			self::fail( 'Unencoded 32-character ASCII passphrase must be rejected.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_KEY_INVALID, $e->get_safe_code() );
			self::assertStringNotContainsString( $ascii_passphrase, $e->getMessage() );
		}

		// Base64 keys with embedded whitespace or non-canonical padding bits must be rejected.
		$raw_bytes = hex2bin( substr( self::SYNTHETIC_ENC_KEY_1, 4 ) );
		self::assertIsString( $raw_bytes );
		$canonical_b64  = base64_encode( $raw_bytes ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Test vector construction.
		$whitespace_b64 = 'base64: ' . $canonical_b64;

		$ws_provider = $this->make_provider(
			array( WordPressKeyProvider::CONST_ENC_KEY => $whitespace_b64 )
		);
		self::assertFalse( $ws_provider->is_configured() );

		// Base64-encoded or SHA-256-derived WordPress salt (e.g. SECURE_AUTH_SALT) must be rejected.
		$wp_salt_raw     = 'wp-site-salt-value-with-32-bytes';
		$wp_salt_sha_hex = 'hex:' . hash( 'sha256', $wp_salt_raw );
		$salt_derived    = $this->make_provider(
			array(
				'SECURE_AUTH_SALT'                  => $wp_salt_raw,
				WordPressKeyProvider::CONST_ENC_KEY => $wp_salt_sha_hex,
			)
		);
		try {
			$salt_derived->get_active_encryption_key();
			self::fail( 'Key derived via SHA-256 from SECURE_AUTH_SALT must be rejected.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_KEY_INVALID, $e->get_safe_code() );
			self::assertStringNotContainsString( $wp_salt_raw, $e->getMessage() );
			self::assertStringNotContainsString( $wp_salt_sha_hex, $e->getMessage() );
		}
	}

	/**
	 * 21. Regression: Verify SensitiveValue::wipe() clears internal reference to null
	 * and SodiumCrypto cleans up temporary buffers via try/finally on error paths.
	 */
	public function test_regression_sensitive_memory_cleanup_and_reference_clearing(): void {
		$sv = new SensitiveValue( 'SYNTHETIC_SECRET_BUFFER' );
		$sv->wipe();

		$ref_prop = new \ReflectionProperty( SensitiveValue::class, 'value' );
		self::assertNull( $ref_prop->getValue( $sv ), 'SensitiveValue::$value must be explicitly null after wipe().' );
		self::assertTrue( $sv->is_wiped() );
		self::assertSame( 0, $sv->length() );

		// Verify SodiumCrypto::encrypt() does not corrupt caller SensitiveValue when AAD validation fails.
		$crypto    = new SodiumCrypto( $this->make_provider() );
		$caller_sv = new SensitiveValue( 'SYNTHETIC_CALLER_PLAINTEXT' );

		try {
			$crypto->encrypt( $caller_sv, 'invalid_aad_string' );
			self::fail( 'Expected CryptoException for invalid AAD.' );
		} catch ( CryptoException $e ) {
			self::assertSame( CryptoException::CODE_AAD_INVALID, $e->get_safe_code() );
		}

		self::assertFalse( $caller_sv->is_wiped(), 'Caller SensitiveValue must remain intact when encrypt() fails AAD validation.' );
		self::assertSame( 'SYNTHETIC_CALLER_PLAINTEXT', $caller_sv->reveal() );
	}
}

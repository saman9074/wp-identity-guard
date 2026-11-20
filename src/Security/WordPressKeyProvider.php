<?php
/**
 * WordPress key provider supporting K1 (wp-config.php constants) and K2 (environment variables).
 *
 * @package WPIG\Security
 */

declare(strict_types=1);

namespace WPIG\Security;

use SensitiveParameter;
use WPIG\Contracts\KeyProviderInterface;

/**
 * Resolves and validates 256-bit encryption and HMAC keys from K1
 * (`wp-config.php` constants) or K2 (environment variables).
 *
 * Security invariants (DS-1):
 * - Never reads keys from `wp_options` or any database table.
 * - Never derives keys from WordPress salts (`AUTH_KEY`, etc.).
 * - Requires 256-bit (32-byte) keys with sufficient byte entropy.
 * - Enforces strict cryptographic separation between encryption and HMAC keys.
 * - Supports read-only previous keyrings (`WPIG_ENC_KEYS_PREVIOUS`, `WPIG_HMAC_KEYS_PREVIOUS`).
 * - Fails closed when required keys are missing or invalid.
 */
final class WordPressKeyProvider implements KeyProviderInterface {

	public const CONST_ENC_KEY            = 'WPIG_ENC_KEY';
	public const CONST_ENC_KEY_ID         = 'WPIG_ENC_KEY_ID';
	public const CONST_ENC_KEYS_PREVIOUS  = 'WPIG_ENC_KEYS_PREVIOUS';
	public const CONST_HMAC_KEY           = 'WPIG_HMAC_KEY';
	public const CONST_HMAC_KEY_ID        = 'WPIG_HMAC_KEY_ID';
	public const CONST_HMAC_KEYS_PREVIOUS = 'WPIG_HMAC_KEYS_PREVIOUS';

	/**
	 * Required raw key length in bytes (256 bits).
	 */
	public const KEY_LENGTH_BYTES = 32;

	/**
	 * Default HMAC key ID when WPIG_HMAC_KEY_ID is not explicitly set.
	 */
	public const DEFAULT_HMAC_KEY_ID = 'hmac_v1';

	/**
	 * Constant reader callback (`fn(string $name): mixed`).
	 *
	 * @var callable
	 * @phpstan-var callable(string):mixed
	 */
	private $const_reader;

	/**
	 * Environment variable reader callback (`fn(string $name): string|false`).
	 *
	 * @var callable
	 * @phpstan-var callable(string):(string|false)
	 */
	private $env_reader;

	/**
	 * Validated active encryption key ID.
	 *
	 * @var string|null
	 */
	private ?string $active_enc_key_id = null;

	/**
	 * Validated active + previous encryption keyring (`key_id => SensitiveValue`).
	 *
	 * @var array<string,SensitiveValue>|null
	 */
	private ?array $enc_keyring = null;

	/**
	 * Validated active HMAC key ID.
	 *
	 * @var string|null
	 */
	private ?string $active_hmac_key_id = null;

	/**
	 * Validated active + previous HMAC keyring (`key_id => SensitiveValue`).
	 *
	 * @var array<string,SensitiveValue>|null
	 */
	private ?array $hmac_keyring = null;

	/**
	 * Constructor.
	 *
	 * @param callable|null $const_reader Optional constant lookup override for unit testing.
	 * @param callable|null $env_reader   Optional environment lookup override for unit testing.
	 * @phpstan-param (callable(string):mixed)|null $const_reader
	 * @phpstan-param (callable(string):(string|false))|null $env_reader
	 */
	public function __construct( ?callable $const_reader = null, ?callable $env_reader = null ) {
		$this->const_reader = $const_reader ?? static function ( string $name ): mixed {
			if ( ! defined( $name ) ) {
				return null;
			}
			$val = constant( $name );
			// Preserve distinction between an undefined constant (null) and a defined-as-null constant ('').
			return null === $val ? '' : $val;
		};
		$this->env_reader   = $env_reader ?? static function ( string $name ): string|false {
			return getenv( $name );
		};
	}

	/**
	 * Destructor wipes any cached SensitiveValue keys in memory.
	 */
	public function __destruct() {
		if ( is_array( $this->enc_keyring ) ) {
			foreach ( $this->enc_keyring as $key ) {
				$key->wipe();
			}
		}
		if ( is_array( $this->hmac_keyring ) ) {
			foreach ( $this->hmac_keyring as $key ) {
				$key->wipe();
			}
		}
	}

	/**
	 * Generate a cryptographically secure 256-bit key encoded as `base64:<standard_b64>`.
	 *
	 * @return SensitiveValue Encoded key string suitable for K1/K2 configuration.
	 * @throws CryptoException If CSPRNG or libsodium is unavailable.
	 */
	public static function generate_encoded_key(): SensitiveValue {
		$raw     = null;
		$encoded = null;

		try {
			try {
				if ( function_exists( 'sodium_crypto_aead_xchacha20poly1305_ietf_keygen' ) ) {
					$raw = sodium_crypto_aead_xchacha20poly1305_ietf_keygen();
				} else {
					$raw = random_bytes( self::KEY_LENGTH_BYTES );
				}
			} catch ( \Throwable ) {
				CryptoException::raise(
					CryptoException::CODE_SODIUM_UNAVAILABLE,
					'Cryptographically secure key generation failed.'
				);
			}

			$encoded = 'base64:' . base64_encode( $raw ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Key serialization format.
			return new SensitiveValue( $encoded );
		} finally {
			if ( function_exists( 'sodium_memzero' ) ) {
				if ( is_string( $raw ) ) {
					sodium_memzero( $raw );
				}
				if ( is_string( $encoded ) ) {
					sodium_memzero( $encoded );
				}
			}
		}
	}

	/**
	 * Return the active encryption key identifier.
	 *
	 * @throws CryptoException If keys are missing or invalid.
	 */
	public function get_active_encryption_key_id(): string {
		$this->ensure_loaded();
		assert( null !== $this->active_enc_key_id );
		return $this->active_enc_key_id;
	}

	/**
	 * Return the active 32-byte raw encryption key wrapped in SensitiveValue.
	 *
	 * @throws CryptoException If keys are missing or invalid.
	 */
	public function get_active_encryption_key(): SensitiveValue {
		$this->ensure_loaded();
		assert( null !== $this->active_enc_key_id && null !== $this->enc_keyring );
		return new SensitiveValue( $this->enc_keyring[ $this->active_enc_key_id ]->reveal() );
	}

	/**
	 * Resolve a 32-byte raw encryption key by key ID from the active or previous keyring.
	 *
	 * @param string $key_id Key identifier.
	 * @return SensitiveValue 32-byte raw encryption key.
	 * @throws CryptoException If the key ID is invalid, unknown, or keys are unconfigured.
	 */
	public function get_encryption_key( string $key_id ): SensitiveValue {
		CanonicalAad::assert_valid_key_id( $key_id );
		$this->ensure_loaded();
		assert( null !== $this->enc_keyring );

		if ( ! isset( $this->enc_keyring[ $key_id ] ) ) {
			CryptoException::raise(
				CryptoException::CODE_KEY_UNKNOWN,
				sprintf( 'Encryption key ID "%s" is not present in the configured keyring.', $key_id )
			);
		}

		return new SensitiveValue( $this->enc_keyring[ $key_id ]->reveal() );
	}

	/**
	 * Return the list of configured encryption key IDs (active first, then previous).
	 *
	 * @return string[]
	 * @phpstan-return list<string>
	 * @throws CryptoException If keys are missing or invalid.
	 */
	public function get_encryption_key_ids(): array {
		$this->ensure_loaded();
		assert( null !== $this->enc_keyring );
		return array_keys( $this->enc_keyring );
	}

	/**
	 * Return the active HMAC key identifier.
	 *
	 * @throws CryptoException If keys are missing or invalid.
	 */
	public function get_active_hmac_key_id(): string {
		$this->ensure_loaded();
		assert( null !== $this->active_hmac_key_id );
		return $this->active_hmac_key_id;
	}

	/**
	 * Return the active 32-byte raw HMAC key wrapped in SensitiveValue.
	 *
	 * @throws CryptoException If keys are missing or invalid.
	 */
	public function get_active_hmac_key(): SensitiveValue {
		$this->ensure_loaded();
		assert( null !== $this->active_hmac_key_id && null !== $this->hmac_keyring );
		return new SensitiveValue( $this->hmac_keyring[ $this->active_hmac_key_id ]->reveal() );
	}

	/**
	 * Resolve a 32-byte raw HMAC key by key ID from the active or previous keyring.
	 *
	 * @param string $key_id Key identifier.
	 * @return SensitiveValue 32-byte raw HMAC key.
	 * @throws CryptoException If the key ID is invalid, unknown, or keys are unconfigured.
	 */
	public function get_hmac_key( string $key_id ): SensitiveValue {
		CanonicalAad::assert_valid_key_id( $key_id );
		$this->ensure_loaded();
		assert( null !== $this->hmac_keyring );

		if ( ! isset( $this->hmac_keyring[ $key_id ] ) ) {
			CryptoException::raise(
				CryptoException::CODE_KEY_UNKNOWN,
				sprintf( 'HMAC key ID "%s" is not present in the configured keyring.', $key_id )
			);
		}

		return new SensitiveValue( $this->hmac_keyring[ $key_id ]->reveal() );
	}

	/**
	 * Return true if both encryption and HMAC keys are present, valid, and distinct.
	 */
	public function is_configured(): bool {
		try {
			$this->ensure_loaded();
			return true;
		} catch ( CryptoException ) {
			return false;
		}
	}

	/**
	 * Load and validate K1/K2 keys once per provider instance.
	 *
	 * @throws CryptoException On any missing, malformed, weak, or non-separated key.
	 */
	private function ensure_loaded(): void {
		if ( null !== $this->enc_keyring && null !== $this->hmac_keyring ) {
			return;
		}

		$raw_enc_key_id = $this->read_setting( self::CONST_ENC_KEY_ID );
		if ( ! is_string( $raw_enc_key_id ) || '' === trim( $raw_enc_key_id ) ) {
			CryptoException::raise(
				CryptoException::CODE_KEY_ID_INVALID,
				'Required encryption key identifier (WPIG_ENC_KEY_ID) is missing.'
			);
		}
		$enc_key_id = trim( $raw_enc_key_id );
		CanonicalAad::assert_valid_key_id( $enc_key_id );

		$raw_enc_key = $this->read_setting( self::CONST_ENC_KEY );
		if ( ! is_string( $raw_enc_key ) || '' === $raw_enc_key ) {
			CryptoException::raise(
				CryptoException::CODE_KEY_MISSING,
				'Required encryption key (WPIG_ENC_KEY) is missing.'
			);
		}

		$raw_hmac_key = $this->read_setting( self::CONST_HMAC_KEY );
		if ( ! is_string( $raw_hmac_key ) || '' === $raw_hmac_key ) {
			CryptoException::raise(
				CryptoException::CODE_KEY_MISSING,
				'Required HMAC key (WPIG_HMAC_KEY) is missing.'
			);
		}

		$raw_hmac_key_id = $this->read_setting( self::CONST_HMAC_KEY_ID );
		$hmac_key_id     = is_string( $raw_hmac_key_id ) && '' !== trim( $raw_hmac_key_id )
			? trim( $raw_hmac_key_id )
			: self::DEFAULT_HMAC_KEY_ID;
		CanonicalAad::assert_valid_key_id( $hmac_key_id );

		$enc_ring  = array();
		$hmac_ring = array();

		try {
			$enc_ring[ $enc_key_id ] = $this->decode_and_validate_key( $raw_enc_key, self::CONST_ENC_KEY );

			$prev_enc = $this->parse_previous_keys(
				$this->read_setting( self::CONST_ENC_KEYS_PREVIOUS ),
				self::CONST_ENC_KEYS_PREVIOUS
			);
			foreach ( $prev_enc as $prev_id => $prev_key ) {
				if ( isset( $enc_ring[ $prev_id ] ) ) {
					$prev_key->wipe();
					CryptoException::raise(
						CryptoException::CODE_KEY_ID_INVALID,
						sprintf( 'Duplicate encryption key ID "%s" in WPIG_ENC_KEYS_PREVIOUS.', $prev_id )
					);
				}
				$enc_ring[ $prev_id ] = $prev_key;
			}

			$hmac_ring[ $hmac_key_id ] = $this->decode_and_validate_key( $raw_hmac_key, self::CONST_HMAC_KEY );

			$prev_hmac = $this->parse_previous_keys(
				$this->read_setting( self::CONST_HMAC_KEYS_PREVIOUS ),
				self::CONST_HMAC_KEYS_PREVIOUS
			);
			foreach ( $prev_hmac as $prev_id => $prev_key ) {
				if ( isset( $hmac_ring[ $prev_id ] ) ) {
					$prev_key->wipe();
					CryptoException::raise(
						CryptoException::CODE_KEY_ID_INVALID,
						sprintf( 'Duplicate HMAC key ID "%s" in WPIG_HMAC_KEYS_PREVIOUS.', $prev_id )
					);
				}
				$hmac_ring[ $prev_id ] = $prev_key;
			}

			// Enforce strict cryptographic separation between all encryption and HMAC keys (DS-1).
			foreach ( $enc_ring as $enc_val ) {
				foreach ( $hmac_ring as $hmac_val ) {
					if ( $enc_val->equals( $hmac_val ) ) {
						CryptoException::raise(
							CryptoException::CODE_KEY_SEPARATION,
							'Encryption key and HMAC key must be cryptographically distinct (DS-1).'
						);
					}
				}
			}
		} catch ( CryptoException $e ) {
			foreach ( $enc_ring as $key_val ) {
				$key_val->wipe();
			}
			foreach ( $hmac_ring as $key_val ) {
				$key_val->wipe();
			}
			throw $e;
		}

		$this->active_enc_key_id  = $enc_key_id;
		$this->enc_keyring        = $enc_ring;
		$this->active_hmac_key_id = $hmac_key_id;
		$this->hmac_keyring       = $hmac_ring;
	}

	/**
	 * Read a configuration setting from K1 (constants) or K2 (environment variables).
	 *
	 * Security invariant: If any WPIG_* key constant is defined in K1, the provider
	 * operates strictly in K1 mode and never falls back to K2 environment variables
	 * for missing, empty, or invalid K1 constants.
	 *
	 * @param string $name Constant / environment variable name.
	 * @return mixed
	 */
	private function read_setting( string $name ): mixed {
		$const_val = ( $this->const_reader )( $name );
		if ( null !== $const_val ) {
			return $const_val;
		}

		if ( $this->has_any_k1_constant() ) {
			return null;
		}

		$env_val = ( $this->env_reader )( $name );
		if ( false !== $env_val && '' !== $env_val ) {
			return $env_val;
		}

		return null;
	}

	/**
	 * Return true if any WPIG key constant is defined in K1 (`wp-config.php`).
	 */
	private function has_any_k1_constant(): bool {
		$k1_names = array(
			self::CONST_ENC_KEY,
			self::CONST_ENC_KEY_ID,
			self::CONST_ENC_KEYS_PREVIOUS,
			self::CONST_HMAC_KEY,
			self::CONST_HMAC_KEY_ID,
			self::CONST_HMAC_KEYS_PREVIOUS,
		);

		foreach ( $k1_names as $k1_name ) {
			if ( null !== ( $this->const_reader )( $k1_name ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Strictly decode and validate a 32-byte key from canonical `base64:<44_chars>`,
	 * `hex:<64_hex>`, or 64-character hexadecimal encoding.
	 *
	 * Rejects unencoded 32-character ASCII passphrases, whitespace, non-canonical
	 * base64 padding, wrong key lengths, WordPress salts, and weak placeholders.
	 *
	 * @param string $raw_input Raw configured key string.
	 * @param string $label     Safe setting label for error reporting.
	 * @return SensitiveValue Validated 32-byte binary key.
	 * @throws CryptoException If key encoding, length, salt check, or sanity check fails.
	 */
	private function decode_and_validate_key(
		#[SensitiveParameter] string $raw_input,
		string $label
	): SensitiveValue {
		$bin     = null;
		$decoded = null;

		try {
			$this->assert_not_wp_salt( $raw_input, null, $label );

			if ( str_starts_with( $raw_input, 'base64:' ) ) {
				$b64 = substr( $raw_input, 7 );
				if ( 1 === preg_match( '/^[A-Za-z0-9+\/]{43}=$/', $b64 ) ) {
					$bin = base64_decode( $b64, true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Key decoding.
					if (
						is_string( $bin )
						&& self::KEY_LENGTH_BYTES === strlen( $bin )
						&& hash_equals( base64_encode( $bin ), $b64 ) // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Canonical round-trip check.
					) {
						$decoded = $bin;
					}
				}
			} elseif ( str_starts_with( $raw_input, 'hex:' ) ) {
				$hex = substr( $raw_input, 4 );
				if ( 1 === preg_match( '/^[0-9a-fA-F]{64}$/', $hex ) ) {
					$bin = hex2bin( $hex );
					if ( is_string( $bin ) && self::KEY_LENGTH_BYTES === strlen( $bin ) ) {
						$decoded = $bin;
					}
				}
			} elseif ( 1 === preg_match( '/^[0-9a-fA-F]{64}$/', $raw_input ) ) {
				$bin = hex2bin( $raw_input );
				if ( is_string( $bin ) && self::KEY_LENGTH_BYTES === strlen( $bin ) ) {
					$decoded = $bin;
				}
			}

			if ( ! is_string( $decoded ) || self::KEY_LENGTH_BYTES !== strlen( $decoded ) ) {
				CryptoException::raise(
					CryptoException::CODE_KEY_INVALID,
					sprintf( '%s must decode to exactly %d bytes (256 bits) from canonical base64 or hex.', $label, self::KEY_LENGTH_BYTES )
				);
			}

			$this->assert_not_wp_salt( $raw_input, $decoded, $label );

			// Sanity guard against accidental placeholder/zeroed inputs (e.g. all-zero or repeated bytes).
			// Note: This heuristic is NOT a proof of cryptographic entropy; cryptographic strength relies on
			// CSPRNG key generation via generate_encoded_key() / sodium_crypto_aead_xchacha20poly1305_ietf_keygen().
			$unique_bytes = count( count_chars( $decoded, 1 ) );
			if ( $unique_bytes < 8 ) {
				CryptoException::raise(
					CryptoException::CODE_KEY_INVALID,
					sprintf( '%s failed weak-placeholder key sanity check.', $label )
				);
			}

			return new SensitiveValue( $decoded );
		} finally {
			if ( function_exists( 'sodium_memzero' ) ) {
				if ( is_string( $decoded ) ) {
					sodium_memzero( $decoded );
				}
				if ( is_string( $bin ) ) {
					sodium_memzero( $bin );
				}
			}
		}
	}

	/**
	 * Ensure the configured key does not reuse or directly wrap a WordPress salt constant (K3 rejection).
	 *
	 * @param string      $raw_input     Configured key value.
	 * @param string|null $decoded_bytes Decoded 32-byte key material (if already decoded).
	 * @param string      $label         Safe setting label.
	 * @throws CryptoException If the key matches or derives directly from a WordPress salt.
	 */
	private function assert_not_wp_salt(
		#[SensitiveParameter] string $raw_input,
		#[SensitiveParameter] ?string $decoded_bytes,
		string $label
	): void {
		$salt_constants = array(
			'AUTH_KEY',
			'SECURE_AUTH_KEY',
			'LOGGED_IN_KEY',
			'NONCE_KEY',
			'AUTH_SALT',
			'SECURE_AUTH_SALT',
			'LOGGED_IN_SALT',
			'NONCE_SALT',
		);

		foreach ( $salt_constants as $salt_name ) {
			$salt_val = ( $this->const_reader )( $salt_name );
			if ( ! is_string( $salt_val ) || '' === $salt_val ) {
				continue;
			}

			if ( hash_equals( $salt_val, $raw_input ) ) {
				CryptoException::raise(
					CryptoException::CODE_KEY_INVALID,
					sprintf( '%s must not reuse WordPress salt constant %s (DS-1).', $label, $salt_name )
				);
			}

			if ( is_string( $decoded_bytes ) ) {
				$salt_sha256 = hash( 'sha256', $salt_val, true );
				if (
					( strlen( $salt_val ) === self::KEY_LENGTH_BYTES && hash_equals( $salt_val, $decoded_bytes ) )
					|| hash_equals( $salt_sha256, $decoded_bytes )
				) {
					CryptoException::raise(
						CryptoException::CODE_KEY_INVALID,
						sprintf( '%s must not reuse or derive from WordPress salt constant %s (DS-1).', $label, $salt_name )
					);
				}
			}
		}
	}

	/**
	 * Parse optional previous keyring from an array, JSON object, or `key_id=material,key_id2=material2` string.
	 *
	 * @param mixed  $raw_previous Raw previous keys configuration.
	 * @param string $label        Safe setting label.
	 * @return array<string,SensitiveValue>
	 * @throws CryptoException If previous keyring format or any key within it is invalid.
	 */
	private function parse_previous_keys(
		#[SensitiveParameter] mixed $raw_previous,
		string $label
	): array {
		if ( null === $raw_previous || '' === $raw_previous || array() === $raw_previous ) {
			return array();
		}

		$entries = array();

		if ( is_array( $raw_previous ) ) {
			$entries = $raw_previous;
		} elseif ( is_string( $raw_previous ) ) {
			$trimmed = trim( $raw_previous );
			if ( '' === $trimmed ) {
				return array();
			}

			if ( str_starts_with( $trimmed, '{' ) ) {
				$decoded_json = json_decode( $trimmed, true );
				if ( ! is_array( $decoded_json ) ) {
					CryptoException::raise(
						CryptoException::CODE_KEY_INVALID,
						sprintf( '%s contains malformed JSON keyring configuration.', $label )
					);
				}
				$entries = $decoded_json;
			} else {
				$pairs = explode( ',', $trimmed );
				foreach ( $pairs as $pair ) {
					$pair = trim( $pair );
					if ( '' === $pair ) {
						continue;
					}
					$parts = explode( '=', $pair, 2 );
					if ( 2 !== count( $parts ) ) {
						CryptoException::raise(
							CryptoException::CODE_KEY_INVALID,
							sprintf( '%s entries must use key_id=encoded_key format.', $label )
						);
					}
					$k_id = trim( $parts[0] );
					if ( isset( $entries[ $k_id ] ) ) {
						CryptoException::raise(
							CryptoException::CODE_KEY_ID_INVALID,
							sprintf( 'Duplicate key ID "%s" in %s.', $k_id, $label )
						);
					}
					$entries[ $k_id ] = trim( $parts[1] );
				}
			}
		} else {
			CryptoException::raise(
				CryptoException::CODE_KEY_INVALID,
				sprintf( '%s must be an array, JSON object, or comma-separated keyring string.', $label )
			);
		}

		$ring = array();
		foreach ( $entries as $key_id => $raw_key ) {
			if ( ! is_string( $key_id ) || ! is_string( $raw_key ) || '' === $raw_key ) {
				CryptoException::raise(
					CryptoException::CODE_KEY_INVALID,
					sprintf( '%s contains an invalid key_id or key value.', $label )
				);
			}
			CanonicalAad::assert_valid_key_id( $key_id );
			$ring[ $key_id ] = $this->decode_and_validate_key( $raw_key, "{$label}[{$key_id}]" );
		}

		return $ring;
	}
}

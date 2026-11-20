<?php
/**
 * Centralized builder and validator for canonical AEAD Associated Data (AAD).
 *
 * @package WPIG\Security
 */

declare(strict_types=1);

namespace WPIG\Security;

/**
 * Builds and validates the canonical v1 AEAD Associated Data (AAD) string.
 *
 * Format: `wpig|v1|blog:<blog_id>|<entity_type>:<entity_name>|<subject_id>|<key_id>`
 *
 * Enforces cross-site (`blog_id`), cross-table/column, cross-option,
 * cross-user (`subject_id`), and key-ID cryptographic binding (docs/p01/P01-B1-database-schema.md §2.1).
 */
final class CanonicalAad {

	/**
	 * Canonical AAD protocol prefix.
	 */
	public const PREFIX = 'wpig';

	/**
	 * Canonical AAD format version.
	 */
	public const VERSION = 'v1';

	/**
	 * Allowed entity type for database table columns.
	 */
	public const ENTITY_TYPE_TABLE = 'table';

	/**
	 * Allowed entity type for site options.
	 */
	public const ENTITY_TYPE_OPTION = 'option';

	/**
	 * Build a canonical AAD string for a user-scoped custom table column.
	 *
	 * Example output:
	 * `wpig|v1|blog:1|table:wpig_profiles.national_code_ciphertext|42|k2026_01`
	 *
	 * @param int    $blog_id       Site blog ID (>= 1).
	 * @param string $logical_table Unprefixed logical table name (e.g. 'wpig_profiles').
	 * @param string $column_name   Column name (e.g. 'national_code_ciphertext').
	 * @param int    $wp_user_id    WordPress user ID (>= 1).
	 * @param string $key_id        Encryption key identifier.
	 * @return string Canonical AAD string.
	 * @throws CryptoException If any segment violates canonical format rules.
	 */
	public static function for_table_column(
		int $blog_id,
		string $logical_table,
		string $column_name,
		int $wp_user_id,
		string $key_id
	): string {
		return self::build(
			$blog_id,
			self::ENTITY_TYPE_TABLE,
			$logical_table . '.' . $column_name,
			$wp_user_id,
			$key_id
		);
	}

	/**
	 * Build a canonical AAD string for a site-level encrypted wp_options entry.
	 *
	 * Example output:
	 * `wpig|v1|blog:1|option:wpig_provider_credentials|0|k2026_01`
	 *
	 * @param int    $blog_id     Site blog ID (>= 1).
	 * @param string $option_name Option name (e.g. 'wpig_provider_credentials').
	 * @param string $key_id      Encryption key identifier.
	 * @return string Canonical AAD string.
	 * @throws CryptoException If any segment violates canonical format rules.
	 */
	public static function for_option(
		int $blog_id,
		string $option_name,
		string $key_id
	): string {
		return self::build(
			$blog_id,
			self::ENTITY_TYPE_OPTION,
			$option_name,
			0,
			$key_id
		);
	}

	/**
	 * Build and validate a canonical 6-segment AAD string.
	 *
	 * @param int    $blog_id     Site blog ID (>= 1).
	 * @param string $entity_type Entity type ('table' or 'option').
	 * @param string $entity_name Entity name ('wpig_<table>.<column>' or 'wpig_<option>').
	 * @param int    $subject_id  WP user ID (>= 1 for 'table', 0 for 'option').
	 * @param string $key_id      Encryption key ID ([A-Za-z0-9._-]{1,32}).
	 * @return string Deterministic canonical AAD string.
	 * @throws CryptoException If any parameter is invalid.
	 */
	public static function build(
		int $blog_id,
		string $entity_type,
		string $entity_name,
		int $subject_id,
		string $key_id
	): string {
		self::assert_valid_components( $blog_id, $entity_type, $entity_name, $subject_id, $key_id );

		return sprintf(
			'%s|%s|blog:%d|%s:%s|%d|%s',
			self::PREFIX,
			self::VERSION,
			$blog_id,
			$entity_type,
			$entity_name,
			$subject_id,
			$key_id
		);
	}

	/**
	 * Validate a canonical AAD string and optionally verify that its key_id
	 * segment matches an expected encryption key ID.
	 *
	 * @param string      $aad             Canonical AAD string to validate.
	 * @param string|null $expected_key_id Optional expected key_id segment.
	 * @return array{blog_id:int,entity_type:string,entity_name:string,subject_id:int,key_id:string}
	 * @throws CryptoException If the AAD is malformed or its key_id mismatches.
	 */
	public static function validate( string $aad, ?string $expected_key_id = null ): array {
		$segments = explode( '|', $aad );
		if ( 6 !== count( $segments ) ) {
			CryptoException::raise(
				CryptoException::CODE_AAD_INVALID,
				'Canonical AAD must contain exactly 6 pipe-delimited segments.'
			);
		}

		list( $prefix, $version, $blog_segment, $entity_segment, $subject_segment, $key_id ) = $segments;

		if ( self::PREFIX !== $prefix || self::VERSION !== $version ) {
			CryptoException::raise(
				CryptoException::CODE_AAD_INVALID,
				'Canonical AAD prefix or version is invalid.'
			);
		}

		if ( 1 !== preg_match( '/^blog:([1-9][0-9]*)$/', $blog_segment, $blog_matches ) ) {
			CryptoException::raise(
				CryptoException::CODE_AAD_INVALID,
				'Canonical AAD blog segment must be blog:<positive_int>.'
			);
		}
		$blog_id = (int) $blog_matches[1];

		$entity_parts = explode( ':', $entity_segment );
		if ( 2 !== count( $entity_parts ) ) {
			CryptoException::raise(
				CryptoException::CODE_AAD_INVALID,
				'Canonical AAD entity segment must be <entity_type>:<entity_name>.'
			);
		}
		list( $entity_type, $entity_name ) = $entity_parts;

		if ( 1 !== preg_match( '/^(0|[1-9][0-9]*)$/', $subject_segment ) ) {
			CryptoException::raise(
				CryptoException::CODE_AAD_INVALID,
				'Canonical AAD subject_id segment must be a canonical non-negative integer.'
			);
		}
		$subject_id = (int) $subject_segment;

		self::assert_valid_components( $blog_id, $entity_type, $entity_name, $subject_id, $key_id );

		if ( null !== $expected_key_id && $key_id !== $expected_key_id ) {
			CryptoException::raise(
				CryptoException::CODE_AAD_KEY_MISMATCH,
				'Canonical AAD key_id does not match the target encryption key ID.'
			);
		}

		return array(
			'blog_id'     => $blog_id,
			'entity_type' => $entity_type,
			'entity_name' => $entity_name,
			'subject_id'  => $subject_id,
			'key_id'      => $key_id,
		);
	}

	/**
	 * Validate a key identifier format (`[A-Za-z0-9._-]{1,32}`).
	 *
	 * @param string $key_id Key identifier to check.
	 * @throws CryptoException If the key identifier is invalid.
	 */
	public static function assert_valid_key_id( string $key_id ): void {
		if ( 1 !== preg_match( '/^[A-Za-z0-9._-]{1,32}$/', $key_id ) ) {
			CryptoException::raise(
				CryptoException::CODE_KEY_ID_INVALID,
				'Key ID must be 1..32 ASCII characters matching [A-Za-z0-9._-].'
			);
		}
	}

	/**
	 * Validate individual AAD components.
	 *
	 * @param int    $blog_id     Site blog ID.
	 * @param string $entity_type Entity type ('table' or 'option').
	 * @param string $entity_name Entity name.
	 * @param int    $subject_id  Subject ID.
	 * @param string $key_id      Key ID.
	 * @throws CryptoException If any component violates canonical constraints.
	 */
	private static function assert_valid_components(
		int $blog_id,
		string $entity_type,
		string $entity_name,
		int $subject_id,
		string $key_id
	): void {
		if ( $blog_id < 1 ) {
			CryptoException::raise(
				CryptoException::CODE_AAD_INVALID,
				'Canonical AAD blog_id must be >= 1.'
			);
		}

		if ( self::ENTITY_TYPE_TABLE === $entity_type ) {
			if ( 1 !== preg_match( '/^wpig_[a-z0-9_]+\.[a-z0-9_]+$/', $entity_name ) ) {
				CryptoException::raise(
					CryptoException::CODE_AAD_INVALID,
					'Table entity_name must match wpig_<table>.<column>.'
				);
			}
			if ( $subject_id < 1 ) {
				CryptoException::raise(
					CryptoException::CODE_AAD_INVALID,
					'Table AAD subject_id (wp_user_id) must be >= 1.'
				);
			}
		} elseif ( self::ENTITY_TYPE_OPTION === $entity_type ) {
			if ( 1 !== preg_match( '/^wpig_[a-z0-9_]+$/', $entity_name ) ) {
				CryptoException::raise(
					CryptoException::CODE_AAD_INVALID,
					'Option entity_name must match wpig_<option_name>.'
				);
			}
			if ( 0 !== $subject_id ) {
				CryptoException::raise(
					CryptoException::CODE_AAD_INVALID,
					'Option AAD subject_id must be 0.'
				);
			}
		} else {
			CryptoException::raise(
				CryptoException::CODE_AAD_INVALID,
				'Canonical AAD entity_type must be "table" or "option".'
			);
		}

		if ( 1 !== preg_match( '/^[A-Za-z0-9._-]{1,32}$/', $key_id ) ) {
			CryptoException::raise(
				CryptoException::CODE_AAD_INVALID,
				'Canonical AAD key_id must be 1..32 ASCII characters matching [A-Za-z0-9._-].'
			);
		}
	}
}

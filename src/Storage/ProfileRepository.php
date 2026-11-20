<?php
/**
 * Secure persistence repository for WP Identity Guard user profiles.
 *
 * @package WPIG\Storage
 */

declare(strict_types=1);

namespace WPIG\Storage;

use SensitiveParameter;
use wpdb;
use WPIG\Contracts\CryptoInterface;
use WPIG\Contracts\KeyProviderInterface;
use WPIG\Security\CanonicalAad;
use WPIG\Security\CryptoException;
use WPIG\Security\DataMasker;
use WPIG\Security\IdentityFingerprinter;
use WPIG\Security\IdentityNormalizer;
use WPIG\Security\SensitiveValue;
use WPIG\Security\ValidationException;

/**
 * Connects `wpig_profiles` database persistence with `IdentityNormalizer`,
 * `CryptoInterface` (`SodiumCrypto`), `KeyProviderInterface`, `IdentityFingerprinter`,
 * `CanonicalAad`, and `DataMasker`.
 *
 * Security & Concurrency Invariants (DS-1..DS-4, D14):
 * - Never persists plaintext identity attributes; stores only AEAD ciphertexts,
 *   purpose-separated HMAC-SHA-256 digests, and masked display strings.
 * - Performs normalization, validation, encryption, and HMAC computation before
 *   mutating database state so validation/crypto failures fail closed without
 *   overwriting valid persisted data.
 * - Uses short database transactions (`START TRANSACTION` + `SELECT ... FOR UPDATE` + `COMMIT`/`ROLLBACK`).
 * - Enforces granular version counters (`identity_version`, `mobile_version`, `card_version`).
 * - Enforces `D14` identity binding invariants (`UNBOUND` profiles never reserve a
 *   national code; `BOUND` identity persists across verification expiry; regular
 *   profile updates can never set `BOUND` or overwrite a bound identity).
 * - Never exposes raw database rows through public APIs.
 *
 * @internal Persistence component only. Application callers must enforce authorization
 *           and trusted verification boundaries via `AuthorizationService` and `ProfileAccessBoundary`.
 */
final class ProfileRepository {

	/**
	 * Unprefixed logical table name for AAD and schema mapping.
	 */
	public const LOGICAL_TABLE = 'wpig_profiles';

	/**
	 * Encrypted column names in `wpig_profiles`.
	 */
	public const COL_MOBILE_CIPHERTEXT        = 'mobile_ciphertext';
	public const COL_NATIONAL_CODE_CIPHERTEXT = 'national_code_ciphertext';
	public const COL_BIRTH_DATE_CIPHERTEXT    = 'birth_date_ciphertext';

	/**
	 * WordPress database instance.
	 *
	 * @var wpdb
	 */
	private wpdb $wpdb;

	/**
	 * Authenticated encryption and HMAC service.
	 *
	 * @var CryptoInterface
	 */
	private CryptoInterface $crypto;

	/**
	 * External key provider (K1/K2).
	 *
	 * @var KeyProviderInterface
	 */
	private KeyProviderInterface $key_provider;

	/**
	 * Purpose-separated HMAC fingerprinter.
	 *
	 * @var IdentityFingerprinter
	 */
	private IdentityFingerprinter $fingerprinter;

	/**
	 * UTC clock callback (`fn(): string` returning `Y-m-d H:i:s`).
	 *
	 * @var callable
	 * @phpstan-var callable():string
	 */
	private $clock;

	/**
	 * Site blog ID resolver (`fn(): int` returning positive blog ID for canonical AAD).
	 *
	 * @var callable
	 * @phpstan-var callable():int
	 */
	private $blog_id_resolver;

	/**
	 * Current transaction nesting depth on this repository instance.
	 *
	 * @var int
	 */
	private int $transaction_depth = 0;

	/**
	 * Constructor.
	 *
	 * @param wpdb                       $wpdb             WordPress database object.
	 * @param CryptoInterface            $crypto           Approved AEAD & HMAC service.
	 * @param KeyProviderInterface       $key_provider     Approved K1/K2 key provider.
	 * @param IdentityFingerprinter|null $fingerprinter    Optional fingerprinter (defaults to new instance wrapping $crypto).
	 * @param callable|null              $clock            Optional UTC clock override (`fn(): string`).
	 * @param callable|null              $blog_id_resolver Optional blog ID resolver override (`fn(): int`).
	 * @phpstan-param (callable():string)|null $clock
	 * @phpstan-param (callable():int)|null    $blog_id_resolver
	 */
	public function __construct(
		wpdb $wpdb,
		CryptoInterface $crypto,
		KeyProviderInterface $key_provider,
		?IdentityFingerprinter $fingerprinter = null,
		?callable $clock = null,
		?callable $blog_id_resolver = null
	) {
		$this->wpdb             = $wpdb;
		$this->crypto           = $crypto;
		$this->key_provider     = $key_provider;
		$this->fingerprinter    = $fingerprinter ?? new IdentityFingerprinter( $crypto );
		$this->clock            = $clock ?? static fn(): string => gmdate( 'Y-m-d H:i:s' );
		$this->blog_id_resolver = $blog_id_resolver ?? static function (): int {
			if ( function_exists( 'get_current_blog_id' ) ) {
				return max( 1, (int) get_current_blog_id() );
			}
			return 1;
		};
	}

	/**
	 * Return the underlying WordPress database object for boundary service wiring.
	 *
	 * @internal Reserved for ProfileAccessBoundary consent verification wiring.
	 */
	public function get_wpdb(): wpdb {
		return $this->wpdb;
	}

	/**
	 * Return the repository UTC clock callback.
	 *
	 * @internal Reserved for ProfileAccessBoundary consent verification wiring.
	 * @return callable
	 * @phpstan-return callable():string
	 */
	public function get_clock(): callable {
		return $this->clock;
	}

	/**
	 * Find a user's profile record by WordPress user ID, or return null if none exists.
	 *
	 * @param int $wp_user_id WordPress user ID (`>= 1`).
	 * @return ProfileRecord|null
	 * @throws StorageException If $wp_user_id is invalid.
	 */
	public function find_by_user_id( int $wp_user_id ): ?ProfileRecord {
		$this->assert_valid_user_id( $wp_user_id );

		$row = $this->fetch_raw_row_by_user_id( $wp_user_id, false );
		if ( null === $row ) {
			return null;
		}

		return $this->map_row_to_record( $row );
	}

	/**
	 * Retrieve a user's profile record by WordPress user ID, or throw StorageException if not found.
	 *
	 * @param int $wp_user_id WordPress user ID (`>= 1`).
	 * @return ProfileRecord
	 * @throws StorageException If $wp_user_id is invalid or profile does not exist.
	 */
	public function get_by_user_id( int $wp_user_id ): ProfileRecord {
		$record = $this->find_by_user_id( $wp_user_id );
		if ( null === $record ) {
			StorageException::raise(
				StorageException::CODE_PROFILE_NOT_FOUND,
				'Identity profile record was not found for the specified user.'
			);
		}

		return $record;
	}

	/**
	 * Retrieve an existing profile for a user or create a new `UNBOUND` / `UNVERIFIED` profile.
	 *
	 * @param int $wp_user_id WordPress user ID (`>= 1`).
	 * @return ProfileRecord
	 * @throws StorageException On invalid user ID or database failure.
	 */
	public function get_or_create_profile( int $wp_user_id ): ProfileRecord {
		$existing = $this->find_by_user_id( $wp_user_id );
		if ( null !== $existing ) {
			return $existing;
		}

		return $this->create_profile( $wp_user_id );
	}

	/**
	 * Create a new profile for a WordPress user with optional encrypted identity fields.
	 *
	 * Security invariants:
	 * - New profiles always start as `binding_state = 'UNBOUND'`, `bound_national_code_hmac = NULL`,
	 *   and `identity_state = 'UNVERIFIED'` (`D14`: unverified profiles never reserve a national code).
	 * - Normalization, AEAD encryption, HMAC-SHA-256 fingerprinting, and masking occur before
	 *   opening the database transaction so any validation or key failure fails closed.
	 *
	 * @param int                        $wp_user_id    WordPress user ID (`>= 1`).
	 * @param SensitiveValue|string|null $national_code Optional raw/normalized 10-digit national code.
	 * @param SensitiveValue|string|null $mobile        Optional raw/normalized Iranian mobile number.
	 * @param SensitiveValue|string|null $birth_date    Optional raw/normalized Jalali birth date (`YYYY/MM/DD`).
	 * @return ProfileRecord Newly created safe profile DTO.
	 * @throws ValidationException If any provided identity attribute fails validation.
	 * @throws CryptoException     If encryption or HMAC keys are missing or invalid.
	 * @throws StorageException    If the user ID is invalid, a profile already exists, or DB insert fails.
	 */
	public function create_profile(
		int $wp_user_id,
		#[SensitiveParameter] SensitiveValue|string|null $national_code = null,
		#[SensitiveParameter] SensitiveValue|string|null $mobile = null,
		#[SensitiveParameter] SensitiveValue|string|null $birth_date = null
	): ProfileRecord {
		$this->assert_valid_user_id( $wp_user_id );
		$blog_id = $this->resolve_blog_id();

		$has_any_crypto_field = null !== $national_code || null !== $mobile || null !== $birth_date;

		$enc_key_id  = null;
		$hmac_key_id = null;

		$nc_prepared   = null;
		$mob_prepared  = null;
		$bd_ciphertext = null;

		if ( $has_any_crypto_field ) {
			$enc_key_id  = $this->key_provider->get_active_encryption_key_id();
			$hmac_key_id = $this->key_provider->get_active_hmac_key_id();

			if ( null !== $national_code ) {
				$nc_prepared = $this->prepare_national_code_material(
					$blog_id,
					$wp_user_id,
					$enc_key_id,
					$hmac_key_id,
					$national_code
				);
			}

			if ( null !== $mobile ) {
				$mob_prepared = $this->prepare_mobile_material(
					$blog_id,
					$wp_user_id,
					$enc_key_id,
					$hmac_key_id,
					$mobile
				);
			}

			if ( null !== $birth_date ) {
				$bd_ciphertext = $this->prepare_birth_date_ciphertext(
					$blog_id,
					$wp_user_id,
					$enc_key_id,
					$birth_date
				);
			}
		}

		return $this->run_in_transaction(
			function () use (
				$wp_user_id,
				$enc_key_id,
				$hmac_key_id,
				$nc_prepared,
				$mob_prepared,
				$bd_ciphertext
			): ProfileRecord {
				$existing = $this->fetch_raw_row_by_user_id( $wp_user_id, true );
				if ( null !== $existing ) {
					StorageException::raise(
						StorageException::CODE_PROFILE_ALREADY_EXISTS,
						'An identity profile already exists for this WordPress user.'
					);
				}

				$now   = $this->now_utc();
				$table = $this->get_table_name();

				$data = array(
					'wp_user_id'               => $wp_user_id,
					'country_code'             => 'IR',
					'subject_type'             => 'natural',
					'binding_state'            => ProfileRecord::BINDING_UNBOUND,
					'identity_state'           => ProfileRecord::STATE_UNVERIFIED,
					'identity_version'         => 1,
					'mobile_version'           => 1,
					'card_version'             => 1,
					'mobile_ciphertext'        => $mob_prepared['ciphertext'] ?? null,
					'mobile_hmac'              => $mob_prepared['hmac'] ?? null,
					'mobile_masked'            => $mob_prepared['masked'] ?? null,
					'mobile_verified_at'       => null,
					'national_code_ciphertext' => $nc_prepared['ciphertext'] ?? null,
					'national_code_hmac'       => $nc_prepared['hmac'] ?? null,
					'bound_national_code_hmac' => null,
					'national_code_masked'     => $nc_prepared['masked'] ?? null,
					'birth_date_ciphertext'    => $bd_ciphertext,
					'shahkar_verified_at'      => null,
					'enc_key_id'               => $enc_key_id,
					'hmac_key_id'              => $hmac_key_id,
					'bound_at'                 => null,
					'released_at'              => null,
					'verified_at'              => null,
					'expires_at'               => null,
					'created_at'               => $now,
					'updated_at'               => $now,
				);

				$suppressed = $this->wpdb->suppress_errors( true );
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Custom table insert inside repository transaction.
				$inserted = $this->wpdb->insert( $table, $data );
				$this->wpdb->suppress_errors( $suppressed );

				if ( 1 !== $inserted ) {
					StorageException::raise(
						StorageException::CODE_PROFILE_ALREADY_EXISTS,
						'Failed to create identity profile record (duplicate user or database error).'
					);
				}

				$created_row = $this->fetch_raw_row_by_user_id( $wp_user_id, false );
				if ( null === $created_row ) {
					StorageException::raise(
						StorageException::CODE_DATABASE_ERROR,
						'Failed to load newly created identity profile record.'
					);
				}

				return $this->map_row_to_record( $created_row );
			}
		);
	}

	/**
	 * Securely update a user's mobile number with optimistic/pessimistic version control.
	 *
	 * Versioning & Evidence Rules (Schema §3.3, §5.1):
	 * - Requires `$expected_mobile_version` to match the current persisted `mobile_version`.
	 * - Increments `mobile_version` by 1.
	 * - Invalidates dependent mobile evidence (`mobile_verified_at = NULL`, `shahkar_verified_at = NULL`).
	 * - If `identity_state` was `'VERIFIED'`, transitions `identity_state` to `'PENDING'`
	 *   (requiring OTP + Shahkar re-verification for the new mobile number).
	 * - Preserves `binding_state`, `bound_national_code_hmac`, `identity_version`, and `card_version`.
	 *
	 * @param int                   $wp_user_id              WordPress user ID (`>= 1`).
	 * @param SensitiveValue|string $mobile                  Raw or normalized Iranian mobile number.
	 * @param int                   $expected_mobile_version Expected current `mobile_version` (`>= 1`).
	 * @return ProfileRecord Updated safe profile DTO.
	 * @throws ValidationException If the mobile number is invalid.
	 * @throws CryptoException     If encryption or HMAC keys are missing or invalid.
	 * @throws StorageException    On profile missing, stale `mobile_version`, or DB error.
	 */
	public function update_mobile(
		int $wp_user_id,
		#[SensitiveParameter] SensitiveValue|string $mobile,
		int $expected_mobile_version
	): ProfileRecord {
		$this->assert_valid_user_id( $wp_user_id );
		$this->assert_valid_version( $expected_mobile_version, 'mobile_version' );

		$blog_id      = $this->resolve_blog_id();
		$enc_key_id   = $this->key_provider->get_active_encryption_key_id();
		$hmac_key_id  = $this->key_provider->get_active_hmac_key_id();
		$mob_prepared = $this->prepare_mobile_material(
			$blog_id,
			$wp_user_id,
			$enc_key_id,
			$hmac_key_id,
			$mobile
		);

		return $this->run_in_transaction(
			function () use (
				$blog_id,
				$wp_user_id,
				$expected_mobile_version,
				$enc_key_id,
				$hmac_key_id,
				$mob_prepared
			): ProfileRecord {
				$row = $this->fetch_raw_row_by_user_id( $wp_user_id, true );
				if ( null === $row ) {
					StorageException::raise(
						StorageException::CODE_PROFILE_NOT_FOUND,
						'Identity profile record was not found for mobile update.'
					);
				}

				$current_mobile_version = (int) $row['mobile_version'];
				if ( $current_mobile_version !== $expected_mobile_version ) {
					StorageException::raise(
						StorageException::CODE_VERSION_CONFLICT,
						'Stale mobile_version detected; concurrent profile modification prevented.'
					);
				}

				$new_mobile_version = $current_mobile_version + 1;
				$current_state      = (string) $row['identity_state'];
				$new_identity_state = ProfileRecord::STATE_VERIFIED === $current_state
					? ProfileRecord::STATE_PENDING
					: $current_state;

				$nc_ciphertext = isset( $row['national_code_ciphertext'] ) && is_string( $row['national_code_ciphertext'] )
					? $row['national_code_ciphertext']
					: null;
				$nc_hmac       = isset( $row['national_code_hmac'] ) && is_string( $row['national_code_hmac'] )
					? $row['national_code_hmac']
					: null;

				$row_enc_key_id = $this->resolve_row_enc_key_id(
					array(
						$mob_prepared['ciphertext'],
						$nc_ciphertext,
						isset( $row['birth_date_ciphertext'] ) && is_string( $row['birth_date_ciphertext'] ) ? $row['birth_date_ciphertext'] : null,
					),
					$enc_key_id
				);

				$row_hmac_key_id = $this->resolve_row_hmac_key_id(
					$blog_id,
					$wp_user_id,
					isset( $row['hmac_key_id'] ) && is_string( $row['hmac_key_id'] ) ? $row['hmac_key_id'] : null,
					$hmac_key_id,
					self::COL_NATIONAL_CODE_CIPHERTEXT,
					$nc_ciphertext,
					$nc_hmac
				);

				$now   = $this->now_utc();
				$table = $this->get_table_name();
				$wpdb  = $this->wpdb;

				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom table update inside transaction.
				$updated = $wpdb->query(
					$wpdb->prepare(
						// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is strictly constructed from $wpdb->prefix + constant logical table.
						"UPDATE `{$table}`
						SET mobile_ciphertext = %s,
						    mobile_hmac = %s,
						    mobile_masked = %s,
						    mobile_version = %d,
						    mobile_verified_at = NULL,
						    shahkar_verified_at = NULL,
						    identity_state = %s,
						    enc_key_id = %s,
						    hmac_key_id = %s,
						    updated_at = %s
						WHERE id = %d AND mobile_version = %d",
						$mob_prepared['ciphertext'],
						$mob_prepared['hmac'],
						$mob_prepared['masked'],
						$new_mobile_version,
						$new_identity_state,
						$row_enc_key_id,
						$row_hmac_key_id,
						$now,
						(int) $row['id'],
						$expected_mobile_version
					)
				);

				if ( 1 !== $updated ) {
					StorageException::raise(
						StorageException::CODE_VERSION_CONFLICT,
						'Mobile update failed due to concurrent version modification.'
					);
				}

				$refreshed = $this->fetch_raw_row_by_user_id( $wp_user_id, false );
				if ( null === $refreshed ) {
					StorageException::raise(
						StorageException::CODE_DATABASE_ERROR,
						'Failed to reload profile after mobile update.'
					);
				}

				return $this->map_row_to_record( $refreshed );
			}
		);
	}

	/**
	 * Securely update unbound identity attributes (national code and Jalali birth date).
	 *
	 * Identity Binding & Versioning Rules (D14, Schema §3.2, §3.3, §4.1.1):
	 * - Regular profile updates can NEVER set `binding_state = 'BOUND'` or modify a
	 *   profile whose `binding_state` is already `'BOUND'` (even if `identity_state = 'EXPIRED'`).
	 * - Requires `$expected_identity_version` to match the current persisted `identity_version`.
	 * - Increments `identity_version` by 1.
	 * - Invalidates dependent identity evidence (`shahkar_verified_at = NULL`, `verified_at = NULL`,
	 *   `expires_at = NULL`, `identity_state = 'UNVERIFIED'`, `bound_national_code_hmac = NULL`).
	 * - Preserves `mobile_version`, `mobile_verified_at`, and `card_version` (mobile OTP
	 *   possession remains valid when only identity attributes are edited).
	 *
	 * @param int                   $wp_user_id                WordPress user ID (`>= 1`).
	 * @param SensitiveValue|string $national_code             Raw or normalized 10-digit national code.
	 * @param SensitiveValue|string $birth_date                Raw or normalized Jalali birth date (`YYYY/MM/DD`).
	 * @param int                   $expected_identity_version Expected current `identity_version` (`>= 1`).
	 * @return ProfileRecord Updated safe profile DTO.
	 * @throws ValidationException If national code or birth date fails validation.
	 * @throws CryptoException     If encryption or HMAC keys are missing or invalid.
	 * @throws StorageException    If profile is missing, already `BOUND`, or version conflicts.
	 */
	public function update_identity_data(
		int $wp_user_id,
		#[SensitiveParameter] SensitiveValue|string $national_code,
		#[SensitiveParameter] SensitiveValue|string $birth_date,
		int $expected_identity_version
	): ProfileRecord {
		$this->assert_valid_user_id( $wp_user_id );
		$this->assert_valid_version( $expected_identity_version, 'identity_version' );

		$blog_id     = $this->resolve_blog_id();
		$enc_key_id  = $this->key_provider->get_active_encryption_key_id();
		$hmac_key_id = $this->key_provider->get_active_hmac_key_id();

		$nc_prepared   = $this->prepare_national_code_material(
			$blog_id,
			$wp_user_id,
			$enc_key_id,
			$hmac_key_id,
			$national_code
		);
		$bd_ciphertext = $this->prepare_birth_date_ciphertext(
			$blog_id,
			$wp_user_id,
			$enc_key_id,
			$birth_date
		);

		return $this->run_in_transaction(
			function () use (
				$blog_id,
				$wp_user_id,
				$expected_identity_version,
				$enc_key_id,
				$hmac_key_id,
				$nc_prepared,
				$bd_ciphertext
			): ProfileRecord {
				$row = $this->fetch_raw_row_by_user_id( $wp_user_id, true );
				if ( null === $row ) {
					StorageException::raise(
						StorageException::CODE_PROFILE_NOT_FOUND,
						'Identity profile record was not found for identity update.'
					);
				}

				$current_identity_version = (int) $row['identity_version'];
				if ( $current_identity_version !== $expected_identity_version ) {
					StorageException::raise(
						StorageException::CODE_VERSION_CONFLICT,
						'Stale identity_version detected; concurrent profile modification prevented.'
					);
				}

				if ( ProfileRecord::BINDING_BOUND === (string) $row['binding_state'] ) {
					StorageException::raise(
						StorageException::CODE_BOUND_IDENTITY_IMMUTABLE,
						'Bound identity attributes cannot be modified via regular profile updates (D14).'
					);
				}

				$new_identity_version = $current_identity_version + 1;
				$now                  = $this->now_utc();
				$table                = $this->get_table_name();

				$mob_ciphertext = isset( $row['mobile_ciphertext'] ) && is_string( $row['mobile_ciphertext'] )
					? $row['mobile_ciphertext']
					: null;
				$mob_hmac       = isset( $row['mobile_hmac'] ) && is_string( $row['mobile_hmac'] )
					? $row['mobile_hmac']
					: null;

				$row_enc_key_id = $this->resolve_row_enc_key_id(
					array(
						$nc_prepared['ciphertext'],
						$bd_ciphertext,
						$mob_ciphertext,
					),
					$enc_key_id
				);

				$row_hmac_key_id = $this->resolve_row_hmac_key_id(
					$blog_id,
					$wp_user_id,
					isset( $row['hmac_key_id'] ) && is_string( $row['hmac_key_id'] ) ? $row['hmac_key_id'] : null,
					$hmac_key_id,
					self::COL_MOBILE_CIPHERTEXT,
					$mob_ciphertext,
					$mob_hmac
				);

				$wpdb = $this->wpdb;

				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom table update inside transaction.
				$updated = $wpdb->query(
					$wpdb->prepare(
						// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is strictly constructed from $wpdb->prefix + constant logical table.
						"UPDATE `{$table}`
						SET national_code_ciphertext = %s,
						    national_code_hmac = %s,
						    bound_national_code_hmac = NULL,
						    national_code_masked = %s,
						    birth_date_ciphertext = %s,
						    binding_state = %s,
						    identity_state = %s,
						    identity_version = %d,
						    shahkar_verified_at = NULL,
						    verified_at = NULL,
						    expires_at = NULL,
						    enc_key_id = %s,
						    hmac_key_id = %s,
						    updated_at = %s
						WHERE id = %d AND identity_version = %d AND binding_state != %s",
						$nc_prepared['ciphertext'],
						$nc_prepared['hmac'],
						$nc_prepared['masked'],
						$bd_ciphertext,
						ProfileRecord::BINDING_UNBOUND,
						ProfileRecord::STATE_UNVERIFIED,
						$new_identity_version,
						$row_enc_key_id,
						$row_hmac_key_id,
						$now,
						(int) $row['id'],
						$expected_identity_version,
						ProfileRecord::BINDING_BOUND
					)
				);

				if ( 1 !== $updated ) {
					StorageException::raise(
						StorageException::CODE_VERSION_CONFLICT,
						'Identity update failed due to concurrent version or binding modification.'
					);
				}

				$refreshed = $this->fetch_raw_row_by_user_id( $wp_user_id, false );
				if ( null === $refreshed ) {
					StorageException::raise(
						StorageException::CODE_DATABASE_ERROR,
						'Failed to reload profile after identity update.'
					);
				}

				return $this->map_row_to_record( $refreshed );
			}
		);
	}

	/**
	 * Increment `card_version` without invalidating identity or mobile evidence (Schema §3.3).
	 *
	 * Preserves `identity_version`, `mobile_version`, `mobile_verified_at`,
	 * `shahkar_verified_at`, `binding_state`, `bound_national_code_hmac`,
	 * `enc_key_id`, and `hmac_key_id`.
	 *
	 * @param int $wp_user_id            WordPress user ID (`>= 1`).
	 * @param int $expected_card_version Expected current `card_version` (`>= 1`).
	 * @return ProfileRecord Updated safe profile DTO.
	 * @throws StorageException On missing profile or stale `card_version`.
	 */
	public function increment_card_version(
		int $wp_user_id,
		int $expected_card_version
	): ProfileRecord {
		$this->assert_valid_user_id( $wp_user_id );
		$this->assert_valid_version( $expected_card_version, 'card_version' );

		return $this->run_in_transaction(
			function () use ( $wp_user_id, $expected_card_version ): ProfileRecord {
				$row = $this->fetch_raw_row_by_user_id( $wp_user_id, true );
				if ( null === $row ) {
					StorageException::raise(
						StorageException::CODE_PROFILE_NOT_FOUND,
						'Identity profile record was not found for card_version update.'
					);
				}

				$current_card_version = (int) $row['card_version'];
				if ( $current_card_version !== $expected_card_version ) {
					StorageException::raise(
						StorageException::CODE_VERSION_CONFLICT,
						'Stale card_version detected; concurrent card modification prevented.'
					);
				}

				$new_card_version = $current_card_version + 1;
				$now              = $this->now_utc();
				$table            = $this->get_table_name();
				$wpdb             = $this->wpdb;

				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom table update inside transaction.
				$updated = $wpdb->query(
					$wpdb->prepare(
						// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is strictly constructed from $wpdb->prefix + constant logical table.
						"UPDATE `{$table}`
						SET card_version = %d,
						    updated_at = %s
						WHERE id = %d AND card_version = %d",
						$new_card_version,
						$now,
						(int) $row['id'],
						$expected_card_version
					)
				);

				if ( 1 !== $updated ) {
					StorageException::raise(
						StorageException::CODE_VERSION_CONFLICT,
						'Card version increment failed due to concurrent modification.'
					);
				}

				$refreshed = $this->fetch_raw_row_by_user_id( $wp_user_id, false );
				if ( null === $refreshed ) {
					StorageException::raise(
						StorageException::CODE_DATABASE_ERROR,
						'Failed to reload profile after card_version increment.'
					);
				}

				return $this->map_row_to_record( $refreshed );
			}
		);
	}

	/**
	 * Record mobile possession verification timestamp for a specific `mobile_version`.
	 *
	 * @param int         $wp_user_id              WordPress user ID (`>= 1`).
	 * @param int         $expected_mobile_version Expected current `mobile_version` (`>= 1`).
	 * @param string|null $verified_at_utc         Optional UTC timestamp override.
	 * @return ProfileRecord Updated safe profile DTO.
	 * @throws StorageException If profile is missing, has no encrypted mobile, or `mobile_version` is stale.
	 */
	public function record_mobile_verified(
		int $wp_user_id,
		int $expected_mobile_version,
		?string $verified_at_utc = null
	): ProfileRecord {
		$this->assert_valid_user_id( $wp_user_id );
		$this->assert_valid_version( $expected_mobile_version, 'mobile_version' );

		return $this->run_in_transaction(
			function () use ( $wp_user_id, $expected_mobile_version, $verified_at_utc ): ProfileRecord {
				$row = $this->fetch_raw_row_by_user_id( $wp_user_id, true );
				if ( null === $row ) {
					StorageException::raise(
						StorageException::CODE_PROFILE_NOT_FOUND,
						'Identity profile record was not found for mobile verification.'
					);
				}

				if ( (int) $row['mobile_version'] !== $expected_mobile_version ) {
					StorageException::raise(
						StorageException::CODE_VERSION_CONFLICT,
						'Stale mobile_version detected when recording mobile verification.'
					);
				}

				if ( empty( $row['mobile_ciphertext'] ) || empty( $row['mobile_hmac'] ) ) {
					StorageException::raise(
						StorageException::CODE_UNAUTHORIZED_BINDING_TRANSITION,
						'Cannot mark mobile as verified when no encrypted mobile is stored.'
					);
				}

				$now   = $verified_at_utc ?? $this->now_utc();
				$table = $this->get_table_name();
				$wpdb  = $this->wpdb;

				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom table update inside transaction.
				$updated = $wpdb->query(
					$wpdb->prepare(
						// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is strictly constructed from $wpdb->prefix + constant logical table.
						"UPDATE `{$table}`
						SET mobile_verified_at = %s,
						    updated_at = %s
						WHERE id = %d AND mobile_version = %d",
						$now,
						$now,
						(int) $row['id'],
						$expected_mobile_version
					)
				);

				if ( 1 !== $updated ) {
					StorageException::raise(
						StorageException::CODE_VERSION_CONFLICT,
						'Recording mobile verification failed due to concurrent modification.'
					);
				}

				$refreshed = $this->fetch_raw_row_by_user_id( $wp_user_id, false );
				if ( null === $refreshed ) {
					StorageException::raise(
						StorageException::CODE_DATABASE_ERROR,
						'Failed to reload profile after recording mobile verification.'
					);
				}

				return $this->map_row_to_record( $refreshed );
			}
		);
	}

	/**
	 * Establish or refresh an authoritative `BOUND` identity binding for a verified `(identity_version, mobile_version)`.
	 *
	 * Security & D14 Invariants:
	 * - Reserved strictly for authoritative verification domain transitions (never callable via regular profile edits).
	 * - Requires stored encrypted national code (`national_code_hmac`), birth date, and verified mobile (`mobile_verified_at`).
	 * - Enforces one active `BOUND` WordPress user per `bound_national_code_hmac` per site (`D14`),
	 *   failing closed with `CODE_IDENTITY_CONFLICT` without exposing the conflicting account identity.
	 *
	 * @param int         $wp_user_id                WordPress user ID (`>= 1`).
	 * @param int         $expected_identity_version Captured `identity_version` at verification start.
	 * @param int         $expected_mobile_version   Captured `mobile_version` at verification start.
	 * @param string|null $expires_at_utc            Optional UTC freshness expiry timestamp.
	 * @return ProfileRecord Updated `BOUND` & `VERIFIED` profile DTO.
	 * @throws CryptoException  If keys are missing/invalid or ciphertext/HMAC integrity fails.
	 * @throws StorageException On version mismatch, missing prerequisites, stale HMAC key, or duplicate identity conflict.
	 */
	public function bind_verified_identity(
		int $wp_user_id,
		int $expected_identity_version,
		int $expected_mobile_version,
		?string $expires_at_utc = null
	): ProfileRecord {
		$this->assert_valid_user_id( $wp_user_id );
		$this->assert_valid_version( $expected_identity_version, 'identity_version' );
		$this->assert_valid_version( $expected_mobile_version, 'mobile_version' );

		$blog_id            = $this->resolve_blog_id();
		$active_hmac_key_id = $this->key_provider->get_active_hmac_key_id();

		return $this->run_in_transaction(
			function () use (
				$blog_id,
				$wp_user_id,
				$expected_identity_version,
				$expected_mobile_version,
				$expires_at_utc,
				$active_hmac_key_id
			): ProfileRecord {
				$row = $this->fetch_raw_row_by_user_id( $wp_user_id, true );
				if ( null === $row ) {
					StorageException::raise(
						StorageException::CODE_PROFILE_NOT_FOUND,
						'Identity profile record was not found for binding.'
					);
				}

				if (
					(int) $row['identity_version'] !== $expected_identity_version
					|| (int) $row['mobile_version'] !== $expected_mobile_version
				) {
					StorageException::raise(
						StorageException::CODE_VERSION_CONFLICT,
						'Profile version changed during verification; binding aborted.'
					);
				}

				$nc_hmac = isset( $row['national_code_hmac'] ) && is_string( $row['national_code_hmac'] )
					? $row['national_code_hmac']
					: '';

				if (
					'' === $nc_hmac
					|| empty( $row['national_code_ciphertext'] )
					|| ! is_string( $row['national_code_ciphertext'] )
					|| empty( $row['birth_date_ciphertext'] )
					|| empty( $row['mobile_verified_at'] )
				) {
					StorageException::raise(
						StorageException::CODE_UNAUTHORIZED_BINDING_TRANSITION,
						'Cannot bind identity without encrypted identity attributes and verified mobile possession.'
					);
				}

				$row_hmac_key_id = isset( $row['hmac_key_id'] ) && is_string( $row['hmac_key_id'] )
					? $row['hmac_key_id']
					: '';
				if ( $row_hmac_key_id !== $active_hmac_key_id ) {
					StorageException::raise(
						StorageException::CODE_UNAUTHORIZED_BINDING_TRANSITION,
						'Cannot bind identity while profile HMAC key ID differs from the active HMAC key ID.'
					);
				}

				$decrypted_nc = $this->decrypt_column(
					$blog_id,
					self::COL_NATIONAL_CODE_CIPHERTEXT,
					$wp_user_id,
					$row['national_code_ciphertext']
				);
				try {
					$hmac_matches = $this->fingerprinter->verify_national_code(
						$nc_hmac,
						$decrypted_nc,
						$active_hmac_key_id
					);
				} finally {
					$decrypted_nc->wipe();
				}

				if ( ! $hmac_matches ) {
					CryptoException::raise(
						CryptoException::CODE_AUTH_FAILED,
						'Stored national_code_hmac does not match authenticated national_code_ciphertext.'
					);
				}

				if (
					ProfileRecord::BINDING_BOUND === (string) $row['binding_state']
					&& ! empty( $row['bound_national_code_hmac'] )
					&& ! hash_equals( (string) $row['bound_national_code_hmac'], $nc_hmac )
				) {
					StorageException::raise(
						StorageException::CODE_BOUND_IDENTITY_IMMUTABLE,
						'Profile is already bound to a different national code.'
					);
				}

				$table = $this->get_table_name();
				$wpdb  = $this->wpdb;

				// Pre-check cross-user binding conflict (D14) without exposing conflicting user details.
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom table conflict check inside transaction.
				$conflicting_id = $wpdb->get_var(
					$wpdb->prepare(
						// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is strictly constructed from $wpdb->prefix + constant logical table.
						"SELECT id FROM `{$table}` WHERE bound_national_code_hmac = %s AND wp_user_id != %d LIMIT 1",
						$nc_hmac,
						$wp_user_id
					)
				);

				if ( null !== $conflicting_id ) {
					StorageException::raise(
						StorageException::CODE_IDENTITY_CONFLICT,
						'Identity verification could not be completed due to a binding conflict.'
					);
				}

				$now      = $this->now_utc();
				$bound_at = ! empty( $row['bound_at'] ) ? (string) $row['bound_at'] : $now;

				$suppressed = $wpdb->suppress_errors( true );
				if ( null === $expires_at_utc ) {
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom table update inside transaction.
					$updated = $wpdb->query(
						$wpdb->prepare(
							// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is strictly constructed from $wpdb->prefix + constant logical table.
							"UPDATE `{$table}`
							SET binding_state = %s,
							    identity_state = %s,
							    bound_national_code_hmac = %s,
							    bound_at = %s,
							    shahkar_verified_at = %s,
							    verified_at = %s,
							    expires_at = NULL,
							    updated_at = %s
							WHERE id = %d AND identity_version = %d AND mobile_version = %d",
							ProfileRecord::BINDING_BOUND,
							ProfileRecord::STATE_VERIFIED,
							$nc_hmac,
							$bound_at,
							$now,
							$now,
							$now,
							(int) $row['id'],
							$expected_identity_version,
							$expected_mobile_version
						)
					);
				} else {
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom table update inside transaction.
					$updated = $wpdb->query(
						$wpdb->prepare(
							// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is strictly constructed from $wpdb->prefix + constant logical table.
							"UPDATE `{$table}`
							SET binding_state = %s,
							    identity_state = %s,
							    bound_national_code_hmac = %s,
							    bound_at = %s,
							    shahkar_verified_at = %s,
							    verified_at = %s,
							    expires_at = %s,
							    updated_at = %s
							WHERE id = %d AND identity_version = %d AND mobile_version = %d",
							ProfileRecord::BINDING_BOUND,
							ProfileRecord::STATE_VERIFIED,
							$nc_hmac,
							$bound_at,
							$now,
							$now,
							$expires_at_utc,
							$now,
							(int) $row['id'],
							$expected_identity_version,
							$expected_mobile_version
						)
					);
				}
				$wpdb->suppress_errors( $suppressed );

				if ( false === $updated || 1 !== (int) $updated ) {
					StorageException::raise(
						StorageException::CODE_IDENTITY_CONFLICT,
						'Identity binding failed due to a concurrent binding conflict or version change.'
					);
				}

				$refreshed = $this->fetch_raw_row_by_user_id( $wp_user_id, false );
				if ( null === $refreshed ) {
					StorageException::raise(
						StorageException::CODE_DATABASE_ERROR,
						'Failed to reload profile after binding identity.'
					);
				}

				return $this->map_row_to_record( $refreshed );
			}
		);
	}

	/**
	 * Transition `identity_state` to `'EXPIRED'` if `expires_at <= $now_utc` while preserving `BOUND` state (`D14`).
	 *
	 * Security invariant (Schema §3.2, §4.1.1):
	 * Verification freshness expiry NEVER clears `bound_national_code_hmac` or changes
	 * `binding_state = 'BOUND'`, preventing another WordPress account from claiming
	 * an expired user's national code.
	 *
	 * @param int         $wp_user_id WordPress user ID (`>= 1`).
	 * @param string|null $now_utc    Optional UTC timestamp (`Y-m-d H:i:s`) to evaluate against.
	 * @return ProfileRecord Updated safe profile DTO.
	 * @throws StorageException If profile does not exist.
	 */
	public function mark_expired_if_past( int $wp_user_id, ?string $now_utc = null ): ProfileRecord {
		$this->assert_valid_user_id( $wp_user_id );

		return $this->run_in_transaction(
			function () use ( $wp_user_id, $now_utc ): ProfileRecord {
				$row = $this->fetch_raw_row_by_user_id( $wp_user_id, true );
				if ( null === $row ) {
					StorageException::raise(
						StorageException::CODE_PROFILE_NOT_FOUND,
						'Identity profile record was not found for expiry check.'
					);
				}

				$now        = $now_utc ?? $this->now_utc();
				$expires_at = isset( $row['expires_at'] ) && is_string( $row['expires_at'] ) ? $row['expires_at'] : null;

				if (
					ProfileRecord::STATE_VERIFIED === (string) $row['identity_state']
					&& null !== $expires_at
					&& $expires_at <= $now
				) {
					$table = $this->get_table_name();
					$wpdb  = $this->wpdb;
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom table update inside transaction.
					$wpdb->query(
						$wpdb->prepare(
							// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is strictly constructed from $wpdb->prefix + constant logical table.
							"UPDATE `{$table}`
							SET identity_state = %s,
							    updated_at = %s
							WHERE id = %d",
							ProfileRecord::STATE_EXPIRED,
							$now,
							(int) $row['id']
						)
					);

					$reloaded = $this->fetch_raw_row_by_user_id( $wp_user_id, false );
					if ( null !== $reloaded ) {
						$row = $reloaded;
					}
				}

				return $this->map_row_to_record( $row );
			}
		);
	}

	/**
	 * Authenticate and decrypt a user's stored identity fields using canonical 6-segment AAD.
	 *
	 * Security invariants:
	 * - Binds decryption to `(blog_id, 'wpig_profiles', column_name, wp_user_id, envelope_key_id)`.
	 * - Any ciphertext transplant across users, blogs, or columns fails closed with `CryptoException`.
	 * - Missing or invalid keys fail closed without modifying or overwriting stored ciphertexts.
	 * - Wipes any already-decrypted `SensitiveValue` instances if a subsequent column fails decryption.
	 *
	 * @param int $wp_user_id WordPress user ID (`>= 1`).
	 * @return DecryptedIdentityData
	 * @throws CryptoException If keys are missing/invalid or AEAD authentication fails.
	 */
	public function decrypt_identity_for_user( int $wp_user_id ): DecryptedIdentityData {
		$this->assert_valid_user_id( $wp_user_id );
		$blog_id = $this->resolve_blog_id();

		$row = $this->fetch_raw_row_by_user_id( $wp_user_id, false );
		if ( null === $row ) {
			StorageException::raise(
				StorageException::CODE_PROFILE_NOT_FOUND,
				'Identity profile record was not found for decryption.'
			);
		}

		$record        = $this->map_row_to_record( $row );
		$national_code = null;
		$mobile        = null;
		$birth_date    = null;

		try {
			if ( ! empty( $row['national_code_ciphertext'] ) && is_string( $row['national_code_ciphertext'] ) ) {
				$national_code = $this->decrypt_column(
					$blog_id,
					self::COL_NATIONAL_CODE_CIPHERTEXT,
					$wp_user_id,
					$row['national_code_ciphertext']
				);
			}

			if ( ! empty( $row['mobile_ciphertext'] ) && is_string( $row['mobile_ciphertext'] ) ) {
				$mobile = $this->decrypt_column(
					$blog_id,
					self::COL_MOBILE_CIPHERTEXT,
					$wp_user_id,
					$row['mobile_ciphertext']
				);
			}

			if ( ! empty( $row['birth_date_ciphertext'] ) && is_string( $row['birth_date_ciphertext'] ) ) {
				$birth_date = $this->decrypt_column(
					$blog_id,
					self::COL_BIRTH_DATE_CIPHERTEXT,
					$wp_user_id,
					$row['birth_date_ciphertext']
				);
			}

			return new DecryptedIdentityData(
				$record,
				$national_code,
				$mobile,
				$birth_date
			);
		} catch ( CryptoException $e ) {
			if ( null !== $national_code ) {
				$national_code->wipe();
			}
			if ( null !== $mobile ) {
				$mobile->wipe();
			}
			throw $e;
		}
	}

	/**
	 * Clear unverified PII fields on an `UNBOUND` profile during authorized privacy erasure (Task 5).
	 *
	 * Security Invariants:
	 * - NEVER modifies or releases a `BOUND` profile (`bound_national_code_hmac` is untouched).
	 * - NEVER modifies a profile in `REVIEW_REQUIRED` state.
	 * - Returns `false` if the profile does not exist, is `BOUND`, is in `REVIEW_REQUIRED`,
	 *   or already has no stored PII attributes.
	 *
	 * @param int $wp_user_id WordPress user ID (`>= 1`).
	 * @return bool True if unverified PII fields were cleared; false otherwise.
	 * @throws StorageException On invalid user ID or database failure.
	 */
	public function clear_unbound_profile_pii( int $wp_user_id ): bool {
		$this->assert_valid_user_id( $wp_user_id );

		return $this->run_in_transaction(
			function () use ( $wp_user_id ): bool {
				$row = $this->fetch_raw_row_by_user_id( $wp_user_id, true );
				if ( null === $row ) {
					return false;
				}

				$binding_state  = isset( $row['binding_state'] ) ? (string) $row['binding_state'] : '';
				$identity_state = isset( $row['identity_state'] ) ? (string) $row['identity_state'] : '';

				if (
					ProfileRecord::BINDING_BOUND === $binding_state
					|| ! empty( $row['bound_national_code_hmac'] )
					|| ProfileRecord::STATE_REVIEW_REQUIRED === $identity_state
				) {
					return false;
				}

				$has_pii = ! empty( $row['national_code_ciphertext'] )
					|| ! empty( $row['national_code_hmac'] )
					|| ! empty( $row['national_code_masked'] )
					|| ! empty( $row['birth_date_ciphertext'] )
					|| ! empty( $row['mobile_ciphertext'] )
					|| ! empty( $row['mobile_hmac'] )
					|| ! empty( $row['mobile_masked'] );

				if ( ! $has_pii ) {
					return false;
				}

				$new_identity_version = (int) $row['identity_version'] + 1;
				$new_mobile_version   = (int) $row['mobile_version'] + 1;
				$now                  = $this->now_utc();
				$table                = $this->get_table_name();
				$wpdb                 = $this->wpdb;

				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom table update inside transaction.
				$updated = $wpdb->query(
					$wpdb->prepare(
						// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is strictly constructed from $wpdb->prefix + constant logical table.
						"UPDATE `{$table}`
						SET national_code_ciphertext = NULL,
						    national_code_hmac = NULL,
						    national_code_masked = NULL,
						    birth_date_ciphertext = NULL,
						    mobile_ciphertext = NULL,
						    mobile_hmac = NULL,
						    mobile_masked = NULL,
						    mobile_verified_at = NULL,
						    shahkar_verified_at = NULL,
						    verified_at = NULL,
						    expires_at = NULL,
						    enc_key_id = NULL,
						    hmac_key_id = NULL,
						    identity_state = %s,
						    identity_version = %d,
						    mobile_version = %d,
						    updated_at = %s
						WHERE id = %d AND binding_state != %s AND identity_state != %s",
						ProfileRecord::STATE_UNVERIFIED,
						$new_identity_version,
						$new_mobile_version,
						$now,
						(int) $row['id'],
						ProfileRecord::BINDING_BOUND,
						ProfileRecord::STATE_REVIEW_REQUIRED
					)
				);

				return 1 === (int) $updated;
			}
		);
	}

	/**
	 * Execute a callback inside a short database transaction (`START TRANSACTION` ... `COMMIT`/`ROLLBACK`).
	 *
	 * Supports nested repository calls: only the outermost call issues `START TRANSACTION`
	 * and `COMMIT`, and any exception at any depth rolls back the entire transaction.
	 *
	 * @template T
	 * @param callable():T $callback Transactional operation.
	 * @return T
	 * @throws \Throwable Re-throws any exception after rolling back the transaction.
	 */
	public function run_in_transaction( callable $callback ): mixed {
		$is_outermost = 0 === $this->transaction_depth;
		if ( $is_outermost ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Transaction control.
			$started = $this->wpdb->query( 'START TRANSACTION' );
			if ( false === $started ) {
				StorageException::raise(
					StorageException::CODE_DATABASE_ERROR,
					'Unable to start database transaction.'
				);
			}
		}

		++$this->transaction_depth;

		try {
			$result = $callback();
			--$this->transaction_depth;

			if ( $is_outermost ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Transaction control.
				$committed = $this->wpdb->query( 'COMMIT' );
				if ( false === $committed ) {
					StorageException::raise(
						StorageException::CODE_DATABASE_ERROR,
						'Unable to commit database transaction.'
					);
				}
			}

			return $result;
		} catch ( \Throwable $e ) {
			--$this->transaction_depth;

			if ( $is_outermost ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Transaction rollback on error.
				$this->wpdb->query( 'ROLLBACK' );
			}

			throw $e;
		}
	}

	/**
	 * Normalize, encrypt, fingerprint, and mask a national code outside any DB transaction.
	 *
	 * @param int                   $blog_id       Site blog ID (`>= 1`).
	 * @param int                   $wp_user_id    WordPress user ID (`>= 1`).
	 * @param string                $enc_key_id    Active encryption key ID.
	 * @param string                $hmac_key_id   Active HMAC key ID.
	 * @param SensitiveValue|string $national_code Raw or normalized national code.
	 * @return array{ciphertext:string,hmac:string,masked:string}
	 * @throws ValidationException If national code is invalid.
	 * @throws CryptoException     If encryption or HMAC fails.
	 */
	private function prepare_national_code_material(
		int $blog_id,
		int $wp_user_id,
		string $enc_key_id,
		string $hmac_key_id,
		#[SensitiveParameter] SensitiveValue|string $national_code
	): array {
		$canonical = IdentityNormalizer::normalize_national_code( $national_code );
		try {
			$aad        = CanonicalAad::for_table_column(
				$blog_id,
				self::LOGICAL_TABLE,
				self::COL_NATIONAL_CODE_CIPHERTEXT,
				$wp_user_id,
				$enc_key_id
			);
			$ciphertext = $this->crypto->encrypt( $canonical, $aad );
			$hmac       = $this->fingerprinter->fingerprint_national_code( $canonical, $hmac_key_id );
			$masked     = DataMasker::mask_national_code( $canonical );

			return array(
				'ciphertext' => $ciphertext,
				'hmac'       => $hmac,
				'masked'     => $masked,
			);
		} finally {
			if ( function_exists( 'sodium_memzero' ) ) {
				sodium_memzero( $canonical );
			}
		}
	}

	/**
	 * Normalize, encrypt, fingerprint, and mask a mobile number outside any DB transaction.
	 *
	 * @param int                   $blog_id     Site blog ID (`>= 1`).
	 * @param int                   $wp_user_id  WordPress user ID (`>= 1`).
	 * @param string                $enc_key_id  Active encryption key ID.
	 * @param string                $hmac_key_id Active HMAC key ID.
	 * @param SensitiveValue|string $mobile      Raw or normalized Iranian mobile number.
	 * @return array{ciphertext:string,hmac:string,masked:string}
	 * @throws ValidationException If mobile number is invalid.
	 * @throws CryptoException     If encryption or HMAC fails.
	 */
	private function prepare_mobile_material(
		int $blog_id,
		int $wp_user_id,
		string $enc_key_id,
		string $hmac_key_id,
		#[SensitiveParameter] SensitiveValue|string $mobile
	): array {
		$canonical = IdentityNormalizer::normalize_mobile( $mobile );
		try {
			$aad        = CanonicalAad::for_table_column(
				$blog_id,
				self::LOGICAL_TABLE,
				self::COL_MOBILE_CIPHERTEXT,
				$wp_user_id,
				$enc_key_id
			);
			$ciphertext = $this->crypto->encrypt( $canonical, $aad );
			$hmac       = $this->fingerprinter->fingerprint_mobile( $canonical, $hmac_key_id );
			$masked     = DataMasker::mask_mobile( $canonical );

			return array(
				'ciphertext' => $ciphertext,
				'hmac'       => $hmac,
				'masked'     => $masked,
			);
		} finally {
			if ( function_exists( 'sodium_memzero' ) ) {
				sodium_memzero( $canonical );
			}
		}
	}

	/**
	 * Normalize and encrypt a Jalali birth date (`YYYY/MM/DD`) outside any DB transaction.
	 *
	 * @param int                   $blog_id    Site blog ID (`>= 1`).
	 * @param int                   $wp_user_id WordPress user ID (`>= 1`).
	 * @param string                $enc_key_id Active encryption key ID.
	 * @param SensitiveValue|string $birth_date Raw or normalized Jalali birth date.
	 * @return string Versioned AEAD ciphertext envelope.
	 * @throws ValidationException If birth date is invalid.
	 * @throws CryptoException     If encryption fails.
	 */
	private function prepare_birth_date_ciphertext(
		int $blog_id,
		int $wp_user_id,
		string $enc_key_id,
		#[SensitiveParameter] SensitiveValue|string $birth_date
	): string {
		$canonical = IdentityNormalizer::normalize_jalali_birth_date( $birth_date );
		try {
			$aad = CanonicalAad::for_table_column(
				$blog_id,
				self::LOGICAL_TABLE,
				self::COL_BIRTH_DATE_CIPHERTEXT,
				$wp_user_id,
				$enc_key_id
			);
			return $this->crypto->encrypt( $canonical, $aad );
		} finally {
			if ( function_exists( 'sodium_memzero' ) ) {
				sodium_memzero( $canonical );
			}
		}
	}

	/**
	 * Decrypt a single column envelope using canonical AAD bound to `(blog_id, 'wpig_profiles', column_name, wp_user_id, key_id)`.
	 *
	 * @param int    $blog_id     Site blog ID (`>= 1`).
	 * @param string $column_name Column name in `wpig_profiles`.
	 * @param int    $wp_user_id  WordPress user ID (`>= 1`).
	 * @param string $envelope    Stored ciphertext envelope.
	 * @return SensitiveValue Decrypted plaintext wrapped in SensitiveValue.
	 * @throws CryptoException If envelope, AAD, key, or Poly1305 tag is invalid.
	 */
	private function decrypt_column(
		int $blog_id,
		string $column_name,
		int $wp_user_id,
		string $envelope
	): SensitiveValue {
		$envelope_key_id = $this->crypto->extract_key_id( $envelope );
		$aad             = CanonicalAad::for_table_column(
			$blog_id,
			self::LOGICAL_TABLE,
			$column_name,
			$wp_user_id,
			$envelope_key_id
		);

		return $this->crypto->decrypt( $envelope, $aad );
	}

	/**
	 * Fetch a raw `wpig_profiles` row by `wp_user_id`, optionally acquiring an InnoDB row lock (`FOR UPDATE`).
	 *
	 * @param int  $wp_user_id WordPress user ID (`>= 1`).
	 * @param bool $for_update Whether to append `FOR UPDATE` inside an active transaction.
	 * @return array<string,mixed>|null
	 */
	private function fetch_raw_row_by_user_id( int $wp_user_id, bool $for_update ): ?array {
		$table = $this->get_table_name();
		$wpdb  = $this->wpdb;

		if ( $for_update ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom table row lock inside transaction.
			$row = $wpdb->get_row(
				$wpdb->prepare(
					// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is strictly constructed from $wpdb->prefix + constant logical table.
					"SELECT * FROM `{$table}` WHERE wp_user_id = %d LIMIT 1 FOR UPDATE",
					$wp_user_id
				),
				ARRAY_A
			);
		} else {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom table lookup.
			$row = $wpdb->get_row(
				$wpdb->prepare(
					// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is strictly constructed from $wpdb->prefix + constant logical table.
					"SELECT * FROM `{$table}` WHERE wp_user_id = %d LIMIT 1",
					$wp_user_id
				),
				ARRAY_A
			);
		}

		return is_array( $row ) ? $row : null;
	}

	/**
	 * Map a raw internal database associative array to a safe `ProfileRecord` DTO.
	 *
	 * @param array<string,mixed> $row Raw database row from `wpig_profiles`.
	 * @return ProfileRecord
	 */
	private function map_row_to_record( array $row ): ProfileRecord {
		return new ProfileRecord(
			(int) $row['id'],
			(int) $row['wp_user_id'],
			(string) $row['country_code'],
			(string) $row['subject_type'],
			(string) $row['binding_state'],
			(string) $row['identity_state'],
			(int) $row['identity_version'],
			(int) $row['mobile_version'],
			(int) $row['card_version'],
			isset( $row['mobile_hmac'] ) && is_string( $row['mobile_hmac'] ) && '' !== $row['mobile_hmac']
				? $row['mobile_hmac']
				: null,
			isset( $row['mobile_masked'] ) && is_string( $row['mobile_masked'] ) && '' !== $row['mobile_masked']
				? $row['mobile_masked']
				: null,
			isset( $row['mobile_verified_at'] ) && is_string( $row['mobile_verified_at'] ) && '' !== $row['mobile_verified_at']
				? $row['mobile_verified_at']
				: null,
			isset( $row['national_code_hmac'] ) && is_string( $row['national_code_hmac'] ) && '' !== $row['national_code_hmac']
				? $row['national_code_hmac']
				: null,
			isset( $row['bound_national_code_hmac'] ) && is_string( $row['bound_national_code_hmac'] ) && '' !== $row['bound_national_code_hmac']
				? $row['bound_national_code_hmac']
				: null,
			isset( $row['national_code_masked'] ) && is_string( $row['national_code_masked'] ) && '' !== $row['national_code_masked']
				? $row['national_code_masked']
				: null,
			isset( $row['mobile_ciphertext'] ) && is_string( $row['mobile_ciphertext'] ) && '' !== $row['mobile_ciphertext'],
			isset( $row['national_code_ciphertext'] ) && is_string( $row['national_code_ciphertext'] ) && '' !== $row['national_code_ciphertext'],
			isset( $row['birth_date_ciphertext'] ) && is_string( $row['birth_date_ciphertext'] ) && '' !== $row['birth_date_ciphertext'],
			isset( $row['shahkar_verified_at'] ) && is_string( $row['shahkar_verified_at'] ) && '' !== $row['shahkar_verified_at']
				? $row['shahkar_verified_at']
				: null,
			isset( $row['enc_key_id'] ) && is_string( $row['enc_key_id'] ) && '' !== $row['enc_key_id']
				? $row['enc_key_id']
				: null,
			isset( $row['hmac_key_id'] ) && is_string( $row['hmac_key_id'] ) && '' !== $row['hmac_key_id']
				? $row['hmac_key_id']
				: null,
			isset( $row['bound_at'] ) && is_string( $row['bound_at'] ) && '' !== $row['bound_at']
				? $row['bound_at']
				: null,
			isset( $row['released_at'] ) && is_string( $row['released_at'] ) && '' !== $row['released_at']
				? $row['released_at']
				: null,
			isset( $row['verified_at'] ) && is_string( $row['verified_at'] ) && '' !== $row['verified_at']
				? $row['verified_at']
				: null,
			isset( $row['expires_at'] ) && is_string( $row['expires_at'] ) && '' !== $row['expires_at']
				? $row['expires_at']
				: null,
			(string) $row['created_at'],
			(string) $row['updated_at']
		);
	}

	/**
	 * Resolve the prefixed `wpig_profiles` table name for the current site.
	 */
	private function get_table_name(): string {
		$tables = SchemaDefinition::get_table_names( $this->wpdb->prefix );
		return $tables[ self::LOGICAL_TABLE ];
	}

	/**
	 * Return current UTC timestamp in `Y-m-d H:i:s` format.
	 */
	private function now_utc(): string {
		return (string) ( $this->clock )();
	}

	/**
	 * Resolve and validate the current blog ID (`>= 1`).
	 *
	 * @throws StorageException If blog ID is `< 1`.
	 */
	private function resolve_blog_id(): int {
		$blog_id = (int) ( $this->blog_id_resolver )();
		if ( $blog_id < 1 ) {
			StorageException::raise(
				StorageException::CODE_INVALID_BLOG_ID,
				'Site blog_id must be a positive integer (>= 1).'
			);
		}
		return $blog_id;
	}

	/**
	 * Validate WordPress user ID (`>= 1`).
	 *
	 * @param int $wp_user_id WordPress user ID.
	 * @throws StorageException If $wp_user_id is `< 1`.
	 */
	private function assert_valid_user_id( int $wp_user_id ): void {
		if ( $wp_user_id < 1 ) {
			StorageException::raise(
				StorageException::CODE_INVALID_USER_ID,
				'WordPress user ID must be a positive integer (>= 1).'
			);
		}
	}

	/**
	 * Determine the row-level `enc_key_id` to record after a partial or full ciphertext update.
	 *
	 * Validates that every ciphertext envelope on the row references a configured key ID
	 * in `KeyProviderInterface` (failing closed if any column references a missing/unknown key).
	 * If an untouched ciphertext column on the row still uses a previous key ID,
	 * preserves that older key ID on the row so key-rotation tracking knows the row
	 * still contains pre-rotation ciphertext.
	 *
	 * @param array<int,string|null> $envelopes     All ciphertext envelopes on the row after the update.
	 * @param string                 $active_key_id Active encryption key ID used for the updated column(s).
	 * @return string
	 * @throws CryptoException If any envelope is malformed or references an unknown encryption key ID.
	 */
	private function resolve_row_enc_key_id( array $envelopes, string $active_key_id ): string {
		$non_active_key_id = null;

		foreach ( $envelopes as $envelope ) {
			if ( null === $envelope || '' === $envelope ) {
				continue;
			}
			$env_key_id = $this->crypto->extract_key_id( $envelope );
			$this->key_provider->get_encryption_key( $env_key_id )->wipe();

			if ( $env_key_id !== $active_key_id && null === $non_active_key_id ) {
				$non_active_key_id = $env_key_id;
			}
		}

		return $non_active_key_id ?? $active_key_id;
	}

	/**
	 * Determine the row-level `hmac_key_id` to record after a partial HMAC column update.
	 *
	 * When another HMAC column on the row was not modified in the current call and
	 * `$existing_hmac_key_id` differs from `$active_hmac_key_id`, cryptographically
	 * inspects the untouched column against its authenticated ciphertext to determine
	 * whether that untouched column is already using `$active_hmac_key_id` (from an
	 * earlier partial update) or still using `$existing_hmac_key_id`. Fails closed
	 * if the untouched HMAC is missing its ciphertext or matches neither key.
	 *
	 * @param int         $blog_id              Site blog ID (`>= 1`).
	 * @param int         $wp_user_id           WordPress user ID (`>= 1`).
	 * @param string|null $existing_hmac_key_id Existing `hmac_key_id` on the row.
	 * @param string      $active_hmac_key_id   Active HMAC key ID used for the updated column.
	 * @param string      $untouched_col_name   Untouched ciphertext column name (`COL_NATIONAL_CODE_CIPHERTEXT` or `COL_MOBILE_CIPHERTEXT`).
	 * @param string|null $untouched_ciphertext Untouched ciphertext envelope on the row.
	 * @param string|null $untouched_hmac       Untouched 64-char hex HMAC on the row.
	 * @return string
	 * @throws CryptoException If the untouched column is in an inconsistent or unauthentic state.
	 */
	private function resolve_row_hmac_key_id(
		int $blog_id,
		int $wp_user_id,
		?string $existing_hmac_key_id,
		string $active_hmac_key_id,
		string $untouched_col_name,
		?string $untouched_ciphertext,
		?string $untouched_hmac
	): string {
		$has_untouched_hmac       = null !== $untouched_hmac && '' !== $untouched_hmac;
		$has_untouched_ciphertext = null !== $untouched_ciphertext && '' !== $untouched_ciphertext;

		if ( ! $has_untouched_hmac && ! $has_untouched_ciphertext ) {
			return $active_hmac_key_id;
		}

		if ( $has_untouched_hmac !== $has_untouched_ciphertext ) {
			CryptoException::raise(
				CryptoException::CODE_AUTH_FAILED,
				'Profile row has mismatched ciphertext and HMAC presence on untouched identity field.'
			);
		}

		if ( null === $existing_hmac_key_id || '' === $existing_hmac_key_id ) {
			CryptoException::raise(
				CryptoException::CODE_KEY_MISSING,
				'Profile row is missing hmac_key_id while storing HMAC fingerprints.'
			);
		}

		if ( $existing_hmac_key_id === $active_hmac_key_id ) {
			return $active_hmac_key_id;
		}

		$decrypted = $this->decrypt_column(
			$blog_id,
			$untouched_col_name,
			$wp_user_id,
			(string) $untouched_ciphertext
		);

		try {
			$matches_active = self::COL_NATIONAL_CODE_CIPHERTEXT === $untouched_col_name
				? $this->fingerprinter->verify_national_code( (string) $untouched_hmac, $decrypted, $active_hmac_key_id )
				: $this->fingerprinter->verify_mobile( (string) $untouched_hmac, $decrypted, $active_hmac_key_id );

			if ( $matches_active ) {
				return $active_hmac_key_id;
			}

			$matches_existing = self::COL_NATIONAL_CODE_CIPHERTEXT === $untouched_col_name
				? $this->fingerprinter->verify_national_code( (string) $untouched_hmac, $decrypted, $existing_hmac_key_id )
				: $this->fingerprinter->verify_mobile( (string) $untouched_hmac, $decrypted, $existing_hmac_key_id );

			if ( $matches_existing ) {
				return $existing_hmac_key_id;
			}
		} finally {
			$decrypted->wipe();
		}

		CryptoException::raise(
			CryptoException::CODE_AUTH_FAILED,
			'Untouched profile HMAC does not match authenticated ciphertext under active or existing HMAC key.'
		);
	}

	/**
	 * Validate expected version counter (`>= 1`).
	 *
	 * @param int    $expected_version Expected version number.
	 * @param string $version_label    Version field name for safe error message.
	 * @throws StorageException If $expected_version is `< 1`.
	 */
	private function assert_valid_version( int $expected_version, string $version_label ): void {
		if ( $expected_version < 1 ) {
			StorageException::raise(
				StorageException::CODE_VERSION_CONFLICT,
				sprintf( 'Expected %s must be >= 1.', $version_label )
			);
		}
	}
}

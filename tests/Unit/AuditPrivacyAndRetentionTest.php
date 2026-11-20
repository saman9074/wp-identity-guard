<?php
/**
 * Unit tests for Phase P01-D3 Audit Logging, Privacy Lifecycle, Retention,
 * and Authority Grant Replay/Scope Hardening.
 *
 * All numeric PII/PAN/OTP test vectors are constructed dynamically at runtime so
 * no literal national codes, mobile numbers, or card PANs appear in source files.
 *
 * @package WPIG\Tests\Unit
 */

declare(strict_types=1);

namespace WPIG\Tests\Unit;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionMethod;
use wpdb;
use WPIG\Admin\AdminController;
use WPIG\Admin\SettingsRepository;
use WPIG\Audit\AuditEventRecord;
use WPIG\Audit\AuditRepository;
use WPIG\Audit\AuditService;
use WPIG\Privacy\ConsentRecord;
use WPIG\Privacy\ConsentRepository;
use WPIG\Privacy\PrivacyEraserService;
use WPIG\Privacy\PrivacyExporterService;
use WPIG\Security\AuthenticationContext;
use WPIG\Security\AuthorizationException;
use WPIG\Security\AuthorizationService;
use WPIG\Security\Capabilities;
use WPIG\Security\IdentityFingerprinter;
use WPIG\Security\SensitiveValue;
use WPIG\Security\SodiumCrypto;
use WPIG\Security\ValidationException;
use WPIG\Security\VerificationAuthorityGrant;
use WPIG\Security\WordPressKeyProvider;
use WPIG\Storage\ProfileAccessBoundary;
use WPIG\Storage\ProfileRecord;
use WPIG\Storage\ProfileRepository;
use WPIG\Storage\RetentionService;

/**
 * Verifies all 15 Phase P01-D3 security, audit, privacy, retention, and authority-grant requirements.
 */
final class AuditPrivacyAndRetentionTest extends TestCase {

	private const SYNTHETIC_ENC_KEY  = 'hex:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20';
	private const SYNTHETIC_HMAC_KEY = 'hex:a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0';

	/**
	 * Active server-authenticated principal ID in unit tests.
	 *
	 * @var int
	 */
	private int $current_user_id = 1;

	/**
	 * Construct a synthetic valid 10-digit Iranian national code at runtime.
	 */
	private static function synthetic_national_code(): string {
		return implode( '', array( '0', '0', '1', '3', '5', '4', '2', '4', '1', '9' ) );
	}

	/**
	 * Construct a synthetic valid Iranian mobile number at runtime.
	 */
	private static function synthetic_mobile(): string {
		return '0912' . str_repeat( '3', 3 ) . '6789';
	}

	/**
	 * Construct a synthetic 16-digit PAN at runtime.
	 */
	private static function synthetic_pan(): string {
		return '6037' . str_repeat( '9', 8 ) . '1234';
	}

	/**
	 * Build an in-memory multi-table `wpdb` test double supporting `wpig_audit_events`,
	 * `wpig_consents`, `wpig_profiles`, `wpig_cards`, `wpig_verifications`, and `wpig_otp_challenges`.
	 *
	 * @param string $prefix Table prefix.
	 * @return wpdb
	 */
	private function make_in_memory_wpdb( string $prefix = 'wp_' ): wpdb {
		return new class( $prefix ) extends wpdb {
			/**
			 * Stored audit rows.
			 *
			 * @var list<array<string,mixed>>
			 */
			public array $audit_rows = array();

			/**
			 * Stored consent rows.
			 *
			 * @var list<array<string,mixed>>
			 */
			public array $consent_rows = array();

			/**
			 * Stored profile rows keyed by wp_user_id.
			 *
			 * @var array<int,array<string,mixed>>
			 */
			public array $profile_rows = array();

			/**
			 * Stored card rows.
			 *
			 * @var list<array<string,mixed>>
			 */
			public array $card_rows = array();

			/**
			 * Stored verification rows.
			 *
			 * @var list<array<string,mixed>>
			 */
			public array $verification_rows = array();

			/**
			 * Stored OTP challenge rows.
			 *
			 * @var list<array<string,mixed>>
			 */
			public array $otp_rows = array();

			/**
			 * Executed SQL log.
			 *
			 * @var list<string>
			 */
			public array $queries_log = array();

			/**
			 * Next auto-increment ID.
			 *
			 * @var int
			 */
			private int $next_id = 1;

			/**
			 * Constructor.
			 *
			 * @param string $prefix Table prefix.
			 */
			public function __construct( string $prefix ) {
				$this->prefix = $prefix;
			}

			/**
			 * Execute a prepared SQL statement against in-memory collections.
			 *
			 * @param string $query SQL statement.
			 * @return int|bool
			 */
			public function query( $query ) {
				$sql                 = trim( (string) $query );
				$this->queries_log[] = $sql;

				if ( in_array( strtoupper( $sql ), array( 'START TRANSACTION', 'COMMIT', 'ROLLBACK' ), true ) ) {
					return 1;
				}

				// 1. Audit INSERT.
				if ( str_starts_with( $sql, 'INSERT INTO `' . $this->prefix . 'wpig_audit_events`' ) ) {
					$id              = $this->next_id++;
					$this->insert_id = $id;
					if ( preg_match( "/VALUES\s*\('([^']*)',\s*(NULL|\d+),\s*(NULL|\d+),\s*'([^']*)',\s*'([^']*)',\s*'([^']*)',\s*'([^']*)'\)/s", $sql, $m ) ) {
						$this->audit_rows[] = array(
							'id'                 => $id,
							'correlation_id'     => stripslashes( $m[1] ),
							'actor_user_id'      => 'NULL' === $m[2] ? null : (int) $m[2],
							'target_user_id'     => 'NULL' === $m[3] ? null : (int) $m[3],
							'event_type'         => stripslashes( $m[4] ),
							'outcome'            => stripslashes( $m[5] ),
							'safe_metadata_json' => '' === $m[6] ? null : stripslashes( $m[6] ),
							'occurred_at'        => stripslashes( $m[7] ),
						);
					}
					return 1;
				}

				// 2. Audit DELETE (prune_expired_batch).
				if ( str_starts_with( $sql, 'DELETE FROM `' . $this->prefix . 'wpig_audit_events`' ) ) {
					if ( preg_match( "/occurred_at < '([^']+)'.*LIMIT (\d+)/s", $sql, $m ) ) {
						$cutoff  = $m[1];
						$limit   = (int) $m[2];
						$deleted = 0;
						foreach ( $this->audit_rows as $idx => $row ) {
							if ( $deleted >= $limit ) {
								break;
							}
							if ( (string) $row['occurred_at'] < $cutoff ) {
								unset( $this->audit_rows[ $idx ] );
								++$deleted;
							}
						}
						$this->audit_rows = array_values( $this->audit_rows );
						return $deleted;
					}
					return 0;
				}

				// 3. Consent INSERT.
				if ( str_starts_with( $sql, 'INSERT INTO `' . $this->prefix . 'wpig_consents`' ) ) {
					$id              = $this->next_id++;
					$this->insert_id = $id;
					if ( preg_match( "/VALUES\s*\((\d+),\s*'([^']*)',\s*'([^']*)',\s*'([^']*)',\s*'([^']*)',\s*NULL,\s*(NULL|'[^']*')\)/s", $sql, $m ) ) {
						$exp                  = 'NULL' === $m[6] ? null : trim( $m[6], "'" );
						$this->consent_rows[] = array(
							'id'             => $id,
							'wp_user_id'     => (int) $m[1],
							'notice_version' => stripslashes( $m[2] ),
							'notice_hash'    => stripslashes( $m[3] ),
							'purposes_json'  => stripslashes( $m[4] ),
							'accepted_at'    => stripslashes( $m[5] ),
							'revoked_at'     => null,
							'expires_at'     => $exp,
						);
					}
					return 1;
				}

				// 4. Consent UPDATE (withdraw_consent).
				if ( str_starts_with( $sql, 'UPDATE `' . $this->prefix . 'wpig_consents`' ) ) {
					if ( preg_match( "/SET revoked_at = '([^']+)' WHERE wp_user_id = (\d+) AND revoked_at IS NULL/", $sql, $m ) ) {
						$revoked_at = $m[1];
						$uid        = (int) $m[2];
						$updated    = 0;
						foreach ( $this->consent_rows as $idx => $row ) {
							if ( (int) $row['wp_user_id'] === $uid && null === $row['revoked_at'] ) {
								$this->consent_rows[ $idx ]['revoked_at'] = $revoked_at;
								++$updated;
							}
						}
						return $updated;
					}
					return 0;
				}

				// 5. OTP DELETE.
				if ( str_starts_with( $sql, 'DELETE FROM `' . $this->prefix . 'wpig_otp_challenges`' ) ) {
					if ( preg_match( '/WHERE wp_user_id = (\d+)/', $sql, $m ) ) {
						$uid     = (int) $m[1];
						$deleted = 0;
						foreach ( $this->otp_rows as $idx => $row ) {
							if ( (int) $row['wp_user_id'] === $uid ) {
								unset( $this->otp_rows[ $idx ] );
								++$deleted;
							}
						}
						$this->otp_rows = array_values( $this->otp_rows );
						return $deleted;
					}
					if ( preg_match( "/WHERE expires_at < '([^']+)'.*LIMIT (\d+)/s", $sql, $m ) ) {
						$cutoff  = $m[1];
						$limit   = (int) $m[2];
						$deleted = 0;
						foreach ( $this->otp_rows as $idx => $row ) {
							if ( $deleted >= $limit ) {
								break;
							}
							if ( (string) $row['expires_at'] < $cutoff ) {
								unset( $this->otp_rows[ $idx ] );
								++$deleted;
							}
						}
						$this->otp_rows = array_values( $this->otp_rows );
						return $deleted;
					}
					return 0;
				}

				// 6. Verifications DELETE (prune_terminal_verifications_batch).
				if ( str_starts_with( $sql, 'DELETE FROM `' . $this->prefix . 'wpig_verifications`' ) ) {
					if ( preg_match( "/requested_at < '([^']+)'.*LIMIT (\d+)/s", $sql, $m ) ) {
						$cutoff         = $m[1];
						$limit          = (int) $m[2];
						$referenced_ids = array();
						foreach ( $this->card_rows as $card ) {
							$referenced_ids[ (int) $card['verification_id'] ] = true;
						}
						$deleted = 0;
						foreach ( $this->verification_rows as $idx => $row ) {
							if ( $deleted >= $limit ) {
								break;
							}
							$state = (string) $row['state'];
							$vid   = (int) $row['id'];
							if (
								in_array( $state, array( 'REJECTED', 'EXPIRED', 'FAILED' ), true )
								&& (string) $row['requested_at'] < $cutoff
								&& ! isset( $referenced_ids[ $vid ] )
							) {
								unset( $this->verification_rows[ $idx ] );
								++$deleted;
							}
						}
						$this->verification_rows = array_values( $this->verification_rows );
						return $deleted;
					}
					return 0;
				}

				// 7. Profile UPDATE (clear_unbound_profile_pii or bind_verified_identity).
				if ( str_starts_with( $sql, 'UPDATE `' . $this->prefix . 'wpig_profiles`' ) ) {
					if ( str_contains( $sql, 'SET national_code_ciphertext = NULL' ) && preg_match( '/WHERE id = (\d+)/', $sql, $m ) ) {
						$row_id = (int) $m[1];
						foreach ( $this->profile_rows as $uid => $row ) {
							if (
								(int) $row['id'] === $row_id
								&& 'BOUND' !== (string) $row['binding_state']
								&& 'REVIEW_REQUIRED' !== (string) $row['identity_state']
							) {
								$this->profile_rows[ $uid ]['national_code_ciphertext'] = null;
								$this->profile_rows[ $uid ]['national_code_hmac']       = null;
								$this->profile_rows[ $uid ]['national_code_masked']     = null;
								$this->profile_rows[ $uid ]['birth_date_ciphertext']    = null;
								$this->profile_rows[ $uid ]['mobile_ciphertext']        = null;
								$this->profile_rows[ $uid ]['mobile_hmac']              = null;
								$this->profile_rows[ $uid ]['mobile_masked']            = null;
								$this->profile_rows[ $uid ]['mobile_verified_at']       = null;
								$this->profile_rows[ $uid ]['shahkar_verified_at']      = null;
								$this->profile_rows[ $uid ]['enc_key_id']               = null;
								$this->profile_rows[ $uid ]['hmac_key_id']              = null;
								$this->profile_rows[ $uid ]['identity_state']           = 'UNVERIFIED';
								++$this->profile_rows[ $uid ]['identity_version'];
								++$this->profile_rows[ $uid ]['mobile_version'];
								return 1;
							}
						}
						return 0;
					}

					if ( str_contains( $sql, 'SET binding_state =' ) && preg_match( '/WHERE id = (\d+) AND identity_version = (\d+) AND mobile_version = (\d+)/', $sql, $m ) ) {
						$row_id = (int) $m[1];
						$id_ver = (int) $m[2];
						$mb_ver = (int) $m[3];
						foreach ( $this->profile_rows as $uid => $row ) {
							if (
								(int) $row['id'] === $row_id
								&& (int) $row['identity_version'] === $id_ver
								&& (int) $row['mobile_version'] === $mb_ver
							) {
								$this->profile_rows[ $uid ]['binding_state']            = 'BOUND';
								$this->profile_rows[ $uid ]['identity_state']           = 'VERIFIED';
								$this->profile_rows[ $uid ]['bound_national_code_hmac'] = $row['national_code_hmac'];
								$this->profile_rows[ $uid ]['bound_at']                 = '2026-11-15 10:00:00';
								$this->profile_rows[ $uid ]['shahkar_verified_at']      = '2026-11-15 10:00:00';
								$this->profile_rows[ $uid ]['verified_at']              = '2026-11-15 10:00:00';
								return 1;
							}
						}
						return 0;
					}
				}

				return 1;
			}

			/**
			 * Fetch a single row from in-memory tables.
			 *
			 * @param string|null $query  SQL query.
			 * @param string      $output Output format.
			 * @param int         $y      Row offset.
			 * @return array<string,mixed>|null
			 */
			public function get_row( $query = null, $output = ARRAY_A, $y = 0 ) {
				unset( $output, $y );
				$sql = (string) $query;

				if ( str_contains( $sql, $this->prefix . 'wpig_audit_events' ) && preg_match( '/WHERE id = (\d+)/', $sql, $m ) ) {
					$id = (int) $m[1];
					foreach ( $this->audit_rows as $row ) {
						if ( (int) $row['id'] === $id ) {
							return $row;
						}
					}
					return null;
				}

				if ( str_contains( $sql, $this->prefix . 'wpig_profiles' ) && preg_match( '/WHERE wp_user_id = (\d+)/', $sql, $m ) ) {
					$uid = (int) $m[1];
					return $this->profile_rows[ $uid ] ?? null;
				}

				return null;
			}

			/**
			 * Fetch multiple rows from in-memory tables.
			 *
			 * @param string|null $query  SQL query.
			 * @param string      $output Output format.
			 * @return list<array<string,mixed>>
			 */
			public function get_results( $query = null, $output = ARRAY_A ) {
				unset( $output );
				$sql = (string) $query;

				if ( str_contains( $sql, $this->prefix . 'wpig_audit_events' ) && preg_match( '/WHERE target_user_id = (\d+)/', $sql, $m ) ) {
					$uid = (int) $m[1];
					$out = array();
					foreach ( array_reverse( $this->audit_rows ) as $row ) {
						if ( (int) $row['target_user_id'] === $uid ) {
							$out[] = $row;
						}
					}
					return $out;
				}

				if ( str_contains( $sql, $this->prefix . 'wpig_consents' ) && preg_match( '/WHERE wp_user_id = (\d+)/', $sql, $m ) ) {
					$uid = (int) $m[1];
					$out = array();
					foreach ( array_reverse( $this->consent_rows ) as $row ) {
						if ( (int) $row['wp_user_id'] === $uid ) {
							$out[] = $row;
						}
					}
					return $out;
				}

				if ( str_contains( $sql, $this->prefix . 'wpig_cards' ) && preg_match( '/WHERE wp_user_id = (\d+)/', $sql, $m ) ) {
					$uid = (int) $m[1];
					$out = array();
					foreach ( $this->card_rows as $row ) {
						if ( (int) $row['wp_user_id'] === $uid ) {
							$out[] = array(
								'id'          => $row['id'],
								'masked_pan'  => $row['masked_pan'],
								'state'       => $row['state'],
								'verified_at' => $row['verified_at'],
							);
						}
					}
					return $out;
				}

				return array();
			}

			/**
			 * Fetch a scalar value from in-memory tables.
			 *
			 * @param string|null $query SQL query.
			 * @param int         $x     Column offset.
			 * @param int         $y     Row offset.
			 * @return string|null
			 */
			public function get_var( $query = null, $x = 0, $y = 0 ) {
				unset( $x, $y );
				$sql = (string) $query;

				if ( str_contains( $sql, 'SELECT COUNT(*) FROM `' . $this->prefix . 'wpig_audit_events`' ) ) {
					if ( preg_match( "/WHERE event_type = '([^']+)'/", $sql, $m ) ) {
						$type  = $m[1];
						$count = 0;
						foreach ( $this->audit_rows as $row ) {
							if ( (string) $row['event_type'] === $type ) {
								++$count;
							}
						}
						return (string) $count;
					}
					return (string) count( $this->audit_rows );
				}

				if ( str_contains( $sql, 'SELECT COUNT(*) FROM `' . $this->prefix . 'wpig_otp_challenges`' ) && preg_match( '/WHERE wp_user_id = (\d+)/', $sql, $m ) ) {
					$uid   = (int) $m[1];
					$count = 0;
					foreach ( $this->otp_rows as $row ) {
						if ( (int) $row['wp_user_id'] === $uid ) {
							++$count;
						}
					}
					return (string) $count;
				}

				if ( str_contains( $sql, 'SELECT id FROM `' . $this->prefix . 'wpig_verifications`' ) && preg_match( '/WHERE wp_user_id = (\d+)/', $sql, $m ) ) {
					$uid = (int) $m[1];
					foreach ( $this->verification_rows as $row ) {
						if ( (int) $row['wp_user_id'] === $uid ) {
							return (string) $row['id'];
						}
					}
					return null;
				}

				if ( str_contains( $sql, 'SELECT id FROM `' . $this->prefix . 'wpig_cards`' ) && preg_match( '/WHERE wp_user_id = (\d+)/', $sql, $m ) ) {
					$uid = (int) $m[1];
					foreach ( $this->card_rows as $row ) {
						if ( (int) $row['wp_user_id'] === $uid ) {
							return (string) $row['id'];
						}
					}
					return null;
				}

				if ( str_contains( $sql, 'WHERE bound_national_code_hmac =' ) && preg_match( "/WHERE bound_national_code_hmac = '([^']+)' AND wp_user_id != (\d+)/", $sql, $m ) ) {
					$hmac = $m[1];
					$uid  = (int) $m[2];
					foreach ( $this->profile_rows as $other_uid => $row ) {
						if ( $other_uid !== $uid && isset( $row['bound_national_code_hmac'] ) && $hmac === $row['bound_national_code_hmac'] ) {
							return (string) $row['id'];
						}
					}
					return null;
				}

				return null;
			}
		};
	}

	/**
	 * Build an AuthorizationService test fixture.
	 *
	 * @param int  $active_blog_id Active blog ID.
	 * @param bool $is_multisite   Whether Multisite is active.
	 */
	private function make_authorizer( int $active_blog_id = 1, bool $is_multisite = false ): AuthorizationService {
		$this->current_user_id = 1;
		$users                 = array(
			1  => array(
				'roles' => array( 'administrator' ),
				'caps'  => Capabilities::all(),
				'blogs' => array( 1 ),
			),
			2  => array(
				'roles' => array( 'wpig_auditor' ),
				'caps'  => array( Capabilities::VIEW_REPORTS ),
				'blogs' => array( 1 ),
			),
			11 => array(
				'roles' => array( 'subscriber' ),
				'caps'  => array( 'read' ),
				'blogs' => array( 1 ),
			),
			12 => array(
				'roles' => array( 'customer' ),
				'caps'  => array( 'read' ),
				'blogs' => array( 1 ),
			),
			20 => array(
				'roles' => array( 'administrator' ),
				'caps'  => Capabilities::all(),
				'blogs' => array( 2 ), // Site 2 admin only; not a member of site 1.
			),
		);

		$role_caps = array(
			'administrator' => Capabilities::all(),
			'wpig_auditor'  => array( Capabilities::VIEW_REPORTS ),
			'subscriber'    => array(),
			'customer'      => array(),
		);

		return new AuthorizationService(
			static fn( int $uid ): bool => isset( $users[ $uid ] ),
			static fn( int $uid, string $cap ): bool => isset( $users[ $uid ] )
				&& in_array( $cap, $users[ $uid ]['caps'], true ),
			static fn( int $uid ): array => $users[ $uid ]['roles'] ?? array(),
			static fn(): int => $active_blog_id,
			static fn(): bool => $is_multisite,
			static fn( int $uid, int $b_id ): bool => isset( $users[ $uid ] )
				&& in_array( $b_id, $users[ $uid ]['blogs'], true ),
			static fn( string $role, string $cap ): bool => isset( $role_caps[ $role ] )
				&& in_array( $cap, $role_caps[ $role ], true ),
			AuthenticationContext::wordpress_request( fn(): int => $this->current_user_id )
		);
	}

	/**
	 * Build a ProfileRepository over the in-memory `wpdb`.
	 *
	 * @param wpdb $wpdb In-memory database object.
	 * @param int  $blog_id Active blog ID.
	 */
	private function make_profile_repository( wpdb $wpdb, int $blog_id = 1 ): ProfileRepository {
		$key_map       = array(
			WordPressKeyProvider::CONST_ENC_KEY     => self::SYNTHETIC_ENC_KEY,
			WordPressKeyProvider::CONST_ENC_KEY_ID  => 'k2026_01',
			WordPressKeyProvider::CONST_HMAC_KEY    => self::SYNTHETIC_HMAC_KEY,
			WordPressKeyProvider::CONST_HMAC_KEY_ID => 'hmac_2026_01',
		);
		$key_provider  = new WordPressKeyProvider(
			static fn( string $name ): mixed => $key_map[ $name ] ?? null,
			static fn(): string|false => false
		);
		$crypto        = new SodiumCrypto( $key_provider );
		$fingerprinter = new IdentityFingerprinter( $crypto, $key_provider );

		return new ProfileRepository(
			$wpdb,
			$crypto,
			$key_provider,
			$fingerprinter,
			static fn(): string => '2026-11-15 10:00:00',
			static fn(): int => $blog_id
		);
	}

	/**
	 * Tests 1, 2, 3 & 4:
	 * - Audit event creation with UUID v4 correlation ID, UTC timestamp, and safe metadata.
	 * - Audit metadata allowlist enforcement (unknown keys rejected).
	 * - Rejection of sensitive fields in audit metadata (raw national code, mobile, PAN, OTP, secret keys, HMACs, SensitiveValue, exception messages).
	 * - Append-only AuditRepository behavior (exposes zero UPDATE methods).
	 */
	public function test_audit_event_creation_allowlists_sensitive_rejection_and_append_only_contract(): void {
		$wpdb       = $this->make_in_memory_wpdb();
		$audit_repo = new AuditRepository( $wpdb, static fn(): string => '2026-11-15 09:30:00' );
		$audit_svc  = new AuditService( $audit_repo );

		// 4. Verify AuditRepository is strictly append-only (no update* methods, and never issues UPDATE SQL).
		$reflection = new ReflectionClass( AuditRepository::class );
		foreach ( $reflection->getMethods( ReflectionMethod::IS_PUBLIC ) as $method ) {
			self::assertStringStartsNotWith(
				'update',
				strtolower( $method->getName() ),
				'AuditRepository must not expose any update method.'
			);
		}

		// 1. Valid audit event creation.
		$event = $audit_svc->record(
			AuditService::EVENT_VERIFICATION_ATTEMPTED,
			AuditService::OUTCOME_SUCCESS,
			11,
			11,
			array(
				'provider'         => 'api_ir',
				'operation'        => 'shahkar',
				'identity_version' => 2,
				'mobile_version'   => 1,
			)
		);

		self::assertInstanceOf( AuditEventRecord::class, $event );
		self::assertSame( 1, $event->id );
		self::assertMatchesRegularExpression( AuditService::UUID_V4_PATTERN, $event->correlation_id );
		self::assertSame( 11, $event->actor_user_id );
		self::assertSame( 11, $event->target_user_id );
		self::assertSame( AuditService::EVENT_VERIFICATION_ATTEMPTED, $event->event_type );
		self::assertSame( AuditService::OUTCOME_SUCCESS, $event->outcome );
		self::assertSame( '2026-11-15 09:30:00', $event->occurred_at );
		self::assertSame( 'api_ir', $event->safe_metadata['provider'] );

		$fetched = $audit_repo->find_by_id( 1 );
		self::assertNotNull( $fetched );
		self::assertSame( $event->correlation_id, $fetched->correlation_id );
		self::assertSame( 1, $audit_repo->count_events( AuditService::EVENT_VERIFICATION_ATTEMPTED ) );

		// 2. Reject unknown event type, unknown outcome, and unknown metadata key.
		try {
			$audit_svc->record( 'custom.unapproved_event', AuditService::OUTCOME_SUCCESS );
			self::fail( 'Expected ValidationException for unapproved event_type.' );
		} catch ( ValidationException $e ) {
			self::assertSame( ValidationException::CODE_INVALID_AUDIT_EVENT, $e->get_safe_code() );
		}

		try {
			$audit_svc->record( AuditService::EVENT_SETTINGS_UPDATED, 'UNKNOWN_OUTCOME' );
			self::fail( 'Expected ValidationException for unapproved outcome.' );
		} catch ( ValidationException $e ) {
			self::assertSame( ValidationException::CODE_INVALID_AUDIT_OUTCOME, $e->get_safe_code() );
		}

		try {
			$audit_svc->record(
				AuditService::EVENT_SETTINGS_UPDATED,
				AuditService::OUTCOME_SUCCESS,
				1,
				null,
				array( 'raw_payload' => 'forbidden' )
			);
			self::fail( 'Expected ValidationException for unapproved metadata key.' );
		} catch ( ValidationException $e ) {
			self::assertSame( ValidationException::CODE_INVALID_AUDIT_METADATA, $e->get_safe_code() );
		}

		// 3. Reject sensitive values even when placed under an allowlisted metadata key.
		$sensitive_payloads = array(
			'raw_national_code' => array( 'operation' => self::synthetic_national_code() ),
			'persian_nc'        => array( 'operation' => implode( '', array( '۰', '۰', '۱', '۳', '۵', '۴', '۲', '۴', '۱', '۹' ) ) ),
			'raw_mobile'        => array( 'operation' => self::synthetic_mobile() ),
			'raw_pan'           => array( 'operation' => self::synthetic_pan() ),
			'raw_otp'           => array( 'operation' => '482910' ),
			'hex_hmac_or_key'   => array( 'operation' => str_repeat( 'f', 64 ) ),
			'ciphertext_env'    => array( 'operation' => 'v1:k2026_01:abcdef' ),
			'key_material'      => array( 'operation' => self::SYNTHETIC_ENC_KEY ),
			'bearer_token'      => array( 'operation' => 'Bearer secret_api_token' ),
			'json_payload'      => array( 'operation' => '{"status":"ok"}' ),
			'sensitive_obj'     => array( 'operation' => new SensitiveValue( 'secret' ) ),
		);

		foreach ( $sensitive_payloads as $label => $bad_metadata ) {
			try {
				$audit_svc->record(
					AuditService::EVENT_ADMIN_SECURITY_OPERATION,
					AuditService::OUTCOME_FAILURE,
					1,
					null,
					$bad_metadata
				);
				self::fail( "AuditService must reject sensitive metadata payload: {$label}" );
			} catch ( ValidationException $e ) {
				self::assertSame(
					ValidationException::CODE_SENSITIVE_AUDIT_METADATA,
					$e->get_safe_code(),
					"Unexpected error code for {$label}."
				);
			}
		}

		// Arbitrary exception messages in safe_error_code must be rejected.
		try {
			$audit_svc->record(
				AuditService::EVENT_MIGRATION_FAILED,
				AuditService::OUTCOME_FAILURE,
				1,
				null,
				array( 'safe_error_code' => 'SQLSTATE[42S02]: Table wp_wpig_profiles does not exist' )
			);
			self::fail( 'Arbitrary SQL/exception message in safe_error_code must be rejected.' );
		} catch ( ValidationException $e ) {
			self::assertSame( ValidationException::CODE_INVALID_AUDIT_METADATA, $e->get_safe_code() );
		}
	}

	/**
	 * Tests 5, 6 & 7:
	 * - Authorization-denied event logging across ProfileAccessBoundary and AdminController.
	 * - Settings-update audit logging (`settings.updated` and `settings.update_rejected`).
	 * - Consent acceptance and withdrawal logging (`consent.accepted`, `consent.withdrawn`) and separation from erasure.
	 */
	public function test_authorization_denied_settings_and_consent_audit_logging(): void {
		$wpdb         = $this->make_in_memory_wpdb();
		$audit_repo   = new AuditRepository( $wpdb, static fn(): string => '2026-11-15 10:00:00' );
		$audit_svc    = new AuditService( $audit_repo );
		$authorizer   = $this->make_authorizer();
		$profile_repo = $this->make_profile_repository( $wpdb );
		$boundary     = new ProfileAccessBoundary(
			$profile_repo,
			$authorizer,
			str_repeat( 's', 32 ),
			static fn(): int => 1,
			$audit_svc
		);

		// 5. Cross-user IDOR attempt on ProfileAccessBoundary logs authorization.denied (DENIED).
		$this->current_user_id = 11;
		try {
			$boundary->get_masked_profile( 11, 12, 1 );
			self::fail( 'Expected IDOR denial.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_CROSS_USER_FORBIDDEN, $e->get_safe_code() );
		}

		self::assertSame( 1, $audit_repo->count_events( AuditService::EVENT_AUTHORIZATION_DENIED ) );
		$denied_events = $audit_repo->find_for_target_user( 12 );
		self::assertCount( 1, $denied_events );
		self::assertSame( 11, $denied_events[0]->actor_user_id );
		self::assertSame( 'CROSS_USER_FORBIDDEN', $denied_events[0]->safe_metadata['safe_error_code'] );

		// 6. AdminController settings update and rejection audit logging.
		$this->current_user_id = 1;
		$option_store          = array();
		$settings_repo         = new SettingsRepository(
			$authorizer,
			static fn( string $k, mixed $d = false ): mixed => $option_store[ $k ] ?? $d,
			static function ( string $k, mixed $v ) use ( &$option_store ): bool {
				$option_store[ $k ] = $v;
				return true;
			},
			static function ( string $k, mixed $v ) use ( &$option_store ): bool {
				$option_store[ $k ] = $v;
				return true;
			}
		);
		$controller            = new AdminController(
			$authorizer,
			$settings_repo,
			null,
			static fn( string $nonce ): bool => 'valid_nonce' === $nonce,
			static fn(): string => 'valid_nonce',
			static fn(): bool => false,
			$audit_svc
		);

		$controller->handle_settings_post(
			1,
			'POST',
			array(
				AdminController::NONCE_FIELD => 'valid_nonce',
				'settings'                   => array(
					'default_provider'               => 'api_ir',
					'sandbox_mode'                   => '1',
					'daily_request_budget'           => '500',
					'rate_limit_per_user_hour'       => '10',
					'rate_limit_per_ip_hour'         => '50',
					'security_notifications_enabled' => '1',
					'consent_notice_version'         => '1.1.0',
				),
			)
		);
		self::assertSame( 1, $audit_repo->count_events( AuditService::EVENT_SETTINGS_UPDATED ) );

		// Invalid settings value logs settings.update_rejected (FAILURE).
		try {
			$controller->handle_settings_post(
				1,
				'POST',
				array(
					AdminController::NONCE_FIELD => 'valid_nonce',
					'settings'                   => array(
						'default_provider' => 'evil_provider',
					),
				)
			);
			self::fail( 'Expected ValidationException on invalid provider.' );
		} catch ( ValidationException $e ) {
			self::assertSame( ValidationException::CODE_INVALID_SETTING, $e->get_safe_code() );
		}
		self::assertSame( 1, $audit_repo->count_events( AuditService::EVENT_SETTINGS_UPDATE_REJECTED ) );

		// 7. Consent acceptance and withdrawal logging.
		$consent_repo = new ConsentRepository( $wpdb, $audit_svc, static fn(): string => '2026-11-15 10:05:00' );
		$notice_hash  = ConsentRepository::hash_notice_text( 'WP Identity Guard Privacy Notice v1.0' );
		$consent      = $consent_repo->record_consent(
			11,
			'1.0.0',
			$notice_hash,
			array( 'identity_verification', 'mobile_otp' )
		);

		self::assertInstanceOf( ConsentRecord::class, $consent );
		self::assertTrue( $consent_repo->has_active_consent( 11, 'identity_verification', '2026-11-15 10:06:00' ) );
		self::assertSame( 1, $audit_repo->count_events( AuditService::EVENT_CONSENT_ACCEPTED ) );

		// Withdraw consent: marks revoked_at, logs consent.withdrawn, and keeps consent audit row intact.
		$withdrawn_count = $consent_repo->withdraw_consent( 11, 11 );
		self::assertSame( 1, $withdrawn_count );
		self::assertFalse( $consent_repo->has_active_consent( 11, 'identity_verification', '2026-11-15 10:06:00' ) );
		self::assertSame( 1, $audit_repo->count_events( AuditService::EVENT_CONSENT_WITHDRAWN ) );
		self::assertCount( 1, $consent_repo->find_all_for_user( 11 ) );
	}

	/**
	 * Tests 8, 9, 10, 11, 12 & 13:
	 * - Privacy export output safety (masked national code, masked mobile, masked card PAN, consent records, high-level status).
	 * - Privacy export rejection/exclusion of sensitive fields (decrypted national code, full mobile, birth date, full PAN, keys, HMACs).
	 * - Privacy erasure behavior for UNBOUND profile + transient OTP challenges.
	 * - Preservation of active BOUND identity binding (`D14`) during erasure (`bound_national_code_hmac` untouched).
	 * - Legal-hold and `REVIEW_REQUIRED` erasure blocks.
	 * - Multisite isolation for export and erasure.
	 */
	public function test_privacy_export_erasure_binding_preservation_legal_hold_and_multisite_isolation(): void {
		$wpdb         = $this->make_in_memory_wpdb();
		$audit_repo   = new AuditRepository( $wpdb, static fn(): string => '2026-11-15 11:00:00' );
		$audit_svc    = new AuditService( $audit_repo );
		$authorizer   = $this->make_authorizer( 1, true );
		$profile_repo = $this->make_profile_repository( $wpdb, 1 );
		$consent_repo = new ConsentRepository( $wpdb, $audit_svc, static fn(): string => '2026-11-15 11:00:00' );

		$raw_nc     = self::synthetic_national_code();
		$raw_mobile = self::synthetic_mobile();
		$raw_bd     = '1370/05/12';
		$nc_hmac    = str_repeat( 'c', 64 );
		$mob_hmac   = str_repeat( 'd', 64 );

		// Seed User 11 with a BOUND & VERIFIED profile, a masked card, an OTP challenge, and a consent record.
		$wpdb->profile_rows[11] = array(
			'id'                       => 101,
			'wp_user_id'               => 11,
			'country_code'             => 'IR',
			'subject_type'             => 'natural',
			'binding_state'            => ProfileRecord::BINDING_BOUND,
			'identity_state'           => ProfileRecord::STATE_VERIFIED,
			'identity_version'         => 1,
			'mobile_version'           => 1,
			'card_version'             => 1,
			'mobile_ciphertext'        => 'v1:k2026_01:CIPHERTEXT_MOBILE_SECRET',
			'mobile_hmac'              => $mob_hmac,
			'mobile_masked'            => '0912***6789',
			'mobile_verified_at'       => '2026-11-15 10:00:00',
			'national_code_ciphertext' => 'v1:k2026_01:CIPHERTEXT_NC_SECRET',
			'national_code_hmac'       => $nc_hmac,
			'bound_national_code_hmac' => $nc_hmac,
			'national_code_masked'     => '******2419',
			'birth_date_ciphertext'    => 'v1:k2026_01:CIPHERTEXT_BD_SECRET',
			'shahkar_verified_at'      => '2026-11-15 10:00:00',
			'enc_key_id'               => 'k2026_01',
			'hmac_key_id'              => 'hmac_2026_01',
			'bound_at'                 => '2026-11-15 10:00:00',
			'released_at'              => null,
			'verified_at'              => '2026-11-15 10:00:00',
			'expires_at'               => '2027-11-15 10:00:00',
			'created_at'               => '2026-11-15 09:00:00',
			'updated_at'               => '2026-11-15 10:00:00',
		);

		$wpdb->card_rows[] = array(
			'id'              => 501,
			'wp_user_id'      => 11,
			'verification_id' => 701,
			'card_last4'      => '1234',
			'masked_pan'      => '6037-99**-****-1234',
			'state'           => 'VERIFIED',
			'verified_at'     => '2026-11-15 10:05:00',
		);

		$wpdb->otp_rows[] = array(
			'id'         => 901,
			'wp_user_id' => 11,
			'expires_at' => '2026-11-15 10:15:00',
		);

		$consent_repo->record_consent(
			11,
			'1.0.0',
			ConsentRepository::hash_notice_text( 'Notice v1' ),
			array( 'identity_verification' )
		);

		$exporter = new PrivacyExporterService(
			$profile_repo,
			$consent_repo,
			$authorizer,
			$wpdb,
			$audit_svc,
			static fn( string $email ): int => 'user11@example.test' === $email ? 11 : 0,
			static fn(): int => 1,
			static fn(): string => '2026-11-15 11:00:00'
		);

		// 8 & 9. Export for User 11 returns masked data only and NEVER exposes plaintext, ciphertexts, keys, or HMACs.
		$export_result = $exporter->handle_wp_privacy_export( 'user11@example.test' );
		self::assertTrue( $export_result['done'] );
		self::assertCount( 3, $export_result['data'] );

		$serialized_export = (string) json_encode( $export_result ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode
		self::assertStringContainsString( '******2419', $serialized_export );
		self::assertStringContainsString( '0912***6789', $serialized_export );
		self::assertStringContainsString( '6037-99**-****-1234', $serialized_export );
		self::assertStringNotContainsString( $raw_nc, $serialized_export );
		self::assertStringNotContainsString( $raw_mobile, $serialized_export );
		self::assertStringNotContainsString( $raw_bd, $serialized_export );
		self::assertStringNotContainsString( self::synthetic_pan(), $serialized_export );
		self::assertStringNotContainsString( $nc_hmac, $serialized_export );
		self::assertStringNotContainsString( $mob_hmac, $serialized_export );
		self::assertStringNotContainsString( 'CIPHERTEXT_', $serialized_export );
		self::assertStringNotContainsString( self::SYNTHETIC_ENC_KEY, $serialized_export );
		self::assertStringNotContainsString( self::SYNTHETIC_HMAC_KEY, $serialized_export );

		self::assertSame( 1, $audit_repo->count_events( AuditService::EVENT_PRIVACY_EXPORTED ) );

		// 13. Multisite & cross-user isolation on privacy export:
		// Subscriber 12 cannot export User 11's data, and Site 2 Admin (20) cannot export on Site 1.
		$this->current_user_id = 12;
		try {
			$exporter->export_for_user( 12, 11, 1 );
			self::fail( 'Subscriber 12 must not export User 11 privacy data.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_MISSING_CAPABILITY, $e->get_safe_code() );
		}

		$this->current_user_id = 20;
		try {
			$exporter->export_for_user( 20, 11, 1 );
			self::fail( 'Site 2 admin (20) must be denied privacy export on Site 1.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_MULTISITE_FORBIDDEN, $e->get_safe_code() );
		}

		$this->current_user_id = 1;
		// 11. Erasure on BOUND profile (User 11): deletes transient OTP challenge, but retains BOUND identity binding (D14)!
		$eraser = new PrivacyEraserService(
			$profile_repo,
			$consent_repo,
			$authorizer,
			$wpdb,
			$audit_svc,
			false,
			static fn( string $email ): int => 'user11@example.test' === $email ? 11 : 0,
			static fn(): int => 1
		);

		$erase_bound = $eraser->handle_wp_privacy_erasure( 'user11@example.test' );
		self::assertTrue( $erase_bound['done'] );
		self::assertTrue( $erase_bound['items_removed'], 'Transient OTP challenge must be removed.' );
		self::assertTrue( $erase_bound['items_retained'], 'Active BOUND identity binding must be retained.' );
		self::assertCount( 0, $wpdb->otp_rows );
		self::assertSame( 'BOUND', $wpdb->profile_rows[11]['binding_state'] );
		self::assertSame( $nc_hmac, $wpdb->profile_rows[11]['bound_national_code_hmac'] );

		// 10. Erasure on UNBOUND profile (User 12): clears unverified PII attributes.
		$wpdb->profile_rows[12] = array(
			'id'                       => 102,
			'wp_user_id'               => 12,
			'country_code'             => 'IR',
			'subject_type'             => 'natural',
			'binding_state'            => ProfileRecord::BINDING_UNBOUND,
			'identity_state'           => ProfileRecord::STATE_UNVERIFIED,
			'identity_version'         => 1,
			'mobile_version'           => 1,
			'card_version'             => 1,
			'mobile_ciphertext'        => 'v1:k2026_01:UNBOUND_MOB',
			'mobile_hmac'              => $mob_hmac,
			'mobile_masked'            => '0912***6789',
			'mobile_verified_at'       => null,
			'national_code_ciphertext' => 'v1:k2026_01:UNBOUND_NC',
			'national_code_hmac'       => $nc_hmac,
			'bound_national_code_hmac' => null,
			'national_code_masked'     => '******2419',
			'birth_date_ciphertext'    => 'v1:k2026_01:UNBOUND_BD',
			'shahkar_verified_at'      => null,
			'enc_key_id'               => 'k2026_01',
			'hmac_key_id'              => 'hmac_2026_01',
			'bound_at'                 => null,
			'released_at'              => null,
			'verified_at'              => null,
			'expires_at'               => null,
			'created_at'               => '2026-11-15 09:00:00',
			'updated_at'               => '2026-11-15 10:00:00',
		);

		$erase_unbound = $eraser->erase_for_user( 1, 12, 1 );
		self::assertTrue( $erase_unbound['items_removed'] );
		self::assertFalse( $erase_unbound['items_retained'] );
		self::assertNull( $wpdb->profile_rows[12]['national_code_ciphertext'] );
		self::assertNull( $wpdb->profile_rows[12]['national_code_hmac'] );
		self::assertNull( $wpdb->profile_rows[12]['mobile_ciphertext'] );
		self::assertNull( $wpdb->profile_rows[12]['birth_date_ciphertext'] );

		// 12. Legal hold and REVIEW_REQUIRED block erasure and log privacy.erasure_retained.
		$wpdb->profile_rows[12]['national_code_ciphertext'] = 'v1:k2026_01:HELD_NC';
		$erase_held = $eraser->erase_for_user( 1, 12, 1, true );
		self::assertFalse( $erase_held['items_removed'] );
		self::assertTrue( $erase_held['items_retained'] );
		self::assertSame( 'v1:k2026_01:HELD_NC', $wpdb->profile_rows[12]['national_code_ciphertext'] );

		$wpdb->profile_rows[12]['identity_state'] = ProfileRecord::STATE_REVIEW_REQUIRED;
		$erase_review                             = $eraser->erase_for_user( 1, 12, 1, false );
		self::assertFalse( $erase_review['items_removed'] );
		self::assertTrue( $erase_review['items_retained'] );
		self::assertSame( 'v1:k2026_01:HELD_NC', $wpdb->profile_rows[12]['national_code_ciphertext'] );
	}

	/**
	 * Test 14:
	 * - Bounded retention batch behavior (`1..500` clamping, default `100`).
	 * - Disabled by default (`DISABLED_POLICY_UNRESOLVED`) while `D04` is unresolved (does not invent a retention window).
	 * - Blocked when `legal_hold_active` is true (`BLOCKED_LEGAL_HOLD`).
	 * - Never deletes active verification evidence (`PENDING`, `VERIFIED`, `REVIEW_REQUIRED`) or verifications referenced by `wpig_cards`.
	 */
	public function test_retention_service_policy_guards_legal_hold_and_bounded_batch_pruning(): void {
		$wpdb       = $this->make_in_memory_wpdb();
		$audit_repo = new AuditRepository( $wpdb, static fn(): string => '2026-11-15 12:00:00' );
		$audit_svc  = new AuditService( $audit_repo );

		// Seed 3 old audit events and 1 recent audit event.
		for ( $i = 1; $i <= 3; $i++ ) {
			$audit_svc->record(
				AuditService::EVENT_SETTINGS_UPDATED,
				AuditService::OUTCOME_SUCCESS,
				1,
				null,
				array( 'changed_keys' => array( 'sandbox_mode' ) ),
				null,
				"2025-01-0{$i} 00:00:00"
			);
		}
		$audit_svc->record(
			AuditService::EVENT_SETTINGS_UPDATED,
			AuditService::OUTCOME_SUCCESS,
			1,
			null,
			array( 'changed_keys' => array( 'sandbox_mode' ) ),
			null,
			'2026-11-15 00:00:00'
		);

		// Seed verifications: 1 old FAILED (prunable), 1 old FAILED referenced by a card (not prunable), 1 old VERIFIED (active evidence, not prunable).
		$wpdb->verification_rows = array(
			array(
				'id'           => 10,
				'wp_user_id'   => 11,
				'state'        => 'FAILED',
				'requested_at' => '2025-01-01 00:00:00',
			),
			array(
				'id'           => 11,
				'wp_user_id'   => 11,
				'state'        => 'FAILED',
				'requested_at' => '2025-01-01 00:00:00',
			),
			array(
				'id'           => 12,
				'wp_user_id'   => 11,
				'state'        => 'VERIFIED',
				'requested_at' => '2025-01-01 00:00:00',
			),
		);
		$wpdb->card_rows         = array(
			array(
				'id'              => 1,
				'wp_user_id'      => 11,
				'verification_id' => 11, // References verification #11!
				'card_last4'      => '1234',
				'masked_pan'      => '6037-99**-****-1234',
				'state'           => 'VERIFIED',
				'verified_at'     => '2025-01-01 00:00:00',
			),
		);

		// 14a. Default RetentionService (policy_approved = false because D04 is open) refuses to prune.
		$default_retention = new RetentionService( $wpdb, $audit_repo );
		$diag_default      = $default_retention->get_diagnostics();
		self::assertSame( RetentionService::STATUS_DISABLED_POLICY_UNRESOLVED, $diag_default['status'] );

		$res_unresolved = $default_retention->prune_audit_events_batch( '2026-01-01 00:00:00', 10 );
		self::assertSame( RetentionService::STATUS_DISABLED_POLICY_UNRESOLVED, $res_unresolved['status'] );
		self::assertSame( 0, $res_unresolved['pruned_count'] );
		self::assertCount( 4, $wpdb->audit_rows );

		// 14b. Legal hold active blocks pruning even when policy_approved = true.
		$held_retention = new RetentionService( $wpdb, $audit_repo, true, true );
		self::assertSame( RetentionService::STATUS_BLOCKED_LEGAL_HOLD, $held_retention->get_diagnostics()['status'] );
		self::assertSame( 0, $held_retention->prune_audit_events_batch( '2026-01-01 00:00:00', 10 )['pruned_count'] );
		self::assertSame( 0, $held_retention->prune_terminal_verifications_batch( '2026-01-01 00:00:00', 10 )['pruned_count'] );

		// 14c. Approved policy with batch_size = 2 prunes at most 2 expired audit rows and only the unreferenced terminal verification (#10).
		$active_retention = new RetentionService( $wpdb, $audit_repo, false, true );
		self::assertSame( RetentionService::STATUS_READY_FOR_BOUNDED_PRUNE, $active_retention->get_diagnostics()['status'] );

		$audit_prune = $active_retention->prune_audit_events_batch( '2026-01-01 00:00:00', 2 );
		self::assertSame( RetentionService::STATUS_PRUNED, $audit_prune['status'] );
		self::assertSame( 2, $audit_prune['pruned_count'] );
		self::assertCount( 2, $wpdb->audit_rows );

		$ver_prune = $active_retention->prune_terminal_verifications_batch( '2026-01-01 00:00:00', 100 );
		self::assertSame( RetentionService::STATUS_PRUNED, $ver_prune['status'] );
		self::assertSame( 1, $ver_prune['pruned_count'] );
		self::assertCount( 2, $wpdb->verification_rows, 'Verification #11 (card-referenced) and #12 (VERIFIED) must be preserved.' );
	}

	/**
	 * Test 15:
	 * - Authority grant TTL enforcement (`issued_at_unix` / `expires_at_unix` sealed in HMAC).
	 * - Replay protection across multiple `ProfileAccessBoundary` instances during the grant's lifetime.
	 * - Single-mutation consumption before repository execution.
	 */
	public function test_authority_grant_ttl_expiry_and_cross_instance_replay_protection(): void {
		$wpdb         = $this->make_in_memory_wpdb();
		$audit_repo   = new AuditRepository( $wpdb, static fn(): string => '2026-11-15 12:00:00' );
		$audit_svc    = new AuditService( $audit_repo );
		$authorizer   = $this->make_authorizer( 1, false );
		$profile_repo = $this->make_profile_repository( $wpdb, 1 );

		$nc_plain      = self::synthetic_national_code();
		$key_map       = array(
			WordPressKeyProvider::CONST_ENC_KEY     => self::SYNTHETIC_ENC_KEY,
			WordPressKeyProvider::CONST_ENC_KEY_ID  => 'k2026_01',
			WordPressKeyProvider::CONST_HMAC_KEY    => self::SYNTHETIC_HMAC_KEY,
			WordPressKeyProvider::CONST_HMAC_KEY_ID => 'hmac_2026_01',
		);
		$key_provider  = new WordPressKeyProvider(
			static fn( string $name ): mixed => $key_map[ $name ] ?? null,
			static fn(): string|false => false
		);
		$crypto        = new SodiumCrypto( $key_provider );
		$fingerprinter = new IdentityFingerprinter( $crypto, $key_provider );
		$nc_hmac       = $fingerprinter->fingerprint_national_code( $nc_plain, 'hmac_2026_01' );
		$nc_aad        = \WPIG\Security\CanonicalAad::for_table_column( 1, 'wpig_profiles', 'national_code_ciphertext', 11, 'k2026_01' );
		$nc_ciphertext = $crypto->encrypt( $nc_plain, $nc_aad );

		$wpdb->profile_rows[11] = array(
			'id'                       => 101,
			'wp_user_id'               => 11,
			'country_code'             => 'IR',
			'subject_type'             => 'natural',
			'binding_state'            => ProfileRecord::BINDING_UNBOUND,
			'identity_state'           => ProfileRecord::STATE_UNVERIFIED,
			'identity_version'         => 1,
			'mobile_version'           => 1,
			'card_version'             => 1,
			'mobile_ciphertext'        => 'v1:k2026_01:MOB',
			'mobile_hmac'              => str_repeat( 'e', 64 ),
			'mobile_masked'            => '0912***6789',
			'mobile_verified_at'       => '2026-11-15 10:00:00',
			'national_code_ciphertext' => $nc_ciphertext,
			'national_code_hmac'       => $nc_hmac,
			'bound_national_code_hmac' => null,
			'national_code_masked'     => '******2419',
			'birth_date_ciphertext'    => 'v1:k2026_01:BD',
			'shahkar_verified_at'      => null,
			'enc_key_id'               => 'k2026_01',
			'hmac_key_id'              => 'hmac_2026_01',
			'bound_at'                 => null,
			'released_at'              => null,
			'verified_at'              => null,
			'expires_at'               => null,
			'created_at'               => '2026-11-15 09:00:00',
			'updated_at'               => '2026-11-15 10:00:00',
		);

		$secret    = str_repeat( 'k', 32 );
		$issued_at = 1794744000;

		$consent_repo = new ConsentRepository(
			$wpdb,
			$audit_svc,
			static fn(): string => gmdate( 'Y-m-d H:i:s', $issued_at )
		);
		$consent_repo->record_consent(
			11,
			'1.0.0',
			ConsentRepository::hash_notice_text( 'WPIG Notice v1.0' ),
			array( ConsentRepository::PURPOSE_IDENTITY_VERIFICATION )
		);

		$this->current_user_id = 11;

		// 15a. Expired grant fails closed.
		$expired_grant = VerificationAuthorityGrant::issue( $secret, 1, 11, 1, 1, null, 30, $issued_at );
		$boundary_1    = new ProfileAccessBoundary(
			$profile_repo,
			$authorizer,
			$secret,
			static fn(): int => 1,
			$audit_svc,
			static fn(): int => $issued_at + 31 // 1 second past TTL!
		);

		try {
			$boundary_1->bind_verified_identity( 11, 11, 1, 1, $expired_grant, true, 1 );
			self::fail( 'Expired VerificationAuthorityGrant must fail closed.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_BINDING_AUTHORITY_REQUIRED, $e->get_safe_code() );
		}

		// 15b. Valid grant succeeds on boundary instance A, and logs identity.bound.
		$valid_grant = VerificationAuthorityGrant::issue( $secret, 1, 11, 1, 1, '2027-11-15 10:00:00', 60, $issued_at );
		$boundary_a  = new ProfileAccessBoundary(
			$profile_repo,
			$authorizer,
			$secret,
			static fn(): int => 1,
			$audit_svc,
			static fn(): int => $issued_at + 10
		);

		$bound_record = $boundary_a->bind_verified_identity( 11, 11, 1, 1, $valid_grant, true, 1 );
		self::assertTrue( $bound_record->is_bound() );
		self::assertSame( 1, $audit_repo->count_events( AuditService::EVENT_IDENTITY_BOUND ) );

		// 15c. Replaying a grant on a SECOND ProfileAccessBoundary instance (boundary_b) fails closed!
		$boundary_b = new ProfileAccessBoundary(
			$profile_repo,
			$authorizer,
			$secret,
			static fn(): int => 1,
			$audit_svc,
			static fn(): int => $issued_at + 15
		);

		try {
			$boundary_b->bind_verified_identity( 11, 11, 1, 1, $valid_grant, true, 1 );
			self::fail( 'Replaying consumed grant across a second ProfileAccessBoundary instance must fail closed.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_BINDING_AUTHORITY_REQUIRED, $e->get_safe_code() );
		}
	}

	/**
	 * P01 Security Closure — Tasks 1, 2, 3 & 5:
	 * - Boundary rejects actor-ID spoofing even when target profile exists.
	 * - Boundary rejects decryption and binding when consent is unrecorded, withdrawn, or expired
	 *   (even if caller passes `true` or a stale pre-revocation `ConsentRecord`).
	 * - Boundary logs `identity.sensitive_decrypted` with zero plaintext PII disclosure.
	 */
	public function test_p01_security_closure_spoofing_consent_revocation_and_decryption_audit_redaction(): void {
		$wpdb         = $this->make_in_memory_wpdb();
		$issued_at    = 1794744000;
		$now_utc      = gmdate( 'Y-m-d H:i:s', $issued_at );
		$audit_repo   = new AuditRepository( $wpdb, static fn(): string => $now_utc );
		$audit_svc    = new AuditService( $audit_repo );
		$authorizer   = $this->make_authorizer( 1, false );
		$profile_repo = $this->make_profile_repository( $wpdb, 1 );

		$nc_plain      = self::synthetic_national_code();
		$mob_plain     = self::synthetic_mobile();
		$bd_plain      = '1370/05/12';
		$key_map       = array(
			WordPressKeyProvider::CONST_ENC_KEY     => self::SYNTHETIC_ENC_KEY,
			WordPressKeyProvider::CONST_ENC_KEY_ID  => 'k2026_01',
			WordPressKeyProvider::CONST_HMAC_KEY    => self::SYNTHETIC_HMAC_KEY,
			WordPressKeyProvider::CONST_HMAC_KEY_ID => 'hmac_2026_01',
		);
		$key_provider  = new WordPressKeyProvider(
			static fn( string $name ): mixed => $key_map[ $name ] ?? null,
			static fn(): string|false => false
		);
		$crypto        = new SodiumCrypto( $key_provider );
		$fingerprinter = new IdentityFingerprinter( $crypto, $key_provider );
		$nc_hmac       = $fingerprinter->fingerprint_national_code( $nc_plain, 'hmac_2026_01' );
		$mob_hmac      = $fingerprinter->fingerprint_mobile( $mob_plain, 'hmac_2026_01' );
		$nc_aad        = \WPIG\Security\CanonicalAad::for_table_column( 1, 'wpig_profiles', 'national_code_ciphertext', 11, 'k2026_01' );
		$mob_aad       = \WPIG\Security\CanonicalAad::for_table_column( 1, 'wpig_profiles', 'mobile_ciphertext', 11, 'k2026_01' );
		$bd_aad        = \WPIG\Security\CanonicalAad::for_table_column( 1, 'wpig_profiles', 'birth_date_ciphertext', 11, 'k2026_01' );

		$wpdb->profile_rows[11] = array(
			'id'                       => 101,
			'wp_user_id'               => 11,
			'country_code'             => 'IR',
			'subject_type'             => 'natural',
			'binding_state'            => ProfileRecord::BINDING_UNBOUND,
			'identity_state'           => ProfileRecord::STATE_UNVERIFIED,
			'identity_version'         => 1,
			'mobile_version'           => 1,
			'card_version'             => 1,
			'mobile_ciphertext'        => $crypto->encrypt( $mob_plain, $mob_aad ),
			'mobile_hmac'              => $mob_hmac,
			'mobile_masked'            => '0912***6789',
			'mobile_verified_at'       => $now_utc,
			'national_code_ciphertext' => $crypto->encrypt( $nc_plain, $nc_aad ),
			'national_code_hmac'       => $nc_hmac,
			'bound_national_code_hmac' => null,
			'national_code_masked'     => '******2419',
			'birth_date_ciphertext'    => $crypto->encrypt( $bd_plain, $bd_aad ),
			'shahkar_verified_at'      => null,
			'enc_key_id'               => 'k2026_01',
			'hmac_key_id'              => 'hmac_2026_01',
			'bound_at'                 => null,
			'released_at'              => null,
			'verified_at'              => null,
			'expires_at'               => null,
			'created_at'               => $now_utc,
			'updated_at'               => $now_utc,
		);

		$secret   = str_repeat( 'q', 32 );
		$boundary = new ProfileAccessBoundary(
			$profile_repo,
			$authorizer,
			$secret,
			static fn(): int => 1,
			$audit_svc,
			static fn(): int => $issued_at + 5
		);

		// 1. Actor-ID spoofing: logged in as Customer 12, attempting to act as Subscriber 11 fails closed.
		$this->current_user_id = 12;
		try {
			$boundary->get_masked_profile( 11, 11, 1 );
			self::fail( 'Customer 12 spoofing actor_user_id = 11 must fail closed.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_UNAUTHENTICATED, $e->get_safe_code() );
		}

		// 2. Logged in as Subscriber 11, attempting to decrypt for verification dispatch with boolean true BEFORE consent is recorded fails closed.
		$this->current_user_id = 11;
		try {
			$boundary->decrypt_identity(
				11,
				11,
				AuthorizationService::PURPOSE_VERIFICATION_DISPATCH,
				true,
				1
			);
			self::fail( 'Untrusted boolean true without persisted ConsentRecord must fail closed.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_CONSENT_REQUIRED, $e->get_safe_code() );
		}

		// 3. Record active consent in wpig_consents: decryption now succeeds and logs identity.sensitive_decrypted without raw PII.
		$consent_repo   = new ConsentRepository( $wpdb, $audit_svc, static fn(): string => $now_utc );
		$active_consent = $consent_repo->record_consent(
			11,
			'1.0.0',
			ConsentRepository::hash_notice_text( 'WPIG Notice v1.0.0' ),
			array( ConsentRepository::PURPOSE_IDENTITY_VERIFICATION )
		);

		$decrypted = $boundary->decrypt_identity(
			11,
			11,
			AuthorizationService::PURPOSE_VERIFICATION_DISPATCH,
			$active_consent,
			1
		);
		self::assertNotNull( $decrypted->national_code );
		self::assertSame( $nc_plain, $decrypted->national_code->reveal() );
		self::assertSame( 1, $audit_repo->count_events( AuditService::EVENT_IDENTITY_DECRYPTED ) );

		$all_audit_json = (string) json_encode( $wpdb->audit_rows ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode
		self::assertStringNotContainsString( $nc_plain, $all_audit_json );
		self::assertStringNotContainsString( $mob_plain, $all_audit_json );
		self::assertStringNotContainsString( $bd_plain, $all_audit_json );

		// 4. Withdraw consent in wpig_consents: even passing the pre-revocation $active_consent DTO or boolean true fails closed!
		$consent_repo->withdraw_consent( 11, 11 );

		foreach ( array( true, $active_consent ) as $stale_proof ) {
			try {
				$boundary->decrypt_identity(
					11,
					11,
					AuthorizationService::PURPOSE_VERIFICATION_DISPATCH,
					$stale_proof,
					1
				);
				self::fail( 'Withdrawn consent must fail closed even when stale ConsentRecord or true is passed.' );
			} catch ( AuthorizationException $e ) {
				self::assertSame( AuthorizationException::CODE_CONSENT_REQUIRED, $e->get_safe_code() );
			}
		}

		$grant = VerificationAuthorityGrant::issue( $secret, 1, 11, 1, 1, '2027-11-15 10:00:00', 60, $issued_at );
		try {
			$boundary->bind_verified_identity( 11, 11, 1, 1, $grant, $active_consent, 1 );
			self::fail( 'Binding with withdrawn consent must fail closed.' );
		} catch ( AuthorizationException $e ) {
			self::assertSame( AuthorizationException::CODE_CONSENT_REQUIRED, $e->get_safe_code() );
		}
	}
}

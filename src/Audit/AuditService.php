<?php
/**
 * High-level security audit service enforcing event-type, outcome, and metadata allowlists.
 *
 * @package WPIG\Audit
 */

declare(strict_types=1);

namespace WPIG\Audit;

use WPIG\Security\SensitiveValue;
use WPIG\Security\ValidationException;
use WPIG\Storage\StorageException;

/**
 * Validates and records security audit events into `AuditRepository` (Tasks 2 & 3).
 *
 * Security Invariants (DS-4):
 * - Enforces a strict event-type allowlist (`ALLOWED_EVENT_TYPES`).
 * - Enforces a strict outcome allowlist (`ALLOWED_OUTCOMES`).
 * - Enforces a strict metadata key allowlist (`ALLOWED_METADATA_KEYS`).
 * - Rejects raw national codes, plaintext mobile numbers, full card PANs, OTP codes,
 *   provider credentials, cryptographic keys/HMACs, `SensitiveValue` instances,
 *   arbitrary exception messages, and raw HTTP payloads.
 * - Uses normalized safe error codes (`[A-Z0-9_]{1,64}`) and UUID v4 correlation IDs.
 */
final class AuditService {

	/**
	 * Outcome constants (`SchemaDefinition` §4.6).
	 */
	public const OUTCOME_SUCCESS      = 'SUCCESS';
	public const OUTCOME_FAILURE      = 'FAILURE';
	public const OUTCOME_DENIED       = 'DENIED';
	public const OUTCOME_UNAVAILABLE  = 'UNAVAILABLE';
	public const OUTCOME_RATE_LIMITED = 'RATE_LIMITED';

	/**
	 * Event type constants covering all Task 3 security event categories.
	 */
	public const EVENT_SETTINGS_UPDATED             = 'settings.updated';
	public const EVENT_SETTINGS_UPDATE_REJECTED     = 'settings.update_rejected';
	public const EVENT_AUTHORIZATION_DENIED         = 'authorization.denied';
	public const EVENT_PRIVILEGE_ESCALATION_BLOCKED = 'authorization.privilege_escalation_blocked';
	public const EVENT_VERIFICATION_ATTEMPTED       = 'identity.verification_attempted';
	public const EVENT_IDENTITY_BOUND               = 'identity.bound';
	public const EVENT_IDENTITY_CONFLICT_DETECTED   = 'identity.conflict_detected';
	public const EVENT_IDENTITY_BINDING_RELEASED    = 'identity.binding_released';
	public const EVENT_CARD_VERIFIED                = 'card.verified';
	public const EVENT_CARD_STATE_CHANGED           = 'card.state_changed';
	public const EVENT_CONSENT_ACCEPTED             = 'consent.accepted';
	public const EVENT_CONSENT_WITHDRAWN            = 'consent.withdrawn';
	public const EVENT_PRIVACY_EXPORTED             = 'privacy.exported';
	public const EVENT_PRIVACY_ERASED               = 'privacy.erased';
	public const EVENT_PRIVACY_ERASURE_RETAINED     = 'privacy.erasure_retained';
	public const EVENT_MIGRATION_COMPLETED          = 'migration.completed';
	public const EVENT_MIGRATION_FAILED             = 'migration.failed';
	public const EVENT_KEY_READINESS_FAILED         = 'crypto.key_readiness_failed';
	public const EVENT_ADMIN_SECURITY_OPERATION     = 'admin.security_operation';
	public const EVENT_RETENTION_PRUNED             = 'retention.pruned';
	public const EVENT_IDENTITY_DECRYPTED           = 'identity.sensitive_decrypted';

	/**
	 * Strict allowlist of supported audit event types.
	 *
	 * @var list<string>
	 */
	public const ALLOWED_EVENT_TYPES = array(
		self::EVENT_SETTINGS_UPDATED,
		self::EVENT_SETTINGS_UPDATE_REJECTED,
		self::EVENT_AUTHORIZATION_DENIED,
		self::EVENT_PRIVILEGE_ESCALATION_BLOCKED,
		self::EVENT_VERIFICATION_ATTEMPTED,
		self::EVENT_IDENTITY_BOUND,
		self::EVENT_IDENTITY_CONFLICT_DETECTED,
		self::EVENT_IDENTITY_BINDING_RELEASED,
		self::EVENT_CARD_VERIFIED,
		self::EVENT_CARD_STATE_CHANGED,
		self::EVENT_CONSENT_ACCEPTED,
		self::EVENT_CONSENT_WITHDRAWN,
		self::EVENT_PRIVACY_EXPORTED,
		self::EVENT_PRIVACY_ERASED,
		self::EVENT_PRIVACY_ERASURE_RETAINED,
		self::EVENT_MIGRATION_COMPLETED,
		self::EVENT_MIGRATION_FAILED,
		self::EVENT_KEY_READINESS_FAILED,
		self::EVENT_ADMIN_SECURITY_OPERATION,
		self::EVENT_RETENTION_PRUNED,
		self::EVENT_IDENTITY_DECRYPTED,
	);

	/**
	 * Strict allowlist of supported event outcomes.
	 *
	 * @var list<string>
	 */
	public const ALLOWED_OUTCOMES = array(
		self::OUTCOME_SUCCESS,
		self::OUTCOME_FAILURE,
		self::OUTCOME_DENIED,
		self::OUTCOME_UNAVAILABLE,
		self::OUTCOME_RATE_LIMITED,
	);

	/**
	 * Strict allowlist of safe metadata keys.
	 *
	 * @var list<string>
	 */
	public const ALLOWED_METADATA_KEYS = array(
		'safe_error_code',
		'capability',
		'purpose',
		'section',
		'changed_keys',
		'provider',
		'operation',
		'binding_state',
		'identity_state',
		'card_state',
		'identity_version',
		'mobile_version',
		'card_version',
		'notice_version',
		'schema_version',
		'blog_id',
		'items_removed',
		'items_retained',
		'legal_hold_active',
		'pruned_count',
		'table',
	);

	/**
	 * Regex for canonical lowercase UUID v4 correlation IDs.
	 */
	public const UUID_V4_PATTERN = '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/';

	/**
	 * Regex for normalized safe error codes.
	 */
	public const SAFE_ERROR_CODE_PATTERN = '/^[A-Z0-9_]{1,64}$/';

	/**
	 * Underlying append-only audit repository.
	 *
	 * @var AuditRepository
	 */
	private AuditRepository $repository;

	/**
	 * Constructor.
	 *
	 * @param AuditRepository $repository Append-only audit repository.
	 */
	public function __construct( AuditRepository $repository ) {
		$this->repository = $repository;
	}

	/**
	 * Generate a cryptographically random RFC 4122 / RFC 9562 UUID v4 correlation identifier.
	 */
	public static function generate_correlation_id(): string {
		$bytes    = random_bytes( 16 );
		$bytes[6] = chr( ( ord( $bytes[6] ) & 0x0f ) | 0x40 );
		$bytes[8] = chr( ( ord( $bytes[8] ) & 0x3f ) | 0x80 );
		$hex      = bin2hex( $bytes );

		return sprintf(
			'%s-%s-%s-%s-%s',
			substr( $hex, 0, 8 ),
			substr( $hex, 8, 4 ),
			substr( $hex, 12, 4 ),
			substr( $hex, 16, 4 ),
			substr( $hex, 20, 12 )
		);
	}

	/**
	 * Record a security audit event after validating event type, outcome, correlation ID, and metadata.
	 *
	 * @param string              $event_type     Event type from `ALLOWED_EVENT_TYPES`.
	 * @param string              $outcome        Outcome from `ALLOWED_OUTCOMES`.
	 * @param int|null            $actor_user_id  Optional acting WP user ID (`>= 1` or `null`).
	 * @param int|null            $target_user_id Optional target WP user ID (`>= 1` or `null`).
	 * @param array<string,mixed> $metadata       Optional allowlisted metadata map.
	 * @param string|null         $correlation_id Optional UUID v4 correlation ID (generated if omitted).
	 * @param string|null         $occurred_at    Optional UTC timestamp (`Y-m-d H:i:s`).
	 * @return AuditEventRecord
	 * @throws ValidationException If event type, outcome, correlation ID, or metadata is invalid or contains sensitive data.
	 * @throws StorageException    If database insert fails.
	 */
	public function record(
		string $event_type,
		string $outcome,
		?int $actor_user_id = null,
		?int $target_user_id = null,
		array $metadata = array(),
		?string $correlation_id = null,
		?string $occurred_at = null
	): AuditEventRecord {
		if ( ! in_array( $event_type, self::ALLOWED_EVENT_TYPES, true ) ) {
			ValidationException::raise(
				ValidationException::CODE_INVALID_AUDIT_EVENT,
				'Unsupported or unapproved audit event_type.'
			);
		}

		if ( ! in_array( $outcome, self::ALLOWED_OUTCOMES, true ) ) {
			ValidationException::raise(
				ValidationException::CODE_INVALID_AUDIT_OUTCOME,
				'Unsupported or unapproved audit outcome.'
			);
		}

		$resolved_correlation_id = null !== $correlation_id
			? strtolower( trim( $correlation_id ) )
			: self::generate_correlation_id();

		if ( 1 !== preg_match( self::UUID_V4_PATTERN, $resolved_correlation_id ) ) {
			ValidationException::raise(
				ValidationException::CODE_INVALID_AUDIT_METADATA,
				'Audit correlation_id must be a canonical UUID v4.'
			);
		}

		$validated_metadata = self::validate_and_sanitize_metadata( $metadata );

		return $this->repository->append(
			$resolved_correlation_id,
			$event_type,
			$outcome,
			$actor_user_id,
			$target_user_id,
			$validated_metadata,
			$occurred_at
		);
	}

	/**
	 * Validate a metadata map against `ALLOWED_METADATA_KEYS` and reject any sensitive data patterns.
	 *
	 * @param array<string,mixed> $metadata Candidate metadata map.
	 * @return array<string,scalar|list<string>|null>
	 * @throws ValidationException If an unknown key or sensitive value is detected.
	 */
	public static function validate_and_sanitize_metadata( array $metadata ): array {
		$clean = array();

		foreach ( $metadata as $raw_key => $raw_val ) {
			$key = (string) $raw_key;

			if ( ! in_array( $key, self::ALLOWED_METADATA_KEYS, true ) ) {
				ValidationException::raise(
					ValidationException::CODE_INVALID_AUDIT_METADATA,
					'Audit metadata contains an unapproved key.'
				);
			}

			if ( $raw_val instanceof SensitiveValue ) {
				ValidationException::raise(
					ValidationException::CODE_SENSITIVE_AUDIT_METADATA,
					'SensitiveValue objects must never be passed to audit metadata.'
				);
			}

			if ( null === $raw_val || is_bool( $raw_val ) || is_int( $raw_val ) ) {
				if ( is_int( $raw_val ) ) {
					self::assert_no_sensitive_string( (string) $raw_val );
				}
				$clean[ $key ] = $raw_val;
				continue;
			}

			if ( 'changed_keys' === $key && is_array( $raw_val ) ) {
				$key_list = array();
				foreach ( $raw_val as $item ) {
					if ( ! is_string( $item ) || 1 !== preg_match( '/^[a-z0-9_]{1,64}$/', $item ) ) {
						ValidationException::raise(
							ValidationException::CODE_INVALID_AUDIT_METADATA,
							'changed_keys must contain only lowercase snake_case setting names.'
						);
					}
					self::assert_no_sensitive_string( $item );
					$key_list[] = $item;
				}
				$clean[ $key ] = $key_list;
				continue;
			}

			if ( ! is_string( $raw_val ) ) {
				ValidationException::raise(
					ValidationException::CODE_INVALID_AUDIT_METADATA,
					'Audit metadata values must be scalar or a list of changed_keys.'
				);
			}

			$trimmed = trim( $raw_val );

			if ( 'safe_error_code' === $key ) {
				if ( 1 !== preg_match( self::SAFE_ERROR_CODE_PATTERN, $trimmed ) ) {
					ValidationException::raise(
						ValidationException::CODE_INVALID_AUDIT_METADATA,
						'safe_error_code must be a normalized uppercase code ([A-Z0-9_]{1,64}); arbitrary exception messages are forbidden.'
					);
				}
				$clean[ $key ] = $trimmed;
				continue;
			}

			self::assert_no_sensitive_string( $trimmed );

			if ( strlen( $trimmed ) > 64 || 1 !== preg_match( '/^[A-Za-z0-9._:-]{1,64}$/', $trimmed ) ) {
				ValidationException::raise(
					ValidationException::CODE_INVALID_AUDIT_METADATA,
					'Audit metadata string value exceeds safe token constraints.'
				);
			}

			$clean[ $key ] = $trimmed;
		}

		return $clean;
	}

	/**
	 * Reject any string that resembles a national code, mobile number, card PAN, OTP code,
	 * cryptographic key/ciphertext envelope, 64-char hex digest, or raw HTTP/JSON payload.
	 *
	 * @param string $value Candidate metadata string.
	 * @throws ValidationException If a sensitive pattern is detected.
	 */
	public static function assert_no_sensitive_string( string $value ): void {
		// Normalize Persian/Arabic digits to ASCII before inspecting for numeric PII/PAN/OTP patterns.
		$ascii = strtr(
			$value,
			array(
				'۰' => '0',
				'۱' => '1',
				'۲' => '2',
				'۳' => '3',
				'۴' => '4',
				'۵' => '5',
				'۶' => '6',
				'۷' => '7',
				'۸' => '8',
				'۹' => '9',
				'٠' => '0',
				'١' => '1',
				'٢' => '2',
				'٣' => '3',
				'٤' => '4',
				'٥' => '5',
				'٦' => '6',
				'٧' => '7',
				'٨' => '8',
				'٩' => '9',
			)
		);

		$digits_only = (string) preg_replace( '/\D+/', '', $ascii );

		// Reject 10-digit national codes, 11..14-digit mobile numbers, 16-digit PANs, and 5..8-digit OTP codes.
		if (
			strlen( $digits_only ) >= 5
			|| 1 === preg_match( '/(?:\+98|0098|98|0)?9\d{9}\b/', $ascii )
			|| 1 === preg_match( '/\b\d{10}\b/', $ascii )
			|| 1 === preg_match( '/\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/', $ascii )
		) {
			ValidationException::raise(
				ValidationException::CODE_SENSITIVE_AUDIT_METADATA,
				'Audit metadata rejected: numeric sequence resembles national code, mobile, PAN, or OTP.'
			);
		}

		// Reject ciphertext envelopes, encoded keys, 64-char hex HMAC/keys, Bearer tokens, or JSON/HTTP payloads.
		$lower = strtolower( $ascii );
		if (
			str_starts_with( $lower, 'v1:' )
			|| str_starts_with( $lower, 'base64:' )
			|| str_starts_with( $lower, 'hex:' )
			|| str_contains( $lower, 'bearer ' )
			|| str_contains( $lower, 'http/' )
			|| str_contains( $lower, '{' )
			|| str_contains( $lower, '}' )
			|| 1 === preg_match( '/\b[0-9a-f]{32,64}\b/', $lower )
		) {
			ValidationException::raise(
				ValidationException::CODE_SENSITIVE_AUDIT_METADATA,
				'Audit metadata rejected: value resembles a cryptographic key, digest, token, or raw payload.'
			);
		}
	}

	/**
	 * Return the underlying `AuditRepository` instance.
	 */
	public function get_repository(): AuditRepository {
		return $this->repository;
	}

	/**
	 * Record an `authorization.denied` (`DENIED`) event.
	 *
	 * @param int|null    $actor_user_id   Acting WordPress user ID (`>= 1` or `null`).
	 * @param int|null    $target_user_id  Target WordPress user ID (`>= 1` or `null`).
	 * @param string      $operation       Normalized boundary operation name.
	 * @param string      $safe_error_code Normalized safe error code (`[A-Z0-9_]{1,64}`).
	 * @param string|null $capability      Optional capability checked.
	 * @param string|null $purpose         Optional decryption purpose checked.
	 */
	public function log_authorization_denied(
		?int $actor_user_id,
		?int $target_user_id,
		string $operation,
		string $safe_error_code,
		?string $capability = null,
		?string $purpose = null
	): AuditEventRecord {
		$metadata = array(
			'operation'       => $operation,
			'safe_error_code' => $safe_error_code,
		);
		if ( null !== $capability ) {
			$metadata['capability'] = $capability;
		}
		if ( null !== $purpose ) {
			$metadata['purpose'] = $purpose;
		}

		return $this->record(
			self::EVENT_AUTHORIZATION_DENIED,
			self::OUTCOME_DENIED,
			$actor_user_id,
			$target_user_id,
			$metadata
		);
	}

	/**
	 * Record an `identity.bound` (`SUCCESS`) event.
	 *
	 * @param int $actor_user_id    Acting WordPress user ID.
	 * @param int $target_user_id   Target WordPress user ID.
	 * @param int $identity_version Bound `identity_version`.
	 * @param int $mobile_version   Bound `mobile_version`.
	 */
	public function log_identity_bound(
		int $actor_user_id,
		int $target_user_id,
		int $identity_version,
		int $mobile_version
	): AuditEventRecord {
		return $this->record(
			self::EVENT_IDENTITY_BOUND,
			self::OUTCOME_SUCCESS,
			$actor_user_id,
			$target_user_id,
			array(
				'binding_state'    => 'BOUND',
				'identity_state'   => 'VERIFIED',
				'identity_version' => $identity_version,
				'mobile_version'   => $mobile_version,
			)
		);
	}

	/**
	 * Record an `identity.conflict_detected` (`FAILURE`) event without exposing the conflicting account.
	 *
	 * @param int $actor_user_id    Acting WordPress user ID.
	 * @param int $target_user_id   Target WordPress user ID.
	 * @param int $identity_version Attempted `identity_version`.
	 * @param int $mobile_version   Attempted `mobile_version`.
	 */
	public function log_identity_conflict(
		int $actor_user_id,
		int $target_user_id,
		int $identity_version,
		int $mobile_version
	): AuditEventRecord {
		return $this->record(
			self::EVENT_IDENTITY_CONFLICT_DETECTED,
			self::OUTCOME_FAILURE,
			$actor_user_id,
			$target_user_id,
			array(
				'safe_error_code'  => 'IDENTITY_CONFLICT',
				'identity_version' => $identity_version,
				'mobile_version'   => $mobile_version,
			)
		);
	}

	/**
	 * Record a `settings.updated` (`SUCCESS`) event.
	 *
	 * @param int      $actor_user_id Acting WordPress user ID.
	 * @param string[] $changed_keys  Allowlisted setting keys updated.
	 * @phpstan-param list<string> $changed_keys
	 */
	public function log_settings_updated(
		int $actor_user_id,
		array $changed_keys
	): AuditEventRecord {
		return $this->record(
			self::EVENT_SETTINGS_UPDATED,
			self::OUTCOME_SUCCESS,
			$actor_user_id,
			null,
			array(
				'changed_keys' => $changed_keys,
			)
		);
	}

	/**
	 * Record a `settings.update_rejected` (`FAILURE`) event.
	 *
	 * @param int|null $actor_user_id   Acting WordPress user ID.
	 * @param string   $safe_error_code Normalized validation error code.
	 */
	public function log_settings_update_rejected(
		?int $actor_user_id,
		string $safe_error_code
	): AuditEventRecord {
		return $this->record(
			self::EVENT_SETTINGS_UPDATE_REJECTED,
			self::OUTCOME_FAILURE,
			$actor_user_id,
			null,
			array(
				'safe_error_code' => $safe_error_code,
			)
		);
	}

	/**
	 * Record a `consent.accepted` (`SUCCESS`) event.
	 *
	 * @param int    $actor_user_id  Acting WordPress user ID.
	 * @param int    $target_user_id Target WordPress user ID.
	 * @param string $notice_version Accepted notice version.
	 */
	public function log_consent_accepted(
		int $actor_user_id,
		int $target_user_id,
		string $notice_version
	): AuditEventRecord {
		return $this->record(
			self::EVENT_CONSENT_ACCEPTED,
			self::OUTCOME_SUCCESS,
			$actor_user_id,
			$target_user_id,
			array(
				'notice_version' => $notice_version,
			)
		);
	}

	/**
	 * Record a `consent.withdrawn` (`SUCCESS`) event.
	 *
	 * @param int $actor_user_id  Acting WordPress user ID.
	 * @param int $target_user_id Target WordPress user ID.
	 */
	public function log_consent_withdrawn(
		int $actor_user_id,
		int $target_user_id
	): AuditEventRecord {
		return $this->record(
			self::EVENT_CONSENT_WITHDRAWN,
			self::OUTCOME_SUCCESS,
			$actor_user_id,
			$target_user_id
		);
	}

	/**
	 * Record a `privacy.exported` (`SUCCESS`) event.
	 *
	 * @param int $actor_user_id        Acting WordPress user ID.
	 * @param int $target_user_id       Target WordPress user ID.
	 * @param int $exported_items_count Number of exported data groups/items.
	 */
	public function log_privacy_exported(
		int $actor_user_id,
		int $target_user_id,
		int $exported_items_count
	): AuditEventRecord {
		return $this->record(
			self::EVENT_PRIVACY_EXPORTED,
			self::OUTCOME_SUCCESS,
			$actor_user_id,
			$target_user_id,
			array(
				'pruned_count' => $exported_items_count,
			)
		);
	}

	/**
	 * Record a `privacy.erased` (`SUCCESS`) event.
	 *
	 * @param int $actor_user_id  Acting WordPress user ID.
	 * @param int $target_user_id Target WordPress user ID.
	 * @param int $items_removed  Count of removed items.
	 * @param int $items_retained Count of retained items.
	 */
	public function log_privacy_erased(
		int $actor_user_id,
		int $target_user_id,
		int $items_removed,
		int $items_retained
	): AuditEventRecord {
		return $this->record(
			self::EVENT_PRIVACY_ERASED,
			self::OUTCOME_SUCCESS,
			$actor_user_id,
			$target_user_id,
			array(
				'items_removed'  => $items_removed,
				'items_retained' => $items_retained,
			)
		);
	}

	/**
	 * Record a `privacy.erasure_retained` (`SUCCESS`) event when records are retained due to
	 * legal hold, `REVIEW_REQUIRED`, `D14` active identity binding, or `D04` unresolved policy.
	 *
	 * @param int    $actor_user_id   Acting WordPress user ID.
	 * @param int    $target_user_id  Target WordPress user ID.
	 * @param string $safe_error_code Retention reason code.
	 * @param int    $items_retained  Count of retained items.
	 */
	public function log_privacy_erasure_retained(
		int $actor_user_id,
		int $target_user_id,
		string $safe_error_code,
		int $items_retained
	): AuditEventRecord {
		return $this->record(
			self::EVENT_PRIVACY_ERASURE_RETAINED,
			self::OUTCOME_SUCCESS,
			$actor_user_id,
			$target_user_id,
			array(
				'safe_error_code' => $safe_error_code,
				'items_retained'  => $items_retained,
			)
		);
	}

	/**
	 * Record an `identity.sensitive_decrypted` (`SUCCESS`) event containing only safe purpose metadata.
	 *
	 * @param int    $actor_user_id  Acting WordPress user ID.
	 * @param int    $target_user_id Target WordPress user ID.
	 * @param string $purpose        Authorized decryption purpose (`AuthorizationService::PURPOSE_*`).
	 */
	public function log_identity_decrypted(
		int $actor_user_id,
		int $target_user_id,
		string $purpose
	): AuditEventRecord {
		return $this->record(
			self::EVENT_IDENTITY_DECRYPTED,
			self::OUTCOME_SUCCESS,
			$actor_user_id,
			$target_user_id,
			array(
				'operation' => 'decrypt_identity',
				'purpose'   => $purpose,
			)
		);
	}
}

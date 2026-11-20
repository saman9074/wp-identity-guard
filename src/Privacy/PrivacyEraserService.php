<?php
/**
 * WordPress Personal Data Eraser integration (`PrivacyEraserService`).
 *
 * @package WPIG\Privacy
 */

declare(strict_types=1);

namespace WPIG\Privacy;

use wpdb;
use WPIG\Audit\AuditService;
use WPIG\Security\AuthorizationException;
use WPIG\Security\AuthorizationService;
use WPIG\Security\Capabilities;
use WPIG\Storage\ProfileRecord;
use WPIG\Storage\ProfileRepository;
use WPIG\Storage\SchemaDefinition;

/**
 * Integrates WP Identity Guard with the WordPress Personal Data Eraser API (Task 5).
 *
 * Critical Security & Legal Invariants:
 * - Strictly separates consent withdrawal (`ConsentRepository::withdraw_consent()`) from data erasure.
 * - Strictly separates data erasure from identity-binding release (`D14`): NEVER silently removes
 *   or releases an active `BOUND` identity binding (`bound_national_code_hmac`).
 * - Respects `legal_hold_active` and `REVIEW_REQUIRED` states, retaining all records when active.
 * - Avoids destructive removal of bound identity records, verification evidence (`wpig_verifications`),
 *   and consent audit history (`wpig_consents`) while legal retention decisions (`D04`, `DS-5`) remain open.
 * - Safely removes transient OTP challenges (`wpig_otp_challenges`) and clears unverified PII on
 *   `UNBOUND` profiles when not under legal hold or review lock.
 * - Enforces site-scoped `manage_wpig_settings` authorization and Multisite blog isolation.
 */
final class PrivacyEraserService {

	/**
	 * WordPress eraser slug.
	 */
	public const ERASER_SLUG = 'wp-identity-guard';

	/**
	 * Retention reason codes recorded in `wpig_audit_events`.
	 */
	public const REASON_LEGAL_HOLD        = 'LEGAL_HOLD_ACTIVE';
	public const REASON_REVIEW_REQUIRED   = 'REVIEW_REQUIRED_STATE';
	public const REASON_BOUND_IDENTITY    = 'ACTIVE_IDENTITY_BINDING_D14';
	public const REASON_POLICY_UNRESOLVED = 'RETENTION_POLICY_UNRESOLVED_D04';

	/**
	 * Profile repository.
	 *
	 * @var ProfileRepository
	 */
	private ProfileRepository $profile_repository;

	/**
	 * Consent repository.
	 *
	 * @var ConsentRepository
	 */
	private ConsentRepository $consent_repository;

	/**
	 * Authorization service.
	 *
	 * @var AuthorizationService
	 */
	private AuthorizationService $authorizer;

	/**
	 * WordPress database connection.
	 *
	 * @var wpdb
	 */
	private wpdb $wpdb;

	/**
	 * Optional security audit service.
	 *
	 * @var AuditService|null
	 */
	private ?AuditService $audit_service;

	/**
	 * Whether a legal hold is active on the current site.
	 *
	 * @var bool
	 */
	private bool $legal_hold_active;

	/**
	 * Callback resolving a WordPress user ID from an email address (`fn(string $email): int`).
	 *
	 * @var callable
	 * @phpstan-var callable(string):int
	 */
	private $user_id_by_email_resolver;

	/**
	 * Callback resolving the current acting WordPress user ID (`fn(): int`).
	 *
	 * @var callable
	 * @phpstan-var callable():int
	 */
	private $current_user_id_resolver;

	/**
	 * Whether WordPress hooks have been registered on this instance.
	 *
	 * @var bool
	 */
	private bool $hooks_registered = false;

	/**
	 * Constructor.
	 *
	 * @param ProfileRepository    $profile_repository        Profile repository.
	 * @param ConsentRepository    $consent_repository        Consent repository.
	 * @param AuthorizationService $authorizer                Authorization service.
	 * @param wpdb                 $wpdb                      WordPress database connection.
	 * @param AuditService|null    $audit_service             Optional security audit service.
	 * @param bool                 $legal_hold_active         Whether a legal hold is active (default false).
	 * @param callable|null        $user_id_by_email_resolver Optional resolver (`fn(string $email): int`).
	 * @param callable|null        $current_user_id_resolver  Optional resolver (`fn(): int`).
	 * @phpstan-param (callable(string):int)|null $user_id_by_email_resolver
	 * @phpstan-param (callable():int)|null       $current_user_id_resolver
	 */
	public function __construct(
		ProfileRepository $profile_repository,
		ConsentRepository $consent_repository,
		AuthorizationService $authorizer,
		wpdb $wpdb,
		?AuditService $audit_service = null,
		bool $legal_hold_active = false,
		?callable $user_id_by_email_resolver = null,
		?callable $current_user_id_resolver = null
	) {
		$this->profile_repository = $profile_repository;
		$this->consent_repository = $consent_repository;
		$this->authorizer         = $authorizer;
		$this->wpdb               = $wpdb;
		$this->audit_service      = $audit_service;
		$this->legal_hold_active  = $legal_hold_active;

		$this->user_id_by_email_resolver = $user_id_by_email_resolver ?? static function ( string $email ): int {
			if ( function_exists( 'get_user_by' ) ) {
				$user = get_user_by( 'email', $email );
				if ( false !== $user ) {
					return (int) $user->ID;
				}
			}
			return 0;
		};

		$this->current_user_id_resolver = $current_user_id_resolver ?? function (): int {
			return $this->authorizer->get_authenticated_principal_id();
		};
	}

	/**
	 * Register the WP Identity Guard personal data eraser hook with WordPress exactly once.
	 */
	public function register_hooks(): void {
		if ( $this->hooks_registered ) {
			return;
		}
		if ( function_exists( 'add_filter' ) ) {
			if ( ! function_exists( 'has_filter' ) || false === has_filter( 'wp_privacy_personal_data_erasers', array( $this, 'register_eraser' ) ) ) {
				add_filter( 'wp_privacy_personal_data_erasers', array( $this, 'register_eraser' ) );
			}
			$this->hooks_registered = true;
		}
	}

	/**
	 * Filter callback for `wp_privacy_personal_data_erasers`.
	 *
	 * @param array<string,array<string,mixed>> $erasers Registered WordPress erasers.
	 * @return array<string,array<string,mixed>>
	 */
	public function register_eraser( array $erasers ): array {
		$erasers[ self::ERASER_SLUG ] = array(
			'eraser_friendly_name' => $this->translate( 'WP Identity Guard' ),
			'callback'             => array( $this, 'handle_wp_privacy_erasure' ),
		);

		return $erasers;
	}

	/**
	 * WordPress Personal Data Eraser callback `(string $email_address, int $page = 1)`.
	 *
	 * @param string $email_address Target user email address.
	 * @param int    $page          Erasure page number (`>= 1`).
	 * @return array{items_removed:bool,items_retained:bool,messages:list<string>,done:bool}
	 */
	public function handle_wp_privacy_erasure( string $email_address, int $page = 1 ): array {
		unset( $page );
		$trimmed_email = trim( $email_address );
		if ( '' === $trimmed_email ) {
			return array(
				'items_removed'  => false,
				'items_retained' => false,
				'messages'       => array(),
				'done'           => true,
			);
		}

		$target_user_id = (int) ( $this->user_id_by_email_resolver )( $trimmed_email );
		if ( $target_user_id < 1 ) {
			return array(
				'items_removed'  => false,
				'items_retained' => false,
				'messages'       => array(),
				'done'           => true,
			);
		}

		$actor_user_id = (int) ( $this->current_user_id_resolver )();

		return $this->erase_for_user( $actor_user_id, $target_user_id );
	}

	/**
	 * Execute privacy erasure for `$target_user_id` while enforcing legal hold, `REVIEW_REQUIRED`,
	 * `D14` active identity binding immutability, and `D04`/`DS-5` open retention policy guards.
	 *
	 * Note: Does NOT automatically withdraw consent unless `ConsentRepository::withdraw_consent()`
	 * was invoked separately, and NEVER releases a `BOUND` identity binding.
	 *
	 * @param int      $actor_user_id     Acting WordPress user ID (`>= 1`, requires `manage_wpig_settings`).
	 * @param int      $target_user_id    Target WordPress user ID (`>= 1`).
	 * @param int|null $blog_id           Optional expected site blog ID.
	 * @param bool     $override_hold     Optional per-call legal hold flag (ORed with `$this->legal_hold_active`).
	 * @return array{items_removed:bool,items_retained:bool,messages:list<string>,done:bool}
	 * @throws AuthorizationException If the actor lacks `manage_wpig_settings` or violates Multisite isolation.
	 */
	public function erase_for_user(
		int $actor_user_id,
		int $target_user_id,
		?int $blog_id = null,
		bool $override_hold = false
	): array {
		$this->assert_authorized_for_privacy_erasure( $actor_user_id, $target_user_id, $blog_id );

		$effective_hold = $this->legal_hold_active || $override_hold;
		$profile        = $this->profile_repository->find_by_user_id( $target_user_id );
		$consents       = $this->consent_repository->find_all_for_user( $target_user_id );
		$has_evidence   = $this->has_verification_or_card_records( $target_user_id );

		// 1. Legal hold blocks all destructive removal.
		if ( $effective_hold ) {
			$has_any_records = null !== $profile
				|| array() !== $consents
				|| $has_evidence
				|| $this->count_otp_challenges_for_user( $target_user_id ) > 0;

			if ( $has_any_records && null !== $this->audit_service ) {
				$this->audit_service->log_privacy_erasure_retained(
					$actor_user_id,
					$target_user_id,
					self::REASON_LEGAL_HOLD,
					1
				);
			}

			return array(
				'items_removed'  => false,
				'items_retained' => $has_any_records,
				'messages'       => $has_any_records
					? array( $this->translate( 'WP Identity Guard records were retained because a legal or compliance hold is active.' ) )
					: array(),
				'done'           => true,
			);
		}

		// 2. Profile in REVIEW_REQUIRED state blocks destructive removal.
		if ( null !== $profile && ProfileRecord::STATE_REVIEW_REQUIRED === $profile->identity_state ) {
			if ( null !== $this->audit_service ) {
				$this->audit_service->log_privacy_erasure_retained(
					$actor_user_id,
					$target_user_id,
					self::REASON_REVIEW_REQUIRED,
					1
				);
			}

			return array(
				'items_removed'  => false,
				'items_retained' => true,
				'messages'       => array(
					$this->translate( 'WP Identity Guard profile and verification records were retained because the account is flagged for security review (REVIEW_REQUIRED).' ),
				),
				'done'           => true,
			);
		}

		$removed_count  = 0;
		$retained_count = 0;
		$messages       = array();
		$primary_reason = null;

		// 3. Delete transient OTP challenges (`wpig_otp_challenges`) scoped strictly to `$target_user_id`.
		$deleted_otp = $this->delete_otp_challenges_for_user( $target_user_id );
		if ( $deleted_otp > 0 ) {
			$removed_count += $deleted_otp;
		}

		// 4. Evaluate profile binding state (`UNBOUND` vs `BOUND` per D14).
		if ( null !== $profile ) {
			if ( $profile->is_bound() ) {
				// Never silently release a BOUND identity binding (D14).
				++$retained_count;
				$primary_reason = self::REASON_BOUND_IDENTITY;
				$messages[]     = $this->translate( 'WP Identity Guard retained the active bound identity record (D14 one-account-per-national-code anti-fraud binding cannot be released via self-service erasure).' );
			} else {
				$cleared = $this->profile_repository->clear_unbound_profile_pii( $target_user_id );
				if ( $cleared ) {
					++$removed_count;
				}
			}
		}

		// 5. Retain compliance-governed verification/card evidence and consent audit records while D04/DS-5 are open.
		if ( $has_evidence || array() !== $consents ) {
			++$retained_count;
			if ( null === $primary_reason ) {
				$primary_reason = self::REASON_POLICY_UNRESOLVED;
			}
			$messages[] = $this->translate( 'WP Identity Guard retained compliance-governed verification and consent audit records pending finalized legal retention policy (D04 / DS-5).' );
		}

		$items_removed  = $removed_count > 0;
		$items_retained = $retained_count > 0;

		if ( null !== $this->audit_service ) {
			if ( $items_retained && null !== $primary_reason ) {
				$this->audit_service->log_privacy_erasure_retained(
					$actor_user_id,
					$target_user_id,
					$primary_reason,
					$retained_count
				);
			}

			if ( $items_removed ) {
				$this->audit_service->log_privacy_erased(
					$actor_user_id,
					$target_user_id,
					$removed_count,
					$retained_count
				);
			}
		}

		return array(
			'items_removed'  => $items_removed,
			'items_retained' => $items_retained,
			'messages'       => $messages,
			'done'           => true,
		);
	}

	/**
	 * Assert that `$actor_user_id` holds `manage_wpig_settings` on the active site and that
	 * `$target_user_id` belongs to the active site in Multisite.
	 *
	 * @param int      $actor_user_id  Acting WordPress user ID.
	 * @param int      $target_user_id Target WordPress user ID.
	 * @param int|null $blog_id        Optional expected site blog ID.
	 * @throws AuthorizationException On unauthenticated access, missing capability, or cross-site access.
	 */
	private function assert_authorized_for_privacy_erasure(
		int $actor_user_id,
		int $target_user_id,
		?int $blog_id = null
	): void {
		try {
			$this->authorizer->assert_can_manage_settings( $actor_user_id, $blog_id );

			if ( $target_user_id < 1 ) {
				AuthorizationException::raise(
					AuthorizationException::CODE_FORBIDDEN,
					'Invalid target user ID for privacy erasure.'
				);
			}

			// Verify target user exists and belongs to the active site on Multisite.
			$this->authorizer->assert_valid_target_user_on_blog( $target_user_id, $blog_id );
		} catch ( AuthorizationException $e ) {
			if ( null !== $this->audit_service ) {
				$this->audit_service->log_authorization_denied(
					$actor_user_id > 0 ? $actor_user_id : null,
					$target_user_id > 0 ? $target_user_id : null,
					'privacy_erasure',
					$e->get_safe_code(),
					Capabilities::MANAGE_SETTINGS
				);
			}
			throw $e;
		}
	}

	/**
	 * Count transient OTP challenges for `$wp_user_id`.
	 *
	 * @param int $wp_user_id WordPress user ID (`>= 1`).
	 */
	private function count_otp_challenges_for_user( int $wp_user_id ): int {
		$tables = SchemaDefinition::get_table_names( $this->wpdb->prefix );
		$table  = $tables['wpig_otp_challenges'];
		$wpdb   = $this->wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom OTP challenges count.
		$count = $wpdb->get_var(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is strictly constructed from $wpdb->prefix + constant logical table.
				"SELECT COUNT(*) FROM `{$table}` WHERE wp_user_id = %d",
				$wp_user_id
			)
		);

		return null !== $count ? (int) $count : 0;
	}

	/**
	 * Delete transient OTP challenges for `$wp_user_id`.
	 *
	 * @param int $wp_user_id WordPress user ID (`>= 1`).
	 * @return int Number of deleted rows.
	 */
	private function delete_otp_challenges_for_user( int $wp_user_id ): int {
		$tables = SchemaDefinition::get_table_names( $this->wpdb->prefix );
		$table  = $tables['wpig_otp_challenges'];
		$wpdb   = $this->wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom OTP challenges deletion for target user.
		$deleted = $wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is strictly constructed from $wpdb->prefix + constant logical table.
				"DELETE FROM `{$table}` WHERE wp_user_id = %d",
				$wp_user_id
			)
		);

		return false !== $deleted ? (int) $deleted : 0;
	}

	/**
	 * Check whether `$wp_user_id` has records in `wpig_verifications` or `wpig_cards`.
	 *
	 * @param int $wp_user_id WordPress user ID (`>= 1`).
	 */
	private function has_verification_or_card_records( int $wp_user_id ): bool {
		$tables              = SchemaDefinition::get_table_names( $this->wpdb->prefix );
		$verifications_table = $tables['wpig_verifications'];
		$cards_table         = $tables['wpig_cards'];
		$wpdb                = $this->wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom table existence check.
		$verification_id = $wpdb->get_var(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is strictly constructed from $wpdb->prefix + constant logical table.
				"SELECT id FROM `{$verifications_table}` WHERE wp_user_id = %d LIMIT 1",
				$wp_user_id
			)
		);

		if ( null !== $verification_id ) {
			return true;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom table existence check.
		$card_id = $wpdb->get_var(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is strictly constructed from $wpdb->prefix + constant logical table.
				"SELECT id FROM `{$cards_table}` WHERE wp_user_id = %d LIMIT 1",
				$wp_user_id
			)
		);

		return null !== $card_id;
	}

	/**
	 * Translate a string using WordPress i18n when available.
	 *
	 * @param string $text Source string.
	 */
	private function translate( string $text ): string {
		if ( function_exists( '__' ) ) {
			// phpcs:ignore WordPress.WP.I18n.NonSingularStringLiteralText -- Helper translating fixed eraser messages.
			return (string) __( $text, 'wp-identity-guard' );
		}
		return $text;
	}
}

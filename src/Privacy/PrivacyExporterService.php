<?php
/**
 * WordPress Personal Data Exporter integration (`PrivacyExporterService`).
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
use WPIG\Storage\ProfileRepository;
use WPIG\Storage\SchemaDefinition;

/**
 * Integrates WP Identity Guard with the WordPress Personal Data Exporter API (Task 4).
 *
 * Security & Privacy Invariants:
 * - Exports ONLY approved non-secret, masked summaries (`national_code_masked`, `mobile_masked`,
 *   `pan_masked`, high-level verification/binding status, and consent history).
 * - NEVER invokes `decrypt_identity_for_user()` and NEVER exports decrypted national codes,
 *   full mobile numbers, birth dates, full card PANs, cryptographic keys, or HMAC fingerprints.
 * - Enforces authorization (`manage_wpig_settings` or authenticated profile owner on the current
 *   Multisite blog) and scoping to the target user on the active site.
 */
final class PrivacyExporterService {

	/**
	 * WordPress exporter slug.
	 */
	public const EXPORTER_SLUG = 'wp-identity-guard';

	/**
	 * Profile repository (used strictly for masked `find_by_user_id()`).
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
	 * WordPress database connection (for masked `wpig_cards` status lookup).
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
	 * Callback returning current UTC datetime (`Y-m-d H:i:s`).
	 *
	 * @var callable
	 * @phpstan-var callable():string
	 */
	private $clock;

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
	 * @param callable|null        $user_id_by_email_resolver Optional resolver (`fn(string $email): int`).
	 * @param callable|null        $current_user_id_resolver  Optional resolver (`fn(): int`).
	 * @param callable|null        $clock                     Optional UTC clock (`fn(): string`).
	 * @phpstan-param (callable(string):int)|null $user_id_by_email_resolver
	 * @phpstan-param (callable():int)|null       $current_user_id_resolver
	 * @phpstan-param (callable():string)|null    $clock
	 */
	public function __construct(
		ProfileRepository $profile_repository,
		ConsentRepository $consent_repository,
		AuthorizationService $authorizer,
		wpdb $wpdb,
		?AuditService $audit_service = null,
		?callable $user_id_by_email_resolver = null,
		?callable $current_user_id_resolver = null,
		?callable $clock = null
	) {
		$this->profile_repository = $profile_repository;
		$this->consent_repository = $consent_repository;
		$this->authorizer         = $authorizer;
		$this->wpdb               = $wpdb;
		$this->audit_service      = $audit_service;

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

		$this->clock = $clock ?? static function (): string {
			return gmdate( 'Y-m-d H:i:s' );
		};
	}

	/**
	 * Register the WP Identity Guard personal data exporter hook with WordPress exactly once.
	 */
	public function register_hooks(): void {
		if ( $this->hooks_registered ) {
			return;
		}
		if ( function_exists( 'add_filter' ) ) {
			if ( ! function_exists( 'has_filter' ) || false === has_filter( 'wp_privacy_personal_data_exporters', array( $this, 'register_exporter' ) ) ) {
				add_filter( 'wp_privacy_personal_data_exporters', array( $this, 'register_exporter' ) );
			}
			$this->hooks_registered = true;
		}
	}

	/**
	 * Filter callback for `wp_privacy_personal_data_exporters`.
	 *
	 * @param array<string,array<string,mixed>> $exporters Registered WordPress exporters.
	 * @return array<string,array<string,mixed>>
	 */
	public function register_exporter( array $exporters ): array {
		$exporters[ self::EXPORTER_SLUG ] = array(
			'exporter_friendly_name' => $this->translate( 'WP Identity Guard' ),
			'callback'               => array( $this, 'handle_wp_privacy_export' ),
		);

		return $exporters;
	}

	/**
	 * WordPress Personal Data Exporter callback `(string $email_address, int $page = 1)`.
	 *
	 * @param string $email_address Target user email address.
	 * @param int    $page          Export page number (`>= 1`).
	 * @return array{data:list<array{group_id:string,group_label:string,item_id:string,data:list<array{name:string,value:string}>}>,done:bool}
	 */
	public function handle_wp_privacy_export( string $email_address, int $page = 1 ): array {
		unset( $page );
		$trimmed_email = trim( $email_address );
		if ( '' === $trimmed_email ) {
			return array(
				'data' => array(),
				'done' => true,
			);
		}

		$target_user_id = (int) ( $this->user_id_by_email_resolver )( $trimmed_email );
		if ( $target_user_id < 1 ) {
			return array(
				'data' => array(),
				'done' => true,
			);
		}

		$actor_user_id = (int) ( $this->current_user_id_resolver )();

		return $this->export_for_user( $actor_user_id, $target_user_id );
	}

	/**
	 * Export approved masked personal data for `$target_user_id` after verifying authorization.
	 *
	 * Allowed when `$actor_user_id` holds `manage_wpig_settings` on the active site or when
	 * `$actor_user_id === $target_user_id` on the active site.
	 *
	 * @param int      $actor_user_id  Acting WordPress user ID (`>= 1`).
	 * @param int      $target_user_id Target WordPress user ID (`>= 1`).
	 * @param int|null $blog_id        Optional expected site blog ID.
	 * @return array{data:list<array{group_id:string,group_label:string,item_id:string,data:list<array{name:string,value:string}>}>,done:bool}
	 * @throws AuthorizationException If the actor is unauthorized or violates Multisite isolation.
	 */
	public function export_for_user(
		int $actor_user_id,
		int $target_user_id,
		?int $blog_id = null
	): array {
		$this->assert_authorized_for_privacy_export( $actor_user_id, $target_user_id, $blog_id );

		$export_items = array();
		$now_utc      = (string) ( $this->clock )();

		// 1. Masked Profile & High-Level Verification Status (never decrypted, no HMACs/keys).
		$profile = $this->profile_repository->find_by_user_id( $target_user_id );
		if ( null !== $profile ) {
			$safe_profile   = $profile->to_safe_export_array();
			$export_items[] = array(
				'group_id'    => 'wpig_identity_profile',
				'group_label' => $this->translate( 'WP Identity Guard — Masked Identity Profile' ),
				'item_id'     => 'wpig-profile-' . $target_user_id,
				'data'        => array(
					array(
						'name'  => $this->translate( 'Identity Verification Status' ),
						'value' => (string) $safe_profile['identity_state'],
					),
					array(
						'name'  => $this->translate( 'Identity Binding Status' ),
						'value' => (string) $safe_profile['binding_state'],
					),
					array(
						'name'  => $this->translate( 'Masked National Code' ),
						'value' => null !== $safe_profile['national_code_masked'] ? (string) $safe_profile['national_code_masked'] : $this->translate( 'Not provided' ),
					),
					array(
						'name'  => $this->translate( 'Masked Mobile Number' ),
						'value' => null !== $safe_profile['mobile_masked'] ? (string) $safe_profile['mobile_masked'] : $this->translate( 'Not provided' ),
					),
					array(
						'name'  => $this->translate( 'Verified At (UTC)' ),
						'value' => null !== $safe_profile['verified_at'] ? (string) $safe_profile['verified_at'] : $this->translate( 'Not verified' ),
					),
					array(
						'name'  => $this->translate( 'Verification Expires At (UTC)' ),
						'value' => null !== $safe_profile['expires_at'] ? (string) $safe_profile['expires_at'] : $this->translate( 'None' ),
					),
				),
			);
		}

		// 2. Masked Bank Card Summary (`masked_pan` + `state` only; never full PAN).
		$cards = $this->fetch_masked_cards_for_user( $target_user_id );
		foreach ( $cards as $card_row ) {
			$card_id        = isset( $card_row['id'] ) ? (int) $card_row['id'] : 0;
			$export_items[] = array(
				'group_id'    => 'wpig_cards',
				'group_label' => $this->translate( 'WP Identity Guard — Masked Bank Cards' ),
				'item_id'     => 'wpig-card-' . $card_id,
				'data'        => array(
					array(
						'name'  => $this->translate( 'Masked Card Number' ),
						'value' => isset( $card_row['masked_pan'] ) ? (string) $card_row['masked_pan'] : '',
					),
					array(
						'name'  => $this->translate( 'Card Verification Status' ),
						'value' => isset( $card_row['state'] ) ? (string) $card_row['state'] : '',
					),
					array(
						'name'  => $this->translate( 'Verified At (UTC)' ),
						'value' => isset( $card_row['verified_at'] ) ? (string) $card_row['verified_at'] : $this->translate( 'Not verified' ),
					),
				),
			);
		}

		// 3. Consent Records (`wpig_consents`).
		$consents = $this->consent_repository->find_all_for_user( $target_user_id );
		foreach ( $consents as $consent ) {
			$safe_consent   = $consent->to_safe_export_array( $now_utc );
			$export_items[] = array(
				'group_id'    => 'wpig_consents',
				'group_label' => $this->translate( 'WP Identity Guard — Consent Records' ),
				'item_id'     => 'wpig-consent-' . $consent->id,
				'data'        => array(
					array(
						'name'  => $this->translate( 'Consent Notice Version' ),
						'value' => (string) $safe_consent['notice_version'],
					),
					array(
						'name'  => $this->translate( 'Consented Purposes' ),
						'value' => (string) $safe_consent['purposes'],
					),
					array(
						'name'  => $this->translate( 'Consent Status' ),
						'value' => (string) $safe_consent['status'],
					),
					array(
						'name'  => $this->translate( 'Accepted At (UTC)' ),
						'value' => (string) $safe_consent['accepted_at'],
					),
					array(
						'name'  => $this->translate( 'Withdrawn At (UTC)' ),
						'value' => null !== $safe_consent['revoked_at'] ? (string) $safe_consent['revoked_at'] : $this->translate( 'Not withdrawn' ),
					),
				),
			);
		}

		if ( null !== $this->audit_service ) {
			$this->audit_service->log_privacy_exported(
				$actor_user_id,
				$target_user_id,
				count( $export_items )
			);
		}

		return array(
			'data' => $export_items,
			'done' => true,
		);
	}

	/**
	 * Assert that `$actor_user_id` is authorized to export masked privacy data for `$target_user_id`
	 * and that `$target_user_id` belongs to the active site in Multisite.
	 *
	 * @param int      $actor_user_id  Acting WordPress user ID.
	 * @param int      $target_user_id Target WordPress user ID.
	 * @param int|null $blog_id        Optional expected site blog ID.
	 * @throws AuthorizationException On unauthenticated access, cross-user IDOR, or cross-site access.
	 */
	private function assert_authorized_for_privacy_export(
		int $actor_user_id,
		int $target_user_id,
		?int $blog_id = null
	): void {
		try {
			$this->authorizer->assert_authenticated_actor( $actor_user_id, $blog_id );

			if ( $target_user_id < 1 ) {
				AuthorizationException::raise(
					AuthorizationException::CODE_FORBIDDEN,
					'Invalid target user ID for privacy export.'
				);
			}

			// Verify target user exists and belongs to the active site on Multisite.
			$this->authorizer->assert_valid_target_user_on_blog( $target_user_id, $blog_id );

			if ( $actor_user_id === $target_user_id ) {
				return;
			}

			$this->authorizer->assert_can_manage_settings( $actor_user_id, $blog_id );
		} catch ( AuthorizationException $e ) {
			if ( null !== $this->audit_service ) {
				$this->audit_service->log_authorization_denied(
					$actor_user_id > 0 ? $actor_user_id : null,
					$target_user_id > 0 ? $target_user_id : null,
					'privacy_export',
					$e->get_safe_code(),
					Capabilities::MANAGE_SETTINGS
				);
			}
			throw $e;
		}
	}

	/**
	 * Fetch masked card summaries (`id`, `masked_pan`, `state`, `verified_at`) for `$wp_user_id`.
	 *
	 * @param int $wp_user_id WordPress user ID (`>= 1`).
	 * @return list<array<string,mixed>>
	 */
	private function fetch_masked_cards_for_user( int $wp_user_id ): array {
		$tables = SchemaDefinition::get_table_names( $this->wpdb->prefix );
		$table  = $tables['wpig_cards'];
		$wpdb   = $this->wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom cards table read for privacy export.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is strictly constructed from $wpdb->prefix + constant logical table.
				"SELECT id, masked_pan, state, verified_at FROM `{$table}` WHERE wp_user_id = %d ORDER BY id DESC",
				$wp_user_id
			),
			ARRAY_A
		);

		if ( ! is_array( $rows ) ) {
			return array();
		}

		$result = array();
		foreach ( $rows as $row ) {
			/**
			 * Raw card row.
			 *
			 * @var array<string,mixed> $row
			 */
			$result[] = $row;
		}

		return $result;
	}

	/**
	 * Translate a string using WordPress i18n when available.
	 *
	 * @param string $text Source string.
	 */
	private function translate( string $text ): string {
		if ( function_exists( '__' ) ) {
			// phpcs:ignore WordPress.WP.I18n.NonSingularStringLiteralText -- Helper translating fixed exporter labels.
			return (string) __( $text, 'wp-identity-guard' );
		}
		return $text;
	}
}

<?php
/**
 * Schema definition for the 6 custom WP Identity Guard Free v1.0 tables.
 *
 * @package WPIG\Storage
 */

declare(strict_types=1);

namespace WPIG\Storage;

/**
 * Provides canonical table names, dbDelta-compatible DDL statements, and
 * expected column/index metadata for post-migration verification.
 */
final class SchemaDefinition {

	/**
	 * Current database schema version.
	 */
	public const SCHEMA_VERSION = '1.0.0';

	/**
	 * Unprefixed logical table names.
	 *
	 * @var list<string>
	 */
	public const LOGICAL_TABLES = array(
		'wpig_profiles',
		'wpig_verifications',
		'wpig_cards',
		'wpig_otp_challenges',
		'wpig_consents',
		'wpig_audit_events',
	);

	/**
	 * Return map of logical table name => prefixed table name.
	 *
	 * @param string $prefix WordPress database table prefix (e.g. $wpdb->prefix).
	 * @return array<string,string>
	 */
	public static function get_table_names( string $prefix ): array {
		$tables = array();
		foreach ( self::LOGICAL_TABLES as $logical ) {
			$tables[ $logical ] = $prefix . $logical;
		}
		return $tables;
	}

	/**
	 * Return dbDelta-formatted CREATE TABLE statements keyed by logical table name.
	 *
	 * Note: dbDelta() requires two spaces after PRIMARY KEY, KEY/UNIQUE KEY
	 * instead of INDEX, and no trailing spaces.
	 *
	 * @param string $prefix          WordPress database table prefix.
	 * @param string $charset_collate Charset/collation clause from $wpdb->get_charset_collate().
	 * @return array<string,string>
	 */
	public static function get_create_table_sql( string $prefix, string $charset_collate ): array {
		$t = self::get_table_names( $prefix );

		return array(
			'wpig_profiles'       => "CREATE TABLE {$t['wpig_profiles']} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  wp_user_id bigint(20) unsigned NOT NULL,
  country_code char(2) NOT NULL DEFAULT 'IR',
  subject_type varchar(16) NOT NULL DEFAULT 'natural',
  binding_state varchar(16) NOT NULL DEFAULT 'UNBOUND',
  identity_state varchar(24) NOT NULL DEFAULT 'UNVERIFIED',
  identity_version int(10) unsigned NOT NULL DEFAULT 1,
  mobile_version int(10) unsigned NOT NULL DEFAULT 1,
  card_version int(10) unsigned NOT NULL DEFAULT 1,
  mobile_ciphertext text DEFAULT NULL,
  mobile_hmac char(64) DEFAULT NULL,
  mobile_masked varchar(20) DEFAULT NULL,
  mobile_verified_at datetime DEFAULT NULL,
  national_code_ciphertext text DEFAULT NULL,
  national_code_hmac char(64) DEFAULT NULL,
  bound_national_code_hmac char(64) DEFAULT NULL,
  national_code_masked varchar(16) DEFAULT NULL,
  birth_date_ciphertext text DEFAULT NULL,
  shahkar_verified_at datetime DEFAULT NULL,
  enc_key_id varchar(32) DEFAULT NULL,
  hmac_key_id varchar(32) DEFAULT NULL,
  bound_at datetime DEFAULT NULL,
  released_at datetime DEFAULT NULL,
  verified_at datetime DEFAULT NULL,
  expires_at datetime DEFAULT NULL,
  created_at datetime NOT NULL,
  updated_at datetime NOT NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY uq_wpig_profiles_wp_user (wp_user_id),
  UNIQUE KEY uq_wpig_profiles_bound_nc (bound_national_code_hmac),
  KEY idx_wpig_profiles_state (identity_state,binding_state,expires_at),
  KEY idx_wpig_profiles_nc_hmac (national_code_hmac),
  KEY idx_wpig_profiles_mob_hmac (mobile_hmac),
  KEY idx_wpig_profiles_enc_key (enc_key_id),
  KEY idx_wpig_profiles_hmac_key (hmac_key_id)
) $charset_collate;",

			'wpig_verifications'  => "CREATE TABLE {$t['wpig_verifications']} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  wp_user_id bigint(20) unsigned NOT NULL,
  identity_version int(10) unsigned NOT NULL,
  mobile_version int(10) unsigned NOT NULL,
  card_version int(10) unsigned NOT NULL,
  subject_hmac char(64) DEFAULT NULL,
  idempotency_key char(64) NOT NULL,
  operation varchar(32) NOT NULL,
  provider varchar(32) NOT NULL,
  state varchar(24) NOT NULL,
  safe_error_code varchar(64) DEFAULT NULL,
  http_status smallint(5) unsigned DEFAULT NULL,
  provider_reference varchar(128) DEFAULT NULL,
  latency_ms int(10) unsigned DEFAULT NULL,
  requested_at datetime NOT NULL,
  completed_at datetime DEFAULT NULL,
  expires_at datetime DEFAULT NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY uq_wpig_verifications_idempotency (idempotency_key),
  KEY idx_wpig_verifications_user_op (wp_user_id,operation,identity_version,state),
  KEY idx_wpig_verifications_inflight (operation,subject_hmac,state,requested_at),
  KEY idx_wpig_verifications_requested (requested_at),
  KEY idx_wpig_verifications_state_exp (state,expires_at)
) $charset_collate;",

			'wpig_cards'          => "CREATE TABLE {$t['wpig_cards']} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  wp_user_id bigint(20) unsigned NOT NULL,
  active_user_slot bigint(20) unsigned DEFAULT NULL,
  is_current tinyint(1) unsigned NOT NULL DEFAULT 1,
  identity_version int(10) unsigned NOT NULL,
  card_version int(10) unsigned NOT NULL,
  verification_id bigint(20) unsigned NOT NULL,
  card_last4 char(4) NOT NULL,
  masked_pan varchar(24) NOT NULL,
  state varchar(24) NOT NULL,
  provider varchar(32) NOT NULL,
  verified_at datetime NOT NULL,
  expires_at datetime DEFAULT NULL,
  superseded_at datetime DEFAULT NULL,
  created_at datetime NOT NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY uq_wpig_cards_active_slot (active_user_slot),
  KEY idx_wpig_cards_user_current (wp_user_id,is_current,state),
  KEY idx_wpig_cards_verification (verification_id)
) $charset_collate;",

			'wpig_otp_challenges' => "CREATE TABLE {$t['wpig_otp_challenges']} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  wp_user_id bigint(20) unsigned NOT NULL,
  mobile_version int(10) unsigned NOT NULL,
  mobile_hmac char(64) NOT NULL,
  code_hmac char(64) NOT NULL,
  hmac_key_id varchar(32) NOT NULL,
  state varchar(16) NOT NULL DEFAULT 'PENDING',
  attempts tinyint(3) unsigned NOT NULL DEFAULT 0,
  max_attempts tinyint(3) unsigned NOT NULL DEFAULT 5,
  requester_ip_hmac char(64) DEFAULT NULL,
  expires_at datetime NOT NULL,
  consumed_at datetime DEFAULT NULL,
  created_at datetime NOT NULL,
  PRIMARY KEY  (id),
  KEY idx_wpig_otp_user_state (wp_user_id,mobile_version,state,expires_at),
  KEY idx_wpig_otp_mobile_rate (mobile_hmac,created_at),
  KEY idx_wpig_otp_ip_rate (requester_ip_hmac,created_at),
  KEY idx_wpig_otp_expires (expires_at)
) $charset_collate;",

			'wpig_consents'       => "CREATE TABLE {$t['wpig_consents']} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  wp_user_id bigint(20) unsigned NOT NULL,
  notice_version varchar(32) NOT NULL,
  notice_hash char(64) NOT NULL,
  purposes_json varchar(255) NOT NULL,
  accepted_at datetime NOT NULL,
  revoked_at datetime DEFAULT NULL,
  expires_at datetime DEFAULT NULL,
  PRIMARY KEY  (id),
  KEY idx_wpig_consents_user_version (wp_user_id,notice_version,revoked_at)
) $charset_collate;",

			'wpig_audit_events'   => "CREATE TABLE {$t['wpig_audit_events']} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  correlation_id char(36) NOT NULL,
  actor_user_id bigint(20) unsigned DEFAULT NULL,
  target_user_id bigint(20) unsigned DEFAULT NULL,
  event_type varchar(64) NOT NULL,
  outcome varchar(24) NOT NULL,
  safe_metadata_json text DEFAULT NULL,
  occurred_at datetime NOT NULL,
  PRIMARY KEY  (id),
  KEY idx_wpig_audit_target (target_user_id,occurred_at),
  KEY idx_wpig_audit_actor (actor_user_id,occurred_at),
  KEY idx_wpig_audit_type_time (event_type,occurred_at),
  KEY idx_wpig_audit_occurred (occurred_at)
) $charset_collate;",
		);
	}

	/**
	 * Expected columns per logical table (in order) for post-migration verification.
	 *
	 * @return array<string,list<string>>
	 */
	public static function get_expected_columns(): array {
		return array(
			'wpig_profiles'       => array(
				'id',
				'wp_user_id',
				'country_code',
				'subject_type',
				'binding_state',
				'identity_state',
				'identity_version',
				'mobile_version',
				'card_version',
				'mobile_ciphertext',
				'mobile_hmac',
				'mobile_masked',
				'mobile_verified_at',
				'national_code_ciphertext',
				'national_code_hmac',
				'bound_national_code_hmac',
				'national_code_masked',
				'birth_date_ciphertext',
				'shahkar_verified_at',
				'enc_key_id',
				'hmac_key_id',
				'bound_at',
				'released_at',
				'verified_at',
				'expires_at',
				'created_at',
				'updated_at',
			),
			'wpig_verifications'  => array(
				'id',
				'wp_user_id',
				'identity_version',
				'mobile_version',
				'card_version',
				'subject_hmac',
				'idempotency_key',
				'operation',
				'provider',
				'state',
				'safe_error_code',
				'http_status',
				'provider_reference',
				'latency_ms',
				'requested_at',
				'completed_at',
				'expires_at',
			),
			'wpig_cards'          => array(
				'id',
				'wp_user_id',
				'active_user_slot',
				'is_current',
				'identity_version',
				'card_version',
				'verification_id',
				'card_last4',
				'masked_pan',
				'state',
				'provider',
				'verified_at',
				'expires_at',
				'superseded_at',
				'created_at',
			),
			'wpig_otp_challenges' => array(
				'id',
				'wp_user_id',
				'mobile_version',
				'mobile_hmac',
				'code_hmac',
				'hmac_key_id',
				'state',
				'attempts',
				'max_attempts',
				'requester_ip_hmac',
				'expires_at',
				'consumed_at',
				'created_at',
			),
			'wpig_consents'       => array(
				'id',
				'wp_user_id',
				'notice_version',
				'notice_hash',
				'purposes_json',
				'accepted_at',
				'revoked_at',
				'expires_at',
			),
			'wpig_audit_events'   => array(
				'id',
				'correlation_id',
				'actor_user_id',
				'target_user_id',
				'event_type',
				'outcome',
				'safe_metadata_json',
				'occurred_at',
			),
		);
	}

	/**
	 * Expected indexes per logical table.
	 * Maps logical_table => [ index_name => [ 'unique' => bool, 'columns' => list<string> ] ].
	 *
	 * @return array<string,array<string,array{unique:bool,columns:list<string>}>>
	 */
	public static function get_expected_indexes(): array {
		return array(
			'wpig_profiles'       => array(
				'PRIMARY'                    => array(
					'unique'  => true,
					'columns' => array( 'id' ),
				),
				'uq_wpig_profiles_wp_user'   => array(
					'unique'  => true,
					'columns' => array( 'wp_user_id' ),
				),
				'uq_wpig_profiles_bound_nc'  => array(
					'unique'  => true,
					'columns' => array( 'bound_national_code_hmac' ),
				),
				'idx_wpig_profiles_state'    => array(
					'unique'  => false,
					'columns' => array( 'identity_state', 'binding_state', 'expires_at' ),
				),
				'idx_wpig_profiles_nc_hmac'  => array(
					'unique'  => false,
					'columns' => array( 'national_code_hmac' ),
				),
				'idx_wpig_profiles_mob_hmac' => array(
					'unique'  => false,
					'columns' => array( 'mobile_hmac' ),
				),
				'idx_wpig_profiles_enc_key'  => array(
					'unique'  => false,
					'columns' => array( 'enc_key_id' ),
				),
				'idx_wpig_profiles_hmac_key' => array(
					'unique'  => false,
					'columns' => array( 'hmac_key_id' ),
				),
			),
			'wpig_verifications'  => array(
				'PRIMARY'                           => array(
					'unique'  => true,
					'columns' => array( 'id' ),
				),
				'uq_wpig_verifications_idempotency' => array(
					'unique'  => true,
					'columns' => array( 'idempotency_key' ),
				),
				'idx_wpig_verifications_user_op'    => array(
					'unique'  => false,
					'columns' => array( 'wp_user_id', 'operation', 'identity_version', 'state' ),
				),
				'idx_wpig_verifications_inflight'   => array(
					'unique'  => false,
					'columns' => array( 'operation', 'subject_hmac', 'state', 'requested_at' ),
				),
				'idx_wpig_verifications_requested'  => array(
					'unique'  => false,
					'columns' => array( 'requested_at' ),
				),
				'idx_wpig_verifications_state_exp'  => array(
					'unique'  => false,
					'columns' => array( 'state', 'expires_at' ),
				),
			),
			'wpig_cards'          => array(
				'PRIMARY'                     => array(
					'unique'  => true,
					'columns' => array( 'id' ),
				),
				'uq_wpig_cards_active_slot'   => array(
					'unique'  => true,
					'columns' => array( 'active_user_slot' ),
				),
				'idx_wpig_cards_user_current' => array(
					'unique'  => false,
					'columns' => array( 'wp_user_id', 'is_current', 'state' ),
				),
				'idx_wpig_cards_verification' => array(
					'unique'  => false,
					'columns' => array( 'verification_id' ),
				),
			),
			'wpig_otp_challenges' => array(
				'PRIMARY'                  => array(
					'unique'  => true,
					'columns' => array( 'id' ),
				),
				'idx_wpig_otp_user_state'  => array(
					'unique'  => false,
					'columns' => array( 'wp_user_id', 'mobile_version', 'state', 'expires_at' ),
				),
				'idx_wpig_otp_mobile_rate' => array(
					'unique'  => false,
					'columns' => array( 'mobile_hmac', 'created_at' ),
				),
				'idx_wpig_otp_ip_rate'     => array(
					'unique'  => false,
					'columns' => array( 'requester_ip_hmac', 'created_at' ),
				),
				'idx_wpig_otp_expires'     => array(
					'unique'  => false,
					'columns' => array( 'expires_at' ),
				),
			),
			'wpig_consents'       => array(
				'PRIMARY'                        => array(
					'unique'  => true,
					'columns' => array( 'id' ),
				),
				'idx_wpig_consents_user_version' => array(
					'unique'  => false,
					'columns' => array( 'wp_user_id', 'notice_version', 'revoked_at' ),
				),
			),
			'wpig_audit_events'   => array(
				'PRIMARY'                  => array(
					'unique'  => true,
					'columns' => array( 'id' ),
				),
				'idx_wpig_audit_target'    => array(
					'unique'  => false,
					'columns' => array( 'target_user_id', 'occurred_at' ),
				),
				'idx_wpig_audit_actor'     => array(
					'unique'  => false,
					'columns' => array( 'actor_user_id', 'occurred_at' ),
				),
				'idx_wpig_audit_type_time' => array(
					'unique'  => false,
					'columns' => array( 'event_type', 'occurred_at' ),
				),
				'idx_wpig_audit_occurred'  => array(
					'unique'  => false,
					'columns' => array( 'occurred_at' ),
				),
			),
		);
	}
}

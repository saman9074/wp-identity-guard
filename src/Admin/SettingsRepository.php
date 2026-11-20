<?php
/**
 * Safe, non-autoloaded repository for non-sensitive WP Identity Guard general settings.
 *
 * @package WPIG\Admin
 */

declare(strict_types=1);

namespace WPIG\Admin;

use WPIG\Core\Activator;
use WPIG\Security\AuthorizationException;
use WPIG\Security\AuthorizationService;
use WPIG\Security\ValidationException;

/**
 * Manages the `wpig_settings` option with strict allowlist validation, range enforcement,
 * non-autoloaded persistence, and upgrade preservation (Task 5).
 *
 * Security Invariants:
 * - Never accepts or stores provider API keys, secrets, tokens, or encryption keys.
 * - Requires `manage_wpig_settings` authorization for all writes.
 * - Rejects unknown/unexpected input keys (`ValidationException`) and privilege-escalation claims (`AuthorizationException`).
 * - Preserves `erase_on_uninstall` and `legal_hold_active` lifecycle flags across upgrades without exposing destructive toggles in P01-D2.
 */
final class SettingsRepository {

	/**
	 * WordPress option key for plugin settings (non-autoloaded).
	 */
	public const OPTION_NAME = Activator::SETTINGS_OPTION;

	/**
	 * Allowed values for `default_provider`.
	 *
	 * @var list<string>
	 */
	public const ALLOWED_PROVIDERS = array(
		'none',
		'api_ir',
		'zohal',
	);

	/**
	 * Editable setting keys permitted in Phase P01-D2.
	 *
	 * @var list<string>
	 */
	public const ALLOWED_EDITABLE_KEYS = array(
		'default_provider',
		'sandbox_mode',
		'daily_request_budget',
		'rate_limit_per_user_hour',
		'rate_limit_per_ip_hour',
		'security_notifications_enabled',
		'consent_notice_version',
	);

	/**
	 * Range bounds for numeric settings.
	 */
	public const MIN_DAILY_BUDGET        = 0;
	public const MAX_DAILY_BUDGET        = 100000;
	public const MIN_USER_HOURLY_LIMIT   = 1;
	public const MAX_USER_HOURLY_LIMIT   = 100;
	public const MIN_IP_HOURLY_LIMIT     = 1;
	public const MAX_IP_HOURLY_LIMIT     = 500;
	public const CONSENT_VERSION_PATTERN = '/^[A-Za-z0-9._-]{1,32}$/';

	/**
	 * Authorization service.
	 *
	 * @var AuthorizationService
	 */
	private AuthorizationService $authorizer;

	/**
	 * Option reader callback (`fn(string $option, mixed $default): mixed`).
	 *
	 * @var callable
	 * @phpstan-var callable(string, mixed):mixed
	 */
	private $get_option_fn;

	/**
	 * Option adder callback (`fn(string $option, mixed $value, bool $autoload): bool`).
	 *
	 * @var callable
	 * @phpstan-var callable(string, mixed, bool):bool
	 */
	private $add_option_fn;

	/**
	 * Option updater callback (`fn(string $option, mixed $value, bool $autoload): bool`).
	 *
	 * @var callable
	 * @phpstan-var callable(string, mixed, bool):bool
	 */
	private $update_option_fn;

	/**
	 * Constructor.
	 *
	 * @param AuthorizationService|null $authorizer       Optional authorization service.
	 * @param callable|null             $get_option_fn    Optional option getter override.
	 * @param callable|null             $add_option_fn    Optional option adder override.
	 * @param callable|null             $update_option_fn Optional option updater override.
	 * @phpstan-param (callable(string, mixed):mixed)|null     $get_option_fn
	 * @phpstan-param (callable(string, mixed, bool):bool)|null $add_option_fn
	 * @phpstan-param (callable(string, mixed, bool):bool)|null $update_option_fn
	 */
	public function __construct(
		?AuthorizationService $authorizer = null,
		?callable $get_option_fn = null,
		?callable $add_option_fn = null,
		?callable $update_option_fn = null
	) {
		$this->authorizer = $authorizer ?? new AuthorizationService();

		$this->get_option_fn = $get_option_fn ?? static function ( string $option, mixed $default_value = false ): mixed {
			if ( function_exists( 'get_option' ) ) {
				return get_option( $option, $default_value );
			}
			return $default_value;
		};

		$this->add_option_fn = $add_option_fn ?? static function ( string $option, mixed $value, bool $autoload = false ): bool {
			if ( function_exists( 'add_option' ) ) {
				return (bool) add_option( $option, $value, '', $autoload );
			}
			return false;
		};

		$this->update_option_fn = $update_option_fn ?? static function ( string $option, mixed $value, bool $autoload = false ): bool {
			if ( function_exists( 'update_option' ) ) {
				return (bool) update_option( $option, $value, $autoload );
			}
			return false;
		};
	}

	/**
	 * Return canonical default settings for `wpig_settings`.
	 *
	 * @return array{
	 *   default_provider: string,
	 *   sandbox_mode: bool,
	 *   daily_request_budget: int,
	 *   rate_limit_per_user_hour: int,
	 *   rate_limit_per_ip_hour: int,
	 *   security_notifications_enabled: bool,
	 *   consent_notice_version: string,
	 *   erase_on_uninstall: bool,
	 *   legal_hold_active: bool
	 * }
	 */
	public static function get_default_settings(): array {
		return array(
			'default_provider'               => 'none',
			'sandbox_mode'                   => true,
			'daily_request_budget'           => 100,
			'rate_limit_per_user_hour'       => 5,
			'rate_limit_per_ip_hour'         => 15,
			'security_notifications_enabled' => true,
			'consent_notice_version'         => '1.0',
			'erase_on_uninstall'             => false,
			'legal_hold_active'              => false,
		);
	}

	/**
	 * Normalize and merge stored settings with canonical defaults (preserving valid existing values across upgrades).
	 *
	 * @param mixed $stored Raw value read from `wp_options`.
	 * @return array{
	 *   default_provider: string,
	 *   sandbox_mode: bool,
	 *   daily_request_budget: int,
	 *   rate_limit_per_user_hour: int,
	 *   rate_limit_per_ip_hour: int,
	 *   security_notifications_enabled: bool,
	 *   consent_notice_version: string,
	 *   erase_on_uninstall: bool,
	 *   legal_hold_active: bool
	 * }
	 */
	public static function normalize_stored_settings( mixed $stored ): array {
		$defaults = self::get_default_settings();
		if ( ! is_array( $stored ) ) {
			return $defaults;
		}

		$provider = isset( $stored['default_provider'] ) && is_string( $stored['default_provider'] )
			&& in_array( $stored['default_provider'], self::ALLOWED_PROVIDERS, true )
			? $stored['default_provider']
			: $defaults['default_provider'];

		$sandbox_mode = isset( $stored['sandbox_mode'] )
			? (bool) $stored['sandbox_mode']
			: $defaults['sandbox_mode'];

		$daily_budget = isset( $stored['daily_request_budget'] ) && is_numeric( $stored['daily_request_budget'] )
			? (int) $stored['daily_request_budget']
			: $defaults['daily_request_budget'];
		if ( $daily_budget < self::MIN_DAILY_BUDGET || $daily_budget > self::MAX_DAILY_BUDGET ) {
			$daily_budget = $defaults['daily_request_budget'];
		}

		$user_limit = isset( $stored['rate_limit_per_user_hour'] ) && is_numeric( $stored['rate_limit_per_user_hour'] )
			? (int) $stored['rate_limit_per_user_hour']
			: $defaults['rate_limit_per_user_hour'];
		if ( $user_limit < self::MIN_USER_HOURLY_LIMIT || $user_limit > self::MAX_USER_HOURLY_LIMIT ) {
			$user_limit = $defaults['rate_limit_per_user_hour'];
		}

		$ip_limit = isset( $stored['rate_limit_per_ip_hour'] ) && is_numeric( $stored['rate_limit_per_ip_hour'] )
			? (int) $stored['rate_limit_per_ip_hour']
			: $defaults['rate_limit_per_ip_hour'];
		if ( $ip_limit < self::MIN_IP_HOURLY_LIMIT || $ip_limit > self::MAX_IP_HOURLY_LIMIT ) {
			$ip_limit = $defaults['rate_limit_per_ip_hour'];
		}

		$notifications = isset( $stored['security_notifications_enabled'] )
			? (bool) $stored['security_notifications_enabled']
			: $defaults['security_notifications_enabled'];

		$consent_version = isset( $stored['consent_notice_version'] ) && is_string( $stored['consent_notice_version'] )
			&& 1 === preg_match( self::CONSENT_VERSION_PATTERN, trim( $stored['consent_notice_version'] ) )
			? trim( $stored['consent_notice_version'] )
			: $defaults['consent_notice_version'];

		$erase_on_uninstall = isset( $stored['erase_on_uninstall'] )
			? (bool) $stored['erase_on_uninstall']
			: $defaults['erase_on_uninstall'];

		$legal_hold_active = isset( $stored['legal_hold_active'] )
			? (bool) $stored['legal_hold_active']
			: $defaults['legal_hold_active'];

		return array(
			'default_provider'               => $provider,
			'sandbox_mode'                   => $sandbox_mode,
			'daily_request_budget'           => $daily_budget,
			'rate_limit_per_user_hour'       => $user_limit,
			'rate_limit_per_ip_hour'         => $ip_limit,
			'security_notifications_enabled' => $notifications,
			'consent_notice_version'         => $consent_version,
			'erase_on_uninstall'             => $erase_on_uninstall,
			'legal_hold_active'              => $legal_hold_active,
		);
	}

	/**
	 * Read current normalized plugin settings.
	 *
	 * @return array{
	 *   default_provider: string,
	 *   sandbox_mode: bool,
	 *   daily_request_budget: int,
	 *   rate_limit_per_user_hour: int,
	 *   rate_limit_per_ip_hour: int,
	 *   security_notifications_enabled: bool,
	 *   consent_notice_version: string,
	 *   erase_on_uninstall: bool,
	 *   legal_hold_active: bool
	 * }
	 */
	public function get_settings(): array {
		$stored = ( $this->get_option_fn )( self::OPTION_NAME, false );
		return self::normalize_stored_settings( $stored );
	}

	/**
	 * Validate and persist updated general settings for an authorized administrator (`manage_wpig_settings`).
	 *
	 * @param int                 $actor_user_id Acting WordPress user ID.
	 * @param array<string,mixed> $input         Submitted settings key-value map.
	 * @param int|null            $blog_id       Optional expected site blog ID.
	 * @return array{
	 *   default_provider: string,
	 *   sandbox_mode: bool,
	 *   daily_request_budget: int,
	 *   rate_limit_per_user_hour: int,
	 *   rate_limit_per_ip_hour: int,
	 *   security_notifications_enabled: bool,
	 *   consent_notice_version: string,
	 *   erase_on_uninstall: bool,
	 *   legal_hold_active: bool
	 * }
	 * @throws AuthorizationException If actor lacks `manage_wpig_settings` or submits privilege-escalation claims.
	 * @throws ValidationException    If any field is unknown, malformed, out of range, or attempts to store credentials.
	 */
	public function update_general_settings(
		int $actor_user_id,
		array $input,
		?int $blog_id = null
	): array {
		$this->authorizer->assert_no_privilege_escalation_input( $input, $actor_user_id );
		$this->authorizer->assert_can_manage_settings( $actor_user_id, $blog_id );

		$validated_editable = $this->validate_editable_input( $input );
		$existing_raw       = ( $this->get_option_fn )( self::OPTION_NAME, false );
		$current            = self::normalize_stored_settings( $existing_raw );

		$merged = array(
			'default_provider'               => $validated_editable['default_provider'] ?? $current['default_provider'],
			'sandbox_mode'                   => $validated_editable['sandbox_mode'] ?? $current['sandbox_mode'],
			'daily_request_budget'           => $validated_editable['daily_request_budget'] ?? $current['daily_request_budget'],
			'rate_limit_per_user_hour'       => $validated_editable['rate_limit_per_user_hour'] ?? $current['rate_limit_per_user_hour'],
			'rate_limit_per_ip_hour'         => $validated_editable['rate_limit_per_ip_hour'] ?? $current['rate_limit_per_ip_hour'],
			'security_notifications_enabled' => $validated_editable['security_notifications_enabled'] ?? $current['security_notifications_enabled'],
			'consent_notice_version'         => $validated_editable['consent_notice_version'] ?? $current['consent_notice_version'],
			// Preserve D15 destructive/legal-hold flags without allowing P01-D2 general settings to mutate them.
			'erase_on_uninstall'             => $current['erase_on_uninstall'],
			'legal_hold_active'              => $current['legal_hold_active'],
		);

		if ( false === $existing_raw ) {
			( $this->add_option_fn )( self::OPTION_NAME, $merged, false );
		} else {
			( $this->update_option_fn )( self::OPTION_NAME, $merged, false );
		}

		return $merged;
	}

	/**
	 * Validate a map of candidate editable settings against the strict allowlist and value constraints.
	 *
	 * @param array<string,mixed> $input Raw settings input.
	 * @return array{
	 *   default_provider?: string,
	 *   sandbox_mode?: bool,
	 *   daily_request_budget?: int,
	 *   rate_limit_per_user_hour?: int,
	 *   rate_limit_per_ip_hour?: int,
	 *   security_notifications_enabled?: bool,
	 *   consent_notice_version?: string
	 * }
	 * @throws ValidationException On unexpected fields, invalid types, or out-of-range values.
	 */
	public function validate_editable_input( array $input ): array {
		$validated = array();

		foreach ( $input as $raw_key => $raw_value ) {
			$key = (string) $raw_key;

			if ( ! in_array( $key, self::ALLOWED_EDITABLE_KEYS, true ) ) {
				ValidationException::raise(
					ValidationException::CODE_INVALID_SETTING,
					'Settings payload contains an unsupported or restricted field.'
				);
			}

			switch ( $key ) {
				case 'default_provider':
					if ( ! is_string( $raw_value ) || ! in_array( $raw_value, self::ALLOWED_PROVIDERS, true ) ) {
						ValidationException::raise(
							ValidationException::CODE_INVALID_SETTING,
							'Invalid default_provider setting; must be none, api_ir, or zohal.'
						);
					}
					$validated['default_provider'] = $raw_value;
					break;

				case 'sandbox_mode':
					$validated['sandbox_mode'] = self::parse_strict_bool( $raw_value, 'sandbox_mode' );
					break;

				case 'daily_request_budget':
					$validated['daily_request_budget'] = self::parse_strict_int_range(
						$raw_value,
						self::MIN_DAILY_BUDGET,
						self::MAX_DAILY_BUDGET,
						'daily_request_budget'
					);
					break;

				case 'rate_limit_per_user_hour':
					$validated['rate_limit_per_user_hour'] = self::parse_strict_int_range(
						$raw_value,
						self::MIN_USER_HOURLY_LIMIT,
						self::MAX_USER_HOURLY_LIMIT,
						'rate_limit_per_user_hour'
					);
					break;

				case 'rate_limit_per_ip_hour':
					$validated['rate_limit_per_ip_hour'] = self::parse_strict_int_range(
						$raw_value,
						self::MIN_IP_HOURLY_LIMIT,
						self::MAX_IP_HOURLY_LIMIT,
						'rate_limit_per_ip_hour'
					);
					break;

				case 'security_notifications_enabled':
					$validated['security_notifications_enabled'] = self::parse_strict_bool(
						$raw_value,
						'security_notifications_enabled'
					);
					break;

				case 'consent_notice_version':
					if ( ! is_string( $raw_value ) ) {
						ValidationException::raise(
							ValidationException::CODE_INVALID_SETTING,
							'consent_notice_version must be a string.'
						);
					}
					$trimmed = trim( $raw_value );
					if ( 1 !== preg_match( self::CONSENT_VERSION_PATTERN, $trimmed ) ) {
						ValidationException::raise(
							ValidationException::CODE_INVALID_SETTING,
							'consent_notice_version must be 1..32 characters of [A-Za-z0-9._-].'
						);
					}
					$validated['consent_notice_version'] = $trimmed;
					break;
			}
		}

		return $validated;
	}

	/**
	 * Parse a strict boolean setting from bool, int (0/1), or string ('0'/'1'/'true'/'false').
	 *
	 * @param mixed  $value      Candidate boolean value.
	 * @param string $field_name Field identifier for safe error messages.
	 * @return bool
	 * @throws ValidationException If value is not a recognized boolean representation.
	 */
	private static function parse_strict_bool( mixed $value, string $field_name ): bool {
		if ( is_bool( $value ) ) {
			return $value;
		}
		if ( 1 === $value || '1' === $value || 'true' === $value ) {
			return true;
		}
		if ( 0 === $value || '0' === $value || 'false' === $value ) {
			return false;
		}

		ValidationException::raise(
			ValidationException::CODE_INVALID_SETTING,
			sprintf( 'Setting %s must be a boolean value.', $field_name )
		);
	}

	/**
	 * Parse an integer setting and validate inclusive bounds.
	 *
	 * @param mixed  $value      Candidate integer value.
	 * @param int    $min        Inclusive minimum.
	 * @param int    $max        Inclusive maximum.
	 * @param string $field_name Field identifier for safe error messages.
	 * @return int
	 * @throws ValidationException If value is not an integer or is outside `[$min, $max]`.
	 */
	private static function parse_strict_int_range(
		mixed $value,
		int $min,
		int $max,
		string $field_name
	): int {
		if ( is_int( $value ) ) {
			$int_val = $value;
		} elseif ( is_string( $value ) && 1 === preg_match( '/^\d+$/', trim( $value ) ) ) {
			$int_val = (int) trim( $value );
		} else {
			ValidationException::raise(
				ValidationException::CODE_INVALID_SETTING,
				sprintf( 'Setting %s must be an integer.', $field_name )
			);
		}

		if ( $int_val < $min || $int_val > $max ) {
			ValidationException::raise(
				ValidationException::CODE_INVALID_SETTING,
				sprintf( 'Setting %s must be between %d and %d.', $field_name, $min, $max )
			);
		}

		return $int_val;
	}
}

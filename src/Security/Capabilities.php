<?php
/**
 * WordPress capability definitions and idempotent least-privilege role registration.
 *
 * @package WPIG\Security
 */

declare(strict_types=1);

namespace WPIG\Security;

use WP_Role;
use WP_Roles;

/**
 * Defines and registers WP Identity Guard capabilities per site.
 *
 * Least-Privilege & Security Rules:
 * - Implements the three approved capabilities (`docs/04-security-privacy.md`):
 *   - `manage_wpig_settings`
 *   - `view_wpig_reports`
 *   - `review_wpig_verification`
 * - Grants administrative capabilities by default ONLY to the site's `administrator` role.
 * - Never grants administrative capabilities to `subscriber`, `customer`, or ordinary
 *   unprivileged roles (`contributor`, `author`, `editor`, `shop_manager`), and actively
 *   removes them from disallowed roles during idempotent registration/upgrades.
 * - Supports custom WordPress roles (e.g. `wpig_compliance_officer`, `wpig_auditor`) via
 *   `grant_to_role()` and preserves custom role assignments across activation/reactivation.
 * - Operates strictly on the current site (`$wpdb->prefix . 'user_roles'`) to respect
 *   Multisite site-level boundaries.
 */
final class Capabilities {

	/**
	 * Capability required to manage plugin settings, provider credentials, key rotation, and destructive opt-in erasure (`D15`).
	 */
	public const MANAGE_SETTINGS = 'manage_wpig_settings';

	/**
	 * Capability required to view masked verification reports and audit summaries.
	 */
	public const VIEW_REPORTS = 'view_wpig_reports';

	/**
	 * Capability required to review identity conflicts and execute explicit binding releases (`D14`).
	 */
	public const REVIEW_VERIFICATION = 'review_wpig_verification';

	/**
	 * Capability model version for idempotent upgrade checks.
	 */
	public const VERSION = '1.0.0';

	/**
	 * Non-autoloaded site option recording installed capability schema version.
	 */
	public const VERSION_OPTION = 'wpig_capabilities_version';

	/**
	 * Default WordPress role receiving all WPIG administrative capabilities on activation.
	 */
	public const ROLE_ADMINISTRATOR = 'administrator';

	/**
	 * Roles that must NEVER be granted WPIG administrative capabilities.
	 *
	 * Includes standard unprivileged WordPress and WooCommerce roles.
	 *
	 * @var list<string>
	 */
	public const DISALLOWED_ROLES = array(
		'subscriber',
		'customer',
		'contributor',
		'author',
		'editor',
		'shop_manager',
		'pending',
		'guest',
		'anonymous',
	);

	/**
	 * Return all WP Identity Guard administrative capabilities.
	 *
	 * @return list<string>
	 */
	public static function all(): array {
		return array(
			self::MANAGE_SETTINGS,
			self::VIEW_REPORTS,
			self::REVIEW_VERIFICATION,
		);
	}

	/**
	 * Check whether a capability string is a valid WP Identity Guard capability.
	 *
	 * @param string $capability Capability slug to check.
	 */
	public static function is_valid_capability( string $capability ): bool {
		return in_array( $capability, self::all(), true );
	}

	/**
	 * Check whether a role slug is forbidden from holding WPIG administrative capabilities.
	 *
	 * @param string $role_slug Role identifier.
	 */
	public static function is_disallowed_role( string $role_slug ): bool {
		$normalized = strtolower( trim( $role_slug ) );
		if ( '' === $normalized ) {
			return true;
		}

		return in_array( $normalized, self::DISALLOWED_ROLES, true );
	}

	/**
	 * Idempotently register WPIG capabilities on the current site and sanitize disallowed roles.
	 *
	 * Safe to call repeatedly during plugin activation, reactivation, and version upgrades.
	 * Preserves capabilities granted to custom roles while ensuring `administrator` holds
	 * all WPIG capabilities and disallowed roles (`subscriber`, `customer`, etc.) hold none.
	 *
	 * @param WP_Roles|object|null $roles_provider Optional roles container override for unit testing.
	 * @return bool True if capabilities were synchronized on a valid roles provider.
	 */
	public static function register_for_current_site( ?object $roles_provider = null ): bool {
		$roles = $roles_provider ?? ( function_exists( 'wp_roles' ) ? wp_roles() : null );
		if ( null === $roles || ! method_exists( $roles, 'get_role' ) ) {
			return false;
		}

		// 1. Grant all WPIG capabilities idempotently to the site administrator role.
		$admin_role = $roles->get_role( self::ROLE_ADMINISTRATOR );
		if ( is_object( $admin_role ) && method_exists( $admin_role, 'add_cap' ) ) {
			foreach ( self::all() as $cap ) {
				if ( ! self::role_has_cap( $admin_role, $cap ) ) {
					$admin_role->add_cap( $cap, true );
				}
			}
		}

		// 2. Enforce least privilege: strip any WPIG capabilities from disallowed unprivileged roles.
		foreach ( self::DISALLOWED_ROLES as $disallowed_slug ) {
			$disallowed_role = $roles->get_role( $disallowed_slug );
			if ( ! is_object( $disallowed_role ) || ! method_exists( $disallowed_role, 'remove_cap' ) ) {
				continue;
			}
			foreach ( self::all() as $cap ) {
				if ( self::role_has_cap( $disallowed_role, $cap ) ) {
					$disallowed_role->remove_cap( $cap );
				}
			}
		}

		if ( null === $roles_provider && function_exists( 'get_option' ) && function_exists( 'update_option' ) && function_exists( 'add_option' ) ) {
			if ( false === get_option( self::VERSION_OPTION, false ) ) {
				add_option( self::VERSION_OPTION, self::VERSION, '', false );
			} else {
				update_option( self::VERSION_OPTION, self::VERSION, false );
			}
		}

		return true;
	}

	/**
	 * Ensure capabilities are registered on the current site if the capability version option is missing or outdated.
	 *
	 * @param WP_Roles|object|null $roles_provider Optional roles container override.
	 */
	public static function ensure_registered( ?object $roles_provider = null ): void {
		if ( null === $roles_provider && function_exists( 'get_option' ) ) {
			$installed = get_option( self::VERSION_OPTION, false );
			if ( self::VERSION === $installed ) {
				return;
			}
		}

		self::register_for_current_site( $roles_provider );
	}

	/**
	 * Grant a specific subset of WPIG capabilities to an authorized custom role on the current site.
	 *
	 * Fails closed if the target role is in `DISALLOWED_ROLES` (`subscriber`, `customer`, etc.),
	 * if the role does not exist on the current site, or if any capability is not a valid WPIG capability.
	 *
	 * @param string               $role_slug      Target role slug (e.g. 'wpig_compliance_reviewer').
	 * @param string[]             $capabilities   WPIG capabilities to grant.
	 * @param WP_Roles|object|null $roles_provider Optional roles container override for unit testing.
	 * @phpstan-param list<string> $capabilities
	 * @throws AuthorizationException If the role is disallowed, missing, or capabilities are invalid.
	 */
	public static function grant_to_role(
		string $role_slug,
		array $capabilities,
		?object $roles_provider = null
	): void {
		$normalized_role = strtolower( trim( $role_slug ) );
		if ( self::is_disallowed_role( $normalized_role ) ) {
			AuthorizationException::raise(
				AuthorizationException::CODE_INVALID_ROLE_ASSIGNMENT,
				'Cannot grant WP Identity Guard administrative capabilities to an unprivileged or disallowed role.'
			);
		}

		if ( array() === $capabilities ) {
			AuthorizationException::raise(
				AuthorizationException::CODE_INVALID_ROLE_ASSIGNMENT,
				'At least one valid WP Identity Guard capability must be specified.'
			);
		}

		foreach ( $capabilities as $cap ) {
			if ( ! self::is_valid_capability( $cap ) ) {
				AuthorizationException::raise(
					AuthorizationException::CODE_INVALID_ROLE_ASSIGNMENT,
					'Invalid or unrecognized WP Identity Guard capability specified.'
				);
			}
		}

		$roles = $roles_provider ?? ( function_exists( 'wp_roles' ) ? wp_roles() : null );
		if ( null === $roles || ! method_exists( $roles, 'get_role' ) ) {
			AuthorizationException::raise(
				AuthorizationException::CODE_INVALID_ROLE_ASSIGNMENT,
				'WordPress roles API is unavailable.'
			);
		}

		$role = $roles->get_role( $normalized_role );
		if ( ! is_object( $role ) || ! method_exists( $role, 'add_cap' ) ) {
			AuthorizationException::raise(
				AuthorizationException::CODE_INVALID_ROLE_ASSIGNMENT,
				'Target WordPress role does not exist on the current site.'
			);
		}

		foreach ( array_unique( $capabilities ) as $cap ) {
			if ( ! self::role_has_cap( $role, $cap ) ) {
				$role->add_cap( $cap, true );
			}
		}
	}

	/**
	 * Revoke WPIG capabilities from a custom role on the current site.
	 *
	 * Never revokes capabilities from the primary `administrator` role to preserve
	 * legitimate administrator access.
	 *
	 * @param string               $role_slug      Target custom role slug.
	 * @param list<string>|null    $capabilities   Capabilities to revoke (defaults to all WPIG capabilities).
	 * @param WP_Roles|object|null $roles_provider Optional roles container override.
	 * @throws AuthorizationException If attempting to strip capabilities from `administrator`.
	 */
	public static function revoke_from_role(
		string $role_slug,
		?array $capabilities = null,
		?object $roles_provider = null
	): void {
		$normalized_role = strtolower( trim( $role_slug ) );
		if ( self::ROLE_ADMINISTRATOR === $normalized_role ) {
			AuthorizationException::raise(
				AuthorizationException::CODE_INVALID_ROLE_ASSIGNMENT,
				'Cannot revoke WP Identity Guard capabilities from the primary administrator role.'
			);
		}

		$caps_to_remove = $capabilities ?? self::all();
		foreach ( $caps_to_remove as $cap ) {
			if ( ! self::is_valid_capability( $cap ) ) {
				AuthorizationException::raise(
					AuthorizationException::CODE_INVALID_ROLE_ASSIGNMENT,
					'Invalid capability specified for revocation.'
				);
			}
		}

		$roles = $roles_provider ?? ( function_exists( 'wp_roles' ) ? wp_roles() : null );
		if ( null === $roles || ! method_exists( $roles, 'get_role' ) ) {
			return;
		}

		$role = $roles->get_role( $normalized_role );
		if ( ! is_object( $role ) || ! method_exists( $role, 'remove_cap' ) ) {
			return;
		}

		foreach ( array_unique( $caps_to_remove ) as $cap ) {
			if ( self::role_has_cap( $role, $cap ) ) {
				$role->remove_cap( $cap );
			}
		}
	}

	/**
	 * Check whether a `WP_Role` or role stub already holds a capability with value `true`.
	 *
	 * @param WP_Role|object $role Role object.
	 * @param string         $cap  Capability name.
	 */
	private static function role_has_cap( object $role, string $cap ): bool {
		if ( isset( $role->capabilities ) && is_array( $role->capabilities ) ) {
			return isset( $role->capabilities[ $cap ] ) && true === $role->capabilities[ $cap ];
		}
		if ( method_exists( $role, 'has_cap' ) ) {
			return (bool) $role->has_cap( $cap );
		}
		return false;
	}
}

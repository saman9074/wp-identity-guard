<?php
/**
 * Plugin deactivation handler.
 *
 * @package WPIG\Core
 */

declare(strict_types=1);

namespace WPIG\Core;

/**
 * Handles WP Identity Guard deactivation.
 *
 * Per approved decision D15 (docs/p00/decision-status.md), deactivation must
 * preserve all database tables, identity bindings, verification logs, audit
 * events, and plugin options.
 */
final class Deactivator {

	/**
	 * WordPress register_deactivation_hook callback.
	 *
	 * @param bool $network_wide Whether deactivated network-wide on Multisite.
	 */
	public static function deactivate( bool $network_wide = false ): void {
		unset( $network_wide );

		if ( ! function_exists( 'get_option' ) ) {
			return;
		}

		$existing = get_option( Activator::STATUS_OPTION, false );
		$payload  = is_array( $existing ) ? $existing : array();

		$payload['lifecycle']  = 'deactivated';
		$payload['updated_at'] = gmdate( 'Y-m-d H:i:s' );

		if ( false === $existing ) {
			add_option( Activator::STATUS_OPTION, $payload, '', false );
			return;
		}
		update_option( Activator::STATUS_OPTION, $payload, false );
	}
}

<?php
/**
 * Plugin Name:       WP Identity Guard
 * Plugin URI:        https://github.com/saman9074/wp-identity-guard
 * Description:       Privacy-conscious identity and bank-card ownership verification foundation for WordPress. Early development preview (v0.1.0-alpha.1): identity verification providers, OTP delivery, and bank card ownership verification are not yet implemented. Not a payment gateway.
 * Version:           0.1.0-alpha.1
 * Author:            ArcaneTeam
 * Author URI:        https://github.com/saman9074
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wp-identity-guard
 * Domain Path:       /languages
 * Requires at least: 6.9
 * Requires PHP:      8.3
 * WC requires at least: 10.8
 *
 * Note: WooCommerce is an optional integration only and never a hard dependency.
 *
 * Copyright (C) 2026 ArcaneTeam and contributors.
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 2 of the License, or (at your option)
 * any later version.
 *
 * @package WPIG
 */

defined( 'ABSPATH' ) || exit;

define( 'WPIG_VERSION', '0.1.0-alpha.1' );
define( 'WPIG_PLUGIN_FILE', __FILE__ );
define( 'WPIG_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );

/*
 * Minimal PSR-4 autoloader for the WPIG\ namespace. The Free plugin has no
 * runtime Composer dependencies, so release builds need no vendor/ directory.
 * Class names are PHP identifiers (no path separators beyond "\\"), and the
 * resolved path is confined to src/.
 */
spl_autoload_register(
	static function ( $class_name ) {
		$prefix = 'WPIG\\';
		if ( 0 !== strncmp( $class_name, $prefix, strlen( $prefix ) ) ) {
			return;
		}
		$relative = substr( $class_name, strlen( $prefix ) );
		if ( ! preg_match( '/^[A-Za-z_][A-Za-z0-9_]*(\\\\[A-Za-z_][A-Za-z0-9_]*)*$/', $relative ) ) {
			return;
		}
		$file = WPIG_PLUGIN_DIR . 'src/' . str_replace( '\\', '/', $relative ) . '.php';
		if ( is_readable( $file ) ) {
			require_once $file;
		}
	}
);

register_activation_hook( WPIG_PLUGIN_FILE, array( \WPIG\Core\Activator::class, 'activate' ) );
register_deactivation_hook( WPIG_PLUGIN_FILE, array( \WPIG\Core\Deactivator::class, 'deactivate' ) );

add_action( 'plugins_loaded', array( \WPIG\Plugin::class, 'boot' ) );

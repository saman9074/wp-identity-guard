<?php
/**
 * PHPUnit bootstrap.
 *
 * Unit tests run without WordPress. The WordPress integration bootstrap
 * (WP_TESTS_DIR / wp-phpunit) is selected and wired in P01.
 *
 * @package WPIG\Tests
 */

declare(strict_types=1);

$wpig_autoload = dirname( __DIR__ ) . '/vendor/autoload.php';
if ( ! is_readable( $wpig_autoload ) ) {
	// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- CLI test bootstrap runs before WordPress.
	fwrite( STDERR, "Run `composer install` (approved dev dependencies) before running tests.\n" );
	exit( 1 );
}
require_once $wpig_autoload;

if ( '1' === getenv( 'WPIG_INTEGRATION_BOOTSTRAP' ) ) {
	$wpig_wp_load = getenv( 'WPIG_WP_LOAD_PATH' );
	if ( ! is_string( $wpig_wp_load ) || '' === $wpig_wp_load ) {
		$wpig_wp_load = '/var/www/html/wp-load.php';
	}
	if ( ! is_readable( $wpig_wp_load ) ) {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- CLI test bootstrap.
		fwrite( STDERR, "Integration bootstrap requires a readable WordPress wp-load.php at {$wpig_wp_load}.\n" );
		exit( 1 );
	}
	require_once $wpig_wp_load;
	require_once ABSPATH . 'wp-admin/includes/plugin.php';
	require_once dirname( __DIR__ ) . '/wp-identity-guard.php';
} else {
	if ( ! isset( $GLOBALS['wp_version'] ) ) {
		// Default floor stub for pure unit tests running outside WordPress.
		// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- Intentional test stub when WP is not loaded.
		$GLOBALS['wp_version'] = '6.9.0';
	}
	if ( ! function_exists( 'esc_html' ) ) {
		/**
		 * Pure unit-test stub for WordPress esc_html().
		 *
		 * @param string $text Raw text.
		 */
		function esc_html( string $text ): string { // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound -- Pure unit-test stub when WordPress is not loaded.
			return htmlspecialchars( $text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8' );
		}
	}
	if ( ! function_exists( 'esc_attr' ) ) {
		/**
		 * Pure unit-test stub for WordPress esc_attr().
		 *
		 * @param string $text Raw attribute text.
		 */
		function esc_attr( string $text ): string { // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedFunctionFound -- Pure unit-test stub when WordPress is not loaded.
			return htmlspecialchars( $text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8' );
		}
	}
	if ( ! defined( 'ARRAY_A' ) ) {
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- Pure unit-test stub for WordPress wpdb constant.
		define( 'ARRAY_A', 'ARRAY_A' );
	}
	require_once __DIR__ . '/Unit/WpdbStub.php';
}

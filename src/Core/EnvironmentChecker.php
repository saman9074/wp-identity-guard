<?php
/**
 * Runtime environment requirement checker (D02 support floors).
 *
 * @package WPIG\Core
 */

declare(strict_types=1);

namespace WPIG\Core;

/**
 * Verifies minimum PHP version, required PHP extensions, and minimum WordPress
 * version before plugin activation or migration runs.
 */
final class EnvironmentChecker {

	/**
	 * Minimum supported PHP version (D02).
	 */
	public const MIN_PHP_VERSION = '8.3.0';

	/**
	 * Minimum supported WordPress version (D02).
	 */
	public const MIN_WP_VERSION = '6.9';

	/**
	 * Required PHP runtime extensions.
	 *
	 * @var list<string>
	 */
	public const REQUIRED_EXTENSIONS = array(
		'json',
		'mbstring',
		'sodium',
	);

	/**
	 * Check environment compatibility and return any unmet requirement messages.
	 *
	 * @param string|null   $php_version Optional PHP version override for testing.
	 * @param string|null   $wp_version  Optional WP version override for testing.
	 * @param callable|null $ext_loaded  Optional extension check callback for testing.
	 * @phpstan-param (callable(string):bool)|null $ext_loaded
	 * @return string[] Empty array when compatible; list of safe error strings otherwise.
	 * @phpstan-return list<string>
	 */
	public static function check(
		?string $php_version = null,
		?string $wp_version = null,
		?callable $ext_loaded = null
	): array {
		$errors      = array();
		$runtime_php = $php_version ?? PHP_VERSION;
		$runtime_wp  = $wp_version ?? self::detect_wp_version();
		$checker     = $ext_loaded ?? 'extension_loaded';

		if ( version_compare( $runtime_php, self::MIN_PHP_VERSION, '<' ) ) {
			$errors[] = sprintf(
				'WP Identity Guard requires PHP >= %s (current: %s).',
				self::MIN_PHP_VERSION,
				$runtime_php
			);
		}

		foreach ( self::REQUIRED_EXTENSIONS as $ext ) {
			if ( ! (bool) $checker( $ext ) ) {
				$errors[] = sprintf(
					'WP Identity Guard requires the PHP ext-%s extension.',
					$ext
				);
			}
		}

		if ( '' === $runtime_wp || version_compare( $runtime_wp, self::MIN_WP_VERSION, '<' ) ) {
			$errors[] = sprintf(
				'WP Identity Guard requires WordPress >= %s (current: %s).',
				self::MIN_WP_VERSION,
				'' !== $runtime_wp ? $runtime_wp : 'unknown'
			);
		}

		return $errors;
	}

	/**
	 * Return true if all runtime environment requirements are met.
	 *
	 * @param string|null   $php_version Optional PHP version override for testing.
	 * @param string|null   $wp_version  Optional WP version override for testing.
	 * @param callable|null $ext_loaded  Optional extension check callback for testing.
	 * @phpstan-param (callable(string):bool)|null $ext_loaded
	 */
	public static function is_supported(
		?string $php_version = null,
		?string $wp_version = null,
		?callable $ext_loaded = null
	): bool {
		return array() === self::check( $php_version, $wp_version, $ext_loaded );
	}

	/**
	 * Detect the current WordPress version safely.
	 */
	private static function detect_wp_version(): string {
		if ( function_exists( 'get_bloginfo' ) ) {
			$ver = get_bloginfo( 'version' );
			if ( '' !== $ver ) {
				return $ver;
			}
		}

		if ( isset( $GLOBALS['wp_version'] ) && is_string( $GLOBALS['wp_version'] ) ) {
			return $GLOBALS['wp_version'];
		}

		return '';
	}
}

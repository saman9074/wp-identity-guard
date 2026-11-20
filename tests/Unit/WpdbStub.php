<?php
/**
 * Minimal pure unit-test stub for WordPress `wpdb` when WordPress is not loaded.
 *
 * @package WPIG\Tests\Unit
 */

declare(strict_types=1);

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedClassFound, PEAR.NamingConventions.ValidClassName.StartWithCapital -- Pure unit-test stub for WordPress core wpdb class.
if ( ! class_exists( 'wpdb' ) ) {
	/**
	 * Minimal pure unit-test base class for WordPress `wpdb` when running without WordPress.
	 */
	class wpdb {
		/**
		 * Table prefix.
		 *
		 * @var string
		 */
		public $prefix = 'wp_';

		/**
		 * Last auto-increment insert ID.
		 *
		 * @var int
		 */
		public $insert_id = 0;

		/**
		 * Suppress database errors.
		 *
		 * @param bool $suppress Whether to suppress errors.
		 */
		public function suppress_errors( $suppress = true ) {
			return (bool) $suppress;
		}

		/**
		 * Prepare a SQL query with placeholders.
		 *
		 * @param string $query   Query with %s / %d placeholders.
		 * @param mixed  ...$args Values to substitute.
		 * @return string
		 */
		public function prepare( $query, ...$args ) {
			if ( 1 === count( $args ) && is_array( $args[0] ) ) {
				$args = $args[0];
			}
			$index = 0;
			return (string) preg_replace_callback(
				'/%(?:d|s)/',
				static function ( array $matches ) use ( $args, &$index ): string {
					$val = $args[ $index ] ?? '';
					++$index;
					if ( '%d' === $matches[0] ) {
						return (string) (int) $val;
					}
					return "'" . addslashes( (string) $val ) . "'";
				},
				(string) $query
			);
		}

		/**
		 * Execute a database query.
		 *
		 * @param string $query SQL query.
		 * @return int|bool
		 */
		public function query( $query ) {
			unset( $query );
			return 1;
		}

		/**
		 * Fetch a single row.
		 *
		 * @param string|null $query  SQL query.
		 * @param string      $output Output format.
		 * @param int         $y      Row offset.
		 * @return array<string,mixed>|object|null
		 */
		public function get_row( $query = null, $output = ARRAY_A, $y = 0 ) {
			unset( $query, $output, $y );
			return null;
		}

		/**
		 * Fetch multiple rows.
		 *
		 * @param string|null $query  SQL query.
		 * @param string      $output Output format.
		 * @return array<int,mixed>
		 */
		public function get_results( $query = null, $output = ARRAY_A ) {
			unset( $query, $output );
			return array();
		}

		/**
		 * Fetch a single scalar value.
		 *
		 * @param string|null $query SQL query.
		 * @param int         $x     Column offset.
		 * @param int         $y     Row offset.
		 * @return string|null
		 */
		public function get_var( $query = null, $x = 0, $y = 0 ) {
			unset( $query, $x, $y );
			return null;
		}
	}
}

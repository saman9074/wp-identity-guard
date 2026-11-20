<?php
/**
 * Smoke test for the P01-A unit test harness and Plugin composition root.
 *
 * @package WPIG\Tests\Unit
 */

declare(strict_types=1);

namespace WPIG\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPIG\Plugin;

/**
 * Verifies the unit test harness and Plugin::boot() idempotency without WordPress.
 */
final class PluginBootTest extends TestCase {

	/**
	 * Ensure Plugin::boot() marks the plugin as booted, is idempotent, and creates AdminController once.
	 */
	public function test_boot_is_idempotent(): void {
		Plugin::reset_for_testing();
		self::assertFalse( Plugin::is_booted() );
		self::assertNull( Plugin::get_admin_controller() );

		Plugin::boot();
		self::assertTrue( Plugin::is_booted() );
		$first_controller = Plugin::get_admin_controller();
		self::assertNotNull( $first_controller );

		Plugin::boot();
		self::assertTrue( Plugin::is_booted() );
		self::assertSame( $first_controller, Plugin::get_admin_controller() );

		// When $GLOBALS['wpdb'] is not initialized in unit mode, lazy privacy filter callbacks return array unchanged.
		self::assertSame( array(), Plugin::register_privacy_exporter( array() ) );
		self::assertSame( array(), Plugin::register_privacy_eraser( array() ) );
	}
}

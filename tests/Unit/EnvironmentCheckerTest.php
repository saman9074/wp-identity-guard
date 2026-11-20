<?php
/**
 * Unit tests for EnvironmentChecker (D02 support floors).
 *
 * @package WPIG\Tests\Unit
 */

declare(strict_types=1);

namespace WPIG\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPIG\Core\EnvironmentChecker;

/**
 * Verifies PHP, WordPress, and required extension checks.
 */
final class EnvironmentCheckerTest extends TestCase {

	/**
	 * Supported environment passes with zero errors.
	 */
	public function test_supported_environment_passes(): void {
		$errors = EnvironmentChecker::check(
			'8.3.0',
			'6.9.0',
			static fn( string $ext ): bool => '' !== $ext
		);
		self::assertSame( array(), $errors );
		self::assertTrue(
			EnvironmentChecker::is_supported(
				'8.4.2',
				'7.0.2',
				static fn( string $ext ): bool => '' !== $ext
			)
		);
	}

	/**
	 * Unsupported PHP or WordPress versions or missing extensions are reported cleanly.
	 */
	public function test_unsupported_versions_and_extensions_fail_closed(): void {
		$errors = EnvironmentChecker::check(
			'8.2.99',
			'6.8.2',
			static fn( string $ext ): bool => 'sodium' !== $ext
		);

		self::assertCount( 3, $errors );
		self::assertStringContainsString( 'PHP >= 8.3.0', $errors[0] );
		self::assertStringContainsString( 'ext-sodium', $errors[1] );
		self::assertStringContainsString( 'WordPress >= 6.9', $errors[2] );
	}
}

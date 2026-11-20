<?php
/**
 * Reproducible release ZIP builder and verifier for WP Identity Guard (Free).
 *
 * Packages only production runtime files into `build/wp-identity-guard-v<version>.zip`
 * under the top-level `wp-identity-guard/` plugin directory, strictly honoring
 * `.distignore` rules and verifying that zero dev/test/secret/pack files are included.
 *
 * Usage: php tools/build-release-zip.php [<output-zip-path>]
 *
 * @package WPIG\Tools
 */

declare(strict_types=1);

if ( PHP_SAPI !== 'cli' ) {
	exit( 2 );
}

if ( ! class_exists( 'ZipArchive' ) ) {
	fwrite( STDERR, "Error: PHP ZipArchive extension is required to build the distribution ZIP.\n" );
	exit( 1 );
}

$root_dir    = dirname( __DIR__ );
$plugin_file = $root_dir . '/wp-identity-guard.php';

if ( ! is_readable( $plugin_file ) ) {
	fwrite( STDERR, "Error: Cannot locate wp-identity-guard.php in repository root.\n" );
	exit( 1 );
}

$plugin_contents = (string) file_get_contents( $plugin_file );
$header_version  = null;
$const_version   = null;

if ( preg_match( '/^\s*\*\s*Version:\s*([0-9A-Za-z._-]+)\s*$/m', $plugin_contents, $m ) ) {
	$header_version = $m[1];
}
if ( preg_match( "/define\(\s*'WPIG_VERSION'\s*,\s*'([0-9A-Za-z._-]+)'\s*\)/", $plugin_contents, $m ) ) {
	$const_version = $m[1];
}

if ( null === $header_version || null === $const_version || $header_version !== $const_version ) {
	fwrite(
		STDERR,
		sprintf(
			"Error: Version mismatch in wp-identity-guard.php (Header: %s, WPIG_VERSION: %s).\n",
			(string) $header_version,
			(string) $const_version
		)
	);
	exit( 1 );
}

$version     = $header_version;
$default_out = $root_dir . '/build/wp-identity-guard-v' . $version . '.zip';
$output_zip  = isset( $argv[1] ) && '' !== trim( $argv[1] ) ? trim( $argv[1] ) : $default_out;
$output_dir  = dirname( $output_zip );

if ( ! is_dir( $output_dir ) && ! mkdir( $output_dir, 0755, true ) && ! is_dir( $output_dir ) ) {
	fwrite( STDERR, "Error: Unable to create output directory {$output_dir}.\n" );
	exit( 1 );
}

// Allowed runtime paths inside the WordPress plugin package.
$allowed_files = array(
	'wp-identity-guard.php',
	'uninstall.php',
	'LICENSE',
	'README.md',
	'CHANGELOG.md',
	'SECURITY.md',
);

$src_iterator = new RecursiveIteratorIterator(
	new RecursiveDirectoryIterator( $root_dir . '/src', FilesystemIterator::SKIP_DOTS )
);

foreach ( $src_iterator as $file_info ) {
	if ( ! $file_info instanceof SplFileInfo || ! $file_info->isFile() ) {
		continue;
	}
	if ( '.gitkeep' === $file_info->getFilename() ) {
		continue;
	}
	if ( 'php' !== strtolower( $file_info->getExtension() ) ) {
		continue;
	}
	$rel_path        = substr( $file_info->getPathname(), strlen( $root_dir ) + 1 );
	$allowed_files[] = str_replace( '\\', '/', $rel_path );
}

sort( $allowed_files );

if ( file_exists( $output_zip ) ) {
	unlink( $output_zip );
}

$zip = new ZipArchive();
if ( true !== $zip->open( $output_zip, ZipArchive::CREATE | ZipArchive::OVERWRITE ) ) {
	fwrite( STDERR, "Error: Failed to open {$output_zip} for writing.\n" );
	exit( 1 );
}

$plugin_slug = 'wp-identity-guard';

// Ensure assets/ and languages/ directories exist in the package structure.
$zip->addEmptyDir( $plugin_slug . '/assets' );
$zip->addEmptyDir( $plugin_slug . '/assets/css' );
$zip->addEmptyDir( $plugin_slug . '/assets/js' );
$zip->addEmptyDir( $plugin_slug . '/languages' );

foreach ( $allowed_files as $rel_path ) {
	$abs_path = $root_dir . '/' . $rel_path;
	if ( ! is_file( $abs_path ) || ! is_readable( $abs_path ) ) {
		fwrite( STDERR, "Error: Missing required runtime file {$rel_path}.\n" );
		$zip->close();
		exit( 1 );
	}
	$entry_name = $plugin_slug . '/' . $rel_path;
	if ( ! $zip->addFile( $abs_path, $entry_name ) ) {
		fwrite( STDERR, "Error: Failed to add {$entry_name} to archive.\n" );
		$zip->close();
		exit( 1 );
	}
}

$zip->close();

// Verify the generated archive contents against strict exclusion invariants.
$verify_zip = new ZipArchive();
if ( true !== $verify_zip->open( $output_zip ) ) {
	fwrite( STDERR, "Error: Failed to reopen generated archive {$output_zip} for verification.\n" );
	exit( 1 );
}

$forbidden_fragments = array(
	'/vendor/',
	'/tests/',
	'/tools/',
	'/docs/',
	'/.git',
	'/.env',
	'docker-compose',
	'phpunit.xml',
	'phpstan.neon',
	'phpcs.xml',
	'composer.json',
	'composer.lock',
	'.gitkeep',
);

$entry_count = $verify_zip->numFiles;
$entries     = array();
for ( $i = 0; $i < $entry_count; $i++ ) {
	$name = (string) $verify_zip->getNameIndex( $i );
	$entries[] = $name;

	if ( 0 !== strpos( $name, $plugin_slug . '/' ) ) {
		fwrite( STDERR, "Error: Archive entry {$name} is outside top-level {$plugin_slug}/ directory.\n" );
		$verify_zip->close();
		exit( 1 );
	}

	foreach ( $forbidden_fragments as $frag ) {
		if ( false !== strpos( $name, $frag ) ) {
			fwrite( STDERR, "Error: Forbidden path fragment '{$frag}' found in archive entry {$name}.\n" );
			$verify_zip->close();
			exit( 1 );
		}
	}
}
$verify_zip->close();

$sha256 = (string) hash_file( 'sha256', $output_zip );
$size   = (int) filesize( $output_zip );

echo sprintf(
	"Built and verified %s\n  Version: %s\n  Entries: %d (%d files)\n  Size:    %d bytes\n  SHA-256: %s\n",
	$output_zip,
	$version,
	$entry_count,
	count( $allowed_files ),
	$size,
	$sha256
);

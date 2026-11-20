<?php
/**
 * Offline sensitive-data scanner for tracked files (development tool only).
 *
 * Detects likely secrets and Iranian PII patterns so they never enter Git,
 * fixtures or release artifacts. Matches are printed MASKED; full values are
 * never echoed. This is a heuristic safety net, not a replacement for a
 * dedicated secret scanner or human review.
 *
 * Usage: php tools/sensitive-scan.php [--allow-path=<prefix>]... [<file> ...]
 *        (without files, scans `git ls-files` output)
 * Exit codes: 0 = no findings outside allowed paths, 1 = findings, 2 = usage error.
 *
 * @package WPIG\Tools
 */

declare(strict_types=1);

if ( PHP_SAPI !== 'cli' ) {
	exit( 2 );
}

/**
 * Luhn checksum (bank card PAN candidates).
 */
function wpig_scan_luhn( string $digits ): bool {
	$sum = 0;
	$alt = false;
	for ( $i = strlen( $digits ) - 1; $i >= 0; $i-- ) {
		$n = (int) $digits[ $i ];
		if ( $alt ) {
			$n *= 2;
			if ( $n > 9 ) {
				$n -= 9;
			}
		}
		$sum += $n;
		$alt  = ! $alt;
	}
	return 0 === $sum % 10;
}

/**
 * Iranian national code (code melli) checksum.
 */
function wpig_scan_national_code( string $d ): bool {
	if ( 10 !== strlen( $d ) || preg_match( '/^(\d)\1{9}$/', $d ) ) {
		return false;
	}
	$sum = 0;
	for ( $i = 0; $i < 9; $i++ ) {
		$sum += (int) $d[ $i ] * ( 10 - $i );
	}
	$r     = $sum % 11;
	$check = (int) $d[9];
	return ( $r < 2 && $check === $r ) || ( $r >= 2 && $check === 11 - $r );
}

function wpig_scan_mask( string $v ): string {
	$len = strlen( $v );
	return $len <= 4 ? str_repeat( '*', $len ) : substr( $v, 0, 2 ) . str_repeat( '*', $len - 4 ) . substr( $v, -2 );
}

/**
 * Normalize Persian/Arabic-Indic digits to ASCII.
 */
function wpig_scan_ascii_digits( string $s ): string {
	return strtr(
		$s,
		array(
			'۰' => '0', '۱' => '1', '۲' => '2', '۳' => '3', '۴' => '4', '۵' => '5', '۶' => '6', '۷' => '7', '۸' => '8', '۹' => '9',
			'٠' => '0', '١' => '1', '٢' => '2', '٣' => '3', '٤' => '4', '٥' => '5', '٦' => '6', '٧' => '7', '٨' => '8', '٩' => '9',
		)
	);
}

$args    = array_slice( $argv, 1 );
$allowed = array();
$files   = array();
foreach ( $args as $arg ) {
	if ( 0 === strpos( $arg, '--allow-path=' ) ) {
		$allowed[] = substr( $arg, 13 );
	} else {
		$files[] = $arg;
	}
}
if ( array() === $files ) {
	$out = array();
	exec( 'git ls-files -z --cached --others --exclude-standard', $out, $code );
	if ( 0 !== $code ) {
		fwrite( STDERR, "git ls-files failed; pass files explicitly.\n" );
		exit( 2 );
	}
	$files = array_values( array_filter( explode( "\0", implode( "\n", $out ) ) ) );
}

$secret_patterns = array(
	'PRIVATE_KEY'   => '/-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/',
	'AWS_KEY'       => '/\bAKIA[0-9A-Z]{16}\b/',
	'GITHUB_TOKEN'  => '/\bgh[pousr]_[A-Za-z0-9]{36,}\b/',
	'JWT'           => '/\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/',
	'BEARER_LITERAL'=> '/\bBearer\s+(?!12345abcdef\b)[A-Za-z0-9._~+\/-]{24,}=*/',
	'GENERIC_SECRET'=> '/(?i)\b(?:api[_-]?key|secret|access[_-]?token|password)\b["\']?\s*[:=]\s*["\'][A-Za-z0-9._~+\/-]{16,}["\']/',
);

$findings = 0;
$allowed_hits = 0;
foreach ( $files as $file ) {
	if ( ! is_file( $file ) || filesize( $file ) > 5 * 1024 * 1024 ) {
		continue;
	}
	$raw = (string) file_get_contents( $file );
	if ( false !== strpos( substr( $raw, 0, 8000 ), "\0" ) ) {
		continue; // Binary.
	}
	$is_allowed = false;
	foreach ( $allowed as $prefix ) {
		if ( 0 === strpos( $file, $prefix ) ) {
			$is_allowed = true;
		}
	}
	$text  = wpig_scan_ascii_digits( $raw );
	$lines = explode( "\n", $text );
	$hits  = array();
	foreach ( $lines as $no => $line ) {
		foreach ( $secret_patterns as $kind => $re ) {
			if ( preg_match( $re, $line, $m ) ) {
				$hits[] = sprintf( '%s:%d %s %s', $file, $no + 1, $kind, wpig_scan_mask( $m[0] ) );
			}
		}
		// Alphanumeric boundaries avoid false positives inside hashes/hex/UUIDs.
		if ( preg_match_all( '/(?<![0-9A-Za-z.])(\d{16})(?![0-9A-Za-z.])/', $line, $m ) ) {
			foreach ( $m[1] as $pan ) {
				if ( wpig_scan_luhn( $pan ) && ! preg_match( '/^(\d)\1{15}$/', $pan ) ) {
					$hits[] = sprintf( '%s:%d CARD_PAN_LUHN %s', $file, $no + 1, wpig_scan_mask( $pan ) );
				}
			}
		}
		if ( preg_match_all( '/(?<![0-9A-Za-z.])(\d{10})(?![0-9A-Za-z.])/', $line, $m ) ) {
			foreach ( $m[1] as $nid ) {
				if ( wpig_scan_national_code( $nid ) ) {
					$hits[] = sprintf( '%s:%d NATIONAL_CODE_CHECKSUM %s', $file, $no + 1, wpig_scan_mask( $nid ) );
				}
			}
		}
		if ( preg_match_all( '/(?<!\d)(?:\+98|0098|98|0)(9\d{9})(?!\d)/', $line, $m ) ) {
			foreach ( $m[1] as $mob ) {
				$hits[] = sprintf( '%s:%d IR_MOBILE %s', $file, $no + 1, wpig_scan_mask( '0' . $mob ) );
			}
		}
	}
	foreach ( $hits as $hit ) {
		echo ( $is_allowed ? '[allowed] ' : '[FINDING] ' ), $hit, "\n";
	}
	if ( $is_allowed ) {
		$allowed_hits += count( $hits );
	} else {
		$findings += count( $hits );
	}
}
echo sprintf( "Scanned %d file(s): %d finding(s), %d in allowed paths.\n", count( $files ), $findings, $allowed_hits );
exit( $findings > 0 ? 1 : 0 );

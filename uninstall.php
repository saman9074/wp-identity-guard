<?php
/**
 * Plugin uninstall handler.
 *
 * Per approved owner decision D15 (docs/p00/decision-status.md) and P01-B2
 * scope constraints:
 * - Default `erase_on_uninstall` is `false`.
 * - Uninstall preserves all verification tables, identity bindings, audit
 *   records, and schema metadata by default.
 * - Destructive data erasure is intentionally not executed in P01-B2.
 *
 * @package WPIG
 */

declare(strict_types=1);

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

// D15: Preserve all tables and records on uninstall by default.
// Destructive purge requires explicit admin opt-in, legal-hold checks, and
// audit logging implemented in a later phase.

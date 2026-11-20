<?php
/**
 * Operational readiness status constants and aggregation model.
 *
 * @package WPIG\Admin
 */

declare(strict_types=1);

namespace WPIG\Admin;

/**
 * Defines canonical operational readiness states for WP Identity Guard (Task 7).
 *
 * States:
 * - `READY`: Component meets all runtime and security requirements for its scope.
 * - `ACTION_REQUIRED`: Administrator configuration or compliance prerequisite is pending.
 * - `BLOCKED`: Critical dependency, key, schema, or transport requirement is missing or unsafe.
 * - `NOT_IMPLEMENTED`: Feature or provider integration is reserved for a later phase.
 *
 * Invariant: Overall production identity verification readiness can NEVER be `READY` in P01-D2
 * because live verification workflows and provider adapters (`API.ir`, `Zohal`) are not yet implemented.
 */
final class ReadinessStatus {

	/**
	 * Component is healthy and ready within its current architectural scope.
	 */
	public const READY = 'READY';

	/**
	 * Administrator action or compliance configuration is required.
	 */
	public const ACTION_REQUIRED = 'ACTION_REQUIRED';

	/**
	 * Critical security, schema, key, or runtime dependency is missing or blocked.
	 */
	public const BLOCKED = 'BLOCKED';

	/**
	 * Feature or provider adapter is not implemented in this phase.
	 */
	public const NOT_IMPLEMENTED = 'NOT_IMPLEMENTED';

	/**
	 * Return all valid readiness status codes.
	 *
	 * @return list<string>
	 */
	public static function all(): array {
		return array(
			self::READY,
			self::ACTION_REQUIRED,
			self::BLOCKED,
			self::NOT_IMPLEMENTED,
		);
	}

	/**
	 * Check whether a status string is a valid readiness constant.
	 *
	 * @param string $status Candidate status code.
	 */
	public static function is_valid( string $status ): bool {
		return in_array( $status, self::all(), true );
	}

	/**
	 * Return a human-readable, internationalized label for a readiness status code.
	 *
	 * @param string $status Readiness status code.
	 */
	public static function label( string $status ): string {
		if ( function_exists( '__' ) ) {
			return match ( $status ) {
				self::READY           => (string) __( 'Ready', 'wp-identity-guard' ),
				self::ACTION_REQUIRED => (string) __( 'Action Required', 'wp-identity-guard' ),
				self::BLOCKED         => (string) __( 'Blocked', 'wp-identity-guard' ),
				self::NOT_IMPLEMENTED => (string) __( 'Not Implemented', 'wp-identity-guard' ),
				default               => (string) __( 'Blocked', 'wp-identity-guard' ),
			};
		}

		return match ( $status ) {
			self::READY           => 'Ready',
			self::ACTION_REQUIRED => 'Action Required',
			self::BLOCKED         => 'Blocked',
			self::NOT_IMPLEMENTED => 'Not Implemented',
			default               => 'Blocked',
		};
	}

	/**
	 * Compute overall plugin readiness for production identity verification.
	 *
	 * Task 7 Invariant:
	 * - If any critical subsystem is `BLOCKED`, overall status is `BLOCKED`.
	 * - In P01-D2, live verification workflows and provider connections are `NOT_IMPLEMENTED`,
	 *   so overall production identity verification readiness must NEVER return `READY`.
	 *
	 * @param string[] $subsystem_statuses                List of subsystem readiness statuses.
	 * @param bool     $verification_workflow_implemented Whether live verification workflow is implemented (false in P01-D2).
	 * @phpstan-param list<string> $subsystem_statuses
	 */
	public static function compute_overall_verification_readiness(
		array $subsystem_statuses,
		bool $verification_workflow_implemented = false
	): string {
		foreach ( $subsystem_statuses as $status ) {
			if ( self::BLOCKED === $status || ! self::is_valid( $status ) ) {
				return self::BLOCKED;
			}
		}

		if ( ! $verification_workflow_implemented ) {
			return self::ACTION_REQUIRED;
		}

		foreach ( $subsystem_statuses as $status ) {
			if ( self::NOT_IMPLEMENTED === $status || self::ACTION_REQUIRED === $status ) {
				return self::ACTION_REQUIRED;
			}
		}

		return self::READY;
	}
}

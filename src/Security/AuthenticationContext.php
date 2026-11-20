<?php
/**
 * Server-side authentication context for verifying the acting WordPress principal.
 *
 * @package WPIG\Security
 */

declare(strict_types=1);

namespace WPIG\Security;

/**
 * Establishes and verifies the authenticated server-side execution principal so
 * caller-supplied `$actor_user_id` arguments are never trusted as proof of authentication.
 *
 * Supported execution contexts:
 * - `CONTEXT_WORDPRESS_REQUEST`: Standard WordPress HTTP/admin/REST/frontend request.
 *   Resolves the principal from `get_current_user_id()` (and rejects background cron ticks).
 * - `CONTEXT_WP_CLI`: Trusted WP-CLI command context. Requires `WP_CLI` runtime to be active.
 * - `CONTEXT_WP_CRON`: Trusted WordPress Cron context. Requires `wp_doing_cron()` runtime to be active.
 * - `CONTEXT_INTERNAL_SERVICE`: Explicit server-side service or test harness context bound to a
 *   zero-argument server principal resolver (`callable(): int`).
 */
final class AuthenticationContext {

	public const CONTEXT_WORDPRESS_REQUEST = 'wordpress_request';
	public const CONTEXT_WP_CLI            = 'wp_cli';
	public const CONTEXT_WP_CRON           = 'wp_cron';
	public const CONTEXT_INTERNAL_SERVICE  = 'internal_service';

	/**
	 * Execution context identifier (`CONTEXT_*`).
	 *
	 * @var string
	 */
	private string $context_type;

	/**
	 * Zero-argument callback returning the authenticated principal user ID (`fn(): int`).
	 *
	 * @var callable
	 * @phpstan-var callable():int
	 */
	private $principal_resolver;

	/**
	 * Zero-argument callback verifying whether the execution environment matches `$context_type`.
	 *
	 * @var callable
	 * @phpstan-var callable():bool
	 */
	private $environment_guard;

	/**
	 * Private constructor; instantiate via explicit context factory methods.
	 *
	 * @param string   $context_type       Context type constant (`CONTEXT_*`).
	 * @param callable $principal_resolver Zero-argument principal resolver (`fn(): int`).
	 * @param callable $environment_guard  Zero-argument environment guard (`fn(): bool`).
	 * @phpstan-param callable():int  $principal_resolver
	 * @phpstan-param callable():bool $environment_guard
	 */
	private function __construct(
		string $context_type,
		callable $principal_resolver,
		callable $environment_guard
	) {
		$this->context_type       = $context_type;
		$this->principal_resolver = $principal_resolver;
		$this->environment_guard  = $environment_guard;
	}

	/**
	 * Create the standard WordPress request authentication context.
	 *
	 * Derives the authenticated principal strictly from WordPress server state (`get_current_user_id()`).
	 *
	 * @param callable|null $principal_resolver Optional zero-argument override (`fn(): int`) for unit testing.
	 * @phpstan-param (callable():int)|null $principal_resolver
	 */
	public static function wordpress_request( ?callable $principal_resolver = null ): self {
		$resolver = $principal_resolver ?? static function (): int {
			if ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() ) {
				return 0;
			}
			if ( ! function_exists( 'get_current_user_id' ) ) {
				return 0;
			}
			return max( 0, (int) get_current_user_id() );
		};

		return new self(
			self::CONTEXT_WORDPRESS_REQUEST,
			$resolver,
			static fn(): bool => true
		);
	}

	/**
	 * Create a trusted WP-CLI authentication context.
	 *
	 * Fails closed with `AuthorizationException` if invoked when `WP_CLI` is not active.
	 *
	 * @param int|null      $designated_actor_id Optional explicit WP-CLI acting user ID (`>= 1`).
	 * @param callable|null $cli_detector        Optional WP-CLI environment detector (`fn(): bool`).
	 * @param callable|null $principal_resolver  Optional fallback resolver (`fn(): int`).
	 * @phpstan-param (callable():bool)|null $cli_detector
	 * @phpstan-param (callable():int)|null  $principal_resolver
	 */
	public static function wp_cli(
		?int $designated_actor_id = null,
		?callable $cli_detector = null,
		?callable $principal_resolver = null
	): self {
		$guard = $cli_detector ?? static function (): bool {
			return defined( 'WP_CLI' ) && true === constant( 'WP_CLI' );
		};

		$resolver = static function () use ( $designated_actor_id, $principal_resolver ): int {
			if ( null !== $designated_actor_id ) {
				return max( 0, $designated_actor_id );
			}
			if ( null !== $principal_resolver ) {
				return max( 0, (int) ( $principal_resolver )() );
			}
			if ( function_exists( 'get_current_user_id' ) ) {
				return max( 0, (int) get_current_user_id() );
			}
			return 0;
		};

		return new self(
			self::CONTEXT_WP_CLI,
			$resolver,
			$guard
		);
	}

	/**
	 * Create a trusted WordPress Cron authentication context.
	 *
	 * Fails closed with `AuthorizationException` if invoked when `wp_doing_cron()` is not active.
	 * Defaults to `$designated_actor_id = 0` (system maintenance), which denies user-interactive
	 * profile/capability actions unless a specific cron user principal (`>= 1`) is explicitly bound.
	 *
	 * @param int           $designated_actor_id Explicit acting user ID for the scheduled task (`0` for system tasks).
	 * @param callable|null $cron_detector       Optional cron environment detector (`fn(): bool`).
	 * @phpstan-param (callable():bool)|null $cron_detector
	 */
	public static function wp_cron(
		int $designated_actor_id = 0,
		?callable $cron_detector = null
	): self {
		$guard = $cron_detector ?? static function (): bool {
			return function_exists( 'wp_doing_cron' ) && (bool) wp_doing_cron();
		};

		return new self(
			self::CONTEXT_WP_CRON,
			static fn(): int => max( 0, $designated_actor_id ),
			$guard
		);
	}

	/**
	 * Create a trusted internal service or deterministic test authentication context.
	 *
	 * Binds either a fixed server-authenticated user ID or a zero-argument principal callback.
	 * Never accepts caller-supplied `$actor_user_id` as input to the resolver.
	 *
	 * @internal Reserved for internal service orchestration and deterministic unit testing.
	 *
	 * @param int|callable $principal_source Fixed authenticated user ID (`>= 0`) or zero-argument `fn(): int`.
	 * @phpstan-param int|(callable():int) $principal_source
	 */
	public static function internal_service( int|callable $principal_source ): self {
		$resolver = is_int( $principal_source )
			? static fn(): int => max( 0, $principal_source )
			: static fn(): int => max( 0, (int) ( $principal_source )() );

		return new self(
			self::CONTEXT_INTERNAL_SERVICE,
			$resolver,
			static fn(): bool => true
		);
	}

	/**
	 * Return the active authentication context type (`CONTEXT_*`).
	 */
	public function get_context_type(): string {
		return $this->context_type;
	}

	/**
	 * Resolve the authenticated server-side principal user ID (`0` if unauthenticated).
	 *
	 * @throws AuthorizationException If the execution environment does not match a restricted context (`wp_cli`, `wp_cron`).
	 */
	public function resolve_principal_id(): int {
		if ( ! (bool) ( $this->environment_guard )() ) {
			AuthorizationException::raise(
				AuthorizationException::CODE_UNAUTHENTICATED,
				sprintf(
					'Authentication context "%s" is not permitted in the current runtime environment.',
					$this->context_type
				)
			);
		}

		return max( 0, (int) ( $this->principal_resolver )() );
	}

	/**
	 * Assert that a server-authenticated principal is active and strictly matches `$actor_user_id`.
	 *
	 * Prevents actor-ID spoofing: even if `$actor_user_id` refers to a valid administrator in
	 * `wp_users`, the check fails closed unless the server-side authentication context confirms
	 * that `$actor_user_id` is the actual authenticated principal for this request/execution.
	 *
	 * @param int $actor_user_id Claimed acting WordPress user ID.
	 * @return int Verified server-authenticated principal user ID (`>= 1`).
	 * @throws AuthorizationException If unauthenticated (`<= 0`) or if `$actor_user_id` does not match the server principal.
	 */
	public function assert_principal_matches( int $actor_user_id ): int {
		if ( $actor_user_id < 1 ) {
			AuthorizationException::raise(
				AuthorizationException::CODE_UNAUTHENTICATED,
				'Authentication is required to perform this action.'
			);
		}

		$principal_id = $this->resolve_principal_id();
		if ( $principal_id < 1 ) {
			AuthorizationException::raise(
				AuthorizationException::CODE_UNAUTHENTICATED,
				'No authenticated WordPress principal is active for this request.'
			);
		}

		if ( $principal_id !== $actor_user_id ) {
			AuthorizationException::raise(
				AuthorizationException::CODE_UNAUTHENTICATED,
				'Supplied actor_user_id does not match the authenticated request principal.'
			);
		}

		return $principal_id;
	}
}

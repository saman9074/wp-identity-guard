<?php
/**
 * WordPress administration controller for WP Identity Guard settings and diagnostics.
 *
 * @package WPIG\Admin
 */

declare(strict_types=1);

namespace WPIG\Admin;

use WPIG\Audit\AuditService;
use WPIG\Security\AuthorizationException;
use WPIG\Security\AuthorizationService;
use WPIG\Security\Capabilities;
use WPIG\Security\ValidationException;

/**
 * Registers the "WP Identity Guard" admin menu, enforces capability and CSRF nonce boundaries,
 * processes POST-only general settings updates, and renders the 7 diagnostic/settings sections
 * with WordPress-native accessible HTML, i18n, and RTL support (Tasks 2 & 3).
 *
 * Security Invariants:
 * - Read access requires `manage_wpig_settings` or `view_wpig_reports` on the active site.
 * - Settings modification requires `manage_wpig_settings`, HTTP `POST`, and a valid WordPress nonce.
 * - Rejects any unknown input fields, privilege-escalation claims, or credential fields.
 * - Exposes zero actions for identity binding, binding release, HMAC rotation, or destructive erasure.
 * - Escapes all output (`esc_html`, `esc_attr`, `esc_url`) and never renders secrets, SQL, or stack traces.
 */
final class AdminController {

	/**
	 * WordPress admin menu slug.
	 */
	public const MENU_SLUG = 'wp-identity-guard';

	/**
	 * WordPress nonce action for saving general settings.
	 */
	public const NONCE_ACTION = 'wpig_save_general_settings';

	/**
	 * Form field name for the CSRF nonce.
	 */
	public const NONCE_FIELD = '_wpig_nonce';

	/**
	 * Canonical admin UI section identifiers (Task 2).
	 *
	 * @var list<string>
	 */
	public const SECTIONS = array(
		'overview',
		'environment',
		'database',
		'cryptography',
		'providers',
		'general_settings',
		'security_diagnostics',
	);

	/**
	 * Authorization service.
	 *
	 * @var AuthorizationService
	 */
	private AuthorizationService $authorizer;

	/**
	 * Settings repository.
	 *
	 * @var SettingsRepository
	 */
	private SettingsRepository $settings_repository;

	/**
	 * Diagnostics service.
	 *
	 * @var DiagnosticsService
	 */
	private DiagnosticsService $diagnostics_service;

	/**
	 * Callback verifying a WordPress nonce (`fn(string $nonce, string $action): bool`).
	 *
	 * @var callable
	 * @phpstan-var callable(string, string):bool
	 */
	private $verify_nonce_fn;

	/**
	 * Callback generating a WordPress nonce (`fn(string $action): string`).
	 *
	 * @var callable
	 * @phpstan-var callable(string):string
	 */
	private $create_nonce_fn;

	/**
	 * Callback detecting RTL locale (`fn(): bool`).
	 *
	 * @var callable
	 * @phpstan-var callable():bool
	 */
	private $is_rtl_fn;

	/**
	 * Optional security audit service.
	 *
	 * @var AuditService|null
	 */
	private ?AuditService $audit_service;

	/**
	 * Whether WordPress hooks have been registered on this instance.
	 *
	 * @var bool
	 */
	private bool $hooks_registered = false;

	/**
	 * Constructor.
	 *
	 * @param AuthorizationService|null $authorizer          Optional authorization service.
	 * @param SettingsRepository|null   $settings_repository Optional settings repository.
	 * @param DiagnosticsService|null   $diagnostics_service Optional diagnostics service.
	 * @param callable|null             $verify_nonce_fn     Optional nonce verifier override.
	 * @param callable|null             $create_nonce_fn     Optional nonce generator override.
	 * @param callable|null             $is_rtl_fn           Optional RTL detector override.
	 * @param AuditService|null         $audit_service       Optional security audit service.
	 * @phpstan-param (callable(string, string):bool)|null $verify_nonce_fn
	 * @phpstan-param (callable(string):string)|null       $create_nonce_fn
	 * @phpstan-param (callable():bool)|null               $is_rtl_fn
	 */
	public function __construct(
		?AuthorizationService $authorizer = null,
		?SettingsRepository $settings_repository = null,
		?DiagnosticsService $diagnostics_service = null,
		?callable $verify_nonce_fn = null,
		?callable $create_nonce_fn = null,
		?callable $is_rtl_fn = null,
		?AuditService $audit_service = null
	) {
		$this->authorizer          = $authorizer ?? new AuthorizationService();
		$this->settings_repository = $settings_repository ?? new SettingsRepository( $this->authorizer );
		$this->diagnostics_service = $diagnostics_service ?? new DiagnosticsService(
			$this->authorizer,
			null,
			$this->settings_repository
		);
		$this->audit_service       = $audit_service;

		$this->verify_nonce_fn = $verify_nonce_fn ?? static function ( string $nonce, string $action ): bool {
			if ( '' === $nonce || ! function_exists( 'wp_verify_nonce' ) ) {
				return false;
			}
			return false !== wp_verify_nonce( $nonce, $action );
		};

		$this->create_nonce_fn = $create_nonce_fn ?? static function ( string $action ): string {
			if ( function_exists( 'wp_create_nonce' ) ) {
				return (string) wp_create_nonce( $action );
			}
			return 'wpig_test_nonce';
		};

		$this->is_rtl_fn = $is_rtl_fn ?? static function (): bool {
			if ( function_exists( 'is_rtl' ) ) {
				return (bool) is_rtl();
			}
			return false;
		};
	}

	/**
	 * Register WordPress admin menu hook exactly once when running in the admin context.
	 */
	public function register_hooks(): void {
		if ( $this->hooks_registered ) {
			return;
		}
		if ( function_exists( 'add_action' ) ) {
			if ( ! function_exists( 'has_action' ) || false === has_action( 'admin_menu', array( $this, 'register_admin_menu' ) ) ) {
				add_action( 'admin_menu', array( $this, 'register_admin_menu' ) );
			}
			$this->hooks_registered = true;
		}
	}

	/**
	 * Return the optional configured `AuditService` instance.
	 */
	public function get_audit_service(): ?AuditService {
		return $this->audit_service;
	}

	/**
	 * Register the "WP Identity Guard" top-level admin menu page.
	 *
	 * Grants menu visibility to users holding either `manage_wpig_settings` or `view_wpig_reports`.
	 */
	public function register_admin_menu(): void {
		if ( ! function_exists( 'add_menu_page' ) ) {
			return;
		}

		$required_cap = Capabilities::MANAGE_SETTINGS;
		if (
			function_exists( 'current_user_can' )
			&& ! current_user_can( Capabilities::MANAGE_SETTINGS )
			&& current_user_can( Capabilities::VIEW_REPORTS )
		) {
			$required_cap = Capabilities::VIEW_REPORTS;
		}

		add_menu_page(
			$this->translate( 'WP Identity Guard' ),
			$this->translate( 'WP Identity Guard' ),
			$required_cap,
			self::MENU_SLUG,
			array( $this, 'render_wp_admin_page' ),
			'dashicons-shield-alt',
			81
		);
	}

	/**
	 * WordPress admin callback that resolves the authenticated server principal and outputs the escaped admin page.
	 */
	public function render_wp_admin_page(): void {
		$actor_user_id = $this->authorizer->get_authenticated_principal_id();
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated
		$request_method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['REQUEST_METHOD'] ) ) : 'GET';

		$notice = null;
		if ( 'POST' === strtoupper( $request_method ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce is verified inside handle_settings_post().
			$raw_post = wp_unslash( $_POST );
			try {
				$this->handle_settings_post( $actor_user_id, 'POST', $raw_post );
				$notice = array(
					'type'    => 'success',
					'message' => $this->translate( 'General settings updated.' ),
				);
			} catch ( AuthorizationException | ValidationException $e ) {
				$notice = array(
					'type'    => 'error',
					'message' => $e->getMessage(),
				);
			}
		}

		try {
			$html = $this->render_page( $actor_user_id, null, $notice );
		} catch ( AuthorizationException $e ) {
			if ( function_exists( 'wp_die' ) ) {
				wp_die(
					esc_html( $e->getMessage() ),
					esc_html( $this->translate( 'WP Identity Guard — Access Denied' ) ),
					array( 'response' => 403 )
				);
			}
			return;
		}

		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- All dynamic values inside render_page() are escaped via esc_html/esc_attr.
		echo $html;
	}

	/**
	 * Handle a state-changing General Settings submission with POST-only, capability, and CSRF nonce checks (Task 3).
	 *
	 * @param int                 $actor_user_id  Acting WordPress user ID.
	 * @param string              $request_method HTTP method (`POST` required).
	 * @param array<string,mixed> $post_data      Submitted form payload (including `_wpig_nonce` and `settings`).
	 * @param int|null            $blog_id        Optional expected site blog ID.
	 * @return array<string,mixed> Updated normalized settings.
	 * @throws AuthorizationException On non-POST method, missing capability, invalid/missing nonce, or privilege escalation input.
	 * @throws ValidationException    On invalid, out-of-range, or unexpected setting fields.
	 */
	public function handle_settings_post(
		int $actor_user_id,
		string $request_method,
		array $post_data,
		?int $blog_id = null
	): array {
		try {
			if ( 'POST' !== strtoupper( trim( $request_method ) ) ) {
				AuthorizationException::raise(
					AuthorizationException::CODE_FORBIDDEN,
					'State-changing admin requests must use the HTTP POST method.'
				);
			}

			// Verify capability before processing nonce or form fields.
			$this->authorizer->assert_can_manage_settings( $actor_user_id, $blog_id );

			// Verify CSRF nonce.
			$nonce = isset( $post_data[ self::NONCE_FIELD ] ) && is_string( $post_data[ self::NONCE_FIELD ] )
				? trim( $post_data[ self::NONCE_FIELD ] )
				: '';

			if ( '' === $nonce || ! (bool) ( $this->verify_nonce_fn )( $nonce, self::NONCE_ACTION ) ) {
				AuthorizationException::raise(
					AuthorizationException::CODE_FORBIDDEN,
					'Invalid or missing WordPress security nonce.'
				);
			}

			// Reject any top-level privilege-escalation or forbidden claims.
			$top_level_check = $post_data;
			unset( $top_level_check[ self::NONCE_FIELD ], $top_level_check['_wp_http_referer'], $top_level_check['settings'] );
			$this->authorizer->assert_no_privilege_escalation_input( $top_level_check, $actor_user_id );

			if ( array() !== $top_level_check ) {
				ValidationException::raise(
					ValidationException::CODE_INVALID_SETTING,
					'Unexpected top-level parameters in settings request.'
				);
			}

			if ( ! isset( $post_data['settings'] ) || ! is_array( $post_data['settings'] ) ) {
				ValidationException::raise(
					ValidationException::CODE_INVALID_SETTING,
					'Missing settings payload in POST request.'
				);
			}

			/**
			 * Validated settings input map.
			 *
			 * @var array<string,mixed> $settings_input
			 */
			$settings_input = $post_data['settings'];

			$updated = $this->settings_repository->update_general_settings(
				$actor_user_id,
				$settings_input,
				$blog_id
			);

			if ( null !== $this->audit_service ) {
				$changed_keys = array_keys( $settings_input );
				$this->audit_service->log_settings_updated( $actor_user_id, $changed_keys );
			}

			return $updated;
		} catch ( AuthorizationException $e ) {
			if ( null !== $this->audit_service ) {
				$this->audit_service->log_authorization_denied(
					$actor_user_id > 0 ? $actor_user_id : null,
					null,
					'handle_settings_post',
					$e->get_safe_code(),
					Capabilities::MANAGE_SETTINGS
				);
			}
			throw $e;
		} catch ( ValidationException $e ) {
			if ( null !== $this->audit_service ) {
				$this->audit_service->log_settings_update_rejected(
					$actor_user_id > 0 ? $actor_user_id : null,
					$e->get_safe_code()
				);
			}
			throw $e;
		}
	}

	/**
	 * Render the complete WP Identity Guard admin page HTML for an authorized actor.
	 *
	 * @param int                                    $actor_user_id Acting WordPress user ID.
	 * @param int|null                               $blog_id       Optional expected site blog ID.
	 * @param array{type:string,message:string}|null $notice        Optional admin notice banner.
	 * @return string Fully escaped HTML output.
	 * @throws AuthorizationException If the actor lacks both `manage_wpig_settings` and `view_wpig_reports`.
	 */
	public function render_page(
		int $actor_user_id,
		?int $blog_id = null,
		?array $notice = null
	): string {
		try {
			$report = $this->diagnostics_service->get_authorized_report( $actor_user_id, $blog_id );
		} catch ( AuthorizationException $e ) {
			if ( null !== $this->audit_service ) {
				$this->audit_service->log_authorization_denied(
					$actor_user_id > 0 ? $actor_user_id : null,
					null,
					'render_admin_page',
					$e->get_safe_code(),
					Capabilities::VIEW_REPORTS
				);
			}
			throw $e;
		}
		$settings = $this->settings_repository->get_settings();

		$can_manage_settings = false;
		try {
			$this->authorizer->assert_can_manage_settings( $actor_user_id, $blog_id );
			$can_manage_settings = true;
		} catch ( AuthorizationException $e ) {
			unset( $e );
		}

		$is_rtl   = (bool) ( $this->is_rtl_fn )();
		$dir_attr = $is_rtl ? 'rtl' : 'ltr';
		$rtl_cls  = $is_rtl ? ' wpig-admin-rtl' : '';

		$env    = $report['environment'];
		$db     = $report['database'];
		$crypto = $report['cryptography'];
		$prov   = $report['providers'];
		$sec    = $report['security'];

		ob_start();
		?>
		<div class="wrap wpig-admin-wrap<?php echo esc_attr( $rtl_cls ); ?>" dir="<?php echo esc_attr( $dir_attr ); ?>">
			<h1><?php echo esc_html( $this->translate( 'WP Identity Guard' ) ); ?></h1>

			<?php if ( null !== $notice ) : ?>
				<?php $notice_class = 'success' === $notice['type'] ? 'notice-success' : 'notice-error'; ?>
				<div class="notice <?php echo esc_attr( $notice_class ); ?> is-dismissible" role="status" aria-live="polite">
					<p><?php echo esc_html( $notice['message'] ); ?></p>
				</div>
			<?php endif; ?>

			<nav class="nav-tab-wrapper wp-clearfix" aria-label="<?php echo esc_attr( $this->translate( 'WP Identity Guard Sections' ) ); ?>">
				<a href="#wpig-section-overview" class="nav-tab nav-tab-active"><?php echo esc_html( $this->translate( 'Overview' ) ); ?></a>
				<a href="#wpig-section-environment" class="nav-tab"><?php echo esc_html( $this->translate( 'Environment' ) ); ?></a>
				<a href="#wpig-section-database" class="nav-tab"><?php echo esc_html( $this->translate( 'Database' ) ); ?></a>
				<a href="#wpig-section-cryptography" class="nav-tab"><?php echo esc_html( $this->translate( 'Cryptography' ) ); ?></a>
				<a href="#wpig-section-providers" class="nav-tab"><?php echo esc_html( $this->translate( 'Providers' ) ); ?></a>
				<a href="#wpig-section-general-settings" class="nav-tab"><?php echo esc_html( $this->translate( 'General Settings' ) ); ?></a>
				<a href="#wpig-section-security-diagnostics" class="nav-tab"><?php echo esc_html( $this->translate( 'Security Diagnostics' ) ); ?></a>
			</nav>

			<!-- 1. Overview -->
			<section id="wpig-section-overview" class="wpig-section">
				<h2><?php echo esc_html( $this->translate( 'Overview' ) ); ?></h2>
				<table class="widefat striped">
					<tbody>
						<tr>
							<th scope="row"><?php echo esc_html( $this->translate( 'Plugin Version' ) ); ?></th>
							<td><code><?php echo esc_html( $env['plugin_version'] ); ?></code></td>
						</tr>
						<tr>
							<th scope="row"><?php echo esc_html( $this->translate( 'Foundation Readiness (P01)' ) ); ?></th>
							<td>
								<strong><?php echo esc_html( $report['foundation_readiness'] ); ?></strong>
								(<?php echo esc_html( ReadinessStatus::label( $report['foundation_readiness'] ) ); ?>)
							</td>
						</tr>
						<tr>
							<th scope="row"><?php echo esc_html( $this->translate( 'Production Identity Verification Readiness' ) ); ?></th>
							<td>
								<strong><?php echo esc_html( $report['overall_verification_readiness'] ); ?></strong>
								(<?php echo esc_html( ReadinessStatus::label( $report['overall_verification_readiness'] ) ); ?>)
								<p class="description">
									<?php echo esc_html( $this->translate( 'Live identity verification workflows and provider adapters are not yet active in Phase P01-D2.' ) ); ?>
								</p>
							</td>
						</tr>
					</tbody>
				</table>
			</section>

			<!-- 2. Environment -->
			<section id="wpig-section-environment" class="wpig-section">
				<h2><?php echo esc_html( $this->translate( 'Environment' ) ); ?></h2>
				<table class="widefat striped">
					<tbody>
						<tr>
							<th scope="row"><?php echo esc_html( $this->translate( 'Environment Status' ) ); ?></th>
							<td><code><?php echo esc_html( $env['status'] ); ?></code></td>
						</tr>
						<tr>
							<th scope="row"><?php echo esc_html( $this->translate( 'PHP Version' ) ); ?></th>
							<td>
								<code><?php echo esc_html( $env['php_version'] ); ?></code>
								(<?php echo esc_html( sprintf( $this->translate( 'Minimum required: %s' ), $env['min_php_version'] ) ); ?>)
							</td>
						</tr>
						<tr>
							<th scope="row"><?php echo esc_html( $this->translate( 'WordPress Version' ) ); ?></th>
							<td>
								<code><?php echo esc_html( $env['wp_version'] ); ?></code>
								(<?php echo esc_html( sprintf( $this->translate( 'Minimum required: %s' ), $env['min_wp_version'] ) ); ?>)
							</td>
						</tr>
						<tr>
							<th scope="row"><?php echo esc_html( $this->translate( 'WooCommerce Version (Optional)' ) ); ?></th>
							<td>
								<?php if ( $env['wc_installed'] && null !== $env['wc_version'] ) : ?>
									<code><?php echo esc_html( $env['wc_version'] ); ?></code>
									(<?php echo esc_html( sprintf( $this->translate( 'Minimum required when installed: %s' ), $env['min_wc_version'] ) ); ?>)
								<?php else : ?>
									<?php echo esc_html( $this->translate( 'Not installed (optional)' ) ); ?>
								<?php endif; ?>
							</td>
						</tr>
						<tr>
							<th scope="row"><?php echo esc_html( $this->translate( 'Libsodium Extension (ext-sodium)' ) ); ?></th>
							<td><?php echo esc_html( $env['ext_sodium'] ? $this->translate( 'Available' ) : $this->translate( 'Missing (Blocked)' ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php echo esc_html( $this->translate( 'HTTPS Transport Readiness' ) ); ?></th>
							<td>
								<code><?php echo esc_html( $env['https']['status'] ); ?></code> —
								<?php echo esc_html( $env['https']['summary'] ); ?>
							</td>
						</tr>
					</tbody>
				</table>
			</section>

			<!-- 3. Database -->
			<section id="wpig-section-database" class="wpig-section">
				<h2><?php echo esc_html( $this->translate( 'Database' ) ); ?></h2>
				<table class="widefat striped">
					<tbody>
						<tr>
							<th scope="row"><?php echo esc_html( $this->translate( 'Database Status' ) ); ?></th>
							<td><code><?php echo esc_html( $db['status'] ); ?></code></td>
						</tr>
						<tr>
							<th scope="row"><?php echo esc_html( $this->translate( 'Database Connectivity' ) ); ?></th>
							<td><?php echo esc_html( $db['db_connected'] ? $this->translate( 'Connected' ) : $this->translate( 'Disconnected' ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php echo esc_html( $this->translate( 'Schema Version (Installed / Target)' ) ); ?></th>
							<td>
								<code><?php echo esc_html( $db['current_schema_version'] ); ?></code> /
								<code><?php echo esc_html( $db['target_schema_version'] ); ?></code>
							</td>
						</tr>
						<tr>
							<th scope="row"><?php echo esc_html( $this->translate( 'Migration & Index Readiness' ) ); ?></th>
							<td><?php echo esc_html( $db['migration_ready'] ? $this->translate( 'Verified' ) : $this->translate( 'Action or Migration Required' ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php echo esc_html( $this->translate( 'Maintenance Mode' ) ); ?></th>
							<td><?php echo esc_html( $db['maintenance_mode'] ? $this->translate( 'Active' ) : $this->translate( 'Inactive' ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php echo esc_html( $this->translate( 'Required Schema Tables' ) ); ?></th>
							<td>
								<ul>
									<?php foreach ( $db['table_statuses'] as $logical_table => $is_present ) : ?>
										<li>
											<code><?php echo esc_html( $logical_table ); ?></code>:
											<?php echo esc_html( $is_present ? $this->translate( 'Present' ) : $this->translate( 'Missing' ) ); ?>
										</li>
									<?php endforeach; ?>
								</ul>
							</td>
						</tr>
					</tbody>
				</table>
			</section>

			<!-- 4. Cryptography -->
			<section id="wpig-section-cryptography" class="wpig-section">
				<h2><?php echo esc_html( $this->translate( 'Cryptography' ) ); ?></h2>
				<table class="widefat striped">
					<tbody>
						<tr>
							<th scope="row"><?php echo esc_html( $this->translate( 'Cryptographic Readiness' ) ); ?></th>
							<td><code><?php echo esc_html( $crypto['status'] ); ?></code></td>
						</tr>
						<tr>
							<th scope="row"><?php echo esc_html( $this->translate( 'Encryption Key (WPIG_ENC_KEY)' ) ); ?></th>
							<td>
								<?php echo esc_html( $crypto['encryption_configured'] ? $this->translate( 'Configured' ) : $this->translate( 'Not Configured' ) ); ?>
								<?php if ( null !== $crypto['encryption_key_id'] ) : ?>
									(<?php echo esc_html( sprintf( $this->translate( 'Active Key ID: %s' ), $crypto['encryption_key_id'] ) ); ?>)
								<?php endif; ?>
							</td>
						</tr>
						<tr>
							<th scope="row"><?php echo esc_html( $this->translate( 'HMAC Fingerprint Key (WPIG_HMAC_KEY)' ) ); ?></th>
							<td>
								<?php echo esc_html( $crypto['hmac_configured'] ? $this->translate( 'Configured' ) : $this->translate( 'Not Configured' ) ); ?>
								<?php if ( null !== $crypto['hmac_key_id'] ) : ?>
									(<?php echo esc_html( sprintf( $this->translate( 'Active Key ID: %s' ), $crypto['hmac_key_id'] ) ); ?>)
								<?php endif; ?>
							</td>
						</tr>
						<tr>
							<th scope="row"><?php echo esc_html( $this->translate( 'Key Separation (ENC != HMAC)' ) ); ?></th>
							<td><?php echo esc_html( $crypto['keys_distinct'] ? $this->translate( 'Distinct' ) : $this->translate( 'Invalid or Missing' ) ); ?></td>
						</tr>
						<?php if ( array() !== $crypto['error_codes'] ) : ?>
							<tr>
								<th scope="row"><?php echo esc_html( $this->translate( 'Diagnostic Codes' ) ); ?></th>
								<td><code><?php echo esc_html( implode( ', ', $crypto['error_codes'] ) ); ?></code></td>
							</tr>
						<?php endif; ?>
					</tbody>
				</table>
			</section>

			<!-- 5. Providers -->
			<section id="wpig-section-providers" class="wpig-section">
				<h2><?php echo esc_html( $this->translate( 'Providers' ) ); ?></h2>
				<p><?php echo esc_html( $this->translate( 'Provider integrations are displayed in read-only diagnostic mode. No live provider connections or API credentials are active in Phase P01-D2.' ) ); ?></p>
				<table class="widefat striped">
					<thead>
						<tr>
							<th scope="col"><?php echo esc_html( $this->translate( 'Provider' ) ); ?></th>
							<th scope="col"><?php echo esc_html( $this->translate( 'Status' ) ); ?></th>
							<th scope="col"><?php echo esc_html( $this->translate( 'Default Selection' ) ); ?></th>
							<th scope="col"><?php echo esc_html( $this->translate( 'Details' ) ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $prov['items'] as $provider_item ) : ?>
							<tr>
								<td><strong><?php echo esc_html( $provider_item['name'] ); ?></strong></td>
								<td><code><?php echo esc_html( $provider_item['integration_status'] ); ?></code></td>
								<td><?php echo esc_html( $provider_item['selected_as_default'] ? $this->translate( 'Selected' ) : $this->translate( 'Not Selected' ) ); ?></td>
								<td><?php echo esc_html( $provider_item['summary'] ); ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</section>

			<!-- 6. General Settings -->
			<section id="wpig-section-general-settings" class="wpig-section">
				<h2><?php echo esc_html( $this->translate( 'General Settings' ) ); ?></h2>
				<?php if ( $can_manage_settings ) : ?>
					<?php $nonce_val = (string) ( $this->create_nonce_fn )( self::NONCE_ACTION ); ?>
					<form method="post" action="">
						<input type="hidden" name="<?php echo esc_attr( self::NONCE_FIELD ); ?>" value="<?php echo esc_attr( $nonce_val ); ?>" />
						<table class="form-table" role="presentation">
							<tbody>
								<tr>
									<th scope="row">
										<label for="wpig-default-provider"><?php echo esc_html( $this->translate( 'Default Provider' ) ); ?></label>
									</th>
									<td>
										<select id="wpig-default-provider" name="settings[default_provider]">
											<option value="none" <?php echo 'none' === $settings['default_provider'] ? 'selected="selected"' : ''; ?>>
												<?php echo esc_html( $this->translate( 'None (Disabled)' ) ); ?>
											</option>
											<option value="api_ir" <?php echo 'api_ir' === $settings['default_provider'] ? 'selected="selected"' : ''; ?>>
												<?php echo esc_html( $this->translate( 'API.ir (Not Implemented in P01-D2)' ) ); ?>
											</option>
											<option value="zohal" <?php echo 'zohal' === $settings['default_provider'] ? 'selected="selected"' : ''; ?>>
												<?php echo esc_html( $this->translate( 'Zohal (Not Implemented in P01-D2)' ) ); ?>
											</option>
										</select>
									</td>
								</tr>
								<tr>
									<th scope="row">
										<label for="wpig-sandbox-mode"><?php echo esc_html( $this->translate( 'Sandbox Mode' ) ); ?></label>
									</th>
									<td>
										<input type="hidden" name="settings[sandbox_mode]" value="0" />
										<input type="checkbox" id="wpig-sandbox-mode" name="settings[sandbox_mode]" value="1" <?php echo $settings['sandbox_mode'] ? 'checked="checked"' : ''; ?> />
									</td>
								</tr>
								<tr>
									<th scope="row">
										<label for="wpig-daily-request-budget"><?php echo esc_html( $this->translate( 'Daily Request Budget (0–100000)' ) ); ?></label>
									</th>
									<td>
										<input type="number" id="wpig-daily-request-budget" name="settings[daily_request_budget]" min="0" max="100000" value="<?php echo esc_attr( (string) $settings['daily_request_budget'] ); ?>" />
									</td>
								</tr>
								<tr>
									<th scope="row">
										<label for="wpig-rate-limit-user-hour"><?php echo esc_html( $this->translate( 'Rate Limit per User / Hour (1–100)' ) ); ?></label>
									</th>
									<td>
										<input type="number" id="wpig-rate-limit-user-hour" name="settings[rate_limit_per_user_hour]" min="1" max="100" value="<?php echo esc_attr( (string) $settings['rate_limit_per_user_hour'] ); ?>" />
									</td>
								</tr>
								<tr>
									<th scope="row">
										<label for="wpig-rate-limit-ip-hour"><?php echo esc_html( $this->translate( 'Rate Limit per IP / Hour (1–500)' ) ); ?></label>
									</th>
									<td>
										<input type="number" id="wpig-rate-limit-ip-hour" name="settings[rate_limit_per_ip_hour]" min="1" max="500" value="<?php echo esc_attr( (string) $settings['rate_limit_per_ip_hour'] ); ?>" />
									</td>
								</tr>
								<tr>
									<th scope="row">
										<label for="wpig-security-notifications"><?php echo esc_html( $this->translate( 'Security Notifications Enabled' ) ); ?></label>
									</th>
									<td>
										<input type="hidden" name="settings[security_notifications_enabled]" value="0" />
										<input type="checkbox" id="wpig-security-notifications" name="settings[security_notifications_enabled]" value="1" <?php echo $settings['security_notifications_enabled'] ? 'checked="checked"' : ''; ?> />
									</td>
								</tr>
								<tr>
									<th scope="row">
										<label for="wpig-consent-notice-version"><?php echo esc_html( $this->translate( 'Consent Notice Version' ) ); ?></label>
									</th>
									<td>
										<input type="text" id="wpig-consent-notice-version" name="settings[consent_notice_version]" maxlength="32" value="<?php echo esc_attr( $settings['consent_notice_version'] ); ?>" />
									</td>
								</tr>
							</tbody>
						</table>
						<p class="submit">
							<button type="submit" class="button button-primary"><?php echo esc_html( $this->translate( 'Save General Settings' ) ); ?></button>
						</p>
					</form>
				<?php else : ?>
					<p><?php echo esc_html( $this->translate( 'Read-only view: manage_wpig_settings capability is required to modify settings.' ) ); ?></p>
				<?php endif; ?>
			</section>

			<!-- 7. Security Diagnostics -->
			<section id="wpig-section-security-diagnostics" class="wpig-section">
				<h2><?php echo esc_html( $this->translate( 'Security Diagnostics' ) ); ?></h2>
				<table class="widefat striped">
					<tbody>
						<tr>
							<th scope="row"><?php echo esc_html( $this->translate( 'Capabilities Registered' ) ); ?></th>
							<td><?php echo esc_html( $sec['capabilities_registered'] ? $this->translate( 'Verified' ) : $this->translate( 'Missing' ) ); ?></td>
						</tr>
						<tr>
							<th scope="row"><?php echo esc_html( $this->translate( 'Legal & Compliance Gate (L1–L5)' ) ); ?></th>
							<td><code><?php echo esc_html( $sec['legal_compliance_status'] ); ?></code></td>
						</tr>
						<tr>
							<th scope="row"><?php echo esc_html( $this->translate( 'Verification Workflow Status' ) ); ?></th>
							<td><code><?php echo esc_html( $sec['verification_workflow_status'] ); ?></code></td>
						</tr>
						<tr>
							<th scope="row"><?php echo esc_html( $this->translate( 'Overall Production Verification Status' ) ); ?></th>
							<td><code><?php echo esc_html( $sec['overall_verification_readiness'] ); ?></code></td>
						</tr>
					</tbody>
				</table>
			</section>
		</div>
		<?php
		return (string) ob_get_clean();
	}

	/**
	 * Translate a UI label using WordPress i18n when available.
	 *
	 * @param string $text Source English string.
	 */
	private function translate( string $text ): string {
		if ( function_exists( '__' ) ) {
			// phpcs:ignore WordPress.WP.I18n.NonSingularStringLiteralText -- Central helper translating fixed UI strings.
			return (string) __( $text, 'wp-identity-guard' );
		}
		return $text;
	}
}

<?php
/**
 * Immutable DTO representing a consent record from `wpig_consents`.
 *
 * @package WPIG\Privacy
 */

declare(strict_types=1);

namespace WPIG\Privacy;

/**
 * Immutable consent record DTO (`wpig_consents`).
 *
 * Contains only non-secret consent metadata (`notice_version`, `notice_hash`,
 * `purposes`, `accepted_at`, `revoked_at`, `expires_at`).
 */
final class ConsentRecord {

	/**
	 * Row ID in `wpig_consents`.
	 *
	 * @var int
	 */
	public readonly int $id;

	/**
	 * WordPress user ID.
	 *
	 * @var int
	 */
	public readonly int $wp_user_id;

	/**
	 * Consent notice version identifier.
	 *
	 * @var string
	 */
	public readonly string $notice_version;

	/**
	 * Lowercase hex SHA-256 hash of the canonical notice text (`CHAR(64)`).
	 *
	 * @var string
	 */
	public readonly string $notice_hash;

	/**
	 * Consented purposes list.
	 *
	 * @var list<string>
	 */
	public readonly array $purposes;

	/**
	 * UTC timestamp when consent was accepted (`Y-m-d H:i:s`).
	 *
	 * @var string
	 */
	public readonly string $accepted_at;

	/**
	 * UTC timestamp when consent was withdrawn/revoked (`Y-m-d H:i:s`), or null if not revoked.
	 *
	 * @var string|null
	 */
	public readonly ?string $revoked_at;

	/**
	 * UTC timestamp when consent expires (`Y-m-d H:i:s`), or null if no expiry.
	 *
	 * @var string|null
	 */
	public readonly ?string $expires_at;

	/**
	 * Site blog ID where this consent record was granted (`>= 1`).
	 *
	 * @var int
	 */
	public readonly int $blog_id;

	/**
	 * Constructor.
	 *
	 * @param int         $id             Row ID (`>= 1`).
	 * @param int         $wp_user_id     WordPress user ID (`>= 1`).
	 * @param string      $notice_version Notice version (`1..32` chars).
	 * @param string      $notice_hash    SHA-256 hex notice hash (`64` hex chars).
	 * @param string[]    $purposes       Consented purposes list.
	 * @param string      $accepted_at    UTC acceptance timestamp.
	 * @param string|null $revoked_at     Optional UTC revocation timestamp.
	 * @param string|null $expires_at     Optional UTC expiry timestamp.
	 * @param int         $blog_id        Site blog ID (`>= 1`, default `1`).
	 * @phpstan-param list<string> $purposes
	 */
	public function __construct(
		int $id,
		int $wp_user_id,
		string $notice_version,
		string $notice_hash,
		array $purposes,
		string $accepted_at,
		?string $revoked_at = null,
		?string $expires_at = null,
		int $blog_id = 1
	) {
		$this->id             = $id;
		$this->wp_user_id     = $wp_user_id;
		$this->notice_version = $notice_version;
		$this->notice_hash    = $notice_hash;
		$this->purposes       = $purposes;
		$this->accepted_at    = $accepted_at;
		$this->revoked_at     = $revoked_at;
		$this->expires_at     = $expires_at;
		$this->blog_id        = max( 1, $blog_id );
	}

	/**
	 * Determine whether this consent record is currently active as of `$now_utc`.
	 *
	 * @param string $now_utc UTC timestamp (`Y-m-d H:i:s`).
	 */
	public function is_active( string $now_utc ): bool {
		if ( '' === $this->accepted_at || $this->accepted_at > $now_utc ) {
			return false;
		}

		if ( null !== $this->revoked_at ) {
			return false;
		}

		if ( null !== $this->expires_at && $this->expires_at <= $now_utc ) {
			return false;
		}

		return true;
	}

	/**
	 * Verify that this consent record is active, unrevoked, unexpired, and bound to the
	 * expected user ID, Multisite blog ID, and required operation purpose.
	 *
	 * @param int    $expected_user_id Target WordPress user ID (`>= 1`).
	 * @param int    $expected_blog_id Target site blog ID (`>= 1`).
	 * @param string $required_purpose Operation purpose constant (`ConsentRepository::PURPOSE_*`).
	 * @param string $now_utc          Current UTC timestamp (`Y-m-d H:i:s`).
	 */
	public function is_valid_for(
		int $expected_user_id,
		int $expected_blog_id,
		string $required_purpose,
		string $now_utc
	): bool {
		if (
			$this->id < 1
			|| $expected_user_id < 1
			|| $expected_blog_id < 1
			|| '' === $required_purpose
			|| $this->wp_user_id !== $expected_user_id
			|| $this->blog_id !== $expected_blog_id
		) {
			return false;
		}

		if ( ! $this->is_active( $now_utc ) ) {
			return false;
		}

		return in_array( $required_purpose, $this->purposes, true );
	}

	/**
	 * Export safe consent summary array for WordPress Personal Data Exporter.
	 *
	 * @param string $now_utc Current UTC timestamp (`Y-m-d H:i:s`).
	 * @return array<string,bool|int|string|null>
	 */
	public function to_safe_export_array( string $now_utc ): array {
		return array(
			'id'             => $this->id,
			'wp_user_id'     => $this->wp_user_id,
			'notice_version' => $this->notice_version,
			'notice_hash'    => $this->notice_hash,
			'purposes'       => implode( ', ', $this->purposes ),
			'status'         => $this->is_active( $now_utc ) ? 'ACTIVE' : ( null !== $this->revoked_at ? 'WITHDRAWN' : 'EXPIRED' ),
			'accepted_at'    => $this->accepted_at,
			'revoked_at'     => $this->revoked_at,
			'expires_at'     => $this->expires_at,
		);
	}
}

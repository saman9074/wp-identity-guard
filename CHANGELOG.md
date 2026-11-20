# Changelog

All notable changes to **WP Identity Guard (Free)** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-alpha.1] - 2026-11-20

> **Early Development Preview (`P01 Foundation`):** Identity verification providers, SMS OTP delivery, and bank card ownership verification are **not yet implemented** in this alpha preview. Do not use this release for production identity verification.

### Added
- **P01-B1 / P01-B2 — Versioned Database Schema & Migration Infrastructure:**
  - `WPIG\Storage\SchemaDefinition` defining the 6 custom per-site InnoDB (`utf8mb4`) tables: `wpig_profiles`, `wpig_verifications`, `wpig_cards`, `wpig_otp_challenges`, `wpig_consents`, and `wpig_audit_events`.
  - `WPIG\Storage\MigrationLock` and `WPIG\Storage\SchemaMigrator` implementing session-level `GET_LOCK()` and owner-token heartbeat locking with post-migration column/index verification.
  - `WPIG\Core\Activator`, `WPIG\Core\Deactivator`, `WPIG\Core\EnvironmentChecker`, and non-destructive `uninstall.php` enforcing `D02` support floors (`PHP >= 8.3`, `WordPress >= 6.9`, `ext-sodium`) and `D15` non-destructive lifecycle rules.
- **P01-C1 / P01-C2 — Cryptographic Foundation, Normalization, Fingerprinting & Masking:**
  - `WPIG\Security\SodiumCrypto` implementing `XChaCha20-Poly1305-IETF` AEAD encryption (`v1:<key_id>:<base64url>`) and purpose-separated `HMAC-SHA-256`.
  - `WPIG\Security\CanonicalAad` implementing deterministic 6-segment pipe-delimited Associated Data (`wpig|v1|blog:<blog_id>|<entity_type>:<entity_name>|<subject_id>|<key_id>`).
  - `WPIG\Security\WordPressKeyProvider` implementing `K1` (`wp-config.php` constants) and `K2` (environment variables) keyring resolution with strict encryption/HMAC key separation and zero WordPress salt fallback.
  - `WPIG\Security\SensitiveValue` providing redaction against serialization/debug dumps and best-effort `sodium_memzero()` buffer wiping.
  - `WPIG\Security\IdentityNormalizer`, `WPIG\Security\IdentityFingerprinter`, and `WPIG\Security\DataMasker` for Persian/Arabic-Indic digit normalization, Iranian National ID checksum validation, mobile canonicalization, Jalali birth date validation, and `C1` safe bank card metadata extraction (`card_last4` and `masked_pan` only).
- **P01-C3 — Secure Profile Persistence:**
  - `WPIG\Storage\ProfileRepository`, `WPIG\Storage\ProfileRecord`, and `WPIG\Storage\DecryptedIdentityData` enforcing short InnoDB transactions (`SELECT ... FOR UPDATE`), granular version counters (`identity_version`, `mobile_version`, `card_version`), dependent evidence invalidation, and `D14` bound national-code uniqueness (`uq_wpig_profiles_bound_nc`) persisting across verification freshness expiry.
- **P01-D1 & Security Closure — Authentication, Capabilities & Authorization Boundary:**
  - `WPIG\Security\AuthenticationContext` enforcing server-derived principal validation (`get_current_user_id()`) and explicit runtime guards for `WP-CLI`, `cron`, and internal system tasks.
  - `WPIG\Security\Capabilities` registering least-privilege capabilities (`manage_wpig_settings`, `view_wpig_reports`, `review_wpig_verification`) on `administrator` and stripping them from unprivileged roles.
  - `WPIG\Security\AuthorizationService`, `WPIG\Security\VerificationAuthorityGrant` (same-process, single-use HMAC-sealed binding grants), and `WPIG\Storage\ProfileAccessBoundary`.
- **P01-D2 — Admin Settings & Operational Readiness Diagnostics:**
  - `WPIG\Admin\AdminController`, `WPIG\Admin\SettingsRepository` (non-autoloaded 6-key non-sensitive allowlist), `WPIG\Admin\DiagnosticsService`, and `WPIG\Admin\ReadinessStatus`.
- **P01-D3 — Security Audit Logging, Consent Lifecycle, Retention & WordPress Privacy Integration:**
  - `WPIG\Audit\AuditRepository`, `WPIG\Audit\AuditService`, and `WPIG\Audit\AuditEventRecord` providing append-only security audit logging into `wpig_audit_events` with strict allowlists and sensitive-pattern rejection.
  - `WPIG\Privacy\ConsentRepository` and `WPIG\Privacy\ConsentRecord` managing versioned user consent records (`wpig_consents`).
  - `WPIG\Privacy\PrivacyExporterService` and `WPIG\Privacy\PrivacyEraserService` integrated with WordPress personal data exporter and eraser hooks.
  - `WPIG\Storage\RetentionService` implementing bounded batch pruning (`1..500` rows) disabled by default (`DISABLED_POLICY_UNRESOLVED`) while legal retention decision `D04` remains open.
- **P00 — Repository Bootstrap & Tooling:**
  - Built-in PSR-4 autoloader (`WPIG\`), offline sensitive-data scanner (`tools/sensitive-scan.php`), release ZIP builder (`tools/build-release-zip.php`), PHPCS/WPCS, PHPStan level 6, PHPUnit unit and MariaDB integration test suites, and community/release documentation.

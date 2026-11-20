# WP Identity Guard (Free) — `v0.1.0-alpha.1`

[![License: GPL-2.0-or-later](https://img.shields.io/badge/License-GPL--2.0--or--later-blue.svg)](LICENSE)
[![PHP: >= 8.3](https://img.shields.io/badge/PHP-%3E%3D%208.3-777bb4.svg)](https://www.php.net/)
[![WordPress: >= 6.9](https://img.shields.io/badge/WordPress-%3E%3D%206.9-21759b.svg)](https://wordpress.org/)
[![Status: Alpha Preview](https://img.shields.io/badge/Status-v0.1.0--alpha.1%20(P01%20Foundation)-orange.svg)](CHANGELOG.md)

> [!WARNING]
> **This is an early development preview. Identity verification providers, OTP delivery, and bank card ownership verification are not yet implemented. Do not use this release for production identity verification.**

---

## Project Introduction

**WP Identity Guard** is an open-source, privacy-conscious identity and bank-card ownership verification plugin for WordPress (with optional WooCommerce integration). It is designed to embed identity verification workflows directly inside existing WordPress account screens (WordPress Profile, WooCommerce My Account, Shortcode, and Gutenberg Block) rather than introducing a separate standalone user dashboard.

**Important Scope Distinction:** WP Identity Guard is **not a payment gateway**, does not process financial transactions, and an identity or card ownership verification record does not prove which payment instrument was used at checkout.

---

## Current Development Status (`v0.1.0-alpha.1`)

- **Completed Phase:** **P01 Foundation** (Database schema & locked migrations, `libsodium` AEAD encryption & purpose-separated HMAC-SHA-256 fingerprinting, transactional profile persistence, least-privilege capabilities & authorization boundary, admin settings & readiness diagnostics, append-only audit logging, consent lifecycle, and WordPress personal data exporter/eraser integration).
- **Not Yet Implemented:** **P02–P05** (SMS OTP delivery and verification challenges, Shahkar mobile-to-national-code provider inquiries, bank card ownership inquiries, REST API endpoints, and end-user account UI integrations).
- **Readiness State:** Installing and activating `v0.1.0-alpha.1` initializes the database schema and exposes the **WP Admin → Identity Guard** diagnostics and settings screen. The operational readiness status intentionally reports that live verification is disabled (`OPERATIONAL_VERIFICATION_DISABLED` or `ACTION_REQUIRED`) because no verification provider adapters are implemented in P01.

---

## Features Implemented in P01 Foundation

1. **Versioned Database Schema & Concurrency-Safe Migrations (`WPIG\Storage\SchemaDefinition`, `SchemaMigrator`, `MigrationLock`):**
   - Six custom per-site InnoDB (`utf8mb4`) tables (`{$wpdb->prefix}wpig_profiles`, `wpig_verifications`, `wpig_cards`, `wpig_otp_challenges`, `wpig_consents`, `wpig_audit_events`).
   - Session-level MariaDB/MySQL `GET_LOCK()` and owner-token heartbeat option locking prevent concurrent migration races.
   - Safe activation, non-destructive deactivation, and non-destructive default uninstallation (`D15`).
2. **Cryptographic Foundation (`WPIG\Security\SodiumCrypto`, `WordPressKeyProvider`, `CanonicalAad`, `SensitiveValue`):**
   - Authenticated encryption (`sodium_crypto_aead_xchacha20poly1305_ietf`) with 24-byte random nonces and versioned envelopes (`v1:<key_id>:<base64url>`).
   - 6-segment canonical Associated Data (`wpig|v1|blog:<blog_id>|<entity_type>:<entity_name>|<subject_id>|<key_id>`) binding every ciphertext to its exact blog, table/column (or option), user ID, and key ID.
   - External key loading from `wp-config.php` constants (`K1`) or environment variables (`K2`) with strict encryption/HMAC key separation and zero fallback to WordPress salts (`AUTH_KEY`, etc.).
   - Best-effort userland memory hygiene via `SensitiveValue` and `sodium_memzero()`.
3. **Normalization, Purpose-Separated Fingerprinting & Masking (`WPIG\Security\IdentityNormalizer`, `IdentityFingerprinter`, `DataMasker`):**
   - Persian (`۰-۹`) and Arabic-Indic (`٠-٩`) digit canonicalization to ASCII.
   - Iranian 10-digit National ID checksum validation, mobile canonicalization (`09XXXXXXXXX`), Jalali birth date format validation (`YYYY/MM/DD`), and 16-digit Luhn card PAN extraction to safe metadata (`last4` and masked display string only).
   - Domain-separated keyed `HMAC-SHA-256` fingerprints (`wpig:v1:national_code`, `wpig:v1:mobile`, `wpig:v1:otp_challenge`, `wpig:v1:ip_rate`).
4. **Transactional Profile Persistence & `D14` Identity Binding (`WPIG\Storage\ProfileRepository`, `ProfileAccessBoundary`):**
   - Short InnoDB transactions (`START TRANSACTION` / `SELECT ... FOR UPDATE` / `COMMIT` / `ROLLBACK`).
   - Decoupled monotonic version counters (`identity_version`, `mobile_version`, `card_version`) so card updates do not invalidate mobile or identity verification state.
   - Separation of permanent account binding (`binding_state = 'BOUND'`, `UNIQUE (bound_national_code_hmac)`) from verification freshness (`identity_state = 'EXPIRED'`). Unverified attempts never reserve a national code, and freshness expiry never auto-releases a bound national code to another user.
5. **Authentication, Least-Privilege Capabilities & Authorization (`WPIG\Security\AuthenticationContext`, `Capabilities`, `AuthorizationService`, `VerificationAuthorityGrant`):**
   - Server-derived principal verification (`get_current_user_id()`) preventing client-supplied actor-ID spoofing, with explicit guards for `WP-CLI`, `cron`, and internal system tasks.
   - Three least-privilege capabilities (`manage_wpig_settings`, `view_wpig_reports`, `review_wpig_verification`) granted by default only to site `administrator` and actively stripped from unprivileged roles (`subscriber`, `customer`, etc.).
   - Same-process, single-use HMAC-sealed `VerificationAuthorityGrant` tokens required at `ProfileAccessBoundary::bind_verified_identity()`.
6. **Admin Settings & Readiness Diagnostics (`WPIG\Admin\AdminController`, `SettingsRepository`, `DiagnosticsService`):**
   - Strict 6-key non-sensitive settings allowlist persisted in `wp_options` (`wpig_settings`) with `autoload = 'no'`.
   - Operational readiness cards inspecting PHP/WordPress/WooCommerce floors, `ext-sodium`, HTTPS, schema health, and cryptographic key readiness without exposing raw key material.
7. **Append-Only Security Audit Logging, Consent & WordPress Privacy Integration (`WPIG\Audit\*`, `WPIG\Privacy\*`, `WPIG\Storage\RetentionService`):**
   - Application-layer append-only audit repository (`wpig_audit_events`) with strict event/outcome/metadata allowlists and automated rejection of raw PII, PANs, OTPs, keys, or ciphertexts.
   - Versioned user consent tracking (`wpig_consents`) with SHA-256 notice hashing and revocation support.
   - Integration with WordPress **Tools → Export Personal Data** (masked summaries only) and **Tools → Erase Personal Data** (clears `UNBOUND` PII while retaining `BOUND` anti-abuse bindings and legal-hold records with audit logging).

---

## Planned Features (Roadmap)

| Phase | Milestone | Status |
|---|---|---|
| **P00** | Repository bootstrap, threat model, OpenAPI snapshot validation & architectural decisions | Completed |
| **P01** | Core foundation: schema, migrations, `libsodium` crypto, persistence, authorization, admin diagnostics, audit & WP privacy hooks | **Completed (`v0.1.0-alpha.1`)** |
| **P02** | Mobile OTP challenge service, rate limiting, provider abstraction & Shahkar (`mobile ↔ national_code`) verification | Planned (Next) |
| **P03** | Bank card ownership verification (`card ↔ national_code + birth_date`) under the `C1` zero-PAN-storage model | Planned |
| **P04** | End-user UI & native integrations (WordPress Profile, WooCommerce My Account, Shortcode, Gutenberg Block) & REST endpoints | Planned |
| **P05** | Free v1.0 release hardening, end-to-end tests, localization & packaging | Planned |

---

## Requirements

- **PHP:** `>= 8.3`
- **Required PHP Extensions:** `sodium` (`ext-sodium` with `xchacha20poly1305_ietf`), `json`, `mbstring`, `openssl`
- **WordPress:** `>= 6.9` (Single-site supported in Free v1.0; network-wide Multisite activation is not supported)
- **Database:** MariaDB `>= 10.6` or MySQL `>= 8.0` (`InnoDB`, `utf8mb4`)
- **WooCommerce (Optional):** `>= 10.8` (only when WooCommerce integration is used; never a hard dependency)
- **HTTPS:** Required for live verification workflows

---

## Installation Instructions (Alpha Preview)

### Option 1: Install from the Alpha Release ZIP
1. Download `wp-identity-guard-v0.1.0-alpha.1.zip` from the release artifacts (or build it locally; see [Development Setup](#development-setup)).
2. In WordPress Admin, navigate to **Plugins → Add New Plugin → Upload Plugin**, select the ZIP file, and click **Install Now**.
3. Activate **WP Identity Guard**.
4. Navigate to **WP Admin → Identity Guard** to inspect the environment, database schema, and cryptographic key readiness diagnostics.

### Option 2: Install via WP-CLI
```bash
wp plugin install wp-identity-guard-v0.1.0-alpha.1.zip --activate
```

---

## Configuration Overview (`K1` / `K2` Cryptographic Keys)

WP Identity Guard never stores encryption or HMAC keys in the WordPress database and never falls back to WordPress salts (`AUTH_KEY`, etc.). When keys are not configured, the plugin activates safely and displays `ACTION_REQUIRED` in **WP Admin → Identity Guard**, while all cryptographic operations fail closed.

To configure keys for development or testing, define distinct 256-bit (32-byte) keys in `wp-config.php` (`K1`, recommended default) or as environment variables (`K2`):

```php
// Generate two distinct 32-byte random keys via CLI:
// php -r 'echo "base64:" . base64_encode(random_bytes(32)) . PHP_EOL;'

define( 'WPIG_ENC_KEY', 'base64:<your-32-byte-base64-encryption-key>' );
define( 'WPIG_ENC_KEY_ID', 'k2026_01' );
define( 'WPIG_ENC_KEYS_PREVIOUS', '' ); // Optional JSON map or key_id=base64:... list for rotation

define( 'WPIG_HMAC_KEY', 'base64:<your-distinct-32-byte-base64-hmac-key>' );
define( 'WPIG_HMAC_KEY_ID', 'h2026_01' );
define( 'WPIG_HMAC_KEYS_PREVIOUS', '' );
```

> [!CAUTION]
> - `WPIG_ENC_KEY` and `WPIG_HMAC_KEY` **must be cryptographically distinct** 32-byte keys (`K2` separation).
> - Never commit `wp-config.php` or real keys to version control.
> - Losing `WPIG_ENC_KEY` renders encrypted profile attributes permanently undecryptable.

---

## Security Architecture Overview & Boundaries

- **Fail-Closed Design (`ADR-004`):** Missing keys, missing `ext-sodium`, unauthenticated actors, missing capabilities, revoked/expired consent, or invalid authority grants cause operations to abort before mutating state.
- **Data Minimization at Rest (`C1` / `I2`):**
  - **Bank Cards (`C1`):** Full 16-digit card PANs are never stored in the database (neither in plaintext, encrypted, nor hashed form). Only `card_last4` (`CHAR(4)`) and `masked_pan` (`**** **** **** 1234`) are stored in `wpig_cards` as a display hint.
  - **Identity Attributes (`I2`):** National code, mobile number, and Jalali birth date are AEAD-encrypted (`XChaCha20-Poly1305-IETF`) with per-column 6-segment AAD (`wpig|v1|blog:<blog_id>|table:wpig_profiles.<column>|<wp_user_id>|<key_id>`). National codes and mobile numbers are indexed via purpose-separated `HMAC-SHA-256`.
- **Realistic Security Boundaries (No Exaggerated Guarantees):**
  - **Shared PHP Process:** Because WordPress plugins execute in a shared PHP runtime, a compromised administrator account or malicious co-installed plugin with file/code execution privileges can access `wp-config.php` constants and hook into PHP execution.
  - **Userland Memory Wiping:** `SensitiveValue` uses `sodium_memzero()` to zero its dedicated string buffer on `wipe()` and destruction, but PHP's Zend Engine copy-on-write string handling cannot guarantee erasure of pre-existing string copies prior to wrapping.
  - **Application-Layer Append-Only Audit Table:** `AuditRepository` exposes no `UPDATE` operations in PHP, but a database administrator (`DBA`) with direct SQL root access to MariaDB/MySQL can modify database rows unless external log shipping or DB-level privilege separation is used.

---

## Privacy Principles

- **Explicit Purpose-Bound Consent (`wpig_consents`):** Processing or decrypting identity attributes for verification dispatch requires an active, unrevoked, unexpired consent record bound to the user, site (`blog_id`), notice version, SHA-256 notice hash, and purpose.
- **Masked-Only Personal Data Export:** WordPress Personal Data Exports include only masked identity summaries (`******1234`, `0912***4567`), verification statuses, and consent timestamps—never raw ciphertexts, HMAC digests, or decrypted PII.
- **Anti-Abuse Binding Preservation (`D14`):** Personal data erasure clears unverified PII on `UNBOUND` profiles and revokes active consents, while preserving active `BOUND` national-code bindings (`bound_national_code_hmac`) and legal-hold (`REVIEW_REQUIRED`) records to prevent multi-account identity fraud.
- **Non-Destructive Uninstall Default (`D15`):** Deactivating or uninstalling the plugin preserves tables and audit history by default (`erase_on_uninstall = false`).

---

## Development Setup & Testing Instructions

### Prerequisites
- PHP `>= 8.3` with `ext-sodium`, `ext-mbstring`, `ext-json`, `ext-openssl`
- Composer `>= 2.7`
- Docker & Docker Compose (for live WordPress 7.0.2 + MariaDB 10.11.18 integration tests)

### Install Development Dependencies
```bash
composer install
```

### Run Offline & Static Quality Gates
```bash
composer validate --strict
composer lint            # PHP syntax check across all PHP files
composer cs              # PHP_CodeSniffer (WordPress Coding Standards)
composer stan            # PHPStan level 6 static analysis
composer test:unit       # PHPUnit unit test suite (50 tests, 750 assertions)
composer scan:sensitive  # Scan tracked files for accidental secrets or PII patterns
composer audit           # Composer dependency vulnerability audit
```

### Run WordPress + MariaDB Integration Tests (Docker)
```bash
docker compose up -d
docker compose exec -T -e WPIG_INTEGRATION_BOOTSTRAP=1 \
  -w /var/www/html/wp-content/plugins/wp-identity-guard \
  wordpress ./vendor/bin/phpunit --testsuite integration
```

---

## Contributing & Security Reporting

- Please read [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before opening issues or pull requests.
- **Never** submit real national codes, mobile numbers, bank card numbers, birth dates, OTPs, or API keys in issues, pull requests, or test fixtures. Use synthetic test data only.
- To report a security vulnerability privately, follow the instructions in [SECURITY.md](SECURITY.md).

---

## License

Copyright (C) 2026 ArcaneTeam and contributors.

WP Identity Guard is free software, released under the terms of the **GNU General Public License v2.0 or later** (`GPL-2.0-or-later`). See [LICENSE](LICENSE) for the full license text.

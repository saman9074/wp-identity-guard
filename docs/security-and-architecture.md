# WP Identity Guard (Free) — Security & Architecture Reference

This document describes the public technical architecture, database schema, cryptographic contracts, authorization model, and privacy boundaries implemented in **WP Identity Guard `v0.1.0-alpha.1` (P01 Foundation)**.

---

## 1. Support Floors & Runtime Boundaries

- **PHP:** `>= 8.3` with `ext-sodium`, `ext-json`, `ext-mbstring`, `ext-openssl`
- **WordPress:** `>= 6.9` (Single-site supported in Free v1.0)
- **WooCommerce:** `>= 10.8` (optional integration only; never a hard dependency)
- **Database:** MariaDB `>= 10.6` or MySQL `>= 8.0` (`InnoDB`, `utf8mb4`)
- **Zero Runtime Composer Dependencies:** The plugin uses a built-in PSR-4 autoloader for `WPIG\` in `wp-identity-guard.php` and ships no `vendor/` directory at runtime.

---

## 2. Database Schema (6 Per-Site Custom Tables)

All tables are prefixed with `$wpdb->prefix` for Multisite isolation and created with `InnoDB` and `utf8mb4` via `WPIG\Storage\SchemaDefinition` and `WPIG\Storage\SchemaMigrator` (protected by MariaDB/MySQL `GET_LOCK()` + owner-token heartbeat locking in `MigrationLock`):

| Table | Purpose | Key Invariants |
|---|---|---|
| `{$wpdb->prefix}wpig_profiles` | Per-user identity state, version counters, encrypted attributes & `D14` binding | `UNIQUE (wp_user_id)`, `UNIQUE (bound_national_code_hmac)`; stores `national_code_ciphertext`, `mobile_ciphertext`, `birth_date_ciphertext`, `*_hmac`, and `*_masked` only (zero plaintext PII). |
| `{$wpdb->prefix}wpig_verifications` | Append-only verification attempt and evidence ledger | `UNIQUE (idempotency_key)`; tracks `(identity_version, mobile_version, card_version)` captured at request time. |
| `{$wpdb->prefix}wpig_cards` | Masked bank card ownership evidence (`C1`) | `UNIQUE (active_user_slot)`; stores `card_last4` and `masked_pan` (`**** **** **** 1234`) only—zero full PAN, zero PAN ciphertext, zero PAN HMAC, zero BIN-6. |
| `{$wpdb->prefix}wpig_otp_challenges` | Short-lived, single-use OTP possession challenges | Stores keyed `code_hmac` and `mobile_hmac` only; tracks attempts and expiry. |
| `{$wpdb->prefix}wpig_consents` | Versioned user consent records | Stores `notice_version`, SHA-256 `notice_hash`, `purposes_json`, `accepted_at`, `revoked_at`, `expires_at`. |
| `{$wpdb->prefix}wpig_audit_events` | Application-layer append-only security audit log | Zero `UPDATE` methods in `AuditRepository`; stores `correlation_id`, actor/target IDs, allowlisted `event_type`/`outcome`, and sanitized `safe_metadata_json`. |

---

## 3. Cryptographic Contracts (`SodiumCrypto`, `CanonicalAad`, `WordPressKeyProvider`)

### 3.1 Key Management (`K1` / `K2`)
- **Default (`K1`):** `wp-config.php` constants (`WPIG_ENC_KEY`, `WPIG_ENC_KEY_ID`, `WPIG_ENC_KEYS_PREVIOUS`, `WPIG_HMAC_KEY`, `WPIG_HMAC_KEY_ID`, `WPIG_HMAC_KEYS_PREVIOUS`).
- **Alternative (`K2`):** Environment variables using the exact same canonical names when constants are not defined.
- **Strict Separation & Fail-Closed:** Encryption and HMAC keys must be distinct 32-byte (256-bit) high-entropy keys encoded as `base64:` or `hex:`. There is **zero fallback** to WordPress salts (`AUTH_KEY`, etc.), and missing or invalid keys fail closed before mutating state.

### 3.2 Authenticated Encryption Envelope (`v1`)
- **Cipher:** `sodium_crypto_aead_xchacha20poly1305_ietf_encrypt()` / `_decrypt()` with 24-byte `random_bytes(24)` nonces and 16-byte Poly1305 tags.
- **Format:** `v1:<key_id>:<base64_urlsafe_unpadded(nonce_24B || ciphertext_and_16B_tag)>`
- **Canonical 6-Segment AAD (`WPIG\Security\CanonicalAad`):**
  ```text
  wpig|v1|blog:<blog_id>|<entity_type>:<entity_name>|<subject_id>|<key_id>
  ```
  Example: `wpig|v1|blog:1|table:wpig_profiles.national_code_ciphertext|42|k2026_01`

### 3.3 Purpose-Separated Fingerprints (`HMAC-SHA-256`)
- Computed via `hash_hmac('sha256', $purpose . '|' . $canonical_value, $raw_key, false)` (`64`-char lowercase hex) with domain-separation tags:
  - `wpig:v1:national_code`
  - `wpig:v1:mobile`
  - `wpig:v1:otp_challenge`
  - `wpig:v1:ip_rate`

---

## 4. Identity Binding (`D14`), Authorization & Privacy

- **Identity Binding vs. Verification Freshness (`D14`):**
  - `UNBOUND` profiles have `bound_national_code_hmac = NULL` and never reserve a national code.
  - Once verified and `BOUND`, `bound_national_code_hmac` is enforced unique across the site (`uq_wpig_profiles_bound_nc`).
  - Verification freshness expiry (`mark_expired_if_past()`) transitions only `identity_state` to `'EXPIRED'` while keeping `binding_state = 'BOUND'` and `bound_national_code_hmac` intact, preventing any other account from claiming an expired user's national code.
- **Capabilities (`WPIG\Security\Capabilities`):**
  - Registers exactly three capabilities (`manage_wpig_settings`, `view_wpig_reports`, `review_wpig_verification`) on `administrator` by default and strips them from unprivileged roles (`subscriber`, `customer`, `editor`, `shop_manager`, etc.).
- **Authentication & Boundary Enforcement:**
  - `AuthenticationContext` validates HTTP actors against `get_current_user_id()`, rejecting spoofed `$actor_user_id` inputs.
  - `ProfileAccessBoundary` requires persisted, unrevoked, unexpired `ConsentRecord` proof and a single-use, same-process HMAC-sealed `VerificationAuthorityGrant` before calling `ProfileRepository::bind_verified_identity()`.
- **Privacy & Retention (`D15`):**
  - WordPress Personal Data Exporter outputs masked summaries only.
  - WordPress Personal Data Eraser withdraws active consents and clears `UNBOUND` profile PII while preserving `BOUND` (`D14`) and `REVIEW_REQUIRED` / legal-hold records.
  - `RetentionService` defaults to `$policy_approved = false` (`DISABLED_POLICY_UNRESOLVED`) so no arbitrary legal retention period is invented before site policy approval.
  - Deactivation and default uninstallation preserve all tables and records (`erase_on_uninstall = false`).

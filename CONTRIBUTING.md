# Contributing to WP Identity Guard

Thank you for your interest in contributing to **WP Identity Guard (Free)**. Because this plugin handles high-sensitivity identity verification and cryptographic boundaries, all contributions must follow strict security, privacy, and testing standards.

---

## 1. Mandatory Security & Synthetic-Data Rules

1. **Zero Real PII or Card Data:** Never place real national codes, real mobile numbers, real 16-digit bank card numbers (PANs), real birth dates, or real user records in code, comments, test fixtures, commit messages, issues, or pull requests. Use clearly synthetic values only.
2. **Zero Secrets in Git:** Never commit API keys, bearer tokens, `WPIG_ENC_KEY` / `WPIG_HMAC_KEY` production values, `.env` files, or captured live HTTP traffic (`*.har`, `*.live.json`).
3. **Fail Closed (`ADR-004`):** Any missing cryptographic key, missing capability, unauthenticated principal, revoked/expired consent record, or invalid input must fail closed without mutating persisted state.
4. **No Custom Cryptography:** Use only PHP's `ext-sodium` (`sodium_crypto_aead_xchacha20poly1305_ietf_*`, `sodium_memzero()`) and `hash_hmac('sha256', ...)` through `WPIG\Contracts\CryptoInterface` and `WPIG\Security\CanonicalAad`.
5. **No Full Card PAN Persistence (`C1`):** Free v1.0 must never persist full 16-digit bank card numbers (neither in plaintext, encrypted, nor hashed form). Only `card_last4` and `masked_pan` may be persisted in `wpig_cards`.
6. **Zero Runtime Composer Dependencies:** The Free plugin uses a built-in PSR-4 autoloader in `wp-identity-guard.php` and ships zero `vendor/` packages at runtime. Composer is used strictly for `require-dev` QA tools.

---

## 2. Development Environment Setup

### Requirements
- PHP `>= 8.3` with `sodium`, `mbstring`, `json`, and `openssl` extensions enabled
- Composer `>= 2.7`
- Docker & Docker Compose (for WordPress 7.0.2 + MariaDB 10.11.18 integration tests)

### Setup Steps
```bash
git clone https://github.com/saman9074/wp-identity-guard.git
cd wp-identity-guard
composer install
```

---

## 3. Quality Gates (Required Before Submitting a Pull Request)

Every pull request must pass all offline, static analysis, unit test, and integration test gates:

```bash
# 1. Validate composer.json and composer.lock
composer validate --strict

# 2. PHP syntax lint across all PHP files
composer lint

# 3. WordPress Coding Standards (PHP_CodeSniffer)
composer cs

# 4. PHPStan level 6 static analysis
composer stan

# 5. PHPUnit unit test suite
composer test:unit

# 6. Offline sensitive-data scan
composer scan:sensitive

# 7. Composer dependency security audit
composer audit --no-interaction
```

To run the full WordPress + MariaDB integration test suite in Docker:

```bash
docker compose up -d
docker compose exec -T -e WPIG_INTEGRATION_BOOTSTRAP=1 \
  -w /var/www/html/wp-content/plugins/wp-identity-guard \
  wordpress ./vendor/bin/phpunit --testsuite integration
```

---

## 4. Coding Standards & Commit Guidelines

- **Strict Types:** Every PHP class file under `src/`, `tests/`, and `tools/` must declare `declare(strict_types=1);`.
- **WordPress Coding Standards:** Follow `phpcs.xml.dist` (`WordPress-Core`, `WordPress-Docs`, `WordPress-Extra`, `PHPCompatibilityWP` targeting PHP `8.3-`).
- **Database Queries:** Always use `$wpdb->prepare()` for parameterized SQL queries and `$wpdb->prefix` via `SchemaDefinition::get_table_names()` for Multisite isolation.
- **Conventional Commits:** Use clear, scoped commit messages such as:
  - `feat(p02): implement OTP challenge repository`
  - `fix(security): reject expired consent on decryption boundary`
  - `docs(release): update installation instructions`
  - `test(integration): verify concurrent binding race handling`

---

## 5. Licensing of Contributions

By submitting a pull request or patch to this repository, you agree that your contribution is licensed under the **GNU General Public License v2.0 or later (`GPL-2.0-or-later`)**, as found in the [LICENSE](LICENSE) file.

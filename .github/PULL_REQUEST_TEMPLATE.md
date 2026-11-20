## Summary

<!-- Describe what this pull request changes and why. -->

## Phase / Component Scope

- [ ] `P01` Foundation (`Schema`, `Crypto`, `Persistence`, `Auth`, `Admin`, `Audit`, `Privacy`)
- [ ] `P02` OTP & Shahkar Verification
- [ ] `P03` Bank Card Ownership Verification (`C1`)
- [ ] `P04` Native UI & REST Integrations
- [ ] `P05` Tooling, CI, Documentation, or Release Packaging

## Security & Data-Minimization Checklist

- [ ] **Zero Real PII / Secrets:** No real national codes, mobile numbers, bank card PANs, birth dates, OTPs, API keys, or encryption keys are present in code, tests, comments, or commit messages.
- [ ] **Fail-Closed Enforcement (`ADR-004`):** Missing keys, unauthenticated principals, missing capabilities, revoked/expired consent, or invalid inputs fail closed before mutating state.
- [ ] **Data Minimization (`C1` / `I2`):** No full card PAN is persisted or fingerprinted (`C1`); sensitive identity fields use `SodiumCrypto` AEAD with 6-segment `CanonicalAad` and purpose-separated `HMAC-SHA-256` (`I2`).
- [ ] **Prepared SQL & Multisite Isolation:** All database queries use `$wpdb->prepare()` and `$wpdb->prefix` via `SchemaDefinition::get_table_names()`.

## Quality Gates Verified Locally

- [ ] `composer validate --strict`
- [ ] `composer lint`
- [ ] `composer cs`
- [ ] `composer stan` (PHPStan level 6)
- [ ] `composer test:unit`
- [ ] `composer scan:sensitive`
- [ ] `composer audit --no-interaction`
- [ ] `./vendor/bin/phpunit --testsuite integration` (WordPress + MariaDB integration test suite)

## License Agreement

By submitting this pull request, I confirm that my contribution is licensed under the **GNU General Public License v2.0 or later (`GPL-2.0-or-later`)**.

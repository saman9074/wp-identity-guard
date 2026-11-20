# Security Policy

## Project Status & Supported Versions

**WP Identity Guard** is currently in **early alpha preview (`v0.1.0-alpha.1` — P01 Foundation)**. Live identity verification providers, SMS OTP delivery, and bank card ownership verification are not yet implemented, and no release is currently certified for production identity verification.

| Version | Supported for Security Fixes | Notes |
|---|---|---|
| `0.1.0-alpha.x` | Yes (Development preview) | Active `P01` Foundation preview branch |
| `< 0.1.0-alpha.1` | No | Pre-alpha bootstrap scaffolds |

---

## Reporting a Vulnerability Privately

**Do not report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

Please report suspected vulnerabilities privately using **GitHub Private Vulnerability Reporting**:

1. Navigate to the repository's Security tab:
   **https://github.com/saman9074/wp-identity-guard/security/advisories/new**
2. Provide a clear description of the issue, affected component/file and line numbers, preconditions, and a minimal proof of concept using **synthetic test data only**.

### What to Include
- Affected version or commit SHA.
- Component involved (e.g., `SodiumCrypto`, `CanonicalAad`, `ProfileRepository`, `ProfileAccessBoundary`, `AuthorizationService`, `AdminController`, `AuditService`, `PrivacyEraserService`).
- Step-by-step reproduction instructions using synthetic data.
- Assessment of potential impact (e.g., authorization bypass, cross-user IDOR, Multisite isolation breach, sensitive data leak).

### Strict Data Hygiene Rules for Security Reports
- **Never** include real Iranian national codes, real mobile numbers, real 16-digit bank card numbers (PANs), real birth dates, live OTP codes, production API keys, encryption/HMAC keys, or captured traffic from real individuals.
- **Never** test against third-party identity or SMS providers without explicit authorization from the account owner.

---

## Coordinated Disclosure Process

As an open-source pre-release project, we aim to follow these targets on a best-effort basis:

1. **Acknowledgment:** Confirm receipt of a private vulnerability report within **5 business days**.
2. **Triage & Validation:** Validate the finding and determine severity and remediation scope within **10 business days**.
3. **Remediation & Advisory:** Develop and verify a fix (with unit and integration regression tests) and coordinate disclosure via a GitHub Security Advisory once the patch is available.

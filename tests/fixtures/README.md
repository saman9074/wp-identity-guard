# Test fixtures — fictitious data only

**Never** place real national codes, mobile numbers, card numbers (PAN), birth dates,
OTP codes, API keys, tokens, provider captures or screenshots of real people here.

Rules:
- Fixtures are hand-written or generated at test runtime from deterministic seeds.
- Card numbers must use clearly fictitious values (e.g. non-issued BIN ranges or
  Luhn-invalid strings where the test does not exercise the checksum).
- Provider response fixtures must be synthetic schemas constructed from documented
  contract interfaces, never captured from live traffic or proprietary vendor snapshots.
- `tests/fixtures/live/` and `*.live.json` are git-ignored and must stay empty in CI.
- `composer scan:sensitive` must pass before every commit.

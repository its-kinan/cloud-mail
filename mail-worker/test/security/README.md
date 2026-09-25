# Security tests

These cover the hardening work on the `hardening/security-fixes` branch:

- `crypto.test.mjs` — PBKDF2 password hashing, legacy-hash migration path, iteration tuning
- `svix.test.mjs` — Resend webhook signature verification
- `exempt-path.test.mjs` — auth middleware path exemptions

The repo's vitest setup targets `@cloudflare/vitest-pool-workers` (see the root
`vitest.config.js`), but these modules are pure WebCrypto/JS with no Worker
imports, so they run directly on Node 18+:

```
node --test test/security/
```

Note: the test files import from `../../src/utils/` — keep them in this directory.

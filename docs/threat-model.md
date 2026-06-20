# Threat Model

This document describes what oathkeeper defends against, what it explicitly does not defend against, and the design decisions that implement each defense. Read this before using the library in a security-sensitive context.

---

## Scope

oathkeeper is an **authentication and coarse-grained authorization** library. It answers two questions:

1. **Authentication** — Is this user who they claim to be? (login, session management, MFA)
2. **Authorization** — Does this user hold the required permission or role?

Everything outside those two questions is the application's responsibility.

---

## Defended threats

### Brute-force password attacks

**Threat:** An attacker submits a large number of password guesses against a known account (targeted) or across many accounts (spraying).

**Defense:**
- `argon2id` with OWASP 2023 parameters (~250ms/hash, 64MB memory). GPU-based cracking is economically infeasible.
- Per-account rate limiting (5 attempts / 15 min) stops targeted attacks.
- Per-IP rate limiting (20 attempts / 15 min) stops spraying from a single IP.
- Both limits coexist: distributed IPs bypass per-IP alone; per-account catches them regardless.
- `/login/mfa` is also rate-limited — a stolen MFA challenge token with 10 remaining windows is protected.

**Residual risk:** Distributed botnets using many IPs and many accounts simultaneously. Defending against this requires behavioral analysis and device fingerprinting, which are out of scope.

---

### Credential stuffing

**Threat:** An attacker uses a database of leaked email/password pairs from other breaches to log in.

**Defense:**
- Strong password hashing (argon2id) makes cracking the leaked hash infeasible before the user can be notified.
- TOTP MFA as a second factor — correct credentials alone are not enough.
- Rate limiting slows high-volume automated attempts.

**Residual risk:** Passwords that are reused verbatim from a breach with plaintext exposure. A HaveIBeenPwned check at signup is not implemented (out of scope for v1).

---

### Session hijacking (stolen tokens)

**Threat:** An attacker obtains a valid refresh token and uses it to maintain access indefinitely.

**Defense:**
- Refresh tokens are **rotated on every use** — a used token is immediately revoked and replaced.
- **Reuse detection** — if a token that has already been rotated is presented, the entire token family is revoked and the user is logged out everywhere. The attacker's stolen copy becomes instantly worthless the moment the legitimate user acts.
- **SHA-256 at rest** — the database stores `sha256(rawToken)`, never the raw value. A DB dump reveals nothing usable.
- Short access token TTL (default 15 min) limits the window of a stolen access token.

**Residual risk (known false positive):** A client on a flaky connection may receive a new token but fail to persist it, then retry with the old (now-revoked) token — which fires reuse detection and logs the user out. Treat `AUTH.REFRESH_REUSE_DETECTED` as "ask the user to log in again," not as a confirmed breach.

---

### Account enumeration

**Threat:** An attacker determines whether an email address has an account by observing different responses or timing.

**Defense:**
- `/login` returns `AUTH.INVALID_CREDENTIALS` for both "no account" and "wrong password" — identical message.
- A dummy hash (`hasher.verify(password, await _dummyHash)`) is computed even when no account exists, making the response time identical regardless.
- `/password/reset/request` and `/email/verify/request` always return the same generic `200`, whether or not the email exists.

---

### Token forgery

**Threat:** An attacker forges a JWT to impersonate a user or escalate privileges.

**Defense:**
- JWT algorithm is pinned to `HS256` in `createJwtSigner` — the `alg: none` attack (CVE-2015-9235) is blocked at the library level.
- The `jwtSecret` is validated at boot to be ≥ 32 bytes of entropy. Short secrets are brute-forceable offline against captured tokens.
- Purpose-scoped tokens: the MFA challenge JWT carries `purpose: 'mfa_challenge'`; `/login/mfa` validates this claim explicitly so a regular access token cannot be used to bypass MFA.

---

### Cross-Site Request Forgery (CSRF)

**Threat:** A malicious page tricks the victim's browser into making a state-changing request (e.g., token refresh) using their cookie.

**Defense:** Double-submit cookie pattern (when `csrf: true` and `cookieMode: true`):
1. Login response sets a non-HttpOnly `csrf_token` cookie alongside the `refreshToken` cookie.
2. Client JavaScript reads `csrf_token` and echoes it as `X-CSRF-Token` on every mutating request.
3. The server compares cookie to header in constant time.
4. A cross-origin attacker cannot read the victim's `csrf_token` cookie (Same-Origin Policy), so it cannot forge the header.

**Automatically skipped** for `Authorization: Bearer` requests — not cookie-based, not vulnerable.

---

### Mass assignment / privilege escalation via updates

**Threat:** An attacker includes unexpected fields in a request body (e.g., `role: 'admin'`, `emailVerified: true`) and the application writes them to the DB.

**Defense:** `updateUser` in `postgresStorage` maintains an explicit `ALLOWED_PATCH_FIELDS` whitelist. Any field not on the list throws immediately rather than being silently ignored.

---

### Soft-deleted user re-access

**Threat:** A user account is suspended or deleted, but existing tokens remain valid.

**Defense:** `authenticate` middleware performs a live DB lookup by `user_id` on every request. Soft-deleted, suspended, or locked users are rejected with `401 USER_NOT_FOUND` even if their JWT is otherwise valid and unexpired. The token TTL is irrelevant — the DB is authoritative.

---

### Insecure password reset

**Threat:** Password reset links that are predictable, reusable, long-lived, or that don't invalidate existing sessions.

**Defense:**
- Reset tokens are 32 bytes of `crypto.randomBytes` (base64url) — not predictable.
- Stored as `SHA-256(rawToken)` — a DB dump does not give the attacker the reset link.
- Single-use: the DB `UPDATE ... WHERE used_at IS NULL ... RETURNING *` is atomic under concurrency — exactly one request wins.
- Time-bound: 30-minute TTL (configurable, but short by default).
- **Revokes all refresh tokens** on successful reset — a hijacked session cannot survive the password reset.

---

### SQL injection

**Defense:** All database queries use parameterized statements (`$1`, `$2`, etc.) exclusively. No string interpolation of user input into SQL.

---

### Timing attacks on token comparison

**Threat:** An attacker measures how long a comparison takes to guess secret values byte-by-byte.

**Defense:** `timingSafeEqual` (from `src/utils/constantTime.js`, wrapping `crypto.timingSafeEqual`) is used wherever secrets are compared — CSRF tokens, and anywhere the library compares string values. Argon2's `verify` is also constant-time by library design.

---

### TOTP replay

**Threat:** An attacker intercepts a valid TOTP code and replays it within the same 30-second window.

**Defense:** The replay store tracks used `{secretFingerprint}:{counter}` keys for one window. A code that has already been accepted is rejected even if submitted again within the same window. The key uses a 16-char SHA-256 fingerprint of the secret rather than the raw secret to avoid leaking TOTP secrets into the key namespace.

---

## Out of scope (your responsibility)

| Threat | Reason out of scope |
|---|---|
| Business-logic authorization | Specific to your domain; RBAC + policies provide the mechanism |
| API key authentication | Different auth scheme; adapter seam exists for future addition |
| Server-Side Request Forgery (SSRF) | HTTP client behavior; not an auth concern |
| WebAuthn / Passkeys | Different protocol; not planned for v1 |
| Suspicious login signals (geo, device, velocity) | Requires behavioral analysis infrastructure |
| HaveIBeenPwned check at signup | External API dependency; opt-in for the application |
| DDoS protection at network level | Requires infrastructure-level tooling (WAF, CDN) |
| Secrets management (env var leaks) | Deployment concern; library validates they're present and strong |
| Distributed rate limiting | In-memory only in v1; Redis adapter is the documented upgrade path |

---

## ⚠️ In-memory state — single-process limitation

Two critical security components hold state in process memory:

**Rate limiter (`createMemoryRateLimit`)** — sliding-window counters.
**Replay store (`createMemoryReplayStore`)** — TOTP anti-replay keys.

In a single-process Node.js deployment, these work correctly. In any multi-process deployment — Node cluster, PM2 cluster mode, multiple Kubernetes pods, or any load-balanced setup with more than one process — **each process has its own independent state**:

- A user who hits the rate limit on process A is not rate-limited on process B.
- A TOTP code used on process A can be replayed on process B within the same window.

**This is a real security regression in multi-process deployments.** The fix is a shared Redis-backed adapter implementing the same `RateLimitAdapter` and replay store interfaces. Both interfaces are minimal (2-3 methods each) and straightforward to implement against Redis. This is explicitly the next planned improvement.

Until then: if you run more than one Node.js process, understand and accept this limitation, or implement the Redis adapters.

---

## Assumptions

The threat model assumes:

- The server runs over **HTTPS** (`cookieOptions.secure: true` in production). Unencrypted HTTP exposes all tokens.
- The `jwtSecret` is kept secret from end users and not committed to version control.
- The PostgreSQL database is not publicly accessible.
- The application does not introduce mass-assignment vulnerabilities in its own routes outside of oathkeeper's storage layer.
- Email delivery is reasonably reliable — a delayed reset email is a usability problem, not a security problem.

# oathkeeper

Production-grade authentication and authorization library for Node.js + Express + PostgreSQL.

Raw `pg`, no ORM. CommonJS. Every security default is enforced, not optional.

> **Why this exists.** oathkeeper was built as a learning project — the goal is to understand *the why* behind every auth best practice by implementing it from first principles. Every decision in this codebase (the dummy hash on unknown email, the algorithm-pinned JWT verify, the atomic one-time-token consume, the field whitelist on DB updates) maps to a specific, named, exploited attack. The code and docs explain the reasoning, not just the API.

---

## ⚠️ Current Implementation Notice — In-Memory State

**Two security-critical components run entirely in process memory:**

- **Rate limiter** (`createMemoryRateLimit`) — sliding-window counters stored in a `Map`
- **TOTP replay store** (`createMemoryReplayStore`) — anti-replay keys stored in a `Map`

**This means the current implementation is single-process only.** In any deployment with more than one Node.js process (Node cluster, PM2 cluster mode, multiple Kubernetes pods, any load-balanced setup), each process maintains its own independent counters. A user rate-limited on process A is not rate-limited on process B. A TOTP code used on process A can be replayed on process B within the same 30-second window.

**The roadmap fix is a Redis-backed adapter** for both components. Both interfaces (`RateLimitAdapter`, replay store) are minimal — 2-3 methods each — and straightforward to implement against Redis. This upgrade is the highest-priority next step before any horizontally-scaled deployment.

Until then: run oathkeeper on a **single process only**, or implement and plug in the Redis adapters.

---

## What you get

- **Password storage** with argon2id (memory-hard, GPU-resistant), tuned to OWASP 2023 parameters
- **Stateless access tokens** (short-lived JWTs, HS256, algorithm-pinned) + **stateful refresh tokens** (long-lived, SHA-256-hashed at rest, rotated on every use)
- **Refresh token rotation with reuse detection** — a stolen token self-destructs the moment the legitimate user acts
- **Account enumeration defenses** — uniform responses and constant-time login regardless of whether an account exists
- **MFA** via TOTP (RFC 6238) with replay protection and argon2id-hashed one-time recovery codes
- **Email verification** and **password reset** with opaque, single-use, time-bound tokens
- **Authorization** — RBAC as the floor, an optional ABAC-style policy registry for resource-level rules
- **Rate limiting** — dual-key (per-email + per-IP) on login, per-IP on refresh and MFA endpoints
- **CSRF protection** — double-submit cookie pattern for cookie-mode deployments
- **Structured audit log** — every auth event written to `auth_events` with `user_id`, IP, user-agent, and JSONB metadata
- **Boot-time config validation** — bad config crashes at startup with an actionable error, not during a user's first login
- **Adapter pattern everywhere** — swap the hasher, signer, storage, rate limiter, or mail transport without touching auth logic

---

## Requirements

- Node.js 22+
- PostgreSQL 16+ (uses `gen_random_uuid()`, `CITEXT`, `JSONB`, `INET`, `timestamptz`)
- An email transport you provide (any object matching `{ sendMail: async ({ to, subject, html }) => {} }`)

oathkeeper never opens its own database connection, mail transport, or HTTP server. The host application provides all three.

---

## Installation

```bash
npm install oathkeeper
```

> `argon2` is a native module that compiles on install. If it fails, you likely need C build tools: `npm install --build-from-source argon2`. On ARM Macs this sometimes needs the Xcode Command Line Tools.

---

## Database setup

Run the migrations before starting the server:

```bash
npm run db:migrate
# or: node --env-file=.env scripts/migrate.js
```

```bash
# Spin up a local Postgres for development:
docker run -e POSTGRES_PASSWORD=dev -p 5432:5432 -d postgres:16
```

| Migration | Table(s) | Purpose |
|---|---|---|
| `001_users.sql` | `users` | Accounts (UUID PK, `CITEXT` email, `password_hash`, soft-delete) |
| `002_refresh_tokens.sql` | `refresh_tokens` | Hashed refresh tokens with `family_id` + rotation chain |
| `003_email_verification_tokens.sql` | `email_verification_tokens` | One-time, hashed, time-bound |
| `004_password_reset_tokens.sql` | `password_reset_tokens` | One-time, hashed, 30-minute TTL |
| `005_mfa_recovery_codes.sql` | `mfa_recovery_codes` | argon2id-hashed backup codes, single-use |
| `006_rbac.sql` | `roles`, `permissions`, `user_roles`, `role_permissions` | Role-based access control |
| `007_auth_events.sql` | `auth_events` | Structured audit log (JSONB metadata, indexed by `user_id` and `type`) |

---

## Quickstart — 30 lines to working auth

```bash
# Generate a strong secret (required — the library refuses to boot without it)
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

```js
const express = require('express');
const { Pool } = require('pg');
const { createAuth, createConsoleMail } = require('oathkeeper');

const app = express();
app.use(express.json());

const auth = createAuth({
  pool: new Pool({ connectionString: process.env.DATABASE_URL }),
  jwtSecret: process.env.JWT_SECRET,   // ≥ 32 bytes — crashes at boot if wrong or missing
  baseUrl: 'http://localhost:3000',    // used in email links
  mailer: createConsoleMail(),         // prints emails to stdout — swap for real transport
});

// Mounts: POST /auth/signup  /auth/login  /auth/logout  /auth/refresh
//         /auth/login/mfa    /auth/password/reset/request  /auth/password/reset/confirm
//         /auth/password/change  /auth/mfa/enroll  /auth/mfa/confirm  /auth/mfa/disable
app.use('/auth', auth.router);

// Protect any route — populates req.user or returns 401
app.get('/profile', auth.authenticate, (req, res) => {
  res.json({ user: req.user });
});

app.listen(3000, () => console.log('http://localhost:3000'));
```

That's signup, login, logout, refresh, email verification, password reset, password change, and MFA — running.

See `examples/minimal/index.js` for a copy-pasteable version and `examples/full/index.js` for rate limiting, CSRF, RBAC, and ABAC policies.

---

## Configuration reference

```js
const auth = createAuth({
  // ── required ──────────────────────────────────────────────────────
  pool,                                  // pg.Pool — you open it, you close it
  jwtSecret: process.env.JWT_SECRET,     // ≥ 32 bytes of real entropy
  baseUrl: 'https://app.example.com',    // prefix for email verification / reset URLs
  mailer: { sendMail: async ({ to, subject, html }) => { /* ... */ } },

  // ── optional (defaults shown) ─────────────────────────────────────
  accessTokenTtl:  '15m',    // JWT TTL — must be > 0
  refreshTokenTtl: '7d',     // DB token TTL — must be ≥ accessTokenTtl
  issuer: 'oathkeeper',      // shown in TOTP authenticator apps

  // Cookie mode: refresh token as HttpOnly cookie (browser).
  // Header mode (default): both tokens in JSON body (mobile / API).
  cookieMode: false,
  cookieOptions: {
    secure: true,            // false in production → loud warning (not crash)
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  },

  // argon2 tuning — lower for tests, never lower for production
  hasherConfig: {
    memoryCost: 65536,       // 64 MB
    timeCost: 3,
    parallelism: 4,
  },

  // Rate limiters — built with createRateLimitMiddleware(), passed here
  rateLimiters: {
    login:   [perEmailLimiter, perIpLimiter],
    refresh: [refreshIpLimiter],
    mfa:     [],             // falls back to login limiters if omitted
  },

  csrf: false,               // true enables double-submit CSRF (cookie mode only)
  nodeEnv: process.env.NODE_ENV,
});
```

| Key | Required | Default | Description |
|---|---|---|---|
| `pool` | ✅ | — | `pg.Pool` instance |
| `jwtSecret` | ✅ | — | Min 32 bytes. Crashes at boot if missing or too short |
| `baseUrl` | ✅ | — | Used in email verification and password reset links |
| `mailer` | ✅ | — | `{ sendMail: async ({ to, subject, html }) => {} }` |
| `accessTokenTtl` | | `'15m'` | JWT lifetime. `'0s'` is rejected at boot |
| `refreshTokenTtl` | | `'7d'` | DB token lifetime. Must be ≥ `accessTokenTtl` |
| `issuer` | | `'oathkeeper'` | TOTP issuer label in authenticator apps |
| `cookieMode` | | `false` | `true` → HttpOnly cookie. `false` → JSON body |
| `cookieOptions` | | `{}` | Forwarded to `res.cookie()` |
| `hasherConfig` | | argon2 defaults | `{ memoryCost, timeCost, parallelism }` |
| `rateLimiters` | | `{}` | Map of middleware arrays per route group |
| `csrf` | | `false` | Enable double-submit cookie CSRF (cookie mode only) |
| `nodeEnv` | | `process.env.NODE_ENV` | Used for production cookie-security warning |

---

## The `auth` object

```js
auth.router           // Express Router — mount with app.use('/auth', auth.router)
auth.authenticate     // Middleware: populates req.user + req.auth, or 401
auth.storage          // Raw storage adapter — needed to build rbacService
auth.authService      // Service: signup, login, logout, email, password, MFA
auth.tokenService     // Service: issue, rotate, revoke tokens
auth.mfaService       // Service: enroll, confirm, disable MFA
```

### `req.user` after `authenticate`

```js
req.user = {
  id:            '<uuid>',
  email:         'alice@example.com',
  email_verified: true,
  mfa_enabled:   false,
  last_login_at: '2025-01-01T00:00:00.000Z',
  permissions:   Set { 'doc:read', 'doc:edit' },  // Set<string>
  roles:         [{ id: '<uuid>', name: 'editor' }],
};

req.auth = {
  tokenPayload:   { sub: '<uuid>', email: '...', iat: ..., exp: ... },
  isMfaSatisfied: false,
};
```

`authenticate` does a live DB lookup on every request — a soft-deleted or suspended user is rejected with `AUTH.USER_NOT_FOUND` even if their JWT is valid and unexpired.

---

## HTTP routes

All routes mount under whatever prefix you choose (examples use `/auth`).

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/signup` | — | Create account. 201 on success, 409 on duplicate email |
| `POST` | `/login` | — | Email + password → tokens, or MFA challenge |
| `POST` | `/login/mfa` | mfaToken | Submit TOTP code or recovery code to finish login |
| `POST` | `/refresh` | refresh token | Rotate → new access + refresh pair |
| `POST` | `/logout` | refresh token | Revoke refresh token, clear cookie |
| `POST` | `/password/reset/request` | — | Send reset email (always 200, enumeration-safe) |
| `POST` | `/password/reset/confirm` | — | Token + new password → reset + revoke all sessions |
| `POST` | `/password/change` | Bearer | Current password + new password |
| `POST` | `/mfa/enroll` | Bearer | Begin TOTP enrollment — returns secret + otpauth URI |
| `POST` | `/mfa/confirm` | Bearer | Submit first code to activate MFA + get recovery codes |
| `POST` | `/mfa/disable` | Bearer | Disable MFA (requires password **and** TOTP code) |

### Cookie mode vs header mode

**Header mode** (default — mobile / API / CLI): both tokens returned in the JSON response body. Client stores the access token in memory and sends it as `Authorization: Bearer <token>`.

**Cookie mode** (`cookieMode: true` — browser): the refresh token is set as an `HttpOnly`, `Secure`, `SameSite=Lax` cookie scoped to `Path: /auth/refresh`, so the browser only sends it to that one endpoint. The access token comes back in the JSON body and is stored in memory (never in `localStorage`). When `csrf: true`, login also sets a non-HttpOnly `csrf_token` cookie for the double-submit pattern.

> The refresh cookie `Path` must exactly match the mount point. If you mount at `/api/auth`, the cookie needs `path: '/api/auth/refresh'` — pass this in `cookieOptions`.

---

## Rate limiting

```js
const { createMemoryRateLimit, createRateLimitMiddleware } = require('oathkeeper');

// ⚠️ In-memory — single-process only. See the warning at the top of this README.
const adapter = createMemoryRateLimit();

const perEmailLimiter = createRateLimitMiddleware({
  keyFn: (req) => req.body?.email?.toLowerCase(),
  limit: 5,
  windowMs: 15 * 60 * 1000,
  adapter,
});

const perIpLimiter = createRateLimitMiddleware({
  keyFn: (req) => req.ip,
  limit: 20,
  windowMs: 15 * 60 * 1000,
  adapter,
});

const auth = createAuth({
  ...
  rateLimiters: { login: [perEmailLimiter, perIpLimiter] },
});
```

On the 6th attempt within the window, `AUTH.RATE_LIMITED` (429) is returned with a `Retry-After` header.

The sliding-window algorithm smooths counter resets so a user cannot burst exactly at window boundaries. When a key has been idle for 2× the window duration, its entry is deleted from memory — the Map does not grow unboundedly.

---

## CSRF protection

Enabled with `csrf: true` alongside `cookieMode: true`.

```js
const auth = createAuth({
  cookieMode: true,
  cookieOptions: { secure: true, sameSite: 'lax' },
  csrf: true,
});
```

How it works:
1. Successful login sets a non-HttpOnly `csrf_token` cookie (JavaScript-readable).
2. Your client reads the cookie and sends it as `X-CSRF-Token` on every mutating request.
3. The server compares the header to the cookie in constant time on `POST /refresh` and other cookie-mode endpoints.
4. A cross-origin attacker cannot read the victim's `csrf_token` (Same-Origin Policy), so it cannot forge the header.

Automatically skipped for `Authorization: Bearer` requests — not cookie-based, not vulnerable.

---

## Authorization (RBAC + policies)

RBAC is app-level — the library provides the mechanism, your application provides the rules.

```js
const { createRbacService, createPermissions, createRoleGuard } = require('oathkeeper');

const rbac = createRbacService({
  storage: auth.storage,   // shares the same pg.Pool
  policies: {
    // ABAC policy: RBAC grants 'doc:edit', policy narrows to document owners.
    // Policies can ONLY restrict, never grant — RBAC is always checked first.
    'doc:edit': (user, doc) => doc.ownerId === user.id,
  },
});

const { requirePermission } = createPermissions({ rbacService: rbac });
const { requireRole }       = createRoleGuard({ rbacService: rbac });

// Role + permission CRUD
const editorRole = await rbac.createRole('editor');
await rbac.addPermissionToRole(editorRole.id, 'doc:edit');
await rbac.assignRole(userId, editorRole.id);

// Route guards
app.put('/documents/:id', auth.authenticate, requirePermission('doc:edit'), handler);
app.get('/admin',         auth.authenticate, requireRole('admin'),          handler);

// Programmatic check with ABAC policy
const allowed = await rbac.can(req.user, 'doc:edit', document);
```

**How `can()` works:**
1. Checks RBAC — does this user hold the permission through any role?
2. If yes, and a policy is registered for this permission, runs the policy with `(user, resource)`.
3. Returns `true` only if both pass.

Policies can only restrict, never grant. An attacker cannot manufacture access by manipulating a resource's attributes because RBAC is always the floor.

---

## MFA (TOTP)

Enrollment is two-step to prevent lock-out from half-finished setup:

```js
// Step 1: begin — returns secret + otpauth:// URI for QR code
POST /auth/mfa/enroll
→ { secret: 'BASE32...', uri: 'otpauth://totp/...' }

// Step 2: confirm — prove the user scanned the QR code
POST /auth/mfa/confirm  { "code": "123456" }
→ { recoveryCodes: ["a1b2c3...", ...] }   // 10 codes, shown once, store safely

// Login flow when MFA is enabled:
POST /auth/login  { email, password }
→ 403  { code: "AUTH.MFA_REQUIRED", mfaToken: "<jwt>" }

POST /auth/login/mfa  { mfaToken, code }
→ { user, accessToken, refreshToken }     // code can be TOTP or recovery code
```

Recovery codes are argon2id-hashed at rest, single-use, and returned in plaintext exactly once.

---

## Email flows

These are service-layer calls, not built-in routes, so you control when and how they're triggered:

```js
// After signup — send verification email
await auth.authService.requestEmailVerification(user, { ip, userAgent });

// When the user clicks the link in the email
await auth.authService.confirmEmailVerification(token, { ip, userAgent });
```

Password reset has built-in routes (`/password/reset/request`, `/password/reset/confirm`) but can also be called directly:

```js
await auth.authService.requestPasswordReset(email, { ip, userAgent });
await auth.authService.confirmPasswordReset({ token, newPassword, ip, userAgent });
```

Password reset **revokes all refresh tokens** for the user — an attacker's stolen session cannot survive a reset.

---

## Audit log

Every auth event is written to `auth_events` automatically. No configuration needed.

| Event type | Trigger |
|---|---|
| `signup` | New account created |
| `login.success` | Successful password login |
| `login.failure` | Wrong password or unknown email |
| `login.mfa_success` | MFA login completed |
| `logout` | Refresh token revoked |
| `token.refresh` | Refresh token rotated |
| `token.reuse_detected` | Rotated token presented again (family revoked) |
| `email_verification.requested` | Verification email sent |
| `email_verification.confirmed` | Email confirmed |
| `password.reset.requested` | Reset email sent |
| `password.reset.completed` | Password reset via token |
| `password.changed` | Password changed (authenticated) |
| `mfa.enabled` | MFA enrollment confirmed |
| `mfa.disabled` | MFA disabled |

Each row includes `user_id`, `ip`, `user_agent`, `occurred_at`, and a `metadata` JSONB column for event-specific context (e.g., `token.reuse_detected` includes the `familyId`).

---

## Error model

All errors use a consistent JSON shape:

```json
{ "error": { "code": "AUTH.INVALID_CREDENTIALS", "message": "Invalid email or password" } }
```

Stack traces are never sent to clients. Internal errors return a generic `500` response and are logged to `console.error` server-side.

### Error code reference

| Code | HTTP | Meaning |
|---|---|---|
| `AUTH.INVALID_CREDENTIALS` | 401 | Wrong password or unknown email (deliberately indistinguishable) |
| `AUTH.INVALID_TOKEN` | 401 | Malformed token or bad signature → redirect to login |
| `AUTH.TOKEN_EXPIRED` | 401 | Access token expired → call `/refresh` and retry |
| `AUTH.USER_NOT_FOUND` | 401 | Token valid but user deleted or suspended |
| `AUTH.INVALID_REFRESH_TOKEN` | 401 | Unknown, expired, or already-used refresh token |
| `AUTH.REFRESH_REUSE_DETECTED` | 401 | Rotated token reused — family revoked, log in again |
| `AUTH.MFA_REQUIRED` | 403 | Password correct, second factor needed (carries `mfaToken`) |
| `AUTH.INVALID_MFA_CODE` | 401 | Wrong TOTP code or recovery code |
| `AUTH.MFA_ALREADY_ENABLED` | 409 | MFA enrollment attempted when already active |
| `AUTH.INVALID_OR_EXPIRED_TOKEN` | 401 | One-time token (verification/reset) invalid or expired |
| `AUTH.WEAK_PASSWORD` | 422 | Password too short or on the common-passwords list |
| `AUTH.FORBIDDEN` | 403 | `requirePermission` or `requireRole` rejected the request |
| `AUTH.ROLE_EXISTS` | 409 | `createRole` called with a name that already exists |
| `AUTH.RATE_LIMITED` | 429 | Too many attempts — honor the `Retry-After` header |
| `AUTH.CSRF_INVALID` | 403 | CSRF token missing or mismatched |

`AUTH.TOKEN_EXPIRED` and `AUTH.INVALID_TOKEN` are intentionally distinct. Clients should silently call `/refresh` on the former and redirect to login on the latter. Collapsing them would remove the client's ability to make that decision.

---

## Adapters

Every external dependency sits behind an interface. Swap any layer without touching auth logic.

```js
// PasswordHasher
{ hash(plaintext): Promise<string>, verify(plaintext, hash): Promise<boolean> }

// TokenSigner
{ sign(payload, options): string, verify(token): payload }  // throws on invalid

// StorageAdapter
// Full interface: createUser, getUserByEmail, getUserById, getCredentialByEmail,
// updateUser, updatePassword, softDeleteUser,
// saveRefreshToken, getRefreshToken, rotateRefreshToken, revokeRefreshToken,
// revokeRefreshTokenFamily, revokeAllRefreshTokensForUser, listActiveSessions,
// saveToken, consumeToken,
// saveMfaRecoveryCodes, getMfaRecoveryCodes, consumeMfaRecoveryCode, deleteMfaRecoveryCodes,
// getMfaSecret,
// createRole, deleteRole, addPermissionToRole, removePermissionFromRole,
// assignRole, removeRole, getRolesForUser, getUserPermissions,
// logEvent, withTransaction

// RateLimitAdapter
{ isRateLimited(key, limit, windowMs): boolean, reset(key): void }

// ReplayStore
{ has(key): boolean, set(key, ttlSeconds): void }

// MailAdapter
{ sendMail({ to, subject, html }): Promise<void> }
```

---

## Production checklist

- [ ] `JWT_SECRET` is ≥ 32 bytes of real randomness — not a copied dev value, not in version control
- [ ] `cookieOptions.secure: true` and the application is served over HTTPS
- [ ] `mailer` is a real transport (SendGrid, SES, Postmark, nodemailer) — `createConsoleMail()` is dev-only
- [ ] Migrations have been applied to the production database
- [ ] **Replace `createMemoryRateLimit()` with a Redis-backed adapter** for any multi-process or horizontally-scaled deployment — the in-memory adapter is single-process only and does not share state across pods
- [ ] **Replace `createMemoryReplayStore()` with a Redis-backed adapter** for the same reason — TOTP codes can be replayed across processes with the in-memory store
- [ ] The refresh cookie `Path` matches your mount prefix exactly
- [ ] Audit log retention and shipping are configured (ship `auth_events` rows to your SIEM or log aggregator)
- [ ] `AUTH.REFRESH_REUSE_DETECTED` handling is documented for your clients — it's sometimes a false positive on flaky connections, not always a breach

---

## Security model summary

| Defense | Attack it closes |
|---|---|
| argon2id, 64MB, ~250ms/hash | GPU brute-force of leaked password hashes |
| Constant-time comparison (`timingSafeEqual`) | Timing-based secret extraction |
| Dummy hash on unknown email | Account enumeration via login response timing |
| Identical error for "no user" and "wrong password" | Account enumeration via response messages |
| Algorithm-pinned JWT verify (`algorithms: ['HS256']`) | `alg: none` forgery (CVE-2015-9235) |
| JWT secret ≥ 32 bytes enforced at boot | Offline brute-force of captured tokens |
| Refresh tokens hashed at rest (SHA-256), rotated each use | DB-dump token theft + replay |
| Family revocation on reuse | Stolen/hijacked refresh token persistence |
| `purpose: 'mfa_challenge'` claim | MFA bypass using an unrelated valid JWT |
| DB field whitelist in `updateUser` | Mass-assignment privilege escalation |
| `WHERE deleted_at IS NULL` on every read | Soft-deleted users logging back in |
| Revoke-all-sessions on password reset | Attacker session surviving a reset |
| Double-submit CSRF token (cookie mode) | Cross-site forged state changes |
| Per-email + per-IP rate limiting on login | Brute force and credential spraying |
| Per-IP rate limiting on `/refresh` and `/login/mfa` | Token brute force and TOTP brute force |
| TOTP replay store (per-window, hashed key) | TOTP code reuse within the 30-second window |
| Atomic one-time-token consume (`UPDATE ... WHERE used_at IS NULL RETURNING *`) | Race-condition double-use of reset/verification tokens |
| Parameterized queries everywhere | SQL injection |
| Enumeration-safe reset/verify responses | Email address harvesting via reset endpoint |

---

## Testing

```bash
npm test         # vitest — unit + integration
npm run lint     # eslint
```

Integration tests run against a real Postgres instance and truncate tables between test cases. Set `DATABASE_URL` before running.

Two tests are treated as non-negotiable anchors:

- **Concurrent one-time-token consume** — `Promise.all` of two simultaneous consumes; exactly one must win.
- **TOTP RFC 6238 Appendix D vectors** — the 10 published HOTP test vectors; generated codes must match the spec exactly.

---

## Project structure

```
oathkeeper/
├── src/
│   ├── index.js                 public entry point + all exports
│   ├── config/
│   │   └── validate.js          boot-time config validation
│   ├── services/
│   │   ├── authService.js
│   │   ├── tokenService.js
│   │   ├── mfaService.js
│   │   └── rbacService.js
│   ├── routes/
│   │   └── index.js  signup  login  logout  refresh  password  mfa
│   ├── middleware/
│   │   └── authenticate  errorMapper  rateLimit  csrf  requirePermission  requireRole
│   ├── adapters/
│   │   └── storage/  hasher/  rateLimit/  replayStore/  mail/
│   ├── utils/
│   │   └── jwt  totp  random  encodeDecode  constantTime
│   ├── constants/
│   │   └── passwords.js
│   ├── error.js
│   └── migrations/
│       └── 001_users  002_refresh_tokens  003_email_verification  004_password_reset
│           005_mfa_recovery_codes  006_rbac  007_auth_events
├── examples/
│   ├── minimal/index.js         signup + login in ~30 lines
│   └── full/index.js            rate limiting, CSRF, RBAC, MFA, audit log
├── docs/
│   ├── architecture.md          three-layer design + data flow diagrams
│   └── threat-model.md          defended threats, out-of-scope, assumptions
└── tests/
    └── (18 test files, 271 tests)
```

---

## Build status

All 22 tasks complete. 271 tests passing.

| Phase | Tasks | State |
|---|---|---|
| Setup & foundations | T01–T05 — skeleton, migrations, crypto utils, password hasher, JWT util | ✅ |
| Storage layer | T06–T07 — Postgres adapters, RBAC + audit schema | ✅ |
| Core auth services | T08–T10 — token service, signup, login/logout | ✅ |
| HTTP layer | T11–T12 — signup/login/logout routes, `authenticate` middleware | ✅ |
| Refresh endpoint | T13 — `POST /refresh`, rotation + reuse detection | ✅ |
| Email flows | T14–T16 — mail adapter, email verification, password reset/change | ✅ |
| MFA | T17–T18 — TOTP utility (RFC 6238), enroll/confirm/disable, recovery codes | ✅ |
| Authorization | T19 — RBAC service, `requirePermission`, `requireRole`, `can()`, policy registry | ✅ |
| Hardening | T20 — rate limiting (sliding window), CSRF (double-submit cookie) | ✅ |
| Audit + validation | T21 — audit log coverage, boot-time config validation | ✅ |
| Packaging | T22 — `createAuth` factory, examples, README, architecture + threat model docs | ✅ |

---

## License

MIT — Shubham Lakhera

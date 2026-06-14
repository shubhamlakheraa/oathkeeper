# oathkeeper

A from-scratch authentication & authorization library for Node.js + Express + PostgreSQL.

Raw `pg`, no ORM. CommonJS. Security defaults that are not optional.

> **Why this exists.** `oathkeeper` is being built as a learning project — the goal is to understand *the why* behind every auth best practice by implementing it from first principles, rather than to ship yet another package you should depend on in production. Every "paranoid" decision in this codebase (the dummy hash on failed login, the hardcoded JWT algorithm, the atomic one-time-token consume, the field whitelist on updates) maps to a specific, named, exploited attack. The README documents both the API and the reasoning.

---

## Status

**Work in progress — roughly T12 of 22.** The public `createAuth()` factory and several flows below are still being implemented. This README documents the *intended* surface; sections covering unbuilt features are marked **(planned)**.

| Phase | Tasks | State |
|---|---|---|
| Setup & foundations | T01–T05 — skeleton, migrations, crypto utils, password hasher, JWT util | ✅ done |
| Storage layer | T06–T07 — Postgres users + tokens/RBAC/audit | ✅ done |
| Core AuthN services | T08–T10 — token service, signup, login/logout | ✅ done |
| HTTP layer | T11–T12 — signup/login/logout routes, `authenticate` middleware | ✅ done |
| Refresh endpoint | T13 — `POST /refresh` route over rotation logic | ✅ done |
| Email flows | T14–T16 — mail adapter, email verification, password reset/change | 🚧 in progress |
| MFA | T17–T18 — TOTP utility, enroll/confirm/disable, recovery codes | ⬜ planned |
| Authorization | T19 — RBAC service, `requirePermission`, policy registry, `can()` | ⬜ planned |
| Hardening | T20–T21 — rate limiting, CSRF, audit integration, config validation | ⬜ planned |
| Packaging | T22 — `createAuth` factory, examples, docs | ⬜ planned |

The rotation + reuse-detection *logic* (T08) is implemented at the service layer; the `/refresh` HTTP route that exposes it (T13) is in progress.

---

## What you get

- **Password storage** with argon2id (memory-hard, GPU-resistant), tuned to OWASP 2023 parameters.
- **Stateless access tokens** (short-lived JWTs, HS256, algorithm-pinned) + **stateful refresh tokens** (long-lived, hashed at rest, rotated on every use).
- **Refresh token rotation with reuse detection** — a stolen token self-destructs the moment the legitimate user acts.
- **Account-enumeration defenses** — uniform responses and constant-time login regardless of whether an account exists.
- **MFA** via TOTP (RFC 6238) with replay protection and one-time recovery codes. *(planned)*
- **Email verification and password reset** with opaque, single-use, time-bound tokens. *(planned)*
- **Authorization** — RBAC as the floor, an optional ABAC-style policy registry for resource-level rules. *(planned)*
- **Hardening** — dual-key rate limiting, double-submit CSRF, and a structured audit log. *(planned)*
- **Adapter pattern everywhere** — swap the hasher, signer, storage, rate limiter, or mail transport without touching auth logic.

---

## Requirements

- Node.js 22+
- PostgreSQL 14+ (uses `gen_random_uuid()` via `pgcrypto`, `CITEXT`, and `timestamptz`)
- An email transport you provide (any function matching the `MailAdapter` contract)

`oathkeeper` never opens its own database connection, mail transport, or HTTP server. The host application provides all three.

---

## Installation

```bash
npm install oathkeeper
```

> Heads-up: `argon2` is a native module that compiles on install. If it fails, you likely need C build tools (`node-gyp`); try `npm install --build-from-source argon2`. On ARM Macs this sometimes needs the Xcode CLI tools.

---

## Quickstart *(target API — T22)*

```js
const express = require('express');
const { Pool } = require('pg');
const { createAuth } = require('oathkeeper');

const app = express();
app.use(express.json());

const auth = createAuth({
  db: new Pool({ connectionString: process.env.DATABASE_URL }),
  jwtSecret: process.env.JWT_SECRET,            // 32+ bytes, or it refuses to boot
  sendMail: async ({ to, subject, html }) => {  // host's transport
    // wire up SendGrid / SES / Postmark / nodemailer here
  },
});

// Mount the auth routes under a prefix
app.use('/auth', auth.router);

// Protect a route
app.get('/profile', auth.middleware.authenticate, (req, res) => {
  res.json(req.user);
});

app.listen(3000);
```

That's signup, login, logout, refresh, email verification, password reset, and MFA — all mounted under `/auth`.

---

## Database setup

The schema lives in `src/migrations/` as plain SQL files applied in order. A small runner applies them idempotently (`CREATE TABLE IF NOT EXISTS`, etc.).

```bash
# example, adjust to your script
node scripts/migrate.js
```

The migrations create:

| File | Table(s) | Purpose |
|---|---|---|
| `001_users.sql` | `users` | accounts (UUID PK, `CITEXT` email, `password_hash`, soft-delete) |
| `002_refresh_tokens.sql` | `refresh_tokens` | hashed refresh tokens with `family_id` + `replaced_by_id` |
| `003_email_verification.sql` | `email_verification_tokens` | one-time, hashed, time-bound |
| `004_password_reset.sql` | `password_reset_tokens` | one-time, hashed, shorter TTL |
| `005_mfa.sql` | `mfa_recovery_codes` | argon2id-hashed backup codes |
| `006_rbac.sql` | `roles`, `permissions`, `user_roles`, `role_permissions` | role-based access control |
| `007_auth_events.sql` | `auth_events` | structured audit log (JSONB metadata) |

Key schema decisions:

- **UUID primary keys** so IDs don't leak sequential counts or enable enumeration.
- **`CITEXT` email** for case-insensitive uniqueness without `LOWER()` gymnastics on every query.
- **Soft delete** (`deleted_at`) preserves the audit trail and avoids breaking foreign keys; every read filters `WHERE deleted_at IS NULL`.
- **Token tables store hashes, never raw tokens.** The raw token is the credential and lives only in the user's hands.

```sql
CREATE TABLE users (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email          CITEXT UNIQUE NOT NULL,
  password_hash  TEXT NOT NULL,
  email_verified BOOLEAN NOT NULL DEFAULT FALSE,
  mfa_enabled    BOOLEAN NOT NULL DEFAULT FALSE,
  mfa_secret     TEXT,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_login_at  TIMESTAMPTZ,
  deleted_at     TIMESTAMPTZ
);
CREATE INDEX users_email_idx ON users(email) WHERE deleted_at IS NULL;
```

---

## Configuration reference

A single config object is passed to `createAuth()`. There is no global state. Durations are strings (`'15m'`, `'30d'`). Required keys throw **at boot**, not at first request.

```js
createAuth({
  // ---- REQUIRED ----
  db,                                  // pg.Pool (or a storage adapter)
  jwtSecret: process.env.JWT_SECRET,   // >= 32 bytes
  sendMail: async ({ to, subject, html }) => { /* ... */ },

  // ---- OPTIONAL (defaults shown) ----
  accessTokenTtl: '15m',
  refreshTokenTtl: '30d',
  passwordReset:    { ttl: '30m' },
  emailVerification:{ ttl: '24h', required: true },
  mfa:              { enabled: true, issuer: 'MyApp' },

  cookies: {
    enabled: true,    // cookie mode vs header mode
    secure: true,     // HTTPS-only; warns loudly if false in production
    sameSite: 'lax',
  },

  rateLimit: {
    loginPerIp:      { limit: 20, windowMs: 15 * 60 * 1000 },
    loginPerAccount: { limit: 5,  windowMs: 15 * 60 * 1000 },
  },

  adapters: {
    hasher: undefined,       // default: argon2id
    tokenSigner: undefined,  // default: HS256
    storage: undefined,      // default: PostgresStorage
    rateLimit: undefined,    // default: in-memory (single-process only)
  },

  policies: {
    // ABAC-style resource checks, keyed by permission name
    'document:edit': (user, doc) => doc.ownerId === user.id,
  },
});
```

| Key | Type | Default | Notes |
|---|---|---|---|
| `db` | `pg.Pool` | — | **required** |
| `jwtSecret` | string | — | **required**, ≥ 32 bytes |
| `sendMail` | async fn | — | **required**; the library will not boot without it |
| `accessTokenTtl` | duration | `'15m'` | must be > 0 and < 24h |
| `refreshTokenTtl` | duration | `'30d'` | must be longer than `accessTokenTtl` |
| `passwordReset.ttl` | duration | `'30m'` | short by design — a reset implies someone may be probing |
| `emailVerification.ttl` | duration | `'24h'` | — |
| `emailVerification.required` | boolean | `true` | gate logins on a verified email |
| `mfa.enabled` | boolean | `true` | enables the TOTP flows |
| `mfa.issuer` | string | — | shown in authenticator apps |
| `cookies.enabled` | boolean | `true` | cookie mode (browser) vs header mode (API/mobile) |
| `cookies.secure` | boolean | `true` | `false` in production triggers a loud warning |
| `cookies.sameSite` | string | `'lax'` | CSRF posture |
| `rateLimit.*` | object | see above | per-IP and per-account limits |
| `adapters.*` | object | sensible defaults | swap any external dependency |
| `policies` | object | `{}` | permission → `(user, resource) => boolean \| Promise<boolean>` |

Why boot-time validation is opinionated-but-correct: a misconfigured `jwtSecret: 'dev'` in production means forgeable tokens. Catching it when the server *starts* — with an actionable error — is strictly better than discovering it on a user's first login.

---

## The `auth` object

`createAuth()` returns:

```js
auth.router                                  // Express Router, mount under a prefix
auth.middleware.authenticate                 // populate req.user / req.auth or 401
auth.middleware.requirePermission(perm)      // 403 unless the user holds `perm`
auth.middleware.requireRole(role)            // 403 unless the user has `role`
auth.middleware.rateLimit(opts)              // reusable limiter factory
auth.middleware.csrf                          // double-submit cookie guard
auth.services.users                          // user CRUD
auth.services.tokens                         // issue / rotate / revoke tokens
auth.services.rbac                           // role & permission management
auth.services.mfa                            // enroll / confirm / disable
auth.can(user, action, resource?)            // the core authorization check
```

Example wiring with authorization:

```js
app.delete('/documents/:id',
  auth.middleware.authenticate,
  auth.middleware.requirePermission('document:delete'),
  async (req, res) => {
    const doc = await getDoc(req.params.id);
    if (!auth.can(req.user, 'document:delete', doc)) return res.sendStatus(403);
    await deleteDoc(doc.id);
    res.sendStatus(204);
  }
);
```

---

## HTTP routes

All mounted under whatever prefix you pass to `app.use()` (the README assumes `/auth`).

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/signup` | anon | create an account |
| `POST` | `/login` | anon | email + password → tokens, or an MFA challenge |
| `POST` | `/login/mfa` | mfaToken | submit a TOTP / recovery code to finish login *(planned)* |
| `POST` | `/refresh` | refresh token | rotate → new access + refresh pair |
| `POST` | `/logout` | refresh token | revoke refresh token, clear cookies |
| `POST` | `/email/verify/request` | authenticated | send a verification email *(planned)* |
| `GET` | `/email/verify/confirm?token=…` | anon | confirm email *(planned)* |
| `POST` | `/password/reset/request` | anon | send a reset email (always generic 200) *(planned)* |
| `POST` | `/password/reset/confirm` | anon | submit token + new password *(planned)* |
| `POST` | `/password/change` | authenticated | change password with current password *(planned)* |
| `POST` | `/mfa/enroll` | authenticated | begin TOTP enrollment *(planned)* |
| `POST` | `/mfa/confirm` | authenticated | verify first code, activate MFA *(planned)* |
| `POST` | `/mfa/disable` | authenticated | disable MFA (requires password **and** code) *(planned)* |
| `GET` | `/me` | authenticated | current user info |

### Cookie mode vs header mode

- **Cookie mode** (browser): the refresh token is set as an `HttpOnly`, `Secure`, `SameSite=Lax` cookie scoped to **`Path: /auth/refresh`**, so the browser only ever sends it to that one endpoint — not to every API call. The access token comes back in the JSON body and is meant to live in memory. This narrows the CSRF surface dramatically.
- **Header mode** (mobile / API / CLI): both tokens are returned in the JSON body and the client sends the access token as `Authorization: Bearer <token>`.

> The refresh cookie's `Path` must match the mount point exactly. If the cookie is `Path: /auth/refresh` but the route is mounted elsewhere, the browser never sends the cookie and refresh silently fails.

---

## The request contract

After `authenticate` succeeds, two objects are attached to the request:

```js
req.user = {
  id: '<uuid>',
  email: '<string>',
  emailVerified: false,
  mfaEnabled: false,
  roles: ['user', 'editor'],
  permissions: ['document:read', 'document:write'], // a Set or documented array
};

req.auth = {
  tokenPayload: { /* raw JWT claims */ },
  isMfaSatisfied: true,
};
```

`authenticate` verifies the JWT signature **first** (cheap), then does a database lookup by `sub` (a DB hit). The lookup enforces **hard revocation**: a soft-deleted, suspended, or locked user is rejected with `401` even if their token is otherwise valid and unexpired.

---

## Token model

Two tokens, two jobs:

| Token | Lifetime | Stored? | Sent on |
|---|---|---|---|
| Access | short (`15m`) | no — stateless JWT | every request |
| Refresh | long (`30d`) | yes — SHA-256 hash + metadata | only `/refresh` |

**Rotation + reuse detection.** Every refresh token is single-use. Using one revokes it and issues a replacement in the same `family_id`. If a token that has *already* been rotated is presented again, that's reuse — the entire token family is revoked and the user is logged out everywhere. This bounds the blast radius of a stolen refresh token to the window before the legitimate user's next refresh.

**Tokens are hashed at rest.** The database stores `SHA-256(rawToken)`, never the raw value. (SHA-256 is appropriate here precisely because tokens are long, high-entropy random values — no dictionary attack applies, unlike passwords.)

**Rotation is transactional.** Revoking the old token and issuing the new one happen atomically. A partial failure that revoked the old token without issuing a new one would lock the user out permanently.

> **Known false positive.** A client on a flaky connection can receive a new token but fail to persist it before the connection drops, then retry with the old (now-revoked) token — which fires reuse detection. Treat `AUTH.REFRESH_REUSE_DETECTED` as "ask the user to log in again," not as a confirmed breach.

---

## Authorization model *(planned — T19)*

A hybrid model: **RBAC is the floor, policies narrow.**

- **RBAC** answers the coarse question — does this user hold `document:edit` through any of their roles? It's a binary check against the user's permission set.
- **Policies** answer resource-level questions RBAC can't express — "can Alice edit *this specific* document?" You register a function per permission:

```js
policies: {
  'document:edit': (user, doc) => doc.ownerId === user.id,
}
```

`can(user, action, resource?)` runs RBAC first; only if RBAC passes does it run the registered policy. **Policies can only restrict, never grant** — an attacker can't manufacture access by manipulating a resource's attributes, because RBAC is always checked first. Async policies returning a `Promise<boolean>` are supported and awaited.

---

## MFA *(planned — T17–T18)*

TOTP per RFC 6238 (HMAC-SHA1, 6 digits, 30-second period, ±1 window for clock skew), with:

- **Two-step enrollment** — `beginEnrollment` returns a secret + `otpauth://` URI but stores the secret as *pending*; MFA only activates after `confirmEnrollment` proves the user scanned the QR code by submitting a valid code. This prevents lock-out from a half-finished enrollment.
- **Replay protection** — a code used once cannot be reused within its window.
- **Recovery codes** — 10 one-time codes generated at confirmation, returned in plaintext exactly once, stored as **argon2id** hashes (they're short and human-readable, so they need slow hashing).
- **A purpose-scoped challenge token** — after a correct password, MFA users receive a 5-minute JWT carrying `purpose: 'mfa_challenge'`. `/login/mfa` validates that claim explicitly so that no other JWT signed with the same secret (e.g. an access token) can be used to bypass the second factor.

---

## Email-driven flows *(planned — T14–T16)*

Email verification and password reset use **opaque, single-use, time-bound tokens** stored as `SHA-256` hashes (not JWTs — simpler to revoke and to enforce single-use). The atomic consume pattern guarantees one-shot semantics under concurrency:

```sql
UPDATE tokens
   SET used_at = now()
 WHERE id = $1 AND used_at IS NULL AND expires_at > now()
RETURNING *;
```

If two requests race the same token, exactly one gets a row back; the other gets nothing. The database is the lock.

Two non-negotiable invariants:

- **Password reset revokes all of the user's refresh tokens.** Reset is a recovery tool; if it didn't kill existing sessions, a hijacked session would survive the reset. This is not configurable.
- **Enumeration-safe responses.** `/password/reset/request` and `/email/verify/request` return the same generic `200` whether or not the email exists.

---

## Adapters

Every external dependency sits behind an interface, so you can replace any layer without touching auth logic.

```js
// PasswordHasher
{ hash(plaintext) => Promise<string>, verify(plaintext, hash) => Promise<boolean> }

// TokenSigner
{ sign(payload, options) => string, verify(token) => payload /* or throws */ }

// StorageAdapter — createUser, findUserByEmail, findUserById, updateUser,
//   softDeleteUser, saveRefreshToken, findRefreshToken, rotateRefreshToken,
//   revokeRefreshToken, revokeRefreshTokenFamily, revokeAllUserTokens,
//   saveToken, consumeToken, saveMfaRecoveryCodes, consumeMfaRecoveryCode,
//   assignRole, removeRole, getRolesForUser, getUserPermissions, logEvent

// RateLimitAdapter
{ increment(key, windowMs) => { count, ttl }, reset(key) => void }

// MailAdapter — host MUST provide
async sendMail({ to, subject, html, text }) => void
```

Defaults baked in for v1: HS256 single-key signing, argon2id hashing, in-memory rate limiting, Postgres storage. Documented adapter slots for scale: RS256/ES256 with JWKS, Redis rate limiting, Redis permission cache, a `jti` revocation denylist, and a Kafka/ClickHouse event sink.

---

## Error model

Three categories: user-facing (`4xx`, JSON, generic messages), programming (throw at boot with full detail), and internal (`500`, generic externally, full detail logged server-side). Stack traces are never sent to clients.

Errors use a stable, namespaced shape so consumers can branch programmatically:

```json
{ "error": { "code": "AUTH.INVALID_CREDENTIALS", "message": "Invalid email or password" } }
```

### Error code reference

| Code | HTTP | Meaning / client action |
|---|---|---|
| `AUTH.INVALID_CREDENTIALS` | 401 | wrong password **or** unknown email (deliberately indistinguishable) |
| `AUTH.TOKEN_EXPIRED` | 401 | access token expired → silently hit `/refresh` and retry |
| `AUTH.INVALID_TOKEN` | 401 | malformed / bad signature → redirect to login |
| `AUTH.USER_NOT_FOUND` | 401 | token valid but the user is gone (soft-deleted) |
| `AUTH.INVALID_REFRESH_TOKEN` | 401 | unknown or expired refresh token |
| `AUTH.REFRESH_REUSE_DETECTED` | 401 | a rotated token was reused → family revoked, log in again |
| `AUTH.MFA_REQUIRED` | 200/401 | password OK, second factor needed (carries an `mfaToken`) |
| `AUTH.INVALID_MFA_CODE` | 401 | wrong TOTP / recovery code |
| `AUTH.RATE_LIMITED` | 429 | too many attempts; honor the `Retry-After` header |

`TOKEN_EXPIRED` and `INVALID_TOKEN` are intentionally distinct: clients silently refresh on the former and redirect to login on the latter. Collapsing them into a generic `401` would remove the client's ability to make that decision.

---

## Security model

The defenses, and the attack each one closes:

| Defense | Attack it stops |
|---|---|
| argon2id (memory-hard, ~250ms/hash) | GPU brute-force of leaked password hashes |
| Constant-time verify (library `.verify()`, never `===`) | timing-based hash extraction |
| Dummy hash on unknown email (computed once at module load) | account enumeration via login timing |
| Identical error/response for "no user" vs "wrong password" | account enumeration via messages |
| Algorithm-pinned JWT verify (`algorithms: ['HS256']`) | the `alg: none` forgery class (CVE-2015-9235) |
| Refresh tokens hashed at rest, rotated each use | DB-leak token theft + replay |
| Family revocation on reuse | stolen / hijacked refresh tokens |
| `purpose` claim on the MFA challenge token | MFA bypass with an unrelated valid JWT |
| Update field whitelist | mass-assignment privilege escalation |
| `WHERE deleted_at IS NULL` on every read | soft-deleted users logging back in |
| Revoke-all-on-password-reset | attacker session surviving a reset |
| Double-submit CSRF token (cookie mode) | cross-site forged state changes |
| Per-IP + per-account rate limits | brute force and credential spraying |
| Parameterized queries (`$1`, `$2`) everywhere | SQL injection |

---

## Production checklist

- [ ] `JWT_SECRET` is ≥ 32 bytes of real randomness (not a copied dev value).
- [ ] `cookies.secure: true` and the app is served over HTTPS.
- [ ] A real `sendMail` transport is wired up (the console transport is dev-only).
- [ ] The refresh cookie `Path` matches your mount prefix exactly.
- [ ] **Swap the in-memory rate limiter for a Redis-backed adapter** in any multi-process / multi-pod deployment — the in-memory limiter is **single-process only** and each process keeps its own counters.
- [ ] Audit-log retention and shipping are configured.
- [ ] Migrations have been applied to the production database.
- [ ] You've documented the `REFRESH_REUSE_DETECTED` false-positive handling for your clients.

---

## Threat model — scope

**Defended:** brute force, credential stuffing (with MFA), session hijacking, CSRF (cookie mode), token replay, account enumeration, timing attacks, insecure password reset, mass assignment at signup.

**Out of scope for v1 (your responsibility):** business-logic authorization beyond RBAC + policies, API-key auth, SSRF, WebAuthn / passkeys, suspicious-login geo/device signals, and a HaveIBeenPwned check at signup. The design leaves adapter seams for several of these.

---

## Project structure

```
oathkeeper/
├── src/
│   ├── index.js                 # public entry point
│   ├── createAuth.js            # main factory (T22)
│   ├── routes/                  # signup, login, refresh, logout, email, password, mfa
│   ├── middleware/              # authenticate, requirePermission, requireRole, rateLimit, csrf
│   ├── services/                # authService, tokenService, userService, mfaService, rbacService
│   ├── adapters/                # storage/, hasher/, tokenSigner/, rateLimit/, mail/
│   ├── utils/                   # jwt, totp, random, constantTime, errors
│   └── migrations/              # 001_users.sql … 007_auth_events.sql
├── examples/                    # minimal/ and full/
└── tests/                       # unit/ and integration/
```

---

## Testing

```bash
npm test        # unit + integration (vitest)
npm run lint
```

Integration tests run against a local Postgres and truncate tables between cases. Two tests are treated as non-negotiable:

- **Concurrent one-time-token consume** — fire two simultaneous consumes with `Promise.all` and assert exactly one wins.
- **TOTP RFC 6238 vectors** — generated codes must match the spec's published test vectors.

A quick local Postgres for development:

```bash
docker run -e POSTGRES_PASSWORD=dev -p 5432:5432 -d postgres:16
```

---

## Contributing

This is a learning-first project. If you've shipped auth before, the most valuable place to look is the **token rotation + reuse-detection** path in `tokenService.js` — that's where the subtle bugs live. Issues and reviews that point at a specific attack or edge case are especially welcome.

---

## License

MIT.

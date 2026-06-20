# Architecture

oathkeeper is structured in three layers. Each layer has a single responsibility and depends only on the layer below it.

```
┌─────────────────────────────────────────────┐
│             HTTP Layer (routes/)             │  Express Routers
│  signup · login · logout · refresh · mfa    │  input validation
│  password · email verification              │  response shaping
└─────────────────────┬───────────────────────┘
                      │ calls
┌─────────────────────▼───────────────────────┐
│           Service Layer (services/)          │  business logic
│  authService · tokenService · mfaService    │  security invariants
│  rbacService                                │  cross-cutting rules
└─────────────────────┬───────────────────────┘
                      │ calls
┌─────────────────────▼───────────────────────┐
│          Adapter Layer (adapters/)           │  I/O abstractions
│  postgresStorage · argon2Hasher             │  swappable backends
│  memoryRateLimit · memoryReplayStore        │  interface contracts
│  consoleMail                                │
└─────────────────────────────────────────────┘
```

## Layer responsibilities

### HTTP layer (`src/routes/`)

Translates HTTP semantics into service calls and back.

- Reads `req.body`, `req.ip`, `req.headers`
- Validates required fields (400 on missing)
- Calls one service method
- Shapes the response (JSON body, cookies, headers)
- **Does not contain security logic** — that lives in the service layer

### Service layer (`src/services/`)

Contains all security decisions and business rules.

- `authService` — signup, login (with MFA gate), logout, email verification, password reset/change, completeMfaLogin
- `tokenService` — issue access/refresh tokens, rotate with reuse detection, revoke
- `mfaService` — TOTP enrollment, confirmation, disable, recovery codes
- `rbacService` — role/permission CRUD, `can(user, action, resource?)` combining RBAC + policy

Services receive dependencies through factory params (never import global state). This makes them independently testable and replaceable.

### Adapter layer (`src/adapters/`)

Thin wrappers around I/O. Each adapter satisfies a contract (JSDoc typedef) so you can swap backends without touching the service layer.

| Adapter | Default | Swap for |
|---|---|---|
| `storage` | `createPostgresStorage(pool)` | Any DB with the same method surface |
| `hasher` | `createArgon2Hasher()` | bcrypt, scrypt — must be constant-time |
| `rateLimit` | `createMemoryRateLimit()` | Redis-backed (required for multi-process) |
| `replayStore` | `createMemoryReplayStore()` | Redis-backed (required for multi-process) |
| `mailer` | `createConsoleMail()` (dev) | nodemailer, SendGrid, SES, Postmark |

## Middleware

Middleware sits between the HTTP and service layers:

- `authenticate` — verifies the JWT, loads the user from DB, populates `req.user` + `req.auth`
- `errorMapper` — converts `AuthError` subclasses to HTTP status codes, strips stack traces from responses
- `requirePermission(perm)` / `requireRole(role)` — route guards that delegate to `rbacService.can()`
- `createRateLimitMiddleware(opts)` — configurable rate limiter, wraps any `RateLimitAdapter`
- `createCsrfMiddleware()` — double-submit cookie check for cookie-mode endpoints

## Data flow: login

```
POST /auth/login
  → loginRouter (validate body fields)
  → [perEmailLimiter, perIpLimiter] (rate check — 429 if exceeded)
  → authService.login()
      → storage.getCredentialByEmail()        [DB]
      → hasher.verify(password, hash)         [CPU-bound, ~250ms]
      → if MFA: signer.sign(mfaChallenge)     [fast]
      → tokenService.issueRefreshToken()
          → storage.saveRefreshToken()        [DB]
      → storage.logEvent('login.success')     [DB]
  → res.json({ user, accessToken, refreshToken })
```

## Data flow: refresh token rotation

```
POST /auth/refresh
  → [csrfMiddleware] (cookie mode only)
  → [refreshIpLimiter]
  → tokenService.rotateRefreshToken()
      → storage.withTransaction()
          → storage.getRefreshToken(hash)     [DB]
          → if revoked_at: revokeFamily()     [DB] → throw RefreshTokenReuseError
          → insertRefreshToken()              [DB]
          → storage.rotateRefreshToken()      [DB — atomic CAS]
          → storage.getUserById()             [DB]
          → storage.logEvent('token.refresh') [DB]
  → res.json({ accessToken, refreshToken })
```

The rotation is a single Postgres transaction. A crash between "revoke old" and "issue new" rolls back completely — the old token remains valid and the user is not locked out.

## ⚠️ In-memory state

Two components hold state in process memory:

1. **`createMemoryRateLimit()`** — sliding-window counters in a `Map`
2. **`createMemoryReplayStore()`** — TOTP replay keys in a `Map`

**These are single-process only.** In any deployment with more than one Node.js process (cluster module, multiple Kubernetes pods, PM2 in cluster mode), each process has its own independent counters. A request rate-limited on process A can immediately succeed on process B, and a TOTP code used on process A can be replayed on process B.

**The fix is a Redis-backed adapter** that all processes share. The adapter contracts (`RateLimitAdapter.js`, `memoryReplayStore.js`) are minimal — a Redis implementation is a straightforward drop-in. This is explicitly left for the next iteration of this project.

## RBAC is app-level

`rbacService` is not created inside `createAuth()`. The calling application creates it using the storage returned by `createAuth`:

```js
const auth = createAuth({ ... });
const rbac = createRbacService({
  storage: auth.storage,
  policies: { 'doc:edit': (user, doc) => doc.ownerId === user.id },
});
```

**Why app-level?** Authorization rules ("who can edit which document") are domain-specific. A generic auth library cannot know them. The library provides the mechanism (`can()`, `requirePermission()`, the DB schema, the policy registry) — the application provides the rules.

## Directory map

```
src/
├── index.js                  public exports
├── config/
│   └── validate.js           boot-time config validation
├── services/
│   ├── authService.js        signup, login, logout, email, password, MFA login
│   ├── tokenService.js       issue, rotate, revoke tokens
│   ├── mfaService.js         TOTP enroll/confirm/disable, recovery codes
│   └── rbacService.js        roles, permissions, can()
├── routes/
│   ├── index.js              router factory (wires sub-routers)
│   ├── signup.js
│   ├── login.js
│   ├── logout.js
│   ├── refresh.js
│   ├── password.js
│   └── mfa.js
├── middleware/
│   ├── authenticate.js       JWT → req.user + req.auth
│   ├── errorMapper.js        AuthError → HTTP status
│   ├── rateLimit.js          createRateLimitMiddleware factory
│   ├── csrf.js               double-submit cookie guard
│   ├── requirePermission.js  createPermissions factory
│   └── requireRole.js        createRoleGuard factory
├── adapters/
│   ├── storage/
│   │   └── postgresStorage.js
│   ├── hasher/
│   │   └── argon2Hasher.js
│   ├── rateLimit/
│   │   ├── memoryRateLimit.js
│   │   └── RateLimitAdapter.js   (interface typedef)
│   ├── replayStore/
│   │   └── memoryReplayStore.js
│   └── mail/
│       ├── consoleMail.js
│       └── MailAdapter.js        (interface typedef)
├── utils/
│   ├── jwt.js
│   ├── totp.js               RFC 6238 HOTP/TOTP + replay protection
│   ├── random.js             generateToken, sha256, parseTtl
│   ├── encodeDecode.js       base32 encode/decode (RFC 4648)
│   └── constantTime.js       timing-safe string comparison
├── constants/
│   └── passwords.js          common password list, TTL constants
├── error.js                  AuthError subclasses
└── migrations/
    ├── 001_users.sql
    ├── 002_refresh_tokens.sql
    ├── 003_email_verification_tokens.sql
    ├── 004_password_reset_tokens.sql
    ├── 005_mfa_recovery_codes.sql
    ├── 006_rbac.sql
    └── 007_auth_events.sql
```

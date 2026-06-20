'use strict';

/**
 * Full oathkeeper example — every feature wired together.
 *
 * Features demonstrated:
 *   - Rate limiting (per-email + per-IP on login, per-IP on refresh)
 *   - CSRF protection (cookie mode)
 *   - MFA (TOTP) — enroll, confirm, login
 *   - RBAC + ABAC policies — requirePermission, requireRole, can()
 *   - Email verification (requestEmailVerification called after signup)
 *   - Password reset flow
 *   - Audit log (written automatically to auth_events table)
 *
 * Run:
 *   DATABASE_URL=postgres://... \
 *   JWT_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))") \
 *   node examples/full/index.js
 */

const express = require('express');
const { Pool } = require('pg');
const {
  createAuth,
  createConsoleMail,
  createMemoryRateLimit,
  createRateLimitMiddleware,
  createRbacService,
  createPermissions,
  createRoleGuard,
  errorMapper,
} = require('../../src');

// ─── 1. Rate limit adapters ───────────────────────────────────────────────────
//
// ⚠️  IN-MEMORY ONLY — single-process.
// In a multi-process deployment (Node cluster, Kubernetes with multiple pods),
// each process keeps its own counter. A user blocked on process A can reach
// process B unimpeded. Swap createMemoryRateLimit() for a Redis-backed adapter
// before deploying behind a load balancer or in any horizontally-scaled environment.
//
const emailAdapter = createMemoryRateLimit();
const ipAdapter    = createMemoryRateLimit();

const perEmailLimiter = createRateLimitMiddleware({
  keyFn: (req) => req.body?.email?.toLowerCase(),
  limit: 5,
  windowMs: 15 * 60 * 1000, // 5 attempts per account per 15 min
  adapter: emailAdapter,
});

const perIpLimiter = createRateLimitMiddleware({
  keyFn: (req) => req.ip,
  limit: 20,
  windowMs: 15 * 60 * 1000, // 20 attempts per IP per 15 min
  adapter: ipAdapter,
});

const refreshAdapter = createMemoryRateLimit();
const refreshIpLimiter = createRateLimitMiddleware({
  keyFn: (req) => req.ip,
  limit: 60,
  windowMs: 15 * 60 * 1000,
  adapter: refreshAdapter,
});

// ─── 2. createAuth ────────────────────────────────────────────────────────────

const auth = createAuth({
  pool: new Pool({ connectionString: process.env.DATABASE_URL }),
  jwtSecret: process.env.JWT_SECRET,
  baseUrl: process.env.BASE_URL || 'http://localhost:3000',
  mailer: createConsoleMail(),            // swap for nodemailer/SES/SendGrid in prod
  accessTokenTtl: '15m',
  refreshTokenTtl: '7d',
  issuer: 'MyApp',                        // shown in authenticator apps

  // Cookie mode: refresh token as HttpOnly cookie, CSRF protection enabled.
  // Set cookieMode: false for mobile/API clients that store tokens in memory.
  cookieMode: true,
  cookieOptions: {
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000,    // 7 days, matches refreshTokenTtl
  },

  rateLimiters: {
    login: [perEmailLimiter, perIpLimiter],
    refresh: [refreshIpLimiter],
    // mfa: [] — falls back to login limiters automatically
  },

  csrf: true,  // sets non-HttpOnly csrf_token cookie on login; enforced on /refresh
});

// ─── 3. RBAC — app-level, built on top of auth.storage ──────────────────────
//
// RBAC is intentionally app-level: your business rules do not belong inside
// a generic auth library. Build the rbacService after createAuth(), pass
// auth.storage so it shares the same Postgres pool.
//
const rbac = createRbacService({
  storage: auth.storage,
  policies: {
    // ABAC policy: RBAC grants 'doc:edit' capability; this policy narrows it to owners.
    // RBAC is always checked first — policies can only restrict, never grant.
    'doc:edit': (user, doc) => doc.ownerId === user.id,
  },
});

const { requirePermission } = createPermissions({ rbacService: rbac });
const { requireRole } = createRoleGuard({ rbacService: rbac });

// ─── 4. Express app ──────────────────────────────────────────────────────────

const app = express();
app.use(express.json());

// Auth routes: signup, login, logout, refresh, email verification,
// password reset/change, MFA enroll/confirm/disable, login/mfa
app.use('/auth', auth.router);

// ─── Protected routes ─────────────────────────────────────────────────────────

// Any authenticated user
app.get('/profile', auth.authenticate, (req, res) => {
  res.json({ user: req.user });
});

// Only users with the 'admin' role
app.get('/admin', auth.authenticate, requireRole('admin'), (req, res) => {
  res.json({ message: 'Admin area' });
});

// Only users with 'doc:read' permission
app.get('/documents', auth.authenticate, requirePermission('doc:read'), (req, res) => {
  res.json({ documents: [] });
});

// Permission + ABAC policy: user must have 'doc:edit' AND own the document
app.put('/documents/:id', auth.authenticate, requirePermission('doc:edit'), async (req, res) => {
  const doc = await getDocById(req.params.id); // your DB call
  const allowed = await rbac.can(req.user, 'doc:edit', doc);
  if (!allowed) return res.status(403).json({ error: { code: 'AUTH.FORBIDDEN', message: 'Forbidden' } });
  res.json({ updated: true });
});

// ─── App-level: request email verification after signup ───────────────────────
// The library exposes requestEmailVerification as a service call, not an automatic
// post-signup route, so you control when and how verification emails are sent.
app.post('/auth/email/verify/request', auth.authenticate, async (req, res, next) => {
  try {
    await auth.authService.requestEmailVerification(req.user, {
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });
    res.json({ message: 'Verification email sent.' });
  } catch (err) { next(err); }
});

app.post('/auth/email/verify/confirm', async (req, res, next) => {
  try {
    const { token } = req.body;
    await auth.authService.confirmEmailVerification(token, {
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });
    res.json({ message: 'Email verified.' });
  } catch (err) { next(err); }
});

// Error handling — uses oathkeeper's error mapper so your app speaks the same shape
app.use(errorMapper);

// ─── Role seeding example (run once at startup / in a migration) ──────────────
async function seedRoles() {
  try {
    const editorRole = await rbac.createRole('editor');
    await rbac.addPermissionToRole(editorRole.id, 'doc:read');
    await rbac.addPermissionToRole(editorRole.id, 'doc:edit');

    const adminRole = await rbac.createRole('admin');
    await rbac.addPermissionToRole(adminRole.id, 'doc:read');
    await rbac.addPermissionToRole(adminRole.id, 'doc:edit');
    await rbac.addPermissionToRole(adminRole.id, 'user:delete');
  } catch (err) {
    // RoleAlreadyExistsError is thrown on duplicate — safe to ignore on re-runs
    if (err.code !== 'AUTH.ROLE_EXISTS') throw err;
  }
}

// Placeholder — replace with your actual DB query
async function getDocById(id) {
  return { id, ownerId: 'some-user-id', title: 'Example doc' };
}

app.listen(3000, async () => {
  await seedRoles().catch(console.error);
  console.log('Listening on http://localhost:3000');
});

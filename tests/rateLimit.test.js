const express = require('express');
const request = require('supertest');
const { createMemoryRateLimit } = require('../src/adapters/rateLimit/memoryRateLimit');
const { createRateLimitMiddleware } = require('../src/middleware/rateLimit');
const { createCsrfMiddleware, setCsrfCookie } = require('../src/middleware/csrf');
const { createAuthRouter } = require('../src/routes/index');
const { errorMapper } = require('../src/middleware/errorMapper');
const { InvalidCredentialsError } = require('../src/error');
const cookieParser = require('cookie-parser');

// ─── helpers ────────────────────────────────────────────────────────────────

function makeAuthService(overrides = {}) {
  return {
    signup: async () => ({ user: { id: 'u1', email: 'u@x.com' }, alreadyExists: false }),
    login: async () => ({ user: { id: 'u1', email: 'u@x.com' }, accessToken: 'at', refreshToken: 'rt' }),
    logout: async () => {},
    ...overrides,
  };
}

function makeTokenService(overrides = {}) {
  return {
    rotateRefreshToken: async () => ({ accessToken: 'at2', refreshToken: 'rt2' }),
    ...overrides,
  };
}

const mockAuthenticate = (req, _res, next) => { req.user = { id: 'u1' }; next(); };

function buildApp(opts = {}) {
  const app = express();
  app.use(express.json());
  app.use(cookieParser());
  app.use('/auth', createAuthRouter({
    authService: opts.authService ?? makeAuthService(),
    tokenService: opts.tokenService ?? makeTokenService(),
    signer: opts.signer ?? null,
    mfaService: opts.mfaService ?? null,
    authenticate: mockAuthenticate,
    cookieMode: opts.cookieMode ?? false,
    cookieOptions: opts.cookieOptions ?? {},
    rateLimiters: opts.rateLimiters ?? {},
    csrf: opts.csrf ?? false,
  }));
  app.use(errorMapper);
  return app;
}

// ─── memoryRateLimit unit tests ──────────────────────────────────────────────

describe('createMemoryRateLimit', () => {
  it('allows requests up to the limit', () => {
    const adapter = createMemoryRateLimit();
    for (let i = 0; i < 5; i++) {
      expect(adapter.isRateLimited('key', 5, 60_000)).toBe(false);
    }
  });

  // AC1: 6th attempt is blocked
  it('blocks on the request that would exceed the limit', () => {
    const adapter = createMemoryRateLimit();
    for (let i = 0; i < 5; i++) adapter.isRateLimited('key', 5, 60_000);
    expect(adapter.isRateLimited('key', 5, 60_000)).toBe(true);
  });

  // AC2: after windowMs elapses, limit resets
  it('allows again after the window elapses', async () => {
    const adapter = createMemoryRateLimit();
    const windowMs = 50;
    for (let i = 0; i < 5; i++) adapter.isRateLimited('key', 5, windowMs);
    expect(adapter.isRateLimited('key', 5, windowMs)).toBe(true);

    // Sliding window: prevCount is only zeroed out after 2× the window has passed.
    // Waiting > 2× windowMs guarantees the previous window's weight drops to zero.
    await new Promise((r) => setTimeout(r, windowMs * 2 + 20));
    expect(adapter.isRateLimited('key', 5, windowMs)).toBe(false);
  });

  it('reset() clears the counter immediately', () => {
    const adapter = createMemoryRateLimit();
    for (let i = 0; i < 5; i++) adapter.isRateLimited('key', 5, 60_000);
    expect(adapter.isRateLimited('key', 5, 60_000)).toBe(true);

    adapter.reset('key');
    expect(adapter.isRateLimited('key', 5, 60_000)).toBe(false);
  });

  it('different keys are tracked independently', () => {
    const adapter = createMemoryRateLimit();
    for (let i = 0; i < 5; i++) adapter.isRateLimited('a@x.com', 5, 60_000);
    // 'a@x.com' is now limited; 'b@x.com' is untouched
    expect(adapter.isRateLimited('a@x.com', 5, 60_000)).toBe(true);
    expect(adapter.isRateLimited('b@x.com', 5, 60_000)).toBe(false);
  });

  // AC7: concurrency — parallel synchronous increments are atomic in Node.js single thread
  it('counts correctly when isRateLimited is called concurrently via Promise.all', async () => {
    const adapter = createMemoryRateLimit();
    const limit = 20;
    // Fire 20 concurrent "requests" — synchronous Map ops, no real race in Node.js single thread
    const results = await Promise.all(
      Array.from({ length: limit }, () => Promise.resolve(adapter.isRateLimited('ip', limit, 60_000))),
    );
    // All 20 should have been allowed (counter goes 0→19, all < limit)
    expect(results.every((r) => r === false)).toBe(true);
    // The very next call (21st) must be blocked — counter is now exactly limit
    expect(adapter.isRateLimited('ip', limit, 60_000)).toBe(true);
  });
});

// ─── createRateLimitMiddleware HTTP tests ────────────────────────────────────

describe('createRateLimitMiddleware (via HTTP)', () => {
  // AC1: 6 rapid attempts on the same account → 429 on 6th with Retry-After
  it('returns 429 on 6th request and includes Retry-After header (per-account)', async () => {
    const adapter = createMemoryRateLimit();
    const perEmailLimiter = createRateLimitMiddleware({
      keyFn: (req) => req.body?.email?.toLowerCase(),
      limit: 5,
      windowMs: 15 * 60 * 1000,
      adapter,
    });

    const authService = makeAuthService({
      login: async () => { throw new InvalidCredentialsError(); },
    });
    const app = buildApp({ authService, rateLimiters: { login: [perEmailLimiter] } });

    for (let i = 0; i < 5; i++) {
      const res = await request(app).post('/auth/login').send({ email: 'target@x.com', password: 'x' });
      expect(res.status).toBe(401); // wrong creds, rate limit not yet triggered
    }

    const res = await request(app).post('/auth/login').send({ email: 'target@x.com', password: 'x' });
    expect(res.status).toBe(429);
    expect(res.body.error.code).toBe('AUTH.RATE_LIMITED');
    expect(res.headers['retry-after']).toBeDefined();
    expect(Number(res.headers['retry-after'])).toBeGreaterThan(0);
  });

  // AC3: per-IP limit triggers on 21st attempt regardless of account
  it('returns 429 on 21st request per-IP regardless of which account is used', async () => {
    const adapter = createMemoryRateLimit();
    const perIpLimiter = createRateLimitMiddleware({
      keyFn: (req) => req.ip,
      limit: 20,
      windowMs: 15 * 60 * 1000,
      adapter,
    });

    const authService = makeAuthService({
      login: async () => { throw new InvalidCredentialsError(); },
    });
    const app = buildApp({ authService, rateLimiters: { login: [perIpLimiter] } });

    for (let i = 0; i < 20; i++) {
      const res = await request(app)
        .post('/auth/login')
        .send({ email: `user${i}@x.com`, password: 'x' }); // different accounts
      expect(res.status).toBe(401);
    }

    const res = await request(app).post('/auth/login').send({ email: 'another@x.com', password: 'x' });
    expect(res.status).toBe(429);
    expect(res.body.error.code).toBe('AUTH.RATE_LIMITED');
  });

  it('dual limiter: per-account fires first when same account is targeted', async () => {
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

    const authService = makeAuthService({
      login: async () => { throw new InvalidCredentialsError(); },
    });
    const app = buildApp({ authService, rateLimiters: { login: [perEmailLimiter, perIpLimiter] } });

    for (let i = 0; i < 5; i++) {
      await request(app).post('/auth/login').send({ email: 'target@x.com', password: 'x' });
    }
    const res = await request(app).post('/auth/login').send({ email: 'target@x.com', password: 'x' });
    expect(res.status).toBe(429);
  });

  // AC7: concurrent requests are all counted (no counter loss under parallel load)
  it('counts concurrent requests correctly — no counter drops under parallel load', async () => {
    const adapter = createMemoryRateLimit();
    const limiter = createRateLimitMiddleware({
      keyFn: (req) => req.body?.email?.toLowerCase(),
      limit: 20,
      windowMs: 60_000,
      adapter,
    });

    const app = buildApp({
      authService: makeAuthService({ login: async () => { throw new InvalidCredentialsError(); } }),
      rateLimiters: { login: [limiter] },
    });

    // Fire 20 requests concurrently
    const results = await Promise.all(
      Array.from({ length: 20 }, () =>
        request(app).post('/auth/login').send({ email: 'target@x.com', password: 'x' }),
      ),
    );
    const statuses = results.map((r) => r.status);
    // All 20 should be allowed (limit=20); 21st should be blocked
    expect(statuses.every((s) => s === 401)).toBe(true);

    const last = await request(app).post('/auth/login').send({ email: 'target@x.com', password: 'x' });
    expect(last.status).toBe(429);
  });
});

// ─── createCsrfMiddleware unit tests ─────────────────────────────────────────

describe('createCsrfMiddleware', () => {
  function buildCsrfApp(extraMiddleware = []) {
    const app = express();
    app.use(cookieParser());
    app.use(createCsrfMiddleware());
    extraMiddleware.forEach((mw) => app.use(mw));
    app.post('/protected', (_req, res) => res.json({ ok: true }));
    app.get('/safe', (_req, res) => res.json({ ok: true }));
    app.use(errorMapper);
    return app;
  }

  // AC5: passes with matching token
  it('passes POST with matching X-CSRF-Token header and cookie', async () => {
    const app = buildCsrfApp();
    const token = 'abc123';
    const res = await request(app)
      .post('/protected')
      .set('Cookie', `csrf_token=${token}`)
      .set('x-csrf-token', token);
    expect(res.status).toBe(200);
  });

  // AC4: blocks without matching header
  it('blocks POST with no X-CSRF-Token header', async () => {
    const app = buildCsrfApp();
    const res = await request(app)
      .post('/protected')
      .set('Cookie', 'csrf_token=abc123');
    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('AUTH.CSRF_INVALID');
  });

  it('blocks POST with mismatched X-CSRF-Token', async () => {
    const app = buildCsrfApp();
    const res = await request(app)
      .post('/protected')
      .set('Cookie', 'csrf_token=abc123')
      .set('x-csrf-token', 'wrong-token');
    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('AUTH.CSRF_INVALID');
  });

  it('blocks POST with no csrf_token cookie', async () => {
    const app = buildCsrfApp();
    const res = await request(app)
      .post('/protected')
      .set('x-csrf-token', 'abc123');
    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('AUTH.CSRF_INVALID');
  });

  // AC6: Bearer requests skip CSRF
  it('skips CSRF check for Authorization: Bearer requests', async () => {
    const app = buildCsrfApp();
    const res = await request(app)
      .post('/protected')
      .set('Authorization', 'Bearer some.jwt.token');
    // No csrf_token cookie, no X-CSRF-Token header — but Bearer auth skips the check
    expect(res.status).toBe(200);
  });

  it('skips CSRF check for safe GET requests', async () => {
    const app = buildCsrfApp();
    const res = await request(app).get('/safe');
    expect(res.status).toBe(200);
  });
});

// ─── Full route flow: login → CSRF cookie → refresh ─────────────────────────

describe('CSRF integration — login sets csrf_token, refresh enforces it', () => {
  const COOKIE_OPTS = { secure: false, sameSite: 'lax' };

  function buildCsrfApp(overrides = {}) {
    return buildApp({
      cookieMode: true,
      cookieOptions: COOKIE_OPTS,
      csrf: true,
      ...overrides,
    });
  }

  it('login (cookie mode + csrf) sets a non-HttpOnly csrf_token cookie', async () => {
    const app = buildCsrfApp();
    const res = await request(app).post('/auth/login').send({ email: 'u@x.com', password: 'pw' });
    expect(res.status).toBe(200);

    const setCookies = res.headers['set-cookie'] ?? [];
    const csrfCookie = (Array.isArray(setCookies) ? setCookies : [setCookies])
      .find((c) => c.startsWith('csrf_token='));

    expect(csrfCookie).toBeDefined();
    // csrf_token must NOT be HttpOnly — JavaScript must be able to read it
    expect(csrfCookie).not.toMatch(/HttpOnly/i);
  });

  it('login does NOT set csrf_token in header mode', async () => {
    const app = buildApp({ cookieMode: false, csrf: false });
    const res = await request(app).post('/auth/login').send({ email: 'u@x.com', password: 'pw' });
    expect(res.status).toBe(200);

    const setCookies = res.headers['set-cookie'] ?? [];
    const csrfCookie = (Array.isArray(setCookies) ? setCookies : [setCookies])
      .find((c) => c.startsWith('csrf_token='));
    expect(csrfCookie).toBeUndefined();
  });

  it('refresh passes when X-CSRF-Token matches the csrf_token cookie', async () => {
    const app = buildCsrfApp();

    // Step 1: login to get the csrf_token cookie value
    const loginRes = await request(app).post('/auth/login').send({ email: 'u@x.com', password: 'pw' });
    const allCookies = [].concat(loginRes.headers['set-cookie'] ?? []);
    const csrfCookieLine = allCookies.find((c) => c.startsWith('csrf_token='));
    const csrfToken = csrfCookieLine?.split(';')[0]?.split('=')[1];

    expect(csrfToken).toBeDefined();

    // Step 2: refresh with matching header + cookie
    const refreshRes = await request(app)
      .post('/auth/refresh')
      .set('Cookie', `refreshToken=rt; csrf_token=${csrfToken}`)
      .set('x-csrf-token', csrfToken);

    expect(refreshRes.status).toBe(200);
    expect(refreshRes.body.accessToken).toBeDefined();
  });

  it('refresh returns 403 when X-CSRF-Token header is absent', async () => {
    const app = buildCsrfApp();
    const token = 'legit-token-abc123';

    const res = await request(app)
      .post('/auth/refresh')
      .set('Cookie', `refreshToken=rt; csrf_token=${token}`);
    // No X-CSRF-Token header → blocked
    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('AUTH.CSRF_INVALID');
  });

  it('refresh returns 403 when X-CSRF-Token does not match the cookie', async () => {
    const app = buildCsrfApp();

    const res = await request(app)
      .post('/auth/refresh')
      .set('Cookie', 'refreshToken=rt; csrf_token=real-token')
      .set('x-csrf-token', 'tampered-token');

    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('AUTH.CSRF_INVALID');
  });

  it('refresh with Authorization: Bearer skips CSRF even without the cookie', async () => {
    const app = buildCsrfApp();

    const res = await request(app)
      .post('/auth/refresh')
      .set('Authorization', 'Bearer some.jwt.token')
      .send({ refreshToken: 'rt' });

    // CSRF is skipped for Bearer; refresh fails only because it's in header mode and
    // returns an error from tokenService (which succeeds in our mock).
    expect(res.status).not.toBe(403);
  });
});

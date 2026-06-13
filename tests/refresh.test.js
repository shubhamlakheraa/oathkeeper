const express = require('express');
const request = require('supertest');
const { Pool } = require('pg');
const { createPostgresStorage } = require('../src/adapters/storage/postgresStorage');
const { createArgon2Hasher } = require('../src/adapters/hasher/argon2Hasher');
const { createJwtSigner } = require('../src/utils/jwt');
const { createTokenService } = require('../src/services/tokenService');
const { createAuthService } = require('../src/services/authService');
const { createRefreshRouter } = require('../src/routes/refresh');
const { createLoginRouter } = require('../src/routes/login');
const { errorMapper } = require('../src/middleware/errorMapper');

const DATABASE_URL = process.env.DATABASE_URL;
const HASHER_CONFIG = { memoryCost: 1024, timeCost: 1, parallelism: 1 };

function buildApp({ tokenService, authService = null, cookieMode = false, cookieOptions = {} }) {
  const app = express();
  app.use(express.json());
  if (authService) {
    app.use('/auth', createLoginRouter({ authService, cookieMode, cookieOptions }));
  }
  app.use('/auth', createRefreshRouter({ tokenService, cookieMode, cookieOptions }));
  app.use(errorMapper);
  return app;
}

describe('POST /auth/refresh (integration)', () => {
  let pool;
  let storage;
  let signer;
  let tokenService;
  let authService;

  beforeAll(() => {
    if (!DATABASE_URL) {
      throw new Error(
        'DATABASE_URL not set. Run migrations and ensure .env is loaded before running these tests.',
      );
    }
    pool = new Pool({ connectionString: DATABASE_URL });
    storage = createPostgresStorage(pool);
    signer = createJwtSigner({ secret: 'test-secret-do-not-use-anywhere-else' });
    tokenService = createTokenService({
      storage,
      signer,
      accessTokenTtl: '5m',
      refreshTokenTtl: '7d',
    });
    authService = createAuthService({
      storage,
      hasher: createArgon2Hasher(HASHER_CONFIG),
      tokenService,
      signer,
    });
  });

  beforeEach(async () => {
    await pool.query(
      'TRUNCATE TABLE users, roles, permissions, role_permissions RESTART IDENTITY CASCADE',
    );
  });

  afterAll(async () => {
    await pool.end();
  });

  async function loginAndGetTokens(app, email = 'u@x.com', password = 'ValidPassword1!') {
    await authService.signup({ email, password, ip: null, userAgent: null });
    const res = await request(app)
      .post('/auth/login')
      .send({ email, password });
    return { accessToken: res.body.accessToken, refreshToken: res.body.refreshToken };
  }

  describe('header mode', () => {
    const app = buildApp({ tokenService: null, cookieMode: false });
    let appWithLogin;

    beforeAll(() => {
      appWithLogin = buildApp({ tokenService, authService, cookieMode: false });
    });

    it('first refresh → new access + refresh token pair; old token is revoked', async () => {
      const { refreshToken: t1 } = await loginAndGetTokens(appWithLogin);

      const res = await request(appWithLogin)
        .post('/auth/refresh')
        .send({ refreshToken: t1 });

      expect(res.status).toBe(200);
      expect(typeof res.body.accessToken).toBe('string');
      expect(typeof res.body.refreshToken).toBe('string');
      expect(res.body.refreshToken).not.toBe(t1);

      // old token must now be revoked
      const reuse = await request(appWithLogin)
        .post('/auth/refresh')
        .send({ refreshToken: t1 });
      expect(reuse.status).toBe(401);
      expect(reuse.body.error.code).toBe('AUTH.REFRESH_REUSE_DETECTED');
    });

    it('unknown token → 401 INVALID_REFRESH_TOKEN', async () => {
      const app2 = buildApp({ tokenService, cookieMode: false });
      const res = await request(app2)
        .post('/auth/refresh')
        .send({ refreshToken: 'does-not-exist' });

      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('AUTH.INVALID_REFRESH_TOKEN');
    });

    it('missing token body → 401 INVALID_REFRESH_TOKEN', async () => {
      const app2 = buildApp({ tokenService, cookieMode: false });
      const res = await request(app2).post('/auth/refresh').send({});

      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('AUTH.INVALID_REFRESH_TOKEN');
    });

    it('reuse of already-rotated token → 401 REFRESH_REUSE_DETECTED', async () => {
      const app2 = buildApp({ tokenService, authService, cookieMode: false });
      const { refreshToken: t1 } = await loginAndGetTokens(app2, 'reuse@x.com');

      const r2 = await request(app2).post('/auth/refresh').send({ refreshToken: t1 });
      const t2 = r2.body.refreshToken;

      // rotate t2 to get t3 — now t1 is already-rotated
      await request(app2).post('/auth/refresh').send({ refreshToken: t2 });

      const reuse = await request(app2).post('/auth/refresh').send({ refreshToken: t1 });
      expect(reuse.status).toBe(401);
      expect(reuse.body.error.code).toBe('AUTH.REFRESH_REUSE_DETECTED');
    });

    it('after reuse detection, every token in the family fails', async () => {
      const app2 = buildApp({ tokenService, authService, cookieMode: false });
      const { refreshToken: t1 } = await loginAndGetTokens(app2, 'family@x.com');

      const r2 = await request(app2).post('/auth/refresh').send({ refreshToken: t1 });
      const t2 = r2.body.refreshToken;
      const r3 = await request(app2).post('/auth/refresh').send({ refreshToken: t2 });
      const t3 = r3.body.refreshToken;

      // trigger reuse with t1 — revokes entire family
      await request(app2).post('/auth/refresh').send({ refreshToken: t1 });

      for (const token of [t1, t2, t3]) {
        const res = await request(app2).post('/auth/refresh').send({ refreshToken: token });
        expect(res.status).toBe(401);
      }
    });
  });

  describe('cookie mode', () => {
    const cookieOptions = { secure: false, sameSite: 'lax', maxAge: 604800000 };

    it('first refresh → new Set-Cookie with same security attributes', async () => {
      const app2 = buildApp({ tokenService, authService, cookieMode: true, cookieOptions });
      await authService.signup({ email: 'ck@x.com', password: 'ValidPassword1!', ip: null, userAgent: null });
      const loginRes = await request(app2)
        .post('/auth/login')
        .send({ email: 'ck@x.com', password: 'ValidPassword1!' });

      const loginCookie = loginRes.headers['set-cookie'];
      const rawToken = (Array.isArray(loginCookie) ? loginCookie[0] : loginCookie)
        .split(';')[0]
        .split('=')[1];

      const refreshRes = await request(app2)
        .post('/auth/refresh')
        .set('Cookie', `refreshToken=${rawToken}`);

      expect(refreshRes.status).toBe(200);
      expect(typeof refreshRes.body.accessToken).toBe('string');
      expect(refreshRes.body).not.toHaveProperty('refreshToken');

      const setCookie = refreshRes.headers['set-cookie'];
      expect(setCookie).toBeDefined();
      const cookieStr = Array.isArray(setCookie) ? setCookie.join('; ') : setCookie;
      expect(cookieStr).toMatch(/refreshToken=/);
      expect(cookieStr).toMatch(/HttpOnly/i);
      expect(cookieStr).toMatch(/Path=\/auth\/refresh/i);
    });
  });

  describe('end-to-end: login → refresh → refresh → reuse old → all revoked', () => {
    it('full rotation chain with reuse detection', async () => {
      const app2 = buildApp({ tokenService, authService, cookieMode: false });
      const { refreshToken: t1 } = await loginAndGetTokens(app2, 'e2e@x.com');

      const r2 = await request(app2).post('/auth/refresh').send({ refreshToken: t1 });
      expect(r2.status).toBe(200);
      const t2 = r2.body.refreshToken;

      const r3 = await request(app2).post('/auth/refresh').send({ refreshToken: t2 });
      expect(r3.status).toBe(200);
      const t3 = r3.body.refreshToken;

      // reuse t1 (already rotated) — triggers family revocation
      const reuse = await request(app2).post('/auth/refresh').send({ refreshToken: t1 });
      expect(reuse.status).toBe(401);
      expect(reuse.body.error.code).toBe('AUTH.REFRESH_REUSE_DETECTED');

      // t2 and t3 are now dead too
      for (const token of [t2, t3]) {
        const res = await request(app2).post('/auth/refresh').send({ refreshToken: token });
        expect(res.status).toBe(401);
      }
    });
  });
});

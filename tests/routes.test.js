const express = require('express');
const request = require('supertest');
const { createAuthRouter } = require('../src/routes/index');
const { errorMapper } = require('../src/middleware/errorMapper');
const {
  InvalidCredentialsError,
  MfaRequiredError,
  WeakPasswordError,
} = require('../src/error');

function buildApp({ authService, signer = null, cookieMode = false, cookieOptions = {} }) {
  const app = express();
  app.use(express.json());
  app.use('/auth', createAuthRouter({ authService, signer, cookieMode, cookieOptions }));
  app.use(errorMapper);
  return app;
}

const VALID_USER = { id: 'uuid-1', email: 'u@x.com', mfa_enabled: false };
const ACCESS_TOKEN = 'access.token.jwt';
const REFRESH_TOKEN = 'raw-refresh-token';

function makeAuthService(overrides = {}) {
  return {
    signup: async () => ({ user: VALID_USER, alreadyExists: false }),
    login: async () => ({ user: VALID_USER, accessToken: ACCESS_TOKEN, refreshToken: REFRESH_TOKEN }),
    logout: async () => {},
    ...overrides,
  };
}

describe('POST /auth/signup', () => {
  it('returns 201 and user on success', async () => {
    const app = buildApp({ authService: makeAuthService() });
    const res = await request(app)
      .post('/auth/signup')
      .send({ email: 'u@x.com', password: 'ValidPassword1!' });

    expect(res.status).toBe(201);
    expect(res.body.user.email).toBe('u@x.com');
    expect(res.body.user).not.toHaveProperty('password_hash');
  });

  it('returns 409 when email is already registered', async () => {
    const app = buildApp({
      authService: makeAuthService({ signup: async () => ({ user: null, alreadyExists: true }) }),
    });
    const res = await request(app)
      .post('/auth/signup')
      .send({ email: 'u@x.com', password: 'ValidPassword1!' });

    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('AUTH.EMAIL_TAKEN');
  });

  it('returns 422 for a weak password — no stack trace in body', async () => {
    const app = buildApp({
      authService: makeAuthService({
        signup: async () => { throw new WeakPasswordError('Password must be at least 12 characters'); },
      }),
    });
    const res = await request(app)
      .post('/auth/signup')
      .send({ email: 'u@x.com', password: 'short' });

    expect(res.status).toBe(422);
    expect(res.body.error.code).toBe('AUTH.WEAK_PASSWORD');
    expect(JSON.stringify(res.body)).not.toMatch(/stack/i);
  });
});

describe('POST /auth/login — cookie mode', () => {
  const app = buildApp({ authService: makeAuthService(), cookieMode: true, cookieOptions: { secure: true, sameSite: 'lax', maxAge: 604800000 } });

  it('returns 200 with accessToken in body and refreshToken as HttpOnly cookie', async () => {
    const res = await request(app)
      .post('/auth/login')
      .send({ email: 'u@x.com', password: 'ValidPassword1!' });

    expect(res.status).toBe(200);
    expect(res.body.accessToken).toBe(ACCESS_TOKEN);
    expect(res.body).not.toHaveProperty('refreshToken');

    const setCookie = res.headers['set-cookie'];
    expect(setCookie).toBeDefined();
    const cookieStr = Array.isArray(setCookie) ? setCookie.join('; ') : setCookie;
    expect(cookieStr).toMatch(/refreshToken=/);
    expect(cookieStr).toMatch(/HttpOnly/i);
    expect(cookieStr).toMatch(/Path=\/auth\/refresh/i);
  });
});

describe('POST /auth/login — header mode', () => {
  const app = buildApp({ authService: makeAuthService(), cookieMode: false });

  it('returns 200 with both tokens in body and no Set-Cookie header', async () => {
    const res = await request(app)
      .post('/auth/login')
      .send({ email: 'u@x.com', password: 'ValidPassword1!' });

    expect(res.status).toBe(200);
    expect(res.body.accessToken).toBe(ACCESS_TOKEN);
    expect(res.body.refreshToken).toBe(REFRESH_TOKEN);
    expect(res.headers['set-cookie']).toBeUndefined();
  });

  it('returns 401 AUTH.INVALID_CREDENTIALS on bad creds', async () => {
    const app2 = buildApp({
      authService: makeAuthService({ login: async () => { throw new InvalidCredentialsError(); } }),
    });
    const res = await request(app2)
      .post('/auth/login')
      .send({ email: 'u@x.com', password: 'wrong' });

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('AUTH.INVALID_CREDENTIALS');
    expect(JSON.stringify(res.body)).not.toMatch(/stack/i);
  });

  it('returns 403 AUTH.MFA_REQUIRED when MFA is enabled', async () => {
    const app2 = buildApp({
      authService: makeAuthService({
        login: async () => { throw new MfaRequiredError('mfa.token.here'); },
      }),
    });
    const res = await request(app2)
      .post('/auth/login')
      .send({ email: 'u@x.com', password: 'ValidPassword1!' });

    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('AUTH.MFA_REQUIRED');
    expect(res.body.error.mfaToken).toBe('mfa.token.here');
  });
});

describe('POST /auth/logout — cookie mode', () => {
  const mockSigner = { verify: () => ({ sub: 'uuid-1' }) };

  it('returns 200, clears the cookie, calls authService.logout', async () => {
    let capturedArgs = null;
    const app = buildApp({
      authService: makeAuthService({
        logout: async (args) => { capturedArgs = args; },
      }),
      signer: mockSigner,
      cookieMode: true,
      cookieOptions: { secure: true, sameSite: 'lax' },
    });

    const res = await request(app)
      .post('/auth/logout')
      .set('Cookie', 'refreshToken=raw-refresh-token')
      .set('Authorization', `Bearer ${ACCESS_TOKEN}`);

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);

    const setCookie = res.headers['set-cookie'];
    expect(setCookie).toBeDefined();
    const cookieStr = Array.isArray(setCookie) ? setCookie.join('; ') : setCookie;
    expect(cookieStr).toMatch(/refreshToken=/);
    expect(cookieStr).toMatch(/Path=\/auth\/refresh/i);

    expect(capturedArgs.refreshToken).toBe('raw-refresh-token');
    expect(capturedArgs.userId).toBe('uuid-1');
  });

  it('proceeds with userId null when Authorization header is absent', async () => {
    let capturedUserId;
    const app = buildApp({
      authService: makeAuthService({
        logout: async ({ userId }) => { capturedUserId = userId; },
      }),
      signer: mockSigner,
      cookieMode: true,
    });

    await request(app)
      .post('/auth/logout')
      .set('Cookie', 'refreshToken=raw-refresh-token');

    expect(capturedUserId).toBeNull();
  });
});

describe('errorMapper — no stack traces', () => {
  it('returns 500 with generic message on unhandled errors', async () => {
    const app = buildApp({
      authService: makeAuthService({
        login: async () => { throw new Error('Something exploded'); },
      }),
    });
    const res = await request(app)
      .post('/auth/login')
      .send({ email: 'u@x.com', password: 'x' });

    expect(res.status).toBe(500);
    expect(res.body.error.code).toBe('INTERNAL_ERROR');
    expect(JSON.stringify(res.body)).not.toMatch(/exploded/);
    expect(JSON.stringify(res.body)).not.toMatch(/stack/i);
  });
});

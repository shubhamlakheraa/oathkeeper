const express = require('express');
const request = require('supertest');
const { Pool } = require('pg');
const { createPostgresStorage } = require('../src/adapters/storage/postgresStorage');
const { createJwtSigner } = require('../src/utils/jwt');
const { createAuthenticate } = require('../src/middleware/authenticate');
const { errorMapper } = require('../src/middleware/errorMapper');

const DATABASE_URL = process.env.DATABASE_URL;

function buildApp(authenticate) {
  const app = express();
  app.get('/protected', authenticate, (req, res) => {
    res.json({
      userId: req.user.id,
      email: req.user.email,
      permissions: [...req.user.permissions],
      isMfaSatisfied: req.auth.isMfaSatisfied,
    });
  });
  app.use(errorMapper);
  return app;
}

describe('authenticate middleware (integration)', () => {
  let pool;
  let storage;
  let signer;
  let authenticate;

  beforeAll(() => {
    if (!DATABASE_URL) {
      throw new Error(
        'DATABASE_URL not set. Run migrations and ensure .env is loaded before running these tests.',
      );
    }
    pool = new Pool({ connectionString: DATABASE_URL });
    storage = createPostgresStorage(pool);
    signer = createJwtSigner({ secret: 'test-secret-do-not-use-anywhere-else' });
    authenticate = createAuthenticate({ signer, storage });
  });

  beforeEach(async () => {
    await pool.query(
      'TRUNCATE TABLE users, roles, permissions, role_permissions RESTART IDENTITY CASCADE',
    );
  });

  afterAll(async () => {
    await pool.end();
  });

  async function makeUser(email = 'u@x.com') {
    return storage.createUser({ email, passwordHash: 'h' });
  }

  function tokenFor(user, opts = {}) {
    return signer.sign({ sub: user.id, email: user.email, mfa: false }, { expiresIn: '5m', ...opts });
  }

  it('valid token → 200 with req.user fully populated including permissions Set', async () => {
    const user = await makeUser();
    const token = tokenFor(user);
    const app = buildApp(authenticate);

    const res = await request(app)
      .get('/protected')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.userId).toBe(user.id);
    expect(res.body.email).toBe(user.email);
    expect(Array.isArray(res.body.permissions)).toBe(true);
    expect(res.body.isMfaSatisfied).toBe(false);
  });

  it('no Authorization header → 401 AUTH.INVALID_TOKEN', async () => {
    const app = buildApp(authenticate);
    const res = await request(app).get('/protected');

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('AUTH.INVALID_TOKEN');
  });

  it('malformed token → 401 AUTH.INVALID_TOKEN', async () => {
    const app = buildApp(authenticate);
    const res = await request(app)
      .get('/protected')
      .set('Authorization', 'Bearer not.a.valid.jwt');

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('AUTH.INVALID_TOKEN');
  });

  it('expired token → 401 AUTH.TOKEN_EXPIRED (distinct from invalid)', async () => {
    const user = await makeUser('exp@x.com');
    const expiredToken = tokenFor(user, { expiresIn: -1 });
    const app = buildApp(authenticate);

    const res = await request(app)
      .get('/protected')
      .set('Authorization', `Bearer ${expiredToken}`);

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('AUTH.TOKEN_EXPIRED');
  });

  it('valid token for soft-deleted user → 401 AUTH.USER_NOT_FOUND', async () => {
    const user = await makeUser('gone@x.com');
    const token = tokenFor(user);
    await storage.softDeleteUser(user.id);
    const app = buildApp(authenticate);

    const res = await request(app)
      .get('/protected')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('AUTH.USER_NOT_FOUND');
  });

  it('verify runs before DB lookup — wrong signature never hits the DB', async () => {
    const otherSigner = createJwtSigner({ secret: 'different-secret' });
    const user = await makeUser('spy@x.com');
    const badToken = otherSigner.sign({ sub: user.id }, { expiresIn: '5m' });

    let dbCalled = false;
    const spyStorage = {
      ...storage,
      getUserById: async (...args) => { dbCalled = true; return storage.getUserById(...args); },
      getUserPermissions: async (...args) => { dbCalled = true; return storage.getUserPermissions(...args); },
    };
    const spyAuthenticate = createAuthenticate({ signer, storage: spyStorage });
    const app = buildApp(spyAuthenticate);

    const res = await request(app)
      .get('/protected')
      .set('Authorization', `Bearer ${badToken}`);

    expect(res.status).toBe(401);
    expect(dbCalled).toBe(false);
  });
});

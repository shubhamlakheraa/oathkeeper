const { Pool } = require('pg');
const { createPostgresStorage } = require('../src/adapters/storage/postgresStorage');
const { createArgon2Hasher } = require('../src/adapters/hasher/argon2Hasher');
const { createJwtSigner } = require('../src/utils/jwt');
const { createTokenService } = require('../src/services/tokenService');
const { createAuthService } = require('../src/services/authService');
const { InvalidCredentialsError, MfaRequiredError, InvalidRefreshTokenError } = require('../src/error');

const DATABASE_URL = process.env.DATABASE_URL;
const HASHER_CONFIG = { memoryCost: 1024, timeCost: 1, parallelism: 1 };

describe('authService — login / logout (integration)', () => {
  let pool;
  let storage;
  let hasher;
  let signer;
  let tokenService;
  let service;

  beforeAll(async () => {
    if (!DATABASE_URL) {
      throw new Error(
        'DATABASE_URL not set. Run migrations and ensure .env is loaded before running these tests.',
      );
    }
    pool = new Pool({ connectionString: DATABASE_URL });
    storage = createPostgresStorage(pool);
    hasher = createArgon2Hasher(HASHER_CONFIG);
    signer = createJwtSigner({ secret: 'test-secret-do-not-use-anywhere-else' });
    tokenService = createTokenService({
      storage,
      signer,
      accessTokenTtl: '5m',
      refreshTokenTtl: '7d',
    });
    service = createAuthService({ storage, hasher, tokenService, signer });
  });

  beforeEach(async () => {
    await pool.query(
      'TRUNCATE TABLE users, roles, permissions, role_permissions RESTART IDENTITY CASCADE',
    );
  });

  afterAll(async () => {
    await pool.end();
  });

  async function register(email = 'user@x.com', password = 'ValidPassword1!') {
    const { user } = await service.signup({ email, password, ip: '127.0.0.1', userAgent: 'test' });
    return user;
  }

  describe('login — correct credentials', () => {
    it('returns user, accessToken, and refreshToken on valid credentials', async () => {
      await register('ok@x.com');

      const result = await service.login({
        email: 'ok@x.com',
        password: 'ValidPassword1!',
        ip: '1.2.3.4',
        userAgent: 'Mozilla/5.0',
      });

      expect(result.user).not.toBeNull();
      expect(result.user.email).toBe('ok@x.com');
      expect(result.user).not.toHaveProperty('password_hash');
      expect(typeof result.accessToken).toBe('string');
      expect(typeof result.refreshToken).toBe('string');
    });

    it('access token carries correct claims and verifies with the JWT utility', async () => {
      const user = await register('jwt@x.com');

      const { accessToken } = await service.login({
        email: 'jwt@x.com',
        password: 'ValidPassword1!',
        ip: null,
        userAgent: null,
      });

      const claims = signer.verify(accessToken);
      expect(claims.sub).toBe(user.id);
      expect(claims.email).toBe('jwt@x.com');
      expect(claims.exp).toEqual(expect.any(Number));
    });
  });

  describe('login — wrong password', () => {
    it('throws InvalidCredentialsError on incorrect password', async () => {
      await register('wp@x.com');

      await expect(
        service.login({ email: 'wp@x.com', password: 'WrongPassword1!', ip: null, userAgent: null }),
      ).rejects.toBeInstanceOf(InvalidCredentialsError);
    });
  });

  describe('login — non-existent email', () => {
    it('throws InvalidCredentialsError — same shape as wrong password', async () => {
      await expect(
        service.login({
          email: 'ghost@x.com',
          password: 'ValidPassword1!',
          ip: null,
          userAgent: null,
        }),
      ).rejects.toBeInstanceOf(InvalidCredentialsError);
    });
  });

  describe('login — timing equalization', () => {
    it('non-existent email takes similar time to wrong password (within 10x — argon2 runs both paths)', async () => {
      await register('timing@x.com');

      const t1 = Date.now();
      await service.login({ email: 'timing@x.com', password: 'WrongPassword1!', ip: null, userAgent: null }).catch(() => {});
      const wrongPasswordMs = Date.now() - t1;

      const t2 = Date.now();
      await service.login({ email: 'ghost@x.com', password: 'ValidPassword1!', ip: null, userAgent: null }).catch(() => {});
      const unknownEmailMs = Date.now() - t2;

      // Both paths must run argon2 — neither should return in < 1ms
      expect(wrongPasswordMs).toBeGreaterThan(1);
      expect(unknownEmailMs).toBeGreaterThan(1);

      // Neither should be more than 10x slower than the other
      const ratio = Math.max(wrongPasswordMs, unknownEmailMs) / Math.min(wrongPasswordMs, unknownEmailMs);
      expect(ratio).toBeLessThan(10);
    });
  });

  describe('login — MFA-enabled user', () => {
    it('throws MfaRequiredError with an mfaToken when mfa_enabled is true', async () => {
      const user = await register('mfa@x.com');
      await storage.updateUser(user.id, { mfa_enabled: true });

      const err = await service
        .login({ email: 'mfa@x.com', password: 'ValidPassword1!', ip: null, userAgent: null })
        .catch((e) => e);

      expect(err).toBeInstanceOf(MfaRequiredError);
      expect(typeof err.mfaToken).toBe('string');

      const claims = signer.verify(err.mfaToken);
      expect(claims.sub).toBe(user.id);
      expect(claims.purpose).toBe('mfa_challenge');
    });
  });

  describe('logout', () => {
    it('revokes the refresh token — subsequent rotate throws InvalidRefreshTokenError', async () => {
      await register('logout@x.com');
      const { refreshToken } = await service.login({
        email: 'logout@x.com',
        password: 'ValidPassword1!',
        ip: '1.2.3.4',
        userAgent: 'agent',
      });

      const user = await storage.getUserByEmail('logout@x.com');
      await service.logout({ refreshToken, userId: user.id, ip: '1.2.3.4', userAgent: 'agent' });

      await expect(
        tokenService.rotateRefreshToken(refreshToken, { userAgent: 'agent', ip: '1.2.3.4' }),
      ).rejects.toBeInstanceOf(InvalidRefreshTokenError);
    });
  });

  describe('audit events', () => {
    it('writes login.success with ip and userAgent on successful login', async () => {
      const user = await register('audit-ok@x.com');

      await service.login({
        email: 'audit-ok@x.com',
        password: 'ValidPassword1!',
        ip: '10.0.0.1',
        userAgent: 'AuditAgent/1.0',
      });

      const row = (
        await pool.query(
          "SELECT * FROM auth_events WHERE user_id = $1 AND type = 'login.success'",
          [user.id],
        )
      ).rows[0];

      expect(row).not.toBeNull();
      expect(row.ip).toBe('10.0.0.1');
      expect(row.user_agent).toBe('AuditAgent/1.0');
    });

    it('writes login.failure with ip and userAgent on wrong password', async () => {
      const user = await register('audit-fail@x.com');

      await service
        .login({
          email: 'audit-fail@x.com',
          password: 'WrongPassword1!',
          ip: '10.0.0.2',
          userAgent: 'BadAgent/1.0',
        })
        .catch(() => {});

      const row = (
        await pool.query(
          "SELECT * FROM auth_events WHERE user_id = $1 AND type = 'login.failure'",
          [user.id],
        )
      ).rows[0];

      expect(row).not.toBeNull();
      expect(row.ip).toBe('10.0.0.2');
      expect(row.user_agent).toBe('BadAgent/1.0');
    });

    it('writes logout event with ip and userAgent', async () => {
      const user = await register('audit-logout@x.com');
      const { refreshToken } = await service.login({
        email: 'audit-logout@x.com',
        password: 'ValidPassword1!',
        ip: null,
        userAgent: null,
      });

      await service.logout({
        refreshToken,
        userId: user.id,
        ip: '10.0.0.3',
        userAgent: 'LogoutAgent/1.0',
      });

      const row = (
        await pool.query(
          "SELECT * FROM auth_events WHERE user_id = $1 AND type = 'logout'",
          [user.id],
        )
      ).rows[0];

      expect(row).not.toBeNull();
      expect(row.ip).toBe('10.0.0.3');
      expect(row.user_agent).toBe('LogoutAgent/1.0');
    });
  });
});

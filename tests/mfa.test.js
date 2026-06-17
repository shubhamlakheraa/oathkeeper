const { Pool } = require('pg');
const { createPostgresStorage } = require('../src/adapters/storage/postgresStorage');
const { createArgon2Hasher } = require('../src/adapters/hasher/argon2Hasher');
const { createJwtSigner } = require('../src/utils/jwt');
const { createTokenService } = require('../src/services/tokenService');
const { createAuthService } = require('../src/services/authService');
const { createMfaService } = require('../src/services/mfaService');
const { createMemoryReplayStore } = require('../src/adapters/replayStore/memoryReplayStore');
const { generateCode } = require('../src/utils/totp');
const {
  MfaRequiredError,
  InvalidMfaCodeError,
  InvalidCredentialsError,
  InvalidTokenError,
} = require('../src/error');

const DATABASE_URL = process.env.DATABASE_URL;
const HASHER_CONFIG = { memoryCost: 1024, timeCost: 1, parallelism: 1 };

describe('MFA enroll + confirm + login (integration)', () => {
  let pool;
  let storage;
  let hasher;
  let signer;
  let tokenService;
  let mfaService;
  let service;

  beforeAll(() => {
    if (!DATABASE_URL) throw new Error('DATABASE_URL not set.');
    pool = new Pool({ connectionString: DATABASE_URL });
    storage = createPostgresStorage(pool);
    hasher = createArgon2Hasher(HASHER_CONFIG);
    signer = createJwtSigner({ secret: 'test-secret-do-not-use' });
    tokenService = createTokenService({ storage, signer, accessTokenTtl: '5m', refreshTokenTtl: '7d' });
  });

  beforeEach(async () => {
    await pool.query(
      'TRUNCATE TABLE users, roles, permissions, role_permissions RESTART IDENTITY CASCADE',
    );
    // fresh replay store per test — prevents cross-test replay collisions
    mfaService = createMfaService({ storage, hasher, issuer: 'TestApp', replayStore: createMemoryReplayStore() });
    service = createAuthService({
      storage, hasher, tokenService, signer,
      mailer: { sendMail: async () => {} },
      config: { baseUrl: 'http://localhost:3000' },
      mfaService,
    });
  });

  afterAll(async () => { await pool.end(); });

  async function register(email = 'u@x.com', password = 'ValidPassword1!') {
    const { user } = await service.signup({ email, password, ip: null, userAgent: null });
    return user;
  }

  async function enrollAndConfirm(user) {
    const { secret } = await mfaService.beginEnrollment(user);
    // use the -1 window so the current window remains available for subsequent operations
    const code = generateCode(secret, Date.now() - 30 * 1000);
    const { recoveryCodes } = await mfaService.confirmEnrollment(user, code);
    return { secret, recoveryCodes };
  }

  // ─── beginEnrollment ────────────────────────────────────────────────────────

  describe('beginEnrollment', () => {
    it('returns a base32 secret and otpauth URI, stores pending secret in DB', async () => {
      const user = await register();
      const { secret, uri } = await mfaService.beginEnrollment(user);

      expect(typeof secret).toBe('string');
      expect(/^[A-Z2-7]+$/.test(secret)).toBe(true);
      expect(uri).toMatch(/^otpauth:\/\/totp\//);
      expect(uri).toContain(`secret=${secret}`);

      const stored = await storage.getMfaSecret(user.id);
      expect(stored).toBe(secret);
    });

    it('does not enable MFA until confirmEnrollment', async () => {
      const user = await register();
      await mfaService.beginEnrollment(user);
      const row = (await pool.query('SELECT mfa_enabled FROM users WHERE id = $1', [user.id])).rows[0];
      expect(row.mfa_enabled).toBe(false);
    });
  });

  // ─── confirmEnrollment ──────────────────────────────────────────────────────

  describe('confirmEnrollment', () => {
    it('valid code enables MFA and returns 10 plaintext recovery codes', async () => {
      const user = await register();
      const { secret, recoveryCodes } = await enrollAndConfirm(user);

      expect(recoveryCodes).toHaveLength(10);
      recoveryCodes.forEach((c) => expect(typeof c).toBe('string'));

      const row = (await pool.query('SELECT mfa_enabled FROM users WHERE id = $1', [user.id])).rows[0];
      expect(row.mfa_enabled).toBe(true);
      void secret;
    });

    it('recovery codes are stored as hashes — plaintext is never in the DB', async () => {
      const user = await register();
      const { recoveryCodes } = await enrollAndConfirm(user);

      const rows = (await pool.query(
        'SELECT code_hash FROM mfa_recovery_codes WHERE user_id = $1',
        [user.id],
      )).rows;
      expect(rows).toHaveLength(10);
      rows.forEach((row, i) => {
        expect(row.code_hash).not.toBe(recoveryCodes[i]);
      });
    });

    it('invalid code throws InvalidMfaCodeError and does not enable MFA', async () => {
      const user = await register();
      await mfaService.beginEnrollment(user);

      await expect(
        mfaService.confirmEnrollment(user, '000000'),
      ).rejects.toBeInstanceOf(InvalidMfaCodeError);

      const row = (await pool.query('SELECT mfa_enabled FROM users WHERE id = $1', [user.id])).rows[0];
      expect(row.mfa_enabled).toBe(false);
    });

    it('throws InvalidMfaCodeError if no pending secret exists', async () => {
      const user = await register();
      await expect(
        mfaService.confirmEnrollment(user, '123456'),
      ).rejects.toBeInstanceOf(InvalidMfaCodeError);
    });
  });

  // ─── login MFA challenge flow ────────────────────────────────────────────────

  describe('login with MFA enabled', () => {
    it('login throws MfaRequiredError with a signed mfaToken after enroll+confirm', async () => {
      const user = await register('mfa@x.com');
      await enrollAndConfirm(user);

      const err = await service
        .login({ email: 'mfa@x.com', password: 'ValidPassword1!', ip: null, userAgent: null })
        .catch((e) => e);

      expect(err).toBeInstanceOf(MfaRequiredError);
      expect(typeof err.mfaToken).toBe('string');
      const claims = signer.verify(err.mfaToken);
      expect(claims.purpose).toBe('mfa_challenge');
      expect(claims.sub).toBe(user.id);
    });

    it('completeMfaLogin: valid TOTP code issues tokens and completes login', async () => {
      const user = await register('mfa2@x.com');
      const { secret } = await enrollAndConfirm(user);

      const err = await service
        .login({ email: 'mfa2@x.com', password: 'ValidPassword1!', ip: null, userAgent: null })
        .catch((e) => e);

      const result = await service.completeMfaLogin({
        mfaToken: err.mfaToken,
        code: generateCode(secret),
        userAgent: 'agent',
        ip: '127.0.0.1',
      });

      expect(result.user.email).toBe('mfa2@x.com');
      expect(typeof result.accessToken).toBe('string');
      expect(typeof result.refreshToken).toBe('string');
    });

    it('wrong TOTP code → InvalidMfaCodeError', async () => {
      const user = await register('mfa3@x.com');
      await enrollAndConfirm(user);

      const err = await service
        .login({ email: 'mfa3@x.com', password: 'ValidPassword1!', ip: null, userAgent: null })
        .catch((e) => e);

      await expect(
        service.completeMfaLogin({ mfaToken: err.mfaToken, code: '000000', userAgent: null, ip: null }),
      ).rejects.toBeInstanceOf(InvalidMfaCodeError);
    });

    it('completeMfaLogin rejects token without purpose: mfa_challenge', async () => {
      const user = await register('mfa4@x.com');
      await enrollAndConfirm(user);

      const wrongToken = signer.sign({ sub: user.id }, { expiresIn: '5m' });
      await expect(
        service.completeMfaLogin({ mfaToken: wrongToken, code: '123456', userAgent: null, ip: null }),
      ).rejects.toBeInstanceOf(InvalidTokenError);
    });

    it('completeMfaLogin rejects a regular access token used as mfaToken', async () => {
      const { user } = await service.signup({ email: 'nomfa@x.com', password: 'ValidPassword1!', ip: null, userAgent: null });
      const accessToken = tokenService.issueAccessToken(user);

      await expect(
        service.completeMfaLogin({ mfaToken: accessToken, code: '123456', userAgent: null, ip: null }),
      ).rejects.toBeInstanceOf(InvalidTokenError);
    });
  });

  // ─── recovery codes ──────────────────────────────────────────────────────────

  describe('recovery codes', () => {
    it('valid recovery code completes MFA login', async () => {
      const user = await register('rec@x.com');
      const { recoveryCodes } = await enrollAndConfirm(user);

      const err = await service
        .login({ email: 'rec@x.com', password: 'ValidPassword1!', ip: null, userAgent: null })
        .catch((e) => e);

      const result = await service.completeMfaLogin({
        mfaToken: err.mfaToken,
        code: recoveryCodes[0],
        userAgent: null,
        ip: null,
      });
      expect(result.user.email).toBe('rec@x.com');
    });

    it('recovery code is single-use — second use is rejected', async () => {
      const user = await register('rec2@x.com');
      const { recoveryCodes } = await enrollAndConfirm(user);

      const err1 = await service
        .login({ email: 'rec2@x.com', password: 'ValidPassword1!', ip: null, userAgent: null })
        .catch((e) => e);
      await service.completeMfaLogin({ mfaToken: err1.mfaToken, code: recoveryCodes[0], userAgent: null, ip: null });

      const err2 = await service
        .login({ email: 'rec2@x.com', password: 'ValidPassword1!', ip: null, userAgent: null })
        .catch((e) => e);
      await expect(
        service.completeMfaLogin({ mfaToken: err2.mfaToken, code: recoveryCodes[0], userAgent: null, ip: null }),
      ).rejects.toBeInstanceOf(InvalidMfaCodeError);
    });
  });

  // ─── disable ────────────────────────────────────────────────────────────────

  describe('disable', () => {
    it('correct password + correct TOTP code disables MFA', async () => {
      const user = await register('dis@x.com');
      const { secret } = await enrollAndConfirm(user);

      await mfaService.disable(user, { password: 'ValidPassword1!', code: generateCode(secret) });

      const row = (await pool.query('SELECT mfa_enabled FROM users WHERE id = $1', [user.id])).rows[0];
      expect(row.mfa_enabled).toBe(false);
    });

    it('after disable, mfa_secret is cleared in DB', async () => {
      const user = await register('dis2@x.com');
      const { secret } = await enrollAndConfirm(user);
      await mfaService.disable(user, { password: 'ValidPassword1!', code: generateCode(secret) });

      const row = (await pool.query('SELECT mfa_secret FROM users WHERE id = $1', [user.id])).rows[0];
      expect(row.mfa_secret).toBeNull();
    });

    it('after disable, all recovery codes are deleted', async () => {
      const user = await register('dis3@x.com');
      const { secret } = await enrollAndConfirm(user);
      await mfaService.disable(user, { password: 'ValidPassword1!', code: generateCode(secret) });

      const rows = (await pool.query('SELECT * FROM mfa_recovery_codes WHERE user_id = $1', [user.id])).rows;
      expect(rows).toHaveLength(0);
    });

    it('after disable, login succeeds without MFA challenge', async () => {
      const user = await register('dis4@x.com');
      const { secret } = await enrollAndConfirm(user);
      await mfaService.disable(user, { password: 'ValidPassword1!', code: generateCode(secret) });

      const result = await service.login({
        email: 'dis4@x.com', password: 'ValidPassword1!', ip: null, userAgent: null,
      });
      expect(result.user.email).toBe('dis4@x.com');
      expect(typeof result.accessToken).toBe('string');
    });

    it('wrong password → InvalidCredentialsError, MFA stays enabled', async () => {
      const user = await register('dis5@x.com');
      const { secret } = await enrollAndConfirm(user);

      await expect(
        mfaService.disable(user, { password: 'WrongPassword1!', code: generateCode(secret) }),
      ).rejects.toBeInstanceOf(InvalidCredentialsError);

      const row = (await pool.query('SELECT mfa_enabled FROM users WHERE id = $1', [user.id])).rows[0];
      expect(row.mfa_enabled).toBe(true);
    });

    it('wrong TOTP code → InvalidMfaCodeError, MFA stays enabled', async () => {
      const user = await register('dis6@x.com');
      await enrollAndConfirm(user);

      await expect(
        mfaService.disable(user, { password: 'ValidPassword1!', code: '000000' }),
      ).rejects.toBeInstanceOf(InvalidMfaCodeError);

      const row = (await pool.query('SELECT mfa_enabled FROM users WHERE id = $1', [user.id])).rows[0];
      expect(row.mfa_enabled).toBe(true);
    });
  });
});

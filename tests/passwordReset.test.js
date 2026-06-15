const { Pool } = require('pg');
const { createPostgresStorage } = require('../src/adapters/storage/postgresStorage');
const { createArgon2Hasher } = require('../src/adapters/hasher/argon2Hasher');
const { createJwtSigner } = require('../src/utils/jwt');
const { createTokenService } = require('../src/services/tokenService');
const { createAuthService } = require('../src/services/authService');
const { InvalidCredentialsError, InvalidOrExpiredTokenError, WeakPasswordError } = require('../src/error');
const { sha256 } = require('../src/utils/random');

const DATABASE_URL = process.env.DATABASE_URL;
const HASHER_CONFIG = { memoryCost: 1024, timeCost: 1, parallelism: 1 };

describe('password reset + change (integration)', () => {
  let pool;
  let storage;
  let hasher;
  let signer;
  let tokenService;
  let service;
  let sentMails;

  beforeAll(() => {
    if (!DATABASE_URL) throw new Error('DATABASE_URL not set.');
    pool = new Pool({ connectionString: DATABASE_URL });
    storage = createPostgresStorage(pool);
    hasher = createArgon2Hasher(HASHER_CONFIG);
    signer = createJwtSigner({ secret: 'test-secret-do-not-use-anywhere-else' });
    tokenService = createTokenService({ storage, signer, accessTokenTtl: '5m', refreshTokenTtl: '7d' });
    service = createAuthService({
      storage,
      hasher,
      tokenService,
      signer,
      mailer: { sendMail: async (m) => sentMails.push(m) },
      config: { baseUrl: 'http://localhost:3000' },
    });
  });

  beforeEach(async () => {
    sentMails = [];
    await pool.query(
      'TRUNCATE TABLE users, roles, permissions, role_permissions RESTART IDENTITY CASCADE',
    );
  });

  afterAll(async () => { await pool.end(); });

  async function register(email = 'u@x.com', password = 'ValidPassword1!') {
    const { user } = await service.signup({ email, password, ip: null, userAgent: null });
    return user;
  }

  async function loginAndGetToken(email, password = 'ValidPassword1!') {
    return service.login({ email, password, ip: '127.0.0.1', userAgent: 'agent' });
  }

  function extractResetToken(html) {
    const match = html.match(/token=([A-Za-z0-9%_-]+)/);
    if (!match) throw new Error('No token in email body');
    return decodeURIComponent(match[1]);
  }

  // ─── requestPasswordReset ────────────────────────────────────────────────

  describe('requestPasswordReset', () => {
    it('returns identical generic message for existing email', async () => {
      await register('exists@x.com');
      const result = await service.requestPasswordReset('exists@x.com');
      expect(typeof result.message).toBe('string');
      expect(sentMails).toHaveLength(1);
    });

    it('returns identical generic message for non-existing email — no email sent', async () => {
      const result = await service.requestPasswordReset('ghost@x.com');
      expect(typeof result.message).toBe('string');
      expect(sentMails).toHaveLength(0);
    });

    it('both cases return the same message shape (enumeration protection)', async () => {
      await register('real@x.com');
      const r1 = await service.requestPasswordReset('real@x.com');
      const r2 = await service.requestPasswordReset('fake@x.com');
      expect(r1.message).toBe(r2.message);
    });
  });

  // ─── confirmPasswordReset ────────────────────────────────────────────────

  describe('confirmPasswordReset', () => {
    it('valid token + strong password → password updated, can login with new password', async () => {
      await register('reset@x.com');
      await service.requestPasswordReset('reset@x.com');
      const rawToken = extractResetToken(sentMails[0].html);

      await service.confirmPasswordReset({ token: rawToken, newPassword: 'NewValidPass1!' });

      const { user } = await loginAndGetToken('reset@x.com', 'NewValidPass1!');
      expect(user.email).toBe('reset@x.com');
    });

    it('revokes ALL refresh tokens for user (two-device scenario)', async () => {
      await register('twodev@x.com');

      // device 1 and device 2 both logged in
      const { refreshToken: rt1 } = await loginAndGetToken('twodev@x.com');
      const { refreshToken: rt2 } = await loginAndGetToken('twodev@x.com');

      await service.requestPasswordReset('twodev@x.com');
      const rawToken = extractResetToken(sentMails[0].html);
      await service.confirmPasswordReset({ token: rawToken, newPassword: 'NewValidPass1!' });

      // both refresh tokens must now be revoked
      const hash1 = sha256(rt1);
      const hash2 = sha256(rt2);
      const row1 = (await pool.query('SELECT revoked_at FROM refresh_tokens WHERE token_hash = $1', [hash1])).rows[0];
      const row2 = (await pool.query('SELECT revoked_at FROM refresh_tokens WHERE token_hash = $1', [hash2])).rows[0];
      expect(row1.revoked_at).not.toBeNull();
      expect(row2.revoked_at).not.toBeNull();
    });

    it('reset token is single-use — second use throws InvalidOrExpiredTokenError', async () => {
      await register('singleuse@x.com');
      await service.requestPasswordReset('singleuse@x.com');
      const rawToken = extractResetToken(sentMails[0].html);

      await service.confirmPasswordReset({ token: rawToken, newPassword: 'NewValidPass1!' });
      await expect(
        service.confirmPasswordReset({ token: rawToken, newPassword: 'AnotherPass1!' }),
      ).rejects.toBeInstanceOf(InvalidOrExpiredTokenError);
    });

    it('expired token → InvalidOrExpiredTokenError', async () => {
      await register('exptoken@x.com');
      await service.requestPasswordReset('exptoken@x.com');
      const rawToken = extractResetToken(sentMails[0].html);

      await pool.query(
        `UPDATE password_reset_tokens SET expires_at = now() - interval '1 second' WHERE token_hash = $1`,
        [sha256(rawToken)],
      );

      await expect(
        service.confirmPasswordReset({ token: rawToken, newPassword: 'NewValidPass1!' }),
      ).rejects.toBeInstanceOf(InvalidOrExpiredTokenError);
    });

    it('weak new password → WeakPasswordError, token not consumed', async () => {
      await register('weakpw@x.com');
      await service.requestPasswordReset('weakpw@x.com');
      const rawToken = extractResetToken(sentMails[0].html);

      await expect(
        service.confirmPasswordReset({ token: rawToken, newPassword: 'short' }),
      ).rejects.toBeInstanceOf(WeakPasswordError);

      // token must still be valid — password check runs before consume
      await expect(
        service.confirmPasswordReset({ token: rawToken, newPassword: 'NewValidPass1!' }),
      ).resolves.not.toThrow();
    });
  });

  // ─── changePassword ──────────────────────────────────────────────────────

  describe('changePassword', () => {
    it('correct current password → password updated', async () => {
      const user = await register('change@x.com');
      await service.changePassword(user, {
        currentPassword: 'ValidPassword1!',
        newPassword: 'ChangedPass1!',
        currentRefreshToken: null,
      });

      const { user: u } = await loginAndGetToken('change@x.com', 'ChangedPass1!');
      expect(u.email).toBe('change@x.com');
    });

    it('wrong current password → InvalidCredentialsError', async () => {
      const user = await register('wrongpw@x.com');
      await expect(
        service.changePassword(user, {
          currentPassword: 'WrongPassword1!',
          newPassword: 'ChangedPass1!',
          currentRefreshToken: null,
        }),
      ).rejects.toBeInstanceOf(InvalidCredentialsError);
    });

    it('current session refresh token is preserved; other sessions are revoked', async () => {
      const user = await register('sessions@x.com');
      const { refreshToken: currentRt } = await loginAndGetToken('sessions@x.com');
      const { refreshToken: otherRt } = await loginAndGetToken('sessions@x.com');

      await service.changePassword(user, {
        currentPassword: 'ValidPassword1!',
        newPassword: 'ChangedPass1!',
        currentRefreshToken: currentRt,
      });

      const currentRow = (await pool.query(
        'SELECT revoked_at FROM refresh_tokens WHERE token_hash = $1',
        [sha256(currentRt)],
      )).rows[0];
      const otherRow = (await pool.query(
        'SELECT revoked_at FROM refresh_tokens WHERE token_hash = $1',
        [sha256(otherRt)],
      )).rows[0];

      expect(currentRow.revoked_at).toBeNull();
      expect(otherRow.revoked_at).not.toBeNull();
    });

    it('weak new password → WeakPasswordError', async () => {
      const user = await register('weakchange@x.com');
      await expect(
        service.changePassword(user, {
          currentPassword: 'ValidPassword1!',
          newPassword: 'short',
          currentRefreshToken: null,
        }),
      ).rejects.toBeInstanceOf(WeakPasswordError);
    });
  });
});

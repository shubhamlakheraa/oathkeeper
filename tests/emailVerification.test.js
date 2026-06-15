const { Pool } = require('pg');
const { createPostgresStorage } = require('../src/adapters/storage/postgresStorage');
const { createArgon2Hasher } = require('../src/adapters/hasher/argon2Hasher');
const { createJwtSigner } = require('../src/utils/jwt');
const { createTokenService } = require('../src/services/tokenService');
const { createAuthService } = require('../src/services/authService');
const { sha256 } = require('../src/utils/random');
const { InvalidOrExpiredTokenError } = require('../src/error');

const DATABASE_URL = process.env.DATABASE_URL;

describe('email verification (integration)', () => {
  let pool;
  let storage;
  let service;
  let sentMails;
  let mailer;

  beforeAll(() => {
    if (!DATABASE_URL) {
      throw new Error(
        'DATABASE_URL not set. Run migrations and ensure .env is loaded before running these tests.',
      );
    }
    pool = new Pool({ connectionString: DATABASE_URL });
    storage = createPostgresStorage(pool);
    const signer = createJwtSigner({ secret: 'test-secret-do-not-use-anywhere-else' });
    const tokenService = createTokenService({
      storage,
      signer,
      accessTokenTtl: '5m',
      refreshTokenTtl: '7d',
    });
    mailer = {
      sendMail: async (msg) => { sentMails.push(msg); },
    };
    service = createAuthService({
      storage,
      hasher: createArgon2Hasher({ memoryCost: 1024, timeCost: 1, parallelism: 1 }),
      tokenService,
      signer,
      mailer,
      config: { baseUrl: 'http://localhost:3000' },
    });
  });

  beforeEach(async () => {
    sentMails = [];
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

  function extractToken(html) {
    const match = html.match(/token=([A-Za-z0-9_-]+)/);
    if (!match) throw new Error('No token found in email body');
    return match[1];
  }

  describe('requestEmailVerification', () => {
    it('sends email with to, subject, and a fully-formed copy-pasteable URL', async () => {
      const user = await makeUser('req@x.com');
      await service.requestEmailVerification(user);

      expect(sentMails).toHaveLength(1);
      const mail = sentMails[0];
      expect(mail.to).toBe('req@x.com');
      expect(typeof mail.subject).toBe('string');
      expect(mail.subject.length).toBeGreaterThan(0);
      expect(mail.html).toMatch(/http:\/\/localhost:3000\/auth\/email\/verify\/confirm\?token=/);
    });

    it('stores SHA-256 of raw token — raw token is not in the DB', async () => {
      const user = await makeUser('hash@x.com');
      await service.requestEmailVerification(user);

      const rawToken = extractToken(sentMails[0].html);
      const row = (
        await pool.query(
          'SELECT token_hash FROM email_verification_tokens WHERE user_id = $1',
          [user.id],
        )
      ).rows[0];

      expect(row.token_hash).not.toBe(rawToken);
      expect(row.token_hash).toBe(sha256(rawToken));
    });

    it('logs email_verification.requested event', async () => {
      const user = await makeUser('evt-req@x.com');
      await service.requestEmailVerification(user);

      const row = (
        await pool.query(
          "SELECT * FROM auth_events WHERE user_id = $1 AND type = 'email_verification.requested'",
          [user.id],
        )
      ).rows[0];
      expect(row).not.toBeNull();
    });
  });

  describe('confirmEmailVerification', () => {
    it('valid token → email_verified = true', async () => {
      const user = await makeUser('confirm@x.com');
      await service.requestEmailVerification(user);
      const rawToken = extractToken(sentMails[0].html);

      await service.confirmEmailVerification(rawToken);

      const updated = await storage.getUserById(user.id);
      expect(updated.email_verified).toBe(true);
    });

    it('logs email_verification.confirmed event', async () => {
      const user = await makeUser('evt-confirm@x.com');
      await service.requestEmailVerification(user);
      const rawToken = extractToken(sentMails[0].html);

      await service.confirmEmailVerification(rawToken);

      const row = (
        await pool.query(
          "SELECT * FROM auth_events WHERE user_id = $1 AND type = 'email_verification.confirmed'",
          [user.id],
        )
      ).rows[0];
      expect(row).not.toBeNull();
    });

    it('reuse of already-confirmed token → InvalidOrExpiredTokenError', async () => {
      const user = await makeUser('reuse@x.com');
      await service.requestEmailVerification(user);
      const rawToken = extractToken(sentMails[0].html);

      await service.confirmEmailVerification(rawToken);

      await expect(service.confirmEmailVerification(rawToken)).rejects.toBeInstanceOf(InvalidOrExpiredTokenError);
    });

    it('expired token → InvalidOrExpiredTokenError', async () => {
      const user = await makeUser('expired@x.com');
      await service.requestEmailVerification(user);
      const rawToken = extractToken(sentMails[0].html);

      await pool.query(
        `UPDATE email_verification_tokens SET expires_at = now() - interval '1 second'
         WHERE token_hash = $1`,
        [sha256(rawToken)],
      );

      await expect(service.confirmEmailVerification(rawToken)).rejects.toBeInstanceOf(InvalidOrExpiredTokenError);
    });

    it('unknown token → InvalidOrExpiredTokenError', async () => {
      await expect(
        service.confirmEmailVerification('completely-unknown-token'),
      ).rejects.toBeInstanceOf(InvalidOrExpiredTokenError);
    });
  });
});

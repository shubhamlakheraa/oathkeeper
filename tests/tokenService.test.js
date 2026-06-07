const { Pool } = require('pg');
const { createPostgresStorage } = require('../src/adapters/storage/postgresStorage');
const { createJwtSigner } = require('../src/utils/jwt');
const { createTokenService } = require('../src/services/tokenService');
const { sha256 } = require('../src/utils/random');
const {
  InvalidRefreshTokenError,
  RefreshTokenReuseError,
} = require('../src/error');

const DATABASE_URL = process.env.DATABASE_URL;

describe('tokenService (integration)', () => {
  let pool;
  let storage;
  let signer;
  let service;

  beforeAll(() => {
    if (!DATABASE_URL) {
      throw new Error(
        'DATABASE_URL not set. Run migrations and ensure .env is loaded before running these tests.',
      );
    }
    pool = new Pool({ connectionString: DATABASE_URL });
    storage = createPostgresStorage(pool);
    signer = createJwtSigner({ secret: 'test-secret-do-not-use-anywhere-else' });
    service = createTokenService({
      storage,
      signer,
      accessTokenTtl: '5m',
      refreshTokenTtl: '7d',
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

  async function makeUser(email = 'u@x.com') {
    return storage.createUser({ email, passwordHash: 'h' });
  }

  async function newFamilyId() {
    return (await pool.query('SELECT gen_random_uuid() AS id')).rows[0].id;
  }

  describe('issueAccessToken', () => {
    it('produces a JWT that signer.verify accepts and carries sub/email/mfa', async () => {
      const user = await makeUser('access@x.com');
      const token = service.issueAccessToken(user);
      const claims = signer.verify(token);
      expect(claims.sub).toBe(user.id);
      expect(claims.email).toBe('access@x.com');
      expect(claims.mfa).toBe(false);
      expect(claims.exp).toEqual(expect.any(Number));
    });
  });

  describe('issueRefreshToken', () => {
    it('returns a raw token whose value is not what is stored in the DB', async () => {
      const user = await makeUser();
      const familyId = await newFamilyId();
      const rawToken = await service.issueRefreshToken(user, {
        familyId,
        userAgent: 'a',
        ip: '127.0.0.1',
      });
      expect(typeof rawToken).toBe('string');

      const stored = (
        await pool.query(`SELECT token_hash FROM refresh_tokens WHERE family_id = $1`, [familyId])
      ).rows[0];
      expect(stored.token_hash).not.toBe(rawToken);
      expect(stored.token_hash).toBe(sha256(rawToken));
    });
  });

  describe('rotateRefreshToken — happy path', () => {
    it('issues a new pair, revokes the old, and stamps replaced_by_id to the new row', async () => {
      const user = await makeUser();
      const familyId = await newFamilyId();
      const oldRaw = await service.issueRefreshToken(user, {
        familyId,
        userAgent: 'old-agent',
        ip: '127.0.0.1',
      });

      const { refreshToken: newRaw, accessToken } = await service.rotateRefreshToken(oldRaw, {
        userAgent: 'new-agent',
        ip: '10.0.0.1',
      });

      expect(newRaw).not.toBe(oldRaw);
      expect(typeof newRaw).toBe('string');

      const oldRow = (
        await pool.query(`SELECT * FROM refresh_tokens WHERE token_hash = $1`, [sha256(oldRaw)])
      ).rows[0];
      expect(oldRow.revoked_at).not.toBeNull();
      expect(oldRow.replaced_by_id).not.toBeNull();

      const newRow = (
        await pool.query(`SELECT * FROM refresh_tokens WHERE token_hash = $1`, [sha256(newRaw)])
      ).rows[0];
      expect(newRow.id).toBe(oldRow.replaced_by_id);
      expect(newRow.family_id).toBe(familyId);
      expect(newRow.user_agent).toBe('new-agent');
      expect(newRow.revoked_at).toBeNull();

      const claims = signer.verify(accessToken);
      expect(claims.sub).toBe(user.id);
      expect(claims.email).toBe(user.email);
    });
  });

  describe('rotateRefreshToken — unknown token', () => {
    it('throws InvalidRefreshTokenError when the token does not exist', async () => {
      await expect(
        service.rotateRefreshToken('does-not-exist', { userAgent: 'a', ip: '127.0.0.1' }),
      ).rejects.toBeInstanceOf(InvalidRefreshTokenError);
    });
  });

  describe('rotateRefreshToken — expired token', () => {
    it('throws InvalidRefreshTokenError when the stored token is past expires_at', async () => {
      const expiredService = createTokenService({
        storage,
        signer,
        accessTokenTtl: '5m',
        refreshTokenTtl: '1s',
      });

      const user = await makeUser();
      const familyId = await newFamilyId();
      const raw = await expiredService.issueRefreshToken(user, {
        familyId,
        userAgent: 'a',
        ip: '127.0.0.1',
      });

      await pool.query(
        `UPDATE refresh_tokens SET expires_at = now() - interval '1 second' WHERE token_hash = $1`,
        [sha256(raw)],
      );

      await expect(
        expiredService.rotateRefreshToken(raw, { userAgent: 'a', ip: '127.0.0.1' }),
      ).rejects.toBeInstanceOf(InvalidRefreshTokenError);

      const row = (
        await pool.query(`SELECT revoked_at FROM refresh_tokens WHERE token_hash = $1`, [
          sha256(raw),
        ])
      ).rows[0];
      expect(row.revoked_at).toBeNull();
    });
  });

  describe('rotateRefreshToken — reuse detection', () => {
    it('rotating an already-rotated token throws RefreshTokenReuseError and revokes the entire family', async () => {
      const user = await makeUser();
      const familyId = await newFamilyId();
      const t1 = await service.issueRefreshToken(user, {
        familyId,
        userAgent: 'a',
        ip: '127.0.0.1',
      });

      const { refreshToken: t2 } = await service.rotateRefreshToken(t1, {
        userAgent: 'a',
        ip: '127.0.0.1',
      });
      const { refreshToken: t3 } = await service.rotateRefreshToken(t2, {
        userAgent: 'a',
        ip: '127.0.0.1',
      });

      await expect(
        service.rotateRefreshToken(t1, { userAgent: 'a', ip: '127.0.0.1' }),
      ).rejects.toBeInstanceOf(RefreshTokenReuseError);

      const rows = (
        await pool.query(`SELECT token_hash, revoked_at FROM refresh_tokens WHERE family_id = $1`, [
          familyId,
        ])
      ).rows;
      expect(rows).toHaveLength(3);
      rows.forEach((r) => expect(r.revoked_at).not.toBeNull());

      await expect(
        service.rotateRefreshToken(t3, { userAgent: 'a', ip: '127.0.0.1' }),
      ).rejects.toBeInstanceOf(RefreshTokenReuseError);
    });

    it('after family revocation, every token in the family fails to rotate', async () => {
      const user = await makeUser();
      const familyId = await newFamilyId();
      const t1 = await service.issueRefreshToken(user, {
        familyId,
        userAgent: 'a',
        ip: '127.0.0.1',
      });
      const { refreshToken: t2 } = await service.rotateRefreshToken(t1, {
        userAgent: 'a',
        ip: '127.0.0.1',
      });
      const { refreshToken: t3 } = await service.rotateRefreshToken(t2, {
        userAgent: 'a',
        ip: '127.0.0.1',
      });

      await expect(
        service.rotateRefreshToken(t1, { userAgent: 'a', ip: '127.0.0.1' }),
      ).rejects.toBeInstanceOf(RefreshTokenReuseError);

      for (const raw of [t1, t2, t3]) {
        await expect(
          service.rotateRefreshToken(raw, { userAgent: 'a', ip: '127.0.0.1' }),
        ).rejects.toBeInstanceOf(RefreshTokenReuseError);
      }
    });
  });

  describe('rotateRefreshToken — atomicity', () => {
    it('rolls back the new-token INSERT if the rotate UPDATE finds nothing to revoke', async () => {
      const user = await makeUser();
      const familyId = await newFamilyId();
      const t1 = await service.issueRefreshToken(user, {
        familyId,
        userAgent: 'a',
        ip: '127.0.0.1',
      });

      const failingStorage = {
        ...storage,
        rotateRefreshToken: async () => ({ status: 'ALREADY_REVOKED', token: null }),
      };
      const failingService = createTokenService({
        storage: failingStorage,
        signer,
        accessTokenTtl: '5m',
        refreshTokenTtl: '7d',
      });

      const before = (await pool.query(`SELECT count(*)::int AS n FROM refresh_tokens`)).rows[0].n;

      await expect(
        failingService.rotateRefreshToken(t1, { userAgent: 'a', ip: '127.0.0.1' }),
      ).rejects.toBeInstanceOf(RefreshTokenReuseError);

      const after = (await pool.query(`SELECT count(*)::int AS n FROM refresh_tokens`)).rows[0].n;
      expect(after).toBe(before);
    });
  });

  describe('rotateRefreshToken — soft-deleted user', () => {
    it('throws InvalidRefreshTokenError (not TypeError) when the user was soft-deleted between rotations', async () => {
      const user = await makeUser('gone@x.com');
      const familyId = await newFamilyId();
      const raw = await service.issueRefreshToken(user, {
        familyId,
        userAgent: 'a',
        ip: '127.0.0.1',
      });

      await storage.softDeleteUser(user.id);

      await expect(
        service.rotateRefreshToken(raw, { userAgent: 'a', ip: '127.0.0.1' }),
      ).rejects.toBeInstanceOf(InvalidRefreshTokenError);
    });
  });

  describe('rotateRefreshToken — reuse + family-revoke failure', () => {
    it('preserves RefreshTokenReuseError when revokeRefreshTokenFamily throws', async () => {
      const user = await makeUser();
      const familyId = await newFamilyId();
      const t1 = await service.issueRefreshToken(user, {
        familyId,
        userAgent: 'a',
        ip: '127.0.0.1',
      });
      await service.rotateRefreshToken(t1, { userAgent: 'a', ip: '127.0.0.1' });

      const errors = [];
      const origConsoleError = console.error;
      console.error = (...args) => errors.push(args);

      const flakyStorage = {
        ...storage,
        revokeRefreshTokenFamily: async () => {
          throw new Error('pool exhausted');
        },
      };
      const flakyService = createTokenService({
        storage: flakyStorage,
        signer,
        accessTokenTtl: '5m',
        refreshTokenTtl: '7d',
      });

      try {
        await expect(
          flakyService.rotateRefreshToken(t1, { userAgent: 'a', ip: '127.0.0.1' }),
        ).rejects.toBeInstanceOf(RefreshTokenReuseError);
      } finally {
        console.error = origConsoleError;
      }

      expect(errors.some((args) => args[0] === 'FAMILY_REVOKE_FAILED')).toBe(true);
    });
  });

  describe('revokeRefreshToken / revokeAllForUser', () => {
    it('revokeRefreshToken revokes only the matching token', async () => {
      const user = await makeUser();
      const familyId = await newFamilyId();
      const raw = await service.issueRefreshToken(user, {
        familyId,
        userAgent: 'a',
        ip: '127.0.0.1',
      });
      expect(await service.revokeRefreshToken(raw)).toBe(true);
      const row = (
        await pool.query(`SELECT revoked_at FROM refresh_tokens WHERE token_hash = $1`, [
          sha256(raw),
        ])
      ).rows[0];
      expect(row.revoked_at).not.toBeNull();
    });

    it('revokeAllForUser revokes every active token for the user', async () => {
      const user = await makeUser();
      const fid1 = await newFamilyId();
      const fid2 = await newFamilyId();
      await service.issueRefreshToken(user, { familyId: fid1, userAgent: 'a', ip: '127.0.0.1' });
      await service.issueRefreshToken(user, { familyId: fid2, userAgent: 'a', ip: '127.0.0.1' });

      const count = await service.revokeAllForUser(user.id);
      expect(count).toBe(2);

      const rows = (
        await pool.query(`SELECT revoked_at FROM refresh_tokens WHERE user_id = $1`, [user.id])
      ).rows;
      rows.forEach((r) => expect(r.revoked_at).not.toBeNull());
    });
  });
});

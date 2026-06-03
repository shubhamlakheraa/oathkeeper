const { Pool } = require('pg');
const { createPostgresStorage } = require('../src/adapters/storage/postgresStorage');

const DATABASE_URL = process.env.DATABASE_URL;

describe('postgresStorage (integration)', () => {
  let pool;
  let storage;

  beforeAll(() => {
    if (!DATABASE_URL) {
      throw new Error(
        'DATABASE_URL not set. Run migrations and ensure .env is loaded before running these tests.',
      );
    }
    pool = new Pool({ connectionString: DATABASE_URL });
    storage = createPostgresStorage(pool);
  });

  beforeEach(async () => {
    await pool.query('TRUNCATE TABLE users RESTART IDENTITY CASCADE');
  });

  afterAll(async () => {
    await pool.end();
  });

  describe('createUser', () => {
    it('inserts a row and returns it without password_hash', async () => {
      const user = await storage.createUser({
        email: 'alice@example.com',
        passwordHash: '$argon2id$fake',
      });
      expect(user).toMatchObject({ email: 'alice@example.com' });
      expect(user).not.toHaveProperty('password_hash');
      expect(user.id).toEqual(expect.any(String));
    });

    it('normalizes email to lowercase and trims whitespace', async () => {
      const user = await storage.createUser({
        email: '  Alice@Example.COM  ',
        passwordHash: 'h',
      });
      expect(user.email).toBe('alice@example.com');
    });

    it('rejects duplicate emails with code EMAIL_TAKEN', async () => {
      await storage.createUser({ email: 'x@y.com', passwordHash: 'h' });
      await expect(
        storage.createUser({ email: 'x@y.com', passwordHash: 'h2' }),
      ).rejects.toMatchObject({ code: 'EMAIL_TAKEN' });
    });
  });

  describe('getCredentialByEmail', () => {
    it('returns id, email and password_hash for an active user', async () => {
      await storage.createUser({ email: 'c@x.com', passwordHash: 'stored-hash' });
      const cred = await storage.getCredentialByEmail('c@x.com');
      expect(cred).toMatchObject({ email: 'c@x.com', password_hash: 'stored-hash' });
      expect(cred.id).toEqual(expect.any(String));
    });

    it('is case-insensitive', async () => {
      await storage.createUser({ email: 'c@x.com', passwordHash: 'h' });
      const cred = await storage.getCredentialByEmail('C@X.COM');
      expect(cred).not.toBeNull();
    });

    it('returns null for missing user', async () => {
      const cred = await storage.getCredentialByEmail('missing@x.com');
      expect(cred).toBeNull();
    });

    it('returns null for soft-deleted user', async () => {
      const u = await storage.createUser({ email: 'c@x.com', passwordHash: 'h' });
      await storage.softDeleteUser(u.id);
      const cred = await storage.getCredentialByEmail('c@x.com');
      expect(cred).toBeNull();
    });
  });

  describe('getMfaSecret', () => {
    it('returns the mfa_secret for an active user', async () => {
      const u = await storage.createUser({ email: 'm@x.com', passwordHash: 'h' });
      await storage.updateUser(u.id, { mfa_secret: 'TOTP-SECRET' });
      const secret = await storage.getMfaSecret(u.id);
      expect(secret).toBe('TOTP-SECRET');
    });

    it('returns null when no secret is set', async () => {
      const u = await storage.createUser({ email: 'm@x.com', passwordHash: 'h' });
      const secret = await storage.getMfaSecret(u.id);
      expect(secret).toBeNull();
    });

    it('returns null for a missing user', async () => {
      const secret = await storage.getMfaSecret('00000000-0000-0000-0000-000000000000');
      expect(secret).toBeNull();
    });

    it('returns null for a soft-deleted user', async () => {
      const u = await storage.createUser({ email: 'm@x.com', passwordHash: 'h' });
      await storage.updateUser(u.id, { mfa_secret: 'TOTP-SECRET' });
      await storage.softDeleteUser(u.id);
      const secret = await storage.getMfaSecret(u.id);
      expect(secret).toBeNull();
    });
  });

  describe('getUserByEmail', () => {
    it('finds a user by their email', async () => {
      const created = await storage.createUser({ email: 'a@b.com', passwordHash: 'h' });
      const found = await storage.getUserByEmail('a@b.com');
      expect(found.id).toBe(created.id);
    });

    it('is case-insensitive (CITEXT)', async () => {
      await storage.createUser({ email: 'mike@example.com', passwordHash: 'h' });
      const found = await storage.getUserByEmail('MIKE@example.COM');
      expect(found).not.toBeNull();
      expect(found.email).toBe('mike@example.com');
    });

    it('returns null when no user matches', async () => {
      const found = await storage.getUserByEmail('missing@nowhere.com');
      expect(found).toBeNull();
    });

    it('does not return soft-deleted users', async () => {
      const u = await storage.createUser({ email: 'd@x.com', passwordHash: 'h' });
      await storage.softDeleteUser(u.id);
      const found = await storage.getUserByEmail('d@x.com');
      expect(found).toBeNull();
    });

    it('omits password_hash from the returned row', async () => {
      await storage.createUser({ email: 's@x.com', passwordHash: 'secret-hash' });
      const found = await storage.getUserByEmail('s@x.com');
      expect(found).not.toHaveProperty('password_hash');
    });

    it('omits mfa_secret from the returned row', async () => {
      const u = await storage.createUser({ email: 's@x.com', passwordHash: 'h' });
      await storage.updateUser(u.id, { mfa_secret: 'TOTP-SECRET' });
      const found = await storage.getUserByEmail('s@x.com');
      expect(found).not.toHaveProperty('mfa_secret');
    });
  });

  describe('getUserById', () => {
    it('finds a user by their id', async () => {
      const created = await storage.createUser({ email: 'a@b.com', passwordHash: 'h' });
      const found = await storage.getUserById(created.id);
      expect(found.email).toBe('a@b.com');
    });

    it('returns null when no user matches', async () => {
      const found = await storage.getUserById('00000000-0000-0000-0000-000000000000');
      expect(found).toBeNull();
    });

    it('does not return soft-deleted users', async () => {
      const u = await storage.createUser({ email: 'd@x.com', passwordHash: 'h' });
      await storage.softDeleteUser(u.id);
      const found = await storage.getUserById(u.id);
      expect(found).toBeNull();
    });

    it('omits mfa_secret from the returned row', async () => {
      const u = await storage.createUser({ email: 's@x.com', passwordHash: 'h' });
      await storage.updateUser(u.id, { mfa_secret: 'TOTP-SECRET' });
      const found = await storage.getUserById(u.id);
      expect(found).not.toHaveProperty('mfa_secret');
    });
  });

  describe('updateUser', () => {
    it('patches a whitelisted field and returns the updated row', async () => {
      const u = await storage.createUser({ email: 'a@b.com', passwordHash: 'h' });
      const updated = await storage.updateUser(u.id, { email_verified: true });
      expect(updated.email_verified).toBe(true);
    });

    it('throws when a non-whitelisted field is patched', async () => {
      const u = await storage.createUser({ email: 'a@b.com', passwordHash: 'h' });
      await expect(
        storage.updateUser(u.id, { password_hash: 'attacker' }),
      ).rejects.toThrow(/not patchable/i);
    });

    it('throws even for innocuous-looking non-whitelisted fields like email', async () => {
      const u = await storage.createUser({ email: 'a@b.com', passwordHash: 'h' });
      await expect(storage.updateUser(u.id, { email: 'evil@x.com' })).rejects.toThrow(
        /not patchable/i,
      );
    });

    it('returns the current user unchanged when patches is empty', async () => {
      const u = await storage.createUser({ email: 'a@b.com', passwordHash: 'h' });
      const result = await storage.updateUser(u.id, {});
      expect(result.id).toBe(u.id);
      expect(result.email).toBe('a@b.com');
    });

    it('returns null when patching a soft-deleted user', async () => {
      const u = await storage.createUser({ email: 'a@b.com', passwordHash: 'h' });
      await storage.softDeleteUser(u.id);
      const updated = await storage.updateUser(u.id, { email_verified: true });
      expect(updated).toBeNull();
    });
  });

  describe('softDeleteUser', () => {
    it('marks the user so they are no longer returned by finds', async () => {
      const u = await storage.createUser({ email: 'a@b.com', passwordHash: 'h' });
      await storage.softDeleteUser(u.id);
      expect(await storage.getUserById(u.id)).toBeNull();
      expect(await storage.getUserByEmail('a@b.com')).toBeNull();
    });

    it('does not affect other users', async () => {
      const alice = await storage.createUser({ email: 'a@x.com', passwordHash: 'h' });
      const bob = await storage.createUser({ email: 'b@x.com', passwordHash: 'h' });
      await storage.softDeleteUser(alice.id);
      const stillThere = await storage.getUserById(bob.id);
      expect(stillThere.email).toBe('b@x.com');
    });
  });
});

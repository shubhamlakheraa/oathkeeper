const { Pool } = require('pg');
const { createPostgresStorage } = require('../src/adapters/storage/postgresStorage');
const { createAuthService } = require('../src/services/authService');
const { WeakPasswordError } = require('../src/error');

const DATABASE_URL = process.env.DATABASE_URL;

describe('authService (integration)', () => {
  let pool;
  let storage;
  let hasher;
  let service;

  beforeAll(() => {
    if (!DATABASE_URL) {
      throw new Error(
        'DATABASE_URL not set. Run migrations and ensure .env is loaded before running these tests.',
      );
    }
    pool = new Pool({ connectionString: DATABASE_URL });
    storage = createPostgresStorage(pool);
    hasher = {
      hash: async (p) => '$argon2id$v=19$mock$' + Buffer.from(p).toString('base64'),
    };
    service = createAuthService({ storage, hasher });
  });

  beforeEach(async () => {
    await pool.query(
      'TRUNCATE TABLE users, roles, permissions, role_permissions RESTART IDENTITY CASCADE',
    );
  });

  afterAll(async () => {
    await pool.end();
  });

  describe('signup', () => {
    it('creates a user row and returns it without password_hash', async () => {
      const { user, alreadyExists } = await service.signup({
        email: 'test@x.com',
        password: 'StrongPassword1!',
        ip: '127.0.0.1',
        userAgent: 'test-agent',
      });

      expect(alreadyExists).toBe(false);
      expect(user).not.toBeNull();
      expect(user.email).toBe('test@x.com');
      expect(user).not.toHaveProperty('password_hash');
    });

    it('stores a hashed string, not the plaintext password', async () => {
      const password = 'StrongPassword1!';
      await service.signup({ email: 'hash@x.com', password, ip: null, userAgent: null });

      const row = (
        await pool.query('SELECT password_hash FROM users WHERE email = $1', ['hash@x.com'])
      ).rows[0];

      expect(row.password_hash).not.toBe(password);
      expect(typeof row.password_hash).toBe('string');
      expect(row.password_hash.length).toBeGreaterThan(0);
    });

    it('re-signup with same email returns alreadyExists: true with no duplicate row', async () => {
      await service.signup({
        email: 'dup@x.com',
        password: 'StrongPassword1!',
        ip: null,
        userAgent: null,
      });

      const { user, alreadyExists } = await service.signup({
        email: 'dup@x.com',
        password: 'AnotherStrong1!',
        ip: null,
        userAgent: null,
      });

      expect(alreadyExists).toBe(true);
      expect(user).toBeNull();

      const { rows } = await pool.query(
        'SELECT count(*)::int AS n FROM users WHERE email = $1',
        ['dup@x.com'],
      );
      expect(rows[0].n).toBe(1);
    });

    it('rejects passwords shorter than 12 characters with WeakPasswordError', async () => {
      await expect(
        service.signup({ email: 'short@x.com', password: 'tooshort', ip: null, userAgent: null }),
      ).rejects.toBeInstanceOf(WeakPasswordError);
    });

    it('rejects common passwords with WeakPasswordError', async () => {
      await expect(
        service.signup({
          email: 'common@x.com',
          password: 'password123456',
          ip: null,
          userAgent: null,
        }),
      ).rejects.toBeInstanceOf(WeakPasswordError);
    });

    it('writes a signup auth_events row with correct type, ip, and userAgent', async () => {
      const { user } = await service.signup({
        email: 'events@x.com',
        password: 'StrongPassword1!',
        ip: '10.0.0.1',
        userAgent: 'Mozilla/5.0',
      });

      const row = (
        await pool.query(
          "SELECT * FROM auth_events WHERE user_id = $1 AND type = 'signup'",
          [user.id],
        )
      ).rows[0];

      expect(row).not.toBeNull();
      expect(row.type).toBe('signup');
      expect(row.ip).toBe('10.0.0.1');
      expect(row.user_agent).toBe('Mozilla/5.0');
    });
  });
});

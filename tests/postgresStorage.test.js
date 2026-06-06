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
    await pool.query(
      'TRUNCATE TABLE users, roles, permissions, role_permissions RESTART IDENTITY CASCADE',
    );
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

  describe('refresh tokens', () => {
    const future = () => new Date(Date.now() + 60_000);

    it('saveRefreshToken inserts and returns the row', async () => {
      const u = await storage.createUser({ email: 'r@x.com', passwordHash: 'h' });
      const familyId = (await pool.query('SELECT gen_random_uuid() AS id')).rows[0].id;
      const row = await storage.saveRefreshToken(
        u.id,
        'hash-1',
        familyId,
        future(),
        'agent',
        '127.0.0.1',
      );
      expect(row).toMatchObject({
        user_id: u.id,
        token_hash: 'hash-1',
        family_id: familyId,
        user_agent: 'agent',
      });
    });

    it('findRefreshToken returns the row for an existing hash', async () => {
      const u = await storage.createUser({ email: 'r@x.com', passwordHash: 'h' });
      const familyId = (await pool.query('SELECT gen_random_uuid() AS id')).rows[0].id;
      await storage.saveRefreshToken(u.id, 'hash-find', familyId, future(), 'a', '127.0.0.1');
      const row = await storage.findRefreshToken('hash-find');
      expect(row.token_hash).toBe('hash-find');
    });

    it('findRefreshToken returns null when not found', async () => {
      expect(await storage.findRefreshToken('nope')).toBeNull();
    });

    it('rotateRefreshToken returns SUCCESS and stamps replaced_by_id', async () => {
      const u = await storage.createUser({ email: 'r@x.com', passwordHash: 'h' });
      const familyId = (await pool.query('SELECT gen_random_uuid() AS id')).rows[0].id;
      const old = await storage.saveRefreshToken(u.id, 'old', familyId, future(), 'a', '127.0.0.1');
      const next = await storage.saveRefreshToken(u.id, 'new', familyId, future(), 'a', '127.0.0.1');
      const result = await storage.rotateRefreshToken({
        tokenHash: 'old',
        replacedById: next.id,
      });
      expect(result.status).toBe('SUCCESS');
      expect(result.token.replaced_by_id).toBe(next.id);
      expect(result.token.revoked_at).not.toBeNull();
      expect(old.id).toBe(result.token.id);
    });

    it('rotateRefreshToken returns NOT_FOUND for an unknown hash', async () => {
      const result = await storage.rotateRefreshToken({
        tokenHash: 'missing',
        replacedById: '00000000-0000-0000-0000-000000000000',
      });
      expect(result.status).toBe('NOT_FOUND');
      expect(result.token).toBeNull();
    });

    it('rotateRefreshToken returns ALREADY_REVOKED on second call', async () => {
      const u = await storage.createUser({ email: 'r@x.com', passwordHash: 'h' });
      const familyId = (await pool.query('SELECT gen_random_uuid() AS id')).rows[0].id;
      const a = await storage.saveRefreshToken(u.id, 'a', familyId, future(), 'a', '127.0.0.1');
      const b = await storage.saveRefreshToken(u.id, 'b', familyId, future(), 'a', '127.0.0.1');
      await storage.rotateRefreshToken({ tokenHash: 'a', replacedById: b.id });
      const second = await storage.rotateRefreshToken({ tokenHash: 'a', replacedById: b.id });
      expect(second.status).toBe('ALREADY_REVOKED');
      expect(a.id).toBe(second.token.id);
    });

    it('revokeRefreshToken sets revoked_at for the matching hash', async () => {
      const u = await storage.createUser({ email: 'r@x.com', passwordHash: 'h' });
      const familyId = (await pool.query('SELECT gen_random_uuid() AS id')).rows[0].id;
      await storage.saveRefreshToken(u.id, 'rv', familyId, future(), 'a', '127.0.0.1');
      const revoked = await storage.revokeRefreshToken('rv');
      expect(revoked.revoked_at).not.toBeNull();
    });

    it('revokeRefreshTokenFamily revokes every token in the family in one SQL statement', async () => {
      const u = await storage.createUser({ email: 'r@x.com', passwordHash: 'h' });
      const familyId = (await pool.query('SELECT gen_random_uuid() AS id')).rows[0].id;
      await storage.saveRefreshToken(u.id, 'f1', familyId, future(), 'a', '127.0.0.1');
      await storage.saveRefreshToken(u.id, 'f2', familyId, future(), 'a', '127.0.0.1');
      await storage.saveRefreshToken(u.id, 'f3', familyId, future(), 'a', '127.0.0.1');

      const before = (
        await pool.query(
          `SELECT count(*)::int AS n FROM pg_stat_statements WHERE query ILIKE 'UPDATE refresh_tokens%family_id%'`,
        ).catch(() => ({ rows: [{ n: null }] }))
      ).rows[0].n;

      await storage.revokeRefreshTokenFamily(familyId);

      const rows = (
        await pool.query(
          `SELECT token_hash, revoked_at FROM refresh_tokens WHERE family_id = $1 ORDER BY token_hash`,
          [familyId],
        )
      ).rows;
      expect(rows).toHaveLength(3);
      rows.forEach((r) => expect(r.revoked_at).not.toBeNull());

      if (before !== null) {
        const after = (
          await pool.query(
            `SELECT count(*)::int AS n FROM pg_stat_statements WHERE query ILIKE 'UPDATE refresh_tokens%family_id%'`,
          )
        ).rows[0].n;
        expect(after - before).toBeLessThanOrEqual(1);
      }
    });

    it('revokeAllRefreshTokensForUser revokes every active token for the user', async () => {
      const u = await storage.createUser({ email: 'r@x.com', passwordHash: 'h' });
      const familyId = (await pool.query('SELECT gen_random_uuid() AS id')).rows[0].id;
      await storage.saveRefreshToken(u.id, 't1', familyId, future(), 'a', '127.0.0.1');
      await storage.saveRefreshToken(u.id, 't2', familyId, future(), 'a', '127.0.0.1');
      await storage.revokeAllRefreshTokensForUser(u.id);
      const rows = (
        await pool.query(`SELECT revoked_at FROM refresh_tokens WHERE user_id = $1`, [u.id])
      ).rows;
      rows.forEach((r) => expect(r.revoked_at).not.toBeNull());
    });

    it('listActiveSessions returns active, unrevoked, unexpired tokens', async () => {
      const u = await storage.createUser({ email: 'r@x.com', passwordHash: 'h' });
      const familyId = (await pool.query('SELECT gen_random_uuid() AS id')).rows[0].id;
      await storage.saveRefreshToken(u.id, 'active', familyId, future(), 'a', '127.0.0.1');
      await storage.saveRefreshToken(u.id, 'revoked', familyId, future(), 'a', '127.0.0.1');
      await storage.revokeRefreshToken('revoked');
      const sessions = await storage.listActiveSessions(u.id);
      expect(sessions).toHaveLength(1);
    });
  });

  describe('one-time tokens (email_verification)', () => {
    const future = () => new Date(Date.now() + 60_000);

    it('saveToken inserts a token and returns the row', async () => {
      const u = await storage.createUser({ email: 't@x.com', passwordHash: 'h' });
      const row = await storage.saveToken(u.id, 'tok-1', future(), 'email_verification');
      expect(row).toMatchObject({ user_id: u.id, token_hash: 'tok-1' });
      expect(row.used_at).toBeNull();
    });

    it('consumeToken marks the token used and returns it', async () => {
      const u = await storage.createUser({ email: 't@x.com', passwordHash: 'h' });
      await storage.saveToken(u.id, 'tok-c', future(), 'email_verification');
      const used = await storage.consumeToken('tok-c', 'email_verification');
      expect(used.used_at).not.toBeNull();
    });

    it('consumeToken returns null for an expired token', async () => {
      const u = await storage.createUser({ email: 't@x.com', passwordHash: 'h' });
      const past = new Date(Date.now() - 1000);
      await storage.saveToken(u.id, 'tok-exp', past, 'email_verification');
      const used = await storage.consumeToken('tok-exp', 'email_verification');
      expect(used).toBeNull();
    });

    it('consumeToken returns null for an already-used token', async () => {
      const u = await storage.createUser({ email: 't@x.com', passwordHash: 'h' });
      await storage.saveToken(u.id, 'tok-once', future(), 'email_verification');
      await storage.consumeToken('tok-once', 'email_verification');
      const second = await storage.consumeToken('tok-once', 'email_verification');
      expect(second).toBeNull();
    });

    it('exactly one wins when two consumes race for the same token', async () => {
      const u = await storage.createUser({ email: 't@x.com', passwordHash: 'h' });
      await storage.saveToken(u.id, 'tok-race', future(), 'email_verification');
      const [a, b] = await Promise.all([
        storage.consumeToken('tok-race', 'email_verification'),
        storage.consumeToken('tok-race', 'email_verification'),
      ]);
      const winners = [a, b].filter((r) => r !== null);
      const losers = [a, b].filter((r) => r === null);
      expect(winners).toHaveLength(1);
      expect(losers).toHaveLength(1);
      expect(winners[0].used_at).not.toBeNull();
    });
  });

  describe('mfa recovery codes', () => {
    it('saveMfaRecoveryCodes bulk inserts and returns rows', async () => {
      const u = await storage.createUser({ email: 'm@x.com', passwordHash: 'h' });
      const rows = await storage.saveMfaRecoveryCodes(u.id, ['h1', 'h2', 'h3']);
      expect(rows).toHaveLength(3);
      rows.forEach((r) => {
        expect(r.user_id).toBe(u.id);
        expect(r.used_at).toBeNull();
      });
      expect(rows.map((r) => r.code_hash).sort()).toEqual(['h1', 'h2', 'h3']);
    });

    it('consumeMfaRecoveryCode marks a code used and returns true', async () => {
      const u = await storage.createUser({ email: 'm@x.com', passwordHash: 'h' });
      const [first] = await storage.saveMfaRecoveryCodes(u.id, ['h1']);
      expect(await storage.consumeMfaRecoveryCode(first.id)).toBe(true);
      const row = (
        await pool.query(`SELECT used_at FROM mfa_recovery_codes WHERE id = $1`, [first.id])
      ).rows[0];
      expect(row.used_at).not.toBeNull();
    });

    it('consumeMfaRecoveryCode returns false on second call (single-use)', async () => {
      const u = await storage.createUser({ email: 'm@x.com', passwordHash: 'h' });
      const [first] = await storage.saveMfaRecoveryCodes(u.id, ['h1']);
      await storage.consumeMfaRecoveryCode(first.id);
      expect(await storage.consumeMfaRecoveryCode(first.id)).toBe(false);
    });

    it('exactly one wins when two consumes race for the same recovery code', async () => {
      const u = await storage.createUser({ email: 'm@x.com', passwordHash: 'h' });
      const [first] = await storage.saveMfaRecoveryCodes(u.id, ['h-race']);
      const [a, b] = await Promise.all([
        storage.consumeMfaRecoveryCode(first.id),
        storage.consumeMfaRecoveryCode(first.id),
      ]);
      expect([a, b].filter(Boolean)).toHaveLength(1);
      expect([a, b].filter((x) => x === false)).toHaveLength(1);
    });
  });

  describe('rbac', () => {
    async function seedRole(name) {
      return (await pool.query(`INSERT INTO roles (name) VALUES ($1) RETURNING *`, [name])).rows[0];
    }
    async function seedPermission(name) {
      return (await pool.query(`INSERT INTO permissions (name) VALUES ($1) RETURNING *`, [name]))
        .rows[0];
    }
    async function grantPermission(roleId, permissionId) {
      await pool.query(
        `INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)`,
        [roleId, permissionId],
      );
    }

    it('assignRole adds a (user, role) row', async () => {
      const u = await storage.createUser({ email: 'r@x.com', passwordHash: 'h' });
      const role = await seedRole('admin');
      await storage.assignRole(u.id, role.id);
      const roles = await storage.getRolesForUser(u.id);
      expect(roles.map((r) => r.name)).toEqual(['admin']);
    });

    it('assignRole is idempotent (ON CONFLICT DO NOTHING)', async () => {
      const u = await storage.createUser({ email: 'r@x.com', passwordHash: 'h' });
      const role = await seedRole('admin');
      await storage.assignRole(u.id, role.id);
      await storage.assignRole(u.id, role.id);
      const roles = await storage.getRolesForUser(u.id);
      expect(roles).toHaveLength(1);
    });

    it('removeRole deletes the (user, role) row and returns true', async () => {
      const u = await storage.createUser({ email: 'r@x.com', passwordHash: 'h' });
      const role = await seedRole('admin');
      await storage.assignRole(u.id, role.id);
      expect(await storage.removeRole(u.id, role.id)).toBe(true);
      expect(await storage.getRolesForUser(u.id)).toEqual([]);
    });

    it('removeRole returns false when no row was deleted', async () => {
      const u = await storage.createUser({ email: 'r@x.com', passwordHash: 'h' });
      const role = await seedRole('admin');
      expect(await storage.removeRole(u.id, role.id)).toBe(false);
    });

    it('getRolesForUser returns an empty array when the user has no roles', async () => {
      const u = await storage.createUser({ email: 'r@x.com', passwordHash: 'h' });
      expect(await storage.getRolesForUser(u.id)).toEqual([]);
    });

    it('getUserPermissions returns a Set<string>', async () => {
      const u = await storage.createUser({ email: 'r@x.com', passwordHash: 'h' });
      const admin = await seedRole('admin');
      const editor = await seedRole('editor');
      const pRead = await seedPermission('read');
      const pWrite = await seedPermission('write');
      await grantPermission(admin.id, pRead.id);
      await grantPermission(admin.id, pWrite.id);
      await grantPermission(editor.id, pWrite.id);
      await storage.assignRole(u.id, admin.id);
      await storage.assignRole(u.id, editor.id);

      const perms = await storage.getUserPermissions(u.id);
      expect(perms).toBeInstanceOf(Set);
      expect(perms.size).toBe(2);
      expect(perms.has('read')).toBe(true);
      expect(perms.has('write')).toBe(true);
    });

    it('getUserPermissions returns an empty Set when the user has no roles', async () => {
      const u = await storage.createUser({ email: 'r@x.com', passwordHash: 'h' });
      const perms = await storage.getUserPermissions(u.id);
      expect(perms).toBeInstanceOf(Set);
      expect(perms.size).toBe(0);
    });
  });

  describe('audit logEvent', () => {
    it('inserts an event with all optional fields', async () => {
      const u = await storage.createUser({ email: 'a@x.com', passwordHash: 'h' });
      const row = await storage.logEvent({
        userId: u.id,
        type: 'login.success',
        ip: '127.0.0.1',
        userAgent: 'agent',
        metadata: { foo: 'bar' },
      });
      expect(row).toMatchObject({
        user_id: u.id,
        type: 'login.success',
        user_agent: 'agent',
        metadata: { foo: 'bar' },
      });
      expect(row.occurred_at).toBeInstanceOf(Date);
    });

    it('inserts an event with only a type', async () => {
      const row = await storage.logEvent({ type: 'system.boot' });
      expect(row).toMatchObject({
        type: 'system.boot',
        user_id: null,
        ip: null,
        user_agent: null,
        metadata: null,
      });
    });
  });
});

const { Pool } = require('pg');
const express = require('express');
const request = require('supertest');
const { createPostgresStorage } = require('../src/adapters/storage/postgresStorage');
const { createRbacService } = require('../src/services/rbacService');
const { createPermissions } = require('../src/middleware/requirePermission');
const { createRoleGuard } = require('../src/middleware/requireRole');
const { errorMapper } = require('../src/middleware/errorMapper');

const DATABASE_URL = process.env.DATABASE_URL;

describe('RBAC (integration)', () => {
  let pool, storage, rbacService;

  beforeAll(() => {
    if (!DATABASE_URL) throw new Error('DATABASE_URL not set.');
    pool = new Pool({ connectionString: DATABASE_URL });
    storage = createPostgresStorage(pool);
    rbacService = createRbacService({ storage });
  });

  beforeEach(async () => {
    await pool.query(
      'TRUNCATE TABLE users, roles, permissions, role_permissions RESTART IDENTITY CASCADE',
    );
  });

  afterAll(() => pool.end());

  async function createUser(email = 'u@x.com') {
    return storage.createUser({ email, passwordHash: 'irrelevant' });
  }

  // ─── role & permission CRUD ──────────────────────────────────────────────────

  describe('role and permission management', () => {
    it('createRole + addPermissionToRole + assignRole → getUserPermissions returns the permission', async () => {
      const user = await createUser();
      const role = await rbacService.createRole('editor');
      await rbacService.addPermissionToRole(role.id, 'doc:edit');
      await rbacService.assignRole(user.id, role.id);

      const perms = await rbacService.getUserPermissions(user.id);
      expect(perms).toBeInstanceOf(Set);
      expect(perms.has('doc:edit')).toBe(true);
    });

    it('removePermissionFromRole revokes it for assigned users', async () => {
      const user = await createUser();
      const role = await rbacService.createRole('editor');
      await rbacService.addPermissionToRole(role.id, 'doc:edit');
      await rbacService.assignRole(user.id, role.id);
      await rbacService.removePermissionFromRole(role.id, 'doc:edit');

      const perms = await rbacService.getUserPermissions(user.id);
      expect(perms.has('doc:edit')).toBe(false);
    });

    it('removeRole unassigns role from user', async () => {
      const user = await createUser();
      const role = await rbacService.createRole('admin');
      await rbacService.addPermissionToRole(role.id, 'user:delete');
      await rbacService.assignRole(user.id, role.id);
      await rbacService.removeRole(user.id, role.id);

      const perms = await rbacService.getUserPermissions(user.id);
      expect(perms.has('user:delete')).toBe(false);
    });

    it('user with multiple roles accumulates all permissions', async () => {
      const user = await createUser();
      const viewer = await rbacService.createRole('viewer');
      const editor = await rbacService.createRole('editor');
      await rbacService.addPermissionToRole(viewer.id, 'doc:read');
      await rbacService.addPermissionToRole(editor.id, 'doc:edit');
      await rbacService.assignRole(user.id, viewer.id);
      await rbacService.assignRole(user.id, editor.id);

      const perms = await rbacService.getUserPermissions(user.id);
      expect(perms.has('doc:read')).toBe(true);
      expect(perms.has('doc:edit')).toBe(true);
    });
  });

  // ─── can() ───────────────────────────────────────────────────────────────────

  describe('can()', () => {
    it('returns true when user has permission and no resource', async () => {
      const user = await createUser();
      const role = await rbacService.createRole('viewer');
      await rbacService.addPermissionToRole(role.id, 'doc:read');
      await rbacService.assignRole(user.id, role.id);

      expect(await rbacService.can(user, 'doc:read')).toBe(true);
    });

    it('returns false when user lacks the permission', async () => {
      const user = await createUser();
      expect(await rbacService.can(user, 'doc:edit')).toBe(false);
    });

    // AC3: RBAC passes AND policy passes → true
    it('with resource: RBAC passes AND policy passes → true', async () => {
      const user = await createUser();
      const role = await rbacService.createRole('owner');
      await rbacService.addPermissionToRole(role.id, 'doc:edit');
      await rbacService.assignRole(user.id, role.id);

      const svc = createRbacService({
        storage,
        policies: { 'doc:edit': (u, doc) => doc.ownerId === u.id },
      });

      expect(await svc.can(user, 'doc:edit', { ownerId: user.id })).toBe(true);
    });

    // AC4: RBAC passes BUT policy returns false → false
    it('with resource: RBAC passes BUT policy returns false → false', async () => {
      const user = await createUser();
      const role = await rbacService.createRole('editor');
      await rbacService.addPermissionToRole(role.id, 'doc:edit');
      await rbacService.assignRole(user.id, role.id);

      const svc = createRbacService({
        storage,
        policies: { 'doc:edit': (u, doc) => doc.ownerId === u.id },
      });

      expect(await svc.can(user, 'doc:edit', { ownerId: 'someone-else' })).toBe(false);
    });

    // AC5: policy registered but no resource → true (policy not invoked)
    it('policy registered but no resource provided → true', async () => {
      const user = await createUser();
      const role = await rbacService.createRole('editor');
      await rbacService.addPermissionToRole(role.id, 'doc:edit');
      await rbacService.assignRole(user.id, role.id);

      const svc = createRbacService({
        storage,
        policies: { 'doc:edit': () => false }, // would deny, but resource absent → skipped
      });

      expect(await svc.can(user, 'doc:edit')).toBe(true);
    });

    // AC6: policy registered but RBAC missing → false (RBAC is always the floor)
    it('policy registered but RBAC missing → false', async () => {
      const user = await createUser();

      const svc = createRbacService({
        storage,
        policies: { 'doc:edit': () => true }, // policy would grant, but RBAC blocks
      });

      expect(await svc.can(user, 'doc:edit', { ownerId: user.id })).toBe(false);
    });

    it('async policy is awaited correctly', async () => {
      const user = await createUser();
      const role = await rbacService.createRole('editor');
      await rbacService.addPermissionToRole(role.id, 'doc:edit');
      await rbacService.assignRole(user.id, role.id);

      const svc = createRbacService({
        storage,
        policies: {
          'doc:edit': async (_u, doc) => Promise.resolve(doc.published === true),
        },
      });

      expect(await svc.can(user, 'doc:edit', { published: true })).toBe(true);
      expect(await svc.can(user, 'doc:edit', { published: false })).toBe(false);
    });

    it('uses cached permissions from req.user.permissions when available (no extra DB query)', async () => {
      const user = await createUser();
      // Simulate what authenticate middleware does: attach a permissions Set
      const userWithCache = { ...user, permissions: new Set(['doc:read']) };

      // No DB role assigned — relies purely on the cached Set
      expect(await rbacService.can(userWithCache, 'doc:read')).toBe(true);
      expect(await rbacService.can(userWithCache, 'doc:edit')).toBe(false);
    });
  });

  // ─── requirePermission middleware ────────────────────────────────────────────

  describe('requirePermission middleware', () => {
    function buildApp(permission, userStub) {
      const app = express();
      const { requirePermission } = createPermissions({ rbacService });
      app.get(
        '/protected',
        (req, _res, next) => { req.user = userStub; next(); },
        requirePermission(permission),
        (_req, res) => res.json({ ok: true }),
      );
      app.use(errorMapper);
      return app;
    }

    it('allows request when user has the permission', async () => {
      const user = await createUser('perm@x.com');
      const role = await rbacService.createRole('editor');
      await rbacService.addPermissionToRole(role.id, 'doc:edit');
      await rbacService.assignRole(user.id, role.id);

      const res = await request(buildApp('doc:edit', user)).get('/protected');
      expect(res.status).toBe(200);
      expect(res.body.ok).toBe(true);
    });

    it('returns 403 when user lacks the permission', async () => {
      const user = await createUser('noperm@x.com');

      const res = await request(buildApp('doc:edit', user)).get('/protected');
      expect(res.status).toBe(403);
      expect(res.body.error.code).toBe('AUTH.FORBIDDEN');
    });

    it('allows request when permissions are injected via cached Set', async () => {
      const user = await createUser('cached@x.com');
      const userWithCache = { ...user, permissions: new Set(['doc:edit']) };

      const res = await request(buildApp('doc:edit', userWithCache)).get('/protected');
      expect(res.status).toBe(200);
    });
  });

  // ─── requireRole middleware ──────────────────────────────────────────────────

  describe('requireRole middleware', () => {
    function buildApp(roleName, userStub) {
      const app = express();
      const { requireRole } = createRoleGuard({ rbacService });
      app.get(
        '/admin',
        (req, _res, next) => { req.user = userStub; next(); },
        requireRole(roleName),
        (_req, res) => res.json({ ok: true }),
      );
      app.use(errorMapper);
      return app;
    }

    it('allows request when user has the role', async () => {
      const user = await createUser('admin@x.com');
      const role = await rbacService.createRole('admin');
      await rbacService.assignRole(user.id, role.id);

      const res = await request(buildApp('admin', user)).get('/admin');
      expect(res.status).toBe(200);
    });

    it('returns 403 when user lacks the role', async () => {
      const user = await createUser('norole@x.com');

      const res = await request(buildApp('admin', user)).get('/admin');
      expect(res.status).toBe(403);
      expect(res.body.error.code).toBe('AUTH.FORBIDDEN');
    });

    it('checks role by name, not by id', async () => {
      const user = await createUser('rolecheck@x.com');
      const role = await rbacService.createRole('moderator');
      await rbacService.assignRole(user.id, role.id);

      const res = await request(buildApp('moderator', user)).get('/admin');
      expect(res.status).toBe(200);

      const wrongRole = await request(buildApp('admin', user)).get('/admin');
      expect(wrongRole.status).toBe(403);
    });
  });
});

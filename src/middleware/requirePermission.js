const { ForbiddenError } = require('../error');

function createPermissions({ rbacService }) {
  function requirePermission(permission) {
    return async (req, _res, next) => {
      try {
        const allowed = await rbacService.can(req.user, permission);
        if (!allowed) return next(new ForbiddenError());
        next();
      } catch (err) {
        next(err);
      }
    };
  }
  return { requirePermission };
}

module.exports = { createPermissions };

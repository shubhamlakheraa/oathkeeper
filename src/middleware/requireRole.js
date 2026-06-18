const { ForbiddenError } = require('../error');

function createRoleGuard({ rbacService }) {
  function requireRole(roleName) {
    return async (req, _res, next) => {
      try {
        const roles = await rbacService.getUserRoles(req.user.id);
        const hasRole = roles.some((r) => r.name === roleName);
        if (!hasRole) return next(new ForbiddenError());
        next();
      } catch (err) {
        next(err);
      }
    };
  }
  return { requireRole };
}

module.exports = { createRoleGuard };

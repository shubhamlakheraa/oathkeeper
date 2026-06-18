function createRbacService({ storage, policies = {} }) {
  async function createRole(name) {
    return storage.createRole(name);
  }

  async function deleteRole(roleId) {
    return storage.deleteRole(roleId);
  }

  async function addPermissionToRole(roleId, permissionName) {
    return storage.addPermissionToRole(roleId, permissionName);
  }

  async function removePermissionFromRole(roleId, permissionName) {
    return storage.removePermissionFromRole(roleId, permissionName);
  }

  async function assignRole(userId, roleId) {
    return storage.assignRole(userId, roleId);
  }

  async function removeRole(userId, roleId) {
    return storage.removeRole(userId, roleId);
  }

  async function getUserPermissions(userId) {
    return storage.getUserPermissions(userId);
  }

  async function getUserRoles(userId) {
    return storage.getRolesForUser(userId);
  }

  async function can(user, action, resource) {
    const permissions =
      user.permissions instanceof Set ? user.permissions : await getUserPermissions(user.id);

    if (!permissions.has(action)) return false;

    const policy = policies[action];
    if (policy && resource !== null) {
      return Boolean(await policy(user, resource));
    }

    return true;
  }

  return {
    createRole,
    deleteRole,
    addPermissionToRole,
    removePermissionFromRole,
    assignRole,
    removeRole,
    getUserPermissions,
    getUserRoles,
    can,
  };
}

module.exports = { createRbacService };

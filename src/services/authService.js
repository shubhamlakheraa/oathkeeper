const { WeakPasswordError } = require('../error');

const COMMON_PASSWORDS = new Set([
  'password123456',
  'password123456789',
  '123456789012',
  'qwertyuioplkj',
  'iloveyou123456',
]);

function createAuthService({ storage, hasher }) {
  async function signup({ email, password, ip, userAgent }) {
    const normalizedEmail = email.toLowerCase().trim();

    if (password.length < 12)
      throw new WeakPasswordError('Password must be at least 12 characters');

    if (COMMON_PASSWORDS.has(password))
      throw new WeakPasswordError('Password is too common');

    try {
      const hashedPassword = await hasher.hash(password);
      const user = await storage.withTransaction(async (client) => {
        const u = await storage.createUser(
          { email: normalizedEmail, passwordHash: hashedPassword },
          { client },
        );
        await storage.logEvent({ userId: u.id, type: 'signup', ip, userAgent }, { client });
        return u;
      });
      return { user, alreadyExists: false };
    } catch (err) {
      if (err.code === 'EMAIL_TAKEN') return { user: null, alreadyExists: true };
      throw err;
    }
  }

  return {
    signup,
  };
}

module.exports = { createAuthService };

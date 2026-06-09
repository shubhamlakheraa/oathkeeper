const { WeakPasswordError } = require('../error');

function createAuthService({ storage, hasher }) {
  async function signup({ email, password, ip, userAgent }) {
    const normalizedEmail = email.toLowerCase().trim();
    if (password.length < 12)
      throw new WeakPasswordError('Password must be at least 12 characters');

    const existingUser = await storage.getUserByEmail(normalizedEmail);
    if (existingUser) {
      return { user: null, alreadyExists: true };
    }
    const hashedPassword = await hasher.hash(password);
    const user = await storage.createUser({ email: normalizedEmail, passwordHash: hashedPassword });
    await storage.logEvent({ userId: user.id, type: 'signup', ip, userAgent });
    return { user, alreadyExists: false };
  }

  return {
    signup,
  };
}

module.exports = { createAuthService };

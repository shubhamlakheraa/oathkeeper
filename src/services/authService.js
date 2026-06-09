const { WeakPasswordError, InvalidCredentialsError, MfaRequiredError } = require('../error');
const { COMMON_PASSWORDS } = require('../constants/passwords');

function createAuthService({ storage, hasher, tokenService, signer }) {
  const _dummyHash = hasher.hash('__dummy_password__');

  async function signup({ email, password, ip, userAgent }) {
    const normalizedEmail = email.toLowerCase().trim();

    if (password.length < 12)
      throw new WeakPasswordError('Password must be at least 12 characters');

    if (COMMON_PASSWORDS.has(password)) throw new WeakPasswordError('Password is too common');

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

  async function login({ email, password, userAgent, ip }) {
    const normalizedEmail = email.toLowerCase().trim();
    const credential = await storage.getCredentialByEmail(normalizedEmail);
    const storedHash = credential?.password_hash ?? await _dummyHash;

    const passwordMatches = await hasher.verify(password, storedHash);

    if (!passwordMatches || !credential) {
      await storage.logEvent({ userId: credential?.id ?? null, type: 'login.failure', ip, userAgent });
      throw new InvalidCredentialsError();
    }

    const user = await storage.getUserById(credential.id);

    if (user.mfa_enabled) {
      const mfaToken = signer.sign({ sub: user.id, purpose: 'mfa_challenge' }, { expiresIn: '5m' });
      throw new MfaRequiredError(mfaToken);
    }

    const familyId = crypto.randomUUID();
    const accessToken = tokenService.issueAccessToken(user);
    const refreshToken = await tokenService.issueRefreshToken(user, { familyId, userAgent, ip });
    await storage.updateUser(user.id, { last_login_at: new Date() });
    await storage.logEvent({ userId: user.id, type: 'login.success', ip, userAgent });
    return { user, accessToken, refreshToken };
  }

  async function logout({ refreshToken, userId, ip, userAgent }) {
    await tokenService.revokeRefreshToken(refreshToken);
    await storage.logEvent({ userId, type: 'logout', ip, userAgent });
  }

  return {
    signup,
    login,
    logout,
  };
}

module.exports = { createAuthService };

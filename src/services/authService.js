const { randomUUID } = require('crypto');
const { WeakPasswordError, InvalidCredentialsError, MfaRequiredError, InvalidTokenError } = require('../error');
const { COMMON_PASSWORDS, TTL_MS } = require('../constants/passwords');
const { generateToken, sha256 } = require('../utils/random');

function createAuthService({ storage, hasher, tokenService, signer, mailer, config }) {
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

    if (!credential) {
      await hasher.verify(password, await _dummyHash);
      await storage.logEvent({ userId: null, type: 'login.failure', ip, userAgent });
      throw new InvalidCredentialsError();
    }

    const passwordMatches = await hasher.verify(password, credential.password_hash);
    if (!passwordMatches) {
      await storage.logEvent({ userId: credential.id, type: 'login.failure', ip, userAgent });
      throw new InvalidCredentialsError();
    }

    const user = await storage.getUserById(credential.id);

    if (user.mfa_enabled) {
      const mfaToken = signer.sign({ sub: user.id, purpose: 'mfa_challenge' }, { expiresIn: '5m' });
      throw new MfaRequiredError(mfaToken);
    }

    const familyId = randomUUID();
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

  async function requestEmailVerification(user) {
    const rawToken = generateToken();
    const tokenHash = sha256(rawToken);
    const expiresAt = new Date(Date.now() + TTL_MS);
    await storage.saveToken(user.id, tokenHash, expiresAt, 'email_verification');
    const verifyUrl = `${config.baseUrl}/auth/email/verify/confirm?token=${rawToken}`;
    await mailer.sendMail({
      to: user.email,
      subject: 'Verify your email',
      html: `Click to verify: <a href="${verifyUrl}">${verifyUrl}</a>`,
    });
    await storage.logEvent({ userId: user.id, type: 'email_verification.requested' });
  }

  async function confirmEmailVerification(rawToken) {
    const tokenHash = sha256(rawToken);
    const tokenRow = await storage.consumeToken(tokenHash, 'email_verification');
    if (!tokenRow) throw new InvalidTokenError();
    await storage.updateUser(tokenRow.user_id, { email_verified: true });
    await storage.logEvent({ userId: tokenRow.user_id, type: 'email_verification.confirmed' });
  }

  return {
    signup,
    login,
    logout,
    requestEmailVerification,
    confirmEmailVerification
  };
}

module.exports = { createAuthService };

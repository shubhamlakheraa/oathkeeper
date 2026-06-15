const { randomUUID } = require('crypto');
const {
  WeakPasswordError,
  InvalidCredentialsError,
  MfaRequiredError,
  InvalidTokenError,
  InvalidOrExpiredTokenError,
} = require('../error');
const {
  COMMON_PASSWORDS,
  EMAIL_VERIFICATION_TTL_MS,
  PASSWORD_RESET_TTL_MS,
} = require('../constants/passwords');
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
    const expiresAt = new Date(Date.now() + EMAIL_VERIFICATION_TTL_MS);
    await storage.saveToken(user.id, tokenHash, expiresAt, 'email_verification');
    const verifyUrl = `${config.baseUrl}/auth/email/verify/confirm?token=${encodeURIComponent(rawToken)}`;
    await mailer.sendMail({
      to: user.email,
      subject: 'Verify your email',
      html: `Click to verify: <a href="${verifyUrl}">${verifyUrl}</a>`,
    });
    await storage.logEvent({ userId: user.id, type: 'email_verification.requested' });
  }

  async function confirmEmailVerification(rawToken) {
    const tokenHash = sha256(rawToken);
    await storage.withTransaction(async (client) => {
      const tokenRow = await storage.consumeToken(tokenHash, 'email_verification', { client });
      if (!tokenRow) throw new InvalidTokenError();
      await storage.updateUser(tokenRow.user_id, { email_verified: true }, { client });
      await storage.logEvent(
        { userId: tokenRow.user_id, type: 'email_verification.confirmed' },
        { client },
      );
    });
  }

  async function requestPasswordReset(email) {
    const user = await storage.getUserByEmail(email);
    if (user) {
      const rawToken = generateToken();
      const tokenHash = sha256(rawToken);
      const expiresAt = new Date(Date.now() + PASSWORD_RESET_TTL_MS);
      await storage.saveToken(user.id, tokenHash, expiresAt, 'password_reset');
      const resetUrl = `${config.baseUrl}/reset-password?token=${encodeURIComponent(rawToken)}`;
      await mailer.sendMail({
        to: user.email,
        subject: 'Reset your Password',
        html: `Click to reset: <a href="${resetUrl}">${resetUrl}</a>`,
      });
    }
    return { message: 'If an account exists with that email, a reset link has been sent.' };
  }

  async function confirmPasswordReset({ token, newPassword }) {
    if (newPassword.length < 12) throw new WeakPasswordError('Password must be at least 12 characters');
    if (COMMON_PASSWORDS.has(newPassword)) throw new WeakPasswordError('Password is too common');

    const tokenHash = sha256(token);
    const passwordHash = await hasher.hash(newPassword);

    const userId = await storage.withTransaction(async (client) => {
      const consumed = await storage.consumeToken(tokenHash, 'password_reset', { client });
      if (!consumed) throw new InvalidOrExpiredTokenError();
      await storage.updatePassword(consumed.user_id, passwordHash, { client });
      await storage.logEvent({ userId: consumed.user_id, type: 'password.reset.completed' }, { client });
      return consumed.user_id;
    });

    await tokenService.revokeAllForUser(userId);
  }

  async function changePassword(user, { currentPassword, newPassword, currentRefreshToken }) {
    const credential = await storage.getCredentialByEmail(user.email);
    const valid = await hasher.verify(currentPassword, credential.password_hash);
    if (!valid) throw new InvalidCredentialsError();

    if (newPassword.length < 12) throw new WeakPasswordError('Password must be at least 12 characters');
    if (COMMON_PASSWORDS.has(newPassword)) throw new WeakPasswordError('Password is too common');

    const passwordHash = await hasher.hash(newPassword);
    await storage.updatePassword(user.id, passwordHash);

    const currentTokenHash = currentRefreshToken ? sha256(currentRefreshToken) : null;
    const currentToken = currentTokenHash ? await storage.getRefreshToken(currentTokenHash) : null;
    await tokenService.revokeAllForUser(user.id, { exceptTokenId: currentToken?.id });

    await storage.logEvent({ userId: user.id, type: 'password.changed' });

    return { message: 'Password changed.' };
  }

  return {
    signup,
    login,
    logout,
    requestEmailVerification,
    confirmEmailVerification,
    requestPasswordReset,
    confirmPasswordReset,
    changePassword
  };
}

module.exports = { createAuthService };

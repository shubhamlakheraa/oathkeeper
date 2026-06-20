const crypto = require('crypto');
const { InvalidMfaCodeError, InvalidCredentialsError, MfaAlreadyEnabledError } = require('../error');
const { generateSecret, buildOtpAuthUri, verifyCode } = require('../utils/totp');

function createMfaService({ storage, hasher, issuer, replayStore }) {
  async function beginEnrollment(user) {
    if (user.mfa_enabled) throw new MfaAlreadyEnabledError();
    const secret = generateSecret();
    const uri = buildOtpAuthUri({ secret, accountName: user.email, issuer });
    await storage.updateUser(user.id, { mfa_secret: secret, mfa_enabled: false });
    return { secret, uri };
  }

  async function confirmEnrollment(user, code, { ip = null, userAgent = null } = {}) {
    const secret = await storage.getMfaSecret(user.id);
    if (!secret) throw new InvalidMfaCodeError();

    const { valid } = verifyCode(secret, code, { window: 1, replayStore });
    if (!valid) throw new InvalidMfaCodeError();

    const plaintextCodes = Array.from({ length: 10 }, () => crypto.randomBytes(5).toString('hex'));
    const hashedCodes = await Promise.all(plaintextCodes.map((c) => hasher.hash(c)));

    await storage.withTransaction(async (client) => {
      await storage.saveMfaRecoveryCodes(user.id, hashedCodes, { client });
      await storage.updateUser(user.id, { mfa_enabled: true }, { client });
      await storage.logEvent({ userId: user.id, type: 'mfa.enabled', ip, userAgent }, { client });
    });

    return { recoveryCodes: plaintextCodes };
  }

  async function disable(user, { password, code, ip = null, userAgent = null }) {
    const credential = await storage.getCredentialByEmail(user.email);
    const passwordValid = await hasher.verify(password, credential.password_hash);
    if (!passwordValid) throw new InvalidCredentialsError();

    const codeValid = await verifyMfaForLogin(user.id, code);
    if (!codeValid) throw new InvalidMfaCodeError();

    await storage.updateUser(user.id, { mfa_secret: null, mfa_enabled: false });
    await storage.deleteMfaRecoveryCodes(user.id);
    await storage.logEvent({ userId: user.id, type: 'mfa.disabled', ip, userAgent });

    return { message: 'MFA disabled.' };
  }

  async function verifyMfaForLogin(userId, code) {
    const secret = await storage.getMfaSecret(userId);
    if (!secret) return false;

    const { valid } = verifyCode(secret, code, { window: 1, replayStore });
    if (valid) return true;

    return tryRecoveryCode(userId, code);
  }

  async function tryRecoveryCode(userId, submittedCode) {
    const rows = await storage.getMfaRecoveryCodes(userId);
    for (const stored of rows) {
      const matches = await hasher.verify(submittedCode, stored.code_hash);
      if (matches) {
        await storage.consumeMfaRecoveryCode(stored.id);
        return true;
      }
    }
    return false;
  }

  return { beginEnrollment, confirmEnrollment, disable, verifyMfaForLogin };
}

module.exports = { createMfaService };

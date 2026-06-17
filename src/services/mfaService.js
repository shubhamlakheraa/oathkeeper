const crypto = require('crypto');
const { InvalidMfaCodeError, InvalidCredentialsError } = require('../error');
const { generateSecret, buildOtpAuthUri, verifyCode } = require('../utils/totp');

function createMfaService({ storage, hasher, issuer, replayStore }) {
  async function beginEnrollment(user) {
    const secret = generateSecret();
    const uri = buildOtpAuthUri({ secret, accountName: user.email, issuer });
    await storage.updateUser(user.id, { mfa_secret: secret, mfa_enabled: false });
    return { secret, uri };
  }

  async function confirmEnrollment(user, code) {
    const secret = await storage.getMfaSecret(user.id);
    if (!secret) throw new InvalidMfaCodeError();

    const { valid } = verifyCode(secret, code, { window: 1, replayStore });
    if (!valid) throw new InvalidMfaCodeError();

    const plaintextCodes = Array.from({ length: 10 }, () => crypto.randomBytes(5).toString('hex'));
    const hashedCodes = await Promise.all(plaintextCodes.map((c) => hasher.hash(c)));
    await storage.saveMfaRecoveryCodes(user.id, hashedCodes);

    await storage.updateUser(user.id, { mfa_enabled: true });
    await storage.logEvent({ userId: user.id, type: 'mfa.enabled' });

    return { recoveryCodes: plaintextCodes };
  }

  async function disable(user, { password, code }) {
    const credential = await storage.getCredentialByEmail(user.email);
    const passwordValid = await hasher.verify(password, credential.password_hash);
    if (!passwordValid) throw new InvalidCredentialsError();

    const codeValid = await verifyMfaForLogin(user.id, code);
    if (!codeValid) throw new InvalidMfaCodeError();

    await storage.updateUser(user.id, { mfa_secret: null, mfa_enabled: false });
    await storage.deleteMfaRecoveryCodes(user.id);
    await storage.logEvent({ userId: user.id, type: 'mfa.disabled' });

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

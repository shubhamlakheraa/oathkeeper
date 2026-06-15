const crypto = require('crypto');
const { base32Encode, base32Decode } = require('./encodeDecode');

const STEP_SECONDS = 30;
const DIGITS = 6;

function generateSecret() {
  return base32Encode(crypto.randomBytes(20));
}

function buildOtpAuthUri({ secret, accountName, issuer }) {
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(accountName)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

function generateCode(secret, time = Date.now()) {
  const key = base32Decode(secret);
  const counter = Math.floor(time / 1000 / STEP_SECONDS);

  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));

  const hmac = crypto.createHmac('sha1', key).update(counterBuffer).digest();

  const offset = hmac[hmac.length - 1] & 0x0f;
  const binCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  return (binCode % 10 ** DIGITS).toString().padStart(DIGITS, '0');
}

function verifyCode(secret, submittedCode, { window = 1, replayStore }) {
  for (let i = -window; i <= window; i++) {
    const time = Date.now() + i * STEP_SECONDS * 1000;
    const expectedCode = generateCode(secret, time);

    if (submittedCode === expectedCode) {
      const secretFingerprint = crypto.createHash('sha256').update(secret).digest('hex').slice(0, 16);
      const key = `${secretFingerprint}:${Math.floor(time / 1000 / STEP_SECONDS)}`;

      if (replayStore.has(key)) {
        return { valid: false, usedTime: null };
      }

      replayStore.set(key, STEP_SECONDS * (window * 2 + 1));
      return { valid: true, usedTime: time };
    }
  }

  return { valid: false, usedTime: null };
}

module.exports = { generateSecret, buildOtpAuthUri, generateCode, verifyCode };

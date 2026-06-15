const COMMON_PASSWORDS = new Set([
  'password123456',
  'password123456789',
  '123456789012',
  'qwertyuioplkj',
  'iloveyou123456',
]);

const EMAIL_VERIFICATION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const PASSWORD_RESET_TTL_MS = 30 * 60 * 1000

module.exports = { COMMON_PASSWORDS, EMAIL_VERIFICATION_TTL_MS, PASSWORD_RESET_TTL_MS};

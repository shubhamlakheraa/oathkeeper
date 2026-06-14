const COMMON_PASSWORDS = new Set([
  'password123456',
  'password123456789',
  '123456789012',
  'qwertyuioplkj',
  'iloveyou123456',
]);

const TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

module.exports = { COMMON_PASSWORDS, TTL_MS };

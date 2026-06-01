const argon2 = require('argon2');

const DEFAULT_CONFIG = {
  type: argon2.argon2id,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 1,
};

/**
 * @typedef {Object} PasswordHasher
 * @property {(plaintext: string) => Promise<string>} hash
 * @property {(plaintext: string, storedHash: string) => Promise<boolean>} verify
 */

/**
 * Creates an argon2id-backed PasswordHasher.
 * Any omitted fields fall back to safe defaults (argon2id, 64MB, t=3, p=1).
 * @param {object} [config={}] argon2 options to override (memoryCost, timeCost, parallelism, type).
 * @returns {PasswordHasher}
 */
function createArgon2Hasher(config = {}) {
  const merged = { ...DEFAULT_CONFIG, ...config };
  return {
    async hash(plaintext) {
      return argon2.hash(plaintext, merged);
    },
    async verify(plaintext, storedHash) {
      return argon2.verify(storedHash, plaintext);
    },
  };
}

module.exports = { createArgon2Hasher };

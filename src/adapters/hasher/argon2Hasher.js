const argon2 = require('argon2');

const ARG2_CONFIG = {
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 1,
};

/**
 * @typedef {Object} PasswordHasher
 * @property {(plaintext: string) => Promise<string>} hash
 * @property {(storedHash: string, plaintext: string ) => Promise<boolean>} verify
 */

async function hash(plaintext) {
  return argon2.hash(plaintext, ARG2_CONFIG);
}

async function verify(storedHash, plaintext) {
  return argon2.verify(storedHash, plaintext);
}

module.exports = { hash, verify };

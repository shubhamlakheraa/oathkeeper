const crypto = require('node:crypto');

/**
 * Cryptographically-random URL-safe token (base64url, no padding).
 * @param {number} [bytes=32] Number of random bytes (default 32 → 43 chars).
 * @returns {string} Base64url-encoded token using [A-Za-z0-9_-].
 */
function generateToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

/**
 * SHA-256 digest as lowercase hex.
 * String inputs are hashed as their UTF-8 byte representation (so non-ASCII
 * characters such as emoji are hashed via their UTF-8 encoding, not codepoints).
 * Use for hashing tokens or other non-secret identifiers. NOT for passwords —
 * use a slow KDF (Argon2/bcrypt) for those.
 * @param {string|Buffer} input Value to hash.
 * @returns {string} 64-character lowercase hex digest.
 */
function sha256(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

module.exports = { generateToken, sha256 };

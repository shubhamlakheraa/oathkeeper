const jwt = require('jsonwebtoken');

const ALGORITHM = 'HS256';

/**
 * @typedef {Object} TokenSigner
 * @property {(payload: object, options: { expiresIn: string | number }) => string} sign
 * @property {(token: string) => object} verify
 */

/**
 * Creates a TokenSigner bound to an HS256 secret.
 * @param {object} options
 * @param {string} options.secret HMAC secret used for both signing and verification.
 * @param {string} [options.kid] Optional key id, written to every JWT header for key rotation.
 * @returns {TokenSigner}
 */
function createJwtSigner({ secret, kid } = {}) {
  if (!secret) throw new Error('createJwtSigner: secret is required');

  return {
    /**
     * Signs a payload as a JWT using HS256.
     * @param {object} payload Claims to include in the token.
     * @param {object} options
     * @param {string|number} options.expiresIn Expiration — string like "15m"/"7d" or seconds as a number. Required.
     * @returns {string} The signed JWT.
     */
    sign(payload, { expiresIn } = {}) {
      if (expiresIn === undefined) throw new Error('jwt.sign: expiresIn is required');
      const opts = { algorithm: ALGORITHM, expiresIn };
      if (kid) opts.keyid = kid;
      return jwt.sign(payload, secret, opts);
    },

    /**
     * Verifies a JWT signed with HS256.
     * Algorithm is hardcoded — the "alg" field in the token header is NOT trusted.
     * Throws on bad signature, expiry, wrong algorithm, or malformed token.
     * @param {string} token The JWT to verify.
     * @returns {object} The decoded payload (including iat/exp claims).
     */
    verify(token) {
      return jwt.verify(token, secret, { algorithms: [ALGORITHM] });
    },
  };
}

module.exports = { createJwtSigner };

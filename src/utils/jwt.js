const jwt = require('jsonwebtoken');

const ALGORITHM = 'HS256';

/**
 * Signs a payload as a JWT using HS256.
 * @param {object} payload Claims to include in the token.
 * @param {object} options
 * @param {string} options.secret HMAC secret used to sign.
 * @param {string|number} options.expiresIn Expiration — string like "15m"/"7d" or seconds as a number.
 * @param {string} [options.kid] Optional key id, written to the JWT header for key rotation.
 * @returns {string} The signed JWT.
 */
function sign(payload, { secret, expiresIn, kid } = {}) {
  const opts = { algorithm: ALGORITHM, expiresIn };
  if (kid) opts.keyid = kid;
  return jwt.sign(payload, secret, opts);
}

/**
 * Verifies a JWT signed with HS256.
 * Algorithm is hardcoded — the "alg" field in the token header is NOT trusted.
 * Throws on bad signature, expiry, wrong algorithm, or malformed token.
 * @param {string} token The JWT to verify.
 * @param {object} options
 * @param {string} options.secret HMAC secret used to verify.
 * @returns {object} The decoded payload (including iat/exp claims).
 */
function verify(token, { secret } = {}) {
  return jwt.verify(token, secret, { algorithms: [ALGORITHM] });
}

module.exports = { sign, verify };

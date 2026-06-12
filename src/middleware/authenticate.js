// src/middleware/authenticate.js
const { TokenExpiredError, UserNotFoundError, InvalidTokenError } = require('../error');

function createAuthenticate({ signer, storage }) {
  return async function authenticate(req, res, next) {
    try {
      // 1. extract token
      const header = req.headers.authorization;
      if (!header?.startsWith('Bearer ')) {
        return next(new InvalidTokenError());
      }
      const rawJwt = header.slice(7);

      // 2. verify signature + expiry
      let payload;
      try {
        payload = signer.verify(rawJwt);
      } catch (err) {
        if (err.name === 'TokenExpiredError') return next(new TokenExpiredError());
        return next(new InvalidTokenError());
      }

      // 3. look up user + permissions in DB
      const [user, permissions] = await Promise.all([
        storage.getUserById(payload.sub),
        storage.getUserPermissions(payload.sub),
      ]);
      if (!user) return next(new UserNotFoundError());

      // 4. attach to request
      req.user = { ...user, permissions };
      req.auth = {
        tokenPayload: payload,
        isMfaSatisfied: payload.mfa ?? false,
      };

      next();
    } catch (err) {
      next(err);
    }
  };
}

module.exports = { createAuthenticate };

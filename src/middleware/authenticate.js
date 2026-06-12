const { TokenExpiredError, UserNotFoundError, InvalidTokenError } = require('../error');

function createAuthenticate({ signer, storage }) {
  return async function authenticate(req, res, next) {
    try {
      const header = req.headers.authorization;
      if (!header?.startsWith('Bearer ')) {
        return next(new InvalidTokenError());
      }
      const rawJwt = header.slice(7);

      let payload;
      try {
        payload = signer.verify(rawJwt);
      } catch (err) {
        if (err.name === 'TokenExpiredError') return next(new TokenExpiredError());
        return next(new InvalidTokenError());
      }

      // scoped tokens (e.g. mfa_challenge) must never be accepted as access tokens
      if (payload.purpose) return next(new InvalidTokenError());

      const [user, permissions] = await Promise.all([
        storage.getUserById(payload.sub),
        storage.getUserPermissions(payload.sub),
      ]);
      if (!user) return next(new UserNotFoundError());

      // permissions is a Set<string> — use req.user.permissions.has('name') for checks.
      // Not JSON-serializable directly; spread [...req.user.permissions] before res.json.
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

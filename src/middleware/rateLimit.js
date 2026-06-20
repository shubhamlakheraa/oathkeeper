const { RateLimitedError } = require("../error");

function createRateLimitMiddleware({ keyFn, limit, windowMs, adapter }) {
    return function rateLimitMiddleware(req, res, next) {
      const key = keyFn(req);
      const limited = adapter.isRateLimited(key, limit, windowMs);
  
      if (limited) {
        res.set('Retry-After', Math.ceil(windowMs / 1000));
        return next(new RateLimitedError());
      }
  
      next();
    };
  }
  
  module.exports = { createRateLimitMiddleware };
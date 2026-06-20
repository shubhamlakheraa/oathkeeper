const express = require('express');
const cookieParser = require('cookie-parser');
const { InvalidRefreshTokenError } = require('../error');

/**
 * @param {{ tokenService, cookieMode, cookieOptions?, rateLimiters?, csrfMiddleware? }} opts
 *   rateLimiters  — array of rate-limit middleware applied before the handler (e.g. per-IP).
 *   csrfMiddleware — CSRF middleware injected by createAuthRouter when csrf: true. Runs
 *                    after cookie-parser so req.cookies is populated.
 */
function createRefreshRouter({ tokenService, cookieMode, cookieOptions = {}, rateLimiters = [], csrfMiddleware = null }) {
  const router = express.Router();
  router.use(cookieParser());

  // CSRF check runs after cookie-parser and before rate limiting because a forged
  // request shouldn't consume the legitimate client's rate-limit budget.
  if (csrfMiddleware) router.use(csrfMiddleware);

  router.post('/refresh', ...rateLimiters, async (req, res, next) => {
    try {
      const refreshRawToken = cookieMode ? req.cookies?.refreshToken : req.body?.refreshToken;
      if (!refreshRawToken) return next(new InvalidRefreshTokenError());
      const result = await tokenService.rotateRefreshToken(refreshRawToken, {
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });
      if (cookieMode) {
        res.cookie('refreshToken', result.refreshToken, {
          ...cookieOptions,
          httpOnly: true,
          path: '/auth/refresh',
        });
        return res.json({ accessToken: result.accessToken });
      }

      return res.json({
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
      });
    } catch (error) {
      next(error);
    }
  });
  return router;
}

module.exports = { createRefreshRouter };

const express = require('express');

/**
 * @param {{ authService, cookieMode, cookieOptions?, rateLimiters?, csrfTokenSetter? }} opts
 *   rateLimiters — array of rate-limit middleware applied before the handler.
 *                  Typical setup: [perEmailLimiter, perIpLimiter].
 *   csrfTokenSetter — called with (res) after a successful cookie-mode login to write
 *                     the non-HttpOnly csrf_token cookie. Only needed when csrf: true is
 *                     passed to createAuthRouter. Omit for Bearer/header-mode setups.
 */
function createLoginRouter({ authService, cookieMode, cookieOptions = {}, rateLimiters = [], csrfTokenSetter = null }) {
  const router = express.Router();

  router.post('/login', ...rateLimiters, async (req, res, next) => {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        return res
          .status(400)
          .json({ error: { code: 'VALIDATION_ERROR', message: 'email and password are required' } });
      }

      const result = await authService.login({
        email,
        password,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });

      if (cookieMode) {
        res.cookie('refreshToken', result.refreshToken, {
          ...cookieOptions,
          httpOnly: true,
          path: '/auth/refresh',
        });
        // Set the non-HttpOnly CSRF token cookie so JavaScript can echo it as a header.
        if (csrfTokenSetter) csrfTokenSetter(res);
        return res.json({ user: result.user, accessToken: result.accessToken });
      }

      return res.json({
        user: result.user,
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
      });
    } catch (err) {
      next(err);
    }
  });

  return router;
}

module.exports = { createLoginRouter };

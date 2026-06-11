const express = require('express');

function createLogoutRouter({ authService, signer, cookieMode, cookieOptions = {} }) {
  const router = express.Router();

  router.post('/logout', async (req, res, next) => {
    try {
      const refreshToken = cookieMode
        ? req.cookies?.refreshToken
        : req.body?.refreshToken;

      const authHeader = req.headers['authorization'];
      const rawJwt = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null;
      let userId = null;
      if (rawJwt) {
        try {
          userId = signer.verify(rawJwt).sub;
        } catch {
          // expired or invalid access token — proceed without userId
        }
      }

      await authService.logout({
        refreshToken,
        userId,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });

      if (cookieMode) {
        res.clearCookie('refreshToken', {
          ...cookieOptions,
          httpOnly: true,
          path: '/auth/refresh',
        });
      }

      return res.json({ ok: true });
    } catch (err) {
      next(err);
    }
  });

  return router;
}

module.exports = { createLogoutRouter };

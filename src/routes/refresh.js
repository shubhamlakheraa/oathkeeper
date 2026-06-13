const express = require('express');
const { InvalidRefreshTokenError } = require('../error');
const cookieParser = require('cookie-parser');

function createRefreshRouter({ tokenService, cookieMode, cookieOptions = {} }) {
  const router = express.Router();
  router.use(cookieParser());

  router.post('/refresh', async (req, res, next) => {
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

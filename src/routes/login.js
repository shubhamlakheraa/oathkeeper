const express = require('express');

function createLoginRouter({ authService, cookieMode, cookieOptions = {} }) {
  const router = express.Router();

  router.post('/login', async (req, res, next) => {
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

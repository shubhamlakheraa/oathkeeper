const express = require('express');
const cookieParser = require('cookie-parser');

function createPasswordRouter({ authService, authenticate, cookieMode }) {
  const router = express.Router();
  router.use(cookieParser());

  router.post('/password/reset/request', async (req, res, next) => {
    try {
      const { email } = req.body;
      if (!email) {
        return res.status(400).json({ error: { code: 'VALIDATION_ERROR', message: 'email is required' } });
      }
      const result = await authService.requestPasswordReset(email, {
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });
      return res.json(result);
    } catch (err) {
      next(err);
    }
  });

  router.post('/password/reset/confirm', async (req, res, next) => {
    try {
      const { token, newPassword } = req.body;
      if (!token || !newPassword) {
        return res.status(400).json({ error: { code: 'VALIDATION_ERROR', message: 'token and newPassword are required' } });
      }
      await authService.confirmPasswordReset({
        token,
        newPassword,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });
      return res.json({ message: 'Password has been reset.' });
    } catch (err) {
      next(err);
    }
  });

  router.post('/password/change', authenticate, async (req, res, next) => {
    try {
      const { currentPassword, newPassword } = req.body;
      if (!currentPassword || !newPassword) {
        return res.status(400).json({ error: { code: 'VALIDATION_ERROR', message: 'currentPassword and newPassword are required' } });
      }
      const rawRefreshToken = cookieMode ? req.cookies?.refreshToken : req.body?.refreshToken;

      await authService.changePassword(req.user, {
        currentPassword,
        newPassword,
        currentRefreshToken: rawRefreshToken,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });

      return res.json({ message: 'Password changed.' });
    } catch (err) {
      next(err);
    }
  });

  return router;
}

module.exports = { createPasswordRouter };

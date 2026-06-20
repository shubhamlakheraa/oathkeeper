const express = require('express');

function createMfaRouter({ authService, mfaService, authenticate, cookieMode = false, cookieOptions = {}, rateLimiters = [] }) {
  const router = express.Router();

  router.post('/mfa/enroll', authenticate, async (req, res, next) => {
    try {
      const result = await mfaService.beginEnrollment(req.user);
      return res.json(result);
    } catch (err) { next(err); }
  });

  router.post('/mfa/confirm', authenticate, async (req, res, next) => {
    try {
      const { code } = req.body;
      if (!code) return res.status(400).json({ error: { code: 'VALIDATION_ERROR', message: 'code is required' } });
      const result = await mfaService.confirmEnrollment(req.user, code, {
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });
      return res.json(result);
    } catch (err) { next(err); }
  });

  router.post('/mfa/disable', authenticate, async (req, res, next) => {
    try {
      const { password, code } = req.body;
      if (!password || !code) return res.status(400).json({ error: { code: 'VALIDATION_ERROR', message: 'password and code are required' } });
      await mfaService.disable(req.user, {
        password,
        code,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });
      return res.json({ message: 'MFA disabled.' });
    } catch (err) { next(err); }
  });

  router.post('/login/mfa', ...rateLimiters, async (req, res, next) => {
    try {
      const { mfaToken, code } = req.body;
      if (!mfaToken || !code) return res.status(400).json({ error: { code: 'VALIDATION_ERROR', message: 'mfaToken and code are required' } });
      const { user, accessToken, refreshToken } = await authService.completeMfaLogin({
        mfaToken, code, userAgent: req.headers['user-agent'], ip: req.ip,
      });
      if (cookieMode) {
        res.cookie('refreshToken', refreshToken, { httpOnly: true, path: '/auth/refresh', ...cookieOptions });
        return res.json({ user, accessToken });
      }
      return res.json({ user, accessToken, refreshToken });
    } catch (err) { next(err); }
  });

  return router;
}

module.exports = { createMfaRouter };

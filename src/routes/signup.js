const express = require('express');

function createSignupRouter({ authService }) {
  const router = express.Router();

  router.post('/signup', async (req, res, next) => {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        return res
          .status(400)
          .json({ error: { code: 'VALIDATION_ERROR', message: 'email and password are required' } });
      }

      const result = await authService.signup({
        email,
        password,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });

      if (result.alreadyExists) {
        return res
          .status(409)
          .json({ error: { code: 'AUTH.EMAIL_TAKEN', message: 'Email already registered' } });
      }

      return res.status(201).json({ user: result.user });
    } catch (err) {
      next(err);
    }
  });

  return router;
}

module.exports = { createSignupRouter };

const express = require('express');
const { createSignupRouter } = require('./signup');
const { createLoginRouter } = require('./login');
const { createLogoutRouter } = require('./logout');
const { createRefreshRouter } = require('./refresh');
const { createPasswordRouter } = require('./password');
const { createMfaRouter } = require('./mfa');

function createAuthRouter({ authService, tokenService, mfaService, signer, authenticate, cookieMode = false, cookieOptions = {} }) {
  const router = express.Router();
  router.use(createSignupRouter({ authService }));
  router.use(createLoginRouter({ authService, cookieMode, cookieOptions }));
  router.use(createLogoutRouter({ authService, signer, cookieMode, cookieOptions }));
  router.use(createRefreshRouter({ tokenService, cookieMode, cookieOptions }));
  router.use(createPasswordRouter({ authService, authenticate, cookieMode }));
  router.use(createMfaRouter({ authService, mfaService, authenticate }));
  return router;
}

module.exports = { createAuthRouter };

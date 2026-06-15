const express = require('express');
const { createSignupRouter } = require('./signup');
const { createLoginRouter } = require('./login');
const { createLogoutRouter } = require('./logout');
const { createRefreshRouter } = require('./refresh');
const { createPasswordRouter } = require('./password');

function createAuthRouter({ authService, tokenService, signer, authenticate, cookieMode = false, cookieOptions = {} }) {
  const router = express.Router();
  router.use(createSignupRouter({ authService }));
  router.use(createLoginRouter({ authService, cookieMode, cookieOptions }));
  router.use(createLogoutRouter({ authService, signer, cookieMode, cookieOptions }));
  router.use(createRefreshRouter({ tokenService, cookieMode, cookieOptions }));
  router.use(createPasswordRouter({ authService, authenticate, cookieMode }));
  return router;
}

module.exports = { createAuthRouter };

const express = require('express');
const { createSignupRouter } = require('./signup');
const { createLoginRouter } = require('./login');
const { createLogoutRouter } = require('./logout');
const { createRefreshRouter } = require('./refresh');

function createAuthRouter({ authService, tokenService, signer, cookieMode = false, cookieOptions = {} }) {
  const router = express.Router();
  router.use(createSignupRouter({ authService }));
  router.use(createLoginRouter({ authService, cookieMode, cookieOptions }));
  router.use(createLogoutRouter({ authService, signer, cookieMode, cookieOptions }));
  router.use(createRefreshRouter({ tokenService, cookieMode, cookieOptions }));
  return router;
}

module.exports = { createAuthRouter };

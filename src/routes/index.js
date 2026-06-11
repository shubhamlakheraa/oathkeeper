const express = require('express');
const { createSignupRouter } = require('./signup');
const { createLoginRouter } = require('./login');
const { createLogoutRouter } = require('./logout');

function createAuthRouter({ authService, signer, cookieMode = false, cookieOptions = {} }) {
  const router = express.Router();
  router.use(createSignupRouter({ authService }));
  router.use(createLoginRouter({ authService, cookieMode, cookieOptions }));
  router.use(createLogoutRouter({ authService, signer, cookieMode, cookieOptions }));
  return router;
}

module.exports = { createAuthRouter };

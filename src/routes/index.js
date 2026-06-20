const express = require('express');
const { createSignupRouter } = require('./signup');
const { createLoginRouter } = require('./login');
const { createLogoutRouter } = require('./logout');
const { createRefreshRouter } = require('./refresh');
const { createPasswordRouter } = require('./password');
const { createMfaRouter } = require('./mfa');
const { createCsrfMiddleware, setCsrfCookie } = require('../middleware/csrf');

/**
 * @param {{
 *   authService,
 *   tokenService,
 *   mfaService?,
 *   signer,
 *   authenticate,
 *   cookieMode?,
 *   cookieOptions?,
 *   rateLimiters?,
 *   csrf?
 * }} opts
 *
 * rateLimiters — optional map of middleware arrays keyed by route group:
 *   {
 *     login:   [perEmailMiddleware, perIpMiddleware],  // applied to POST /login
 *     refresh: [perIpMiddleware],                      // applied to POST /refresh
 *   }
 *   Build each entry with createRateLimitMiddleware({ keyFn, limit, windowMs, adapter }).
 *
 * csrf — set to true to enable double-submit cookie CSRF protection (cookie mode only).
 *   When enabled:
 *     - POST /login sets a non-HttpOnly `csrf_token` cookie alongside the refresh token.
 *     - POST /refresh requires an `X-CSRF-Token` header that matches the cookie.
 *   CSRF checks are automatically skipped for requests using `Authorization: Bearer`.
 *
 * ⚠️  WARNING — in-memory rate limiting is single-process only.
 *   createMemoryRateLimit() stores counters in a Map on the heap. In a multi-process
 *   deployment (Node cluster, Kubernetes with multiple pods), each process maintains its
 *   own independent counter. A user blocked on process A can reach process B unimpeded.
 *   For multi-process environments, plug in a Redis-backed RateLimitAdapter instead.
 */
function createAuthRouter({
  authService,
  tokenService,
  mfaService,
  signer,
  authenticate,
  cookieMode = false,
  cookieOptions = {},
  rateLimiters = {},
  csrf = false,
}) {
  const router = express.Router();

  // Build CSRF helpers only when explicitly requested and running in cookie mode.
  // In header/Bearer mode, CSRF protection is unnecessary — browsers don't auto-send
  // Authorization headers, so cross-origin requests can't be forged.
  let csrfMiddleware = null;
  let csrfTokenSetter = null;

  if (csrf && cookieMode) {
    csrfMiddleware = createCsrfMiddleware();
    csrfTokenSetter = (res) => setCsrfCookie(res, { cookieOptions });
  }

  router.use(createSignupRouter({ authService }));
  router.use(createLoginRouter({
    authService,
    cookieMode,
    cookieOptions,
    rateLimiters: rateLimiters.login || [],
    csrfTokenSetter,
  }));
  router.use(createLogoutRouter({ authService, signer, cookieMode, cookieOptions }));
  router.use(createRefreshRouter({
    tokenService,
    cookieMode,
    cookieOptions,
    rateLimiters: rateLimiters.refresh || [],
    csrfMiddleware,
  }));
  router.use(createPasswordRouter({ authService, authenticate, cookieMode }));
  router.use(createMfaRouter({ authService, mfaService, authenticate, cookieMode, cookieOptions }));
  return router;
}

module.exports = { createAuthRouter };

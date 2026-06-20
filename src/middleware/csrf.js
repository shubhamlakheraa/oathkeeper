const crypto = require('crypto');
const { CsrfError } = require('../error');
const { timingSafeEqual } = require('../utils/constantTime');

const CSRF_COOKIE_NAME = 'csrf_token';
const CSRF_HEADER_NAME = 'x-csrf-token';
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Double-submit cookie CSRF middleware.
 *
 * Security model:
 *   1. On login (cookie mode) the server sets a non-HttpOnly `csrf_token` cookie.
 *   2. Client JavaScript reads the cookie and echoes it as the `X-CSRF-Token` request
 *      header on every state-changing call.
 *   3. This middleware compares the header value to the cookie value in constant time.
 *   4. A cross-origin attacker cannot read the victim's cookie (Same-Origin Policy),
 *      so it cannot forge the matching header — the attack fails.
 *
 * Automatically skipped for:
 *   - Safe methods (GET, HEAD, OPTIONS) — not CSRF targets.
 *   - Requests carrying `Authorization: Bearer` — not cookie-based auth, not vulnerable.
 *
 * Requires cookie-parser to run before this middleware so `req.cookies` is populated.
 *
 * @param {{ cookieName?: string, headerName?: string }} options
 */
function createCsrfMiddleware({
  cookieName = CSRF_COOKIE_NAME,
  headerName = CSRF_HEADER_NAME,
} = {}) {
  return function csrf(req, _res, next) {
    if (SAFE_METHODS.has(req.method)) return next();

    // Bearer token auth is not cookie-based — no CSRF risk.
    if (req.headers.authorization?.startsWith('Bearer ')) return next();

    const tokenFromCookie = req.cookies?.[cookieName];
    const tokenFromHeader = req.headers[headerName];

    if (!tokenFromCookie || !tokenFromHeader) return next(new CsrfError());
    if (!timingSafeEqual(tokenFromCookie, tokenFromHeader)) return next(new CsrfError());

    next();
  };
}

/**
 * Generates a cryptographically random CSRF token and writes it as a non-HttpOnly
 * cookie so JavaScript can read and replay it as the `X-CSRF-Token` header.
 *
 * The cookie is deliberately NOT HttpOnly — JavaScript must be able to read it.
 * All other security attributes (Secure, SameSite) are inherited from cookieOptions.
 *
 * Call this immediately after a successful login response in cookie mode.
 *
 * @param {import('express').Response} res
 * @param {{ cookieName?: string, cookieOptions?: object }} options
 * @returns {string} The generated token (available if you need to echo it in the body).
 */
function setCsrfCookie(res, { cookieName = CSRF_COOKIE_NAME, cookieOptions = {} } = {}) {
  const token = crypto.randomBytes(32).toString('hex');
  res.cookie(cookieName, token, {
    ...cookieOptions,
    httpOnly: false, // must be readable by JavaScript
  });
  return token;
}

module.exports = { createCsrfMiddleware, setCsrfCookie };

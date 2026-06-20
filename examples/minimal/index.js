'use strict';

/**
 * Minimal oathkeeper example — signup + login + protected route.
 *
 * What this demonstrates:
 *   - createAuth wires everything in one call
 *   - auth.router mounts all auth endpoints under /auth
 *   - auth.authenticate protects any route you choose
 *
 * Run:
 *   DATABASE_URL=postgres://user:pass@localhost:5432/mydb \
 *   JWT_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))") \
 *   node examples/minimal/index.js
 *
 * Then try:
 *   curl -X POST http://localhost:3000/auth/signup \
 *     -H 'Content-Type: application/json' \
 *     -d '{"email":"alice@example.com","password":"correcthorsebatterystaple1"}'
 *
 *   curl -X POST http://localhost:3000/auth/login \
 *     -H 'Content-Type: application/json' \
 *     -d '{"email":"alice@example.com","password":"correcthorsebatterystaple1"}'
 *   # → { user, accessToken, refreshToken }
 *
 *   curl http://localhost:3000/profile \
 *     -H 'Authorization: Bearer <accessToken>'
 *   # → { id, email, ... }
 */

const express = require('express');
const { Pool } = require('pg');
const { createAuth, createConsoleMail } = require('../../src');

const app = express();
app.use(express.json());

const auth = createAuth({
  pool: new Pool({ connectionString: process.env.DATABASE_URL }),
  jwtSecret: process.env.JWT_SECRET,   // min 32 bytes — crashes at boot if wrong
  baseUrl: 'http://localhost:3000',
  mailer: createConsoleMail(),          // prints emails to stdout — swap for real transport
  accessTokenTtl: '15m',
  refreshTokenTtl: '7d',
});

// All auth routes: POST /auth/signup, /auth/login, /auth/logout,
// /auth/refresh, /auth/password/reset/request, /auth/password/reset/confirm,
// /auth/password/change, /auth/mfa/enroll, /auth/mfa/confirm, /auth/mfa/disable,
// POST /auth/login/mfa
app.use('/auth', auth.router);

// Protected endpoint — authenticate decodes the Bearer token and populates req.user
app.get('/profile', auth.authenticate, (req, res) => {
  res.json({ user: req.user });
});

app.listen(3000, () => console.log('Listening on http://localhost:3000'));

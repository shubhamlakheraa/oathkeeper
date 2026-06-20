const { validateConfig } = require('./config/validate');
const { createPostgresStorage } = require('./adapters/storage/postgresStorage');
const { createArgon2Hasher } = require('./adapters/hasher/argon2Hasher');
const { createJwtSigner } = require('./utils/jwt');
const { createTokenService } = require('./services/tokenService');
const { createAuthService } = require('./services/authService');
const { createMfaService } = require('./services/mfaService');
const { createMemoryReplayStore } = require('./adapters/replayStore/memoryReplayStore');
const { createAuthenticate } = require('./middleware/authenticate');
const { createAuthRouter } = require('./routes/index');

/**
 * Top-level factory. Wires all services, adapters, and middleware together and
 * returns an Express router ready to mount at your chosen path.
 *
 * Config is validated at call time — the process will throw a descriptive error
 * immediately rather than failing silently on the first user request.
 *
 * @param {{
 *   pool: import('pg').Pool,
 *   jwtSecret: string,                  // min 32 bytes — see error message for generation hint
 *   accessTokenTtl?: string,            // default '15m'
 *   refreshTokenTtl?: string,           // default '7d'
 *   baseUrl: string,                    // used in email links, e.g. 'https://app.example.com'
 *   mailer: { sendMail: Function },
 *   issuer?: string,                    // TOTP issuer shown in authenticator apps
 *   cookieMode?: boolean,               // default false — send tokens as HttpOnly cookies
 *   cookieOptions?: object,             // forwarded to res.cookie()
 *   hasherConfig?: object,              // argon2 tuning (memoryCost, timeCost, parallelism)
 *   rateLimiters?: { login?: any[], refresh?: any[], mfa?: any[] },
 *   csrf?: boolean,                     // default false — enable double-submit CSRF (cookie mode only)
 *   nodeEnv?: string,                   // defaults to process.env.NODE_ENV
 * }} config
 *
 * @returns {{
 *   router: import('express').Router,
 *   storage,
 *   authService,
 *   tokenService,
 *   mfaService,
 *   authenticate,
 * }}
 *
 * RBAC is app-level — wire it after createAuth:
 *   const { createRbacService } = require('oathkeeper/services/rbacService');
 *   const rbac = createRbacService({ storage: auth.storage, policies: { 'doc:edit': ... } });
 *   app.get('/docs/:id', auth.authenticate, rbac.requirePermission('doc:edit'), handler);
 */
function createAuth({
  pool,
  jwtSecret,
  accessTokenTtl = '15m',
  refreshTokenTtl = '7d',
  baseUrl,
  mailer,
  issuer = 'oathkeeper',
  cookieMode = false,
  cookieOptions = {},
  hasherConfig,
  rateLimiters = {},
  csrf = false,
  nodeEnv = process.env.NODE_ENV,
}) {
  // Fail fast — bad config must surface at boot, not during a user's first login.
  validateConfig({ jwtSecret, accessTokenTtl, refreshTokenTtl, cookieMode, cookieOptions, nodeEnv });

  const storage = createPostgresStorage(pool);
  const hasher = createArgon2Hasher(hasherConfig);
  const signer = createJwtSigner({ secret: jwtSecret });
  const tokenService = createTokenService({ storage, signer, accessTokenTtl, refreshTokenTtl });
  const replayStore = createMemoryReplayStore();
  const mfaService = createMfaService({ storage, hasher, issuer, replayStore });
  const authService = createAuthService({
    storage,
    hasher,
    tokenService,
    signer,
    mailer,
    config: { baseUrl },
    mfaService,
  });
  const authenticate = createAuthenticate({ signer, storage });

  const router = createAuthRouter({
    authService,
    tokenService,
    mfaService,
    signer,
    authenticate,
    cookieMode,
    cookieOptions,
    rateLimiters,
    csrf,
  });

  return { router, storage, authService, tokenService, mfaService, authenticate };
}

module.exports = { createAuth };

const { validateConfig } = require('./config/validate');
const { createPostgresStorage } = require('./adapters/storage/postgresStorage');
const { createArgon2Hasher } = require('./adapters/hasher/argon2Hasher');
const { createJwtSigner } = require('./utils/jwt');
const { createTokenService } = require('./services/tokenService');
const { createAuthService } = require('./services/authService');
const { createMfaService } = require('./services/mfaService');
const { createRbacService } = require('./services/rbacService');
const { createMemoryReplayStore } = require('./adapters/replayStore/memoryReplayStore');
const { createAuthenticate } = require('./middleware/authenticate');
const { createAuthRouter } = require('./routes/index');

/**
 * Top-level factory — the single public entry point.
 *
 * Validates config at call time (fail-fast: crash at boot, not at first login),
 * wires all internal adapters, services, and middleware, and returns a ready-to-mount
 * Express router plus the raw service layer for app-level composition.
 *
 * @param {{
 *   pool: import('pg').Pool,
 *   jwtSecret: string,         min 32 bytes — generate: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
 *   accessTokenTtl?: string,   default '15m'
 *   refreshTokenTtl?: string,  default '7d'
 *   baseUrl: string,           used in email links, e.g. 'https://app.example.com'
 *   mailer: { sendMail: Function },
 *   issuer?: string,           TOTP issuer shown in authenticator apps, default 'oathkeeper'
 *   cookieMode?: boolean,      default false — HttpOnly cookie vs body token
 *   cookieOptions?: object,    forwarded to res.cookie()
 *   hasherConfig?: object,     argon2 tuning { memoryCost, timeCost, parallelism }
 *   rateLimiters?: {
 *     login?: Middleware[],    applied to POST /login  (per-email + per-IP)
 *     refresh?: Middleware[],  applied to POST /refresh
 *     mfa?: Middleware[],      applied to POST /login/mfa (falls back to login limiters)
 *   },
 *   csrf?: boolean,            default false — double-submit cookie (cookie mode only)
 *   nodeEnv?: string,          defaults to process.env.NODE_ENV
 * }} config
 *
 * @returns {{
 *   router: import('express').Router,  mount with app.use('/auth', auth.router)
 *   authenticate: Middleware,          populates req.user + req.auth, or 401
 *   storage,                           raw storage adapter (needed to build rbacService)
 *   authService,
 *   tokenService,
 *   mfaService,
 * }}
 *
 * RBAC is app-level — build it after createAuth using the returned storage:
 *   const { createRbacService, createPermissions } = require('oathkeeper');
 *   const rbac = createRbacService({ storage: auth.storage, policies: { 'doc:edit': ... } });
 *   const { requirePermission } = createPermissions({ rbacService: rbac });
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

  return { router, authenticate, storage, authService, tokenService, mfaService };
}

// ─── public API ──────────────────────────────────────────────────────────────
// Everything a consuming application may need to import directly.

// Main factory
module.exports = { createAuth };

// Error classes — import for instanceof checks and error code handling
const errors = require('./error');
Object.assign(module.exports, errors);

// RBAC — app-level; build after createAuth using the returned storage
const { createPermissions } = require('./middleware/requirePermission');
const { createRoleGuard } = require('./middleware/requireRole');
module.exports.createRbacService = createRbacService;
module.exports.createPermissions = createPermissions;
module.exports.createRoleGuard = createRoleGuard;

// Rate limiting — create adapters + middleware, pass to createAuth({ rateLimiters })
const { createMemoryRateLimit } = require('./adapters/rateLimit/memoryRateLimit');
const { createRateLimitMiddleware } = require('./middleware/rateLimit');
module.exports.createMemoryRateLimit = createMemoryRateLimit;
module.exports.createRateLimitMiddleware = createRateLimitMiddleware;

// CSRF — createCsrfMiddleware is used internally; setCsrfCookie is exported for custom flows
const { createCsrfMiddleware, setCsrfCookie } = require('./middleware/csrf');
module.exports.createCsrfMiddleware = createCsrfMiddleware;
module.exports.setCsrfCookie = setCsrfCookie;

// Storage adapter — export for testing custom adapters against the same interface
module.exports.createPostgresStorage = createPostgresStorage;

// Mail adapters
const { createConsoleMail } = require('./adapters/mail/consoleMail');
module.exports.createConsoleMail = createConsoleMail;

// Error mapper middleware — re-export so apps can use the same error shape
const { errorMapper } = require('./middleware/errorMapper');
module.exports.errorMapper = errorMapper;

const { parseTtl } = require('../utils/random');

const HINT = 'Generate one with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"';

/**
 * Validates the createAuth config object and throws a descriptive Error on any
 * misconfiguration. Call this at boot time — a crash here is intentional and far
 * better than a subtle failure during a user's first login.
 *
 * Checks performed:
 *   - jwtSecret present and ≥ 32 bytes (short secrets are brute-forceable)
 *   - accessTokenTtl > 0
 *   - refreshTokenTtl ≥ accessTokenTtl (a shorter refresh than access TTL is always a bug)
 *   - cookieOptions.secure !== false in production + cookie mode (loud warning, not error)
 */
function validateConfig({
  jwtSecret,
  accessTokenTtl = '15m',
  refreshTokenTtl = '7d',
  cookieMode = false,
  cookieOptions = {},
  nodeEnv = process.env.NODE_ENV,
} = {}) {
  if (!jwtSecret) {
    throw new Error(`[oathkeeper] Missing required config: jwtSecret. ${HINT}`);
  }

  const secretBytes = Buffer.byteLength(jwtSecret, 'utf8');
  if (secretBytes < 32) {
    throw new Error(
      `[oathkeeper] jwtSecret must be at least 32 bytes (got ${secretBytes}). ${HINT}`,
    );
  }

  let accessMs;
  try {
    accessMs = parseTtl(accessTokenTtl);
  } catch {
    throw new Error(`[oathkeeper] Invalid accessTokenTtl: "${accessTokenTtl}". Expected format: 15m, 1h, 7d.`);
  }
  if (accessMs <= 0) {
    throw new Error(`[oathkeeper] accessTokenTtl must be greater than 0 (got "${accessTokenTtl}").`);
  }

  let refreshMs;
  try {
    refreshMs = parseTtl(refreshTokenTtl);
  } catch {
    throw new Error(`[oathkeeper] Invalid refreshTokenTtl: "${refreshTokenTtl}". Expected format: 15m, 1h, 7d.`);
  }
  if (refreshMs < accessMs) {
    throw new Error(
      `[oathkeeper] refreshTokenTtl ("${refreshTokenTtl}") must be longer than accessTokenTtl ("${accessTokenTtl}"). ` +
      'A refresh token that expires before the access token it issued is always a bug.',
    );
  }

  if (cookieMode && cookieOptions.secure === false && nodeEnv === 'production') {
    // Warn loudly — this is a real attack vector, not a styling issue.
    // Not throwing because some internal networks legitimately serve HTTP.
    console.warn(
      '\n⚠️  [oathkeeper] SECURITY WARNING: cookieOptions.secure is false in cookie mode in production.\n' +
      '   Refresh tokens are transmitted over unencrypted HTTP and are vulnerable to interception.\n' +
      '   Set cookieOptions.secure: true for any production deployment.\n',
    );
  }
}

module.exports = { validateConfig };

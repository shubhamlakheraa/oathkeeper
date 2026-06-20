const { AuthError, MfaRequiredError } = require('../error');

const HTTP_STATUS = {
  'AUTH.INVALID_CREDENTIALS': 401,
  'AUTH.INVALID_REFRESH_TOKEN': 401,
  'AUTH.REFRESH_REUSE_DETECTED': 401,
  'AUTH.MFA_REQUIRED': 403,
  'AUTH.WEAK_PASSWORD': 422,
  'AUTH.INVALID_TOKEN': 401,
  'AUTH.TOKEN_EXPIRED': 401,
  'AUTH.USER_NOT_FOUND': 401,
  'AUTH.INVALID_OR_EXPIRED_TOKEN': 401,
  'AUTH.INVALID_MFA_CODE': 401,
  'AUTH.MFA_ALREADY_ENABLED': 409,
  'AUTH.FORBIDDEN': 403,
  'AUTH.ROLE_EXISTS': 409,
  'AUTH.RATE_LIMITED': 429,
  'AUTH.CSRF_INVALID': 403,
};

function errorMapper(err, _req, res, _next) {
  if (err instanceof MfaRequiredError) {
    return res.status(403).json({
      error: { code: err.code, message: err.message, mfaToken: err.mfaToken },
    });
  }

  if (err instanceof AuthError) {
    const status = HTTP_STATUS[err.code] ?? 400;
    return res.status(status).json({ error: { code: err.code, message: err.message } });
  }

  console.error(err);
  return res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred' } });
}

module.exports = { errorMapper };

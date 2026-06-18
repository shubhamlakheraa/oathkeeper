class AuthError extends Error {
  constructor(message, code) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
  }
}

class InvalidRefreshTokenError extends AuthError {
  constructor() {
    super('Invalid or expired refresh token', 'AUTH.INVALID_REFRESH_TOKEN');
  }
}

class RefreshTokenReuseError extends AuthError {
  constructor() {
    super('Refresh token reuse detected', 'AUTH.REFRESH_REUSE_DETECTED');
  }
}

class InvalidCredentialsError extends AuthError {
  constructor() {
    super('Invalid email or password', 'AUTH.INVALID_CREDENTIALS');
  }
}

class WeakPasswordError extends AuthError {
  constructor(message) {
    super(message, 'AUTH.WEAK_PASSWORD');
  }
}

class MfaRequiredError extends AuthError {
  constructor(mfaToken) {
    super('MFA required', 'AUTH.MFA_REQUIRED');
    this.mfaToken = mfaToken;
  }
}

class InvalidTokenError extends AuthError {
  constructor() {
    super('Invalid token', 'AUTH.INVALID_TOKEN');
  }
}

class TokenExpiredError extends AuthError {
  constructor() {
    super('Token expired', 'AUTH.TOKEN_EXPIRED');
  }
}

class UserNotFoundError extends AuthError {
  constructor() {
    super('User not found', 'AUTH.USER_NOT_FOUND');
  }
}

class InvalidOrExpiredTokenError extends AuthError {
  constructor() {
    super('Invalid or expired token', 'AUTH.INVALID_OR_EXPIRED_TOKEN');
  }
}

class InvalidMfaCodeError extends AuthError {
  constructor() {
    super('Invalid MFA code', 'AUTH.INVALID_MFA_CODE');
  }
}

class MfaAlreadyEnabledError extends AuthError {
  constructor() {
    super('MFA is already enabled', 'AUTH.MFA_ALREADY_ENABLED');
  }
}

class ForbiddenError extends AuthError {
  constructor() {
    super('Forbidden', 'AUTH.FORBIDDEN');
  }
}

class RoleAlreadyExistsError extends AuthError {
  constructor() {
    super('Role already exists', 'AUTH.ROLE_EXISTS');
  }
}

module.exports = {
  AuthError,
  InvalidRefreshTokenError,
  RefreshTokenReuseError,
  InvalidCredentialsError,
  WeakPasswordError,
  MfaRequiredError,
  InvalidTokenError,
  TokenExpiredError,
  UserNotFoundError,
  InvalidOrExpiredTokenError,
  InvalidMfaCodeError,
  MfaAlreadyEnabledError,
  ForbiddenError,
  RoleAlreadyExistsError,
};

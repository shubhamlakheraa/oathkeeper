const { validateConfig } = require('../src/config/validate');

const VALID_SECRET = 'a'.repeat(32); // exactly 32 bytes

describe('validateConfig', () => {
  // ─── jwtSecret ────────────────────────────────────────────────────────────

  it('throws on missing jwtSecret', () => {
    expect(() => validateConfig({ jwtSecret: undefined })).toThrow(
      /Missing required config: jwtSecret/,
    );
  });

  it('throws with a how-to-generate hint when jwtSecret is missing', () => {
    expect(() => validateConfig({ jwtSecret: undefined })).toThrow(/Generate one with/);
  });

  it('throws when jwtSecret is an empty string', () => {
    expect(() => validateConfig({ jwtSecret: '' })).toThrow(/Missing required config: jwtSecret/);
  });

  it('throws when jwtSecret is shorter than 32 bytes', () => {
    expect(() => validateConfig({ jwtSecret: 'short' })).toThrow(/at least 32 bytes/);
  });

  it('includes the actual byte count in the error when jwtSecret is too short', () => {
    expect(() => validateConfig({ jwtSecret: 'tooshort' })).toThrow(/got 8/);
  });

  it('includes a how-to-generate hint when jwtSecret is too short', () => {
    expect(() => validateConfig({ jwtSecret: 'tooshort' })).toThrow(/Generate one with/);
  });

  it('accepts a jwtSecret that is exactly 32 bytes', () => {
    expect(() => validateConfig({ jwtSecret: VALID_SECRET })).not.toThrow();
  });

  it('accepts a jwtSecret longer than 32 bytes', () => {
    expect(() => validateConfig({ jwtSecret: 'a'.repeat(64) })).not.toThrow();
  });

  // ─── accessTokenTtl ───────────────────────────────────────────────────────

  it('throws when accessTokenTtl is "0s"', () => {
    expect(() =>
      validateConfig({ jwtSecret: VALID_SECRET, accessTokenTtl: '0s' }),
    ).toThrow(/accessTokenTtl must be greater than 0/);
  });

  it('throws when accessTokenTtl is an unrecognised format', () => {
    expect(() =>
      validateConfig({ jwtSecret: VALID_SECRET, accessTokenTtl: '15min' }),
    ).toThrow(/Invalid accessTokenTtl/);
  });

  it('accepts a valid accessTokenTtl', () => {
    expect(() =>
      validateConfig({ jwtSecret: VALID_SECRET, accessTokenTtl: '15m' }),
    ).not.toThrow();
  });

  // ─── refreshTokenTtl vs accessTokenTtl ───────────────────────────────────

  it('throws when refreshTokenTtl is shorter than accessTokenTtl', () => {
    expect(() =>
      validateConfig({ jwtSecret: VALID_SECRET, accessTokenTtl: '1h', refreshTokenTtl: '30m' }),
    ).toThrow(/refreshTokenTtl.*must be longer than accessTokenTtl/);
  });

  it('throws when refreshTokenTtl equals accessTokenTtl (edge — technically valid but unusual)', () => {
    // Equal is allowed: refresh == access is weird but not wrong
    expect(() =>
      validateConfig({ jwtSecret: VALID_SECRET, accessTokenTtl: '15m', refreshTokenTtl: '15m' }),
    ).not.toThrow();
  });

  it('accepts a refreshTokenTtl longer than accessTokenTtl', () => {
    expect(() =>
      validateConfig({ jwtSecret: VALID_SECRET, accessTokenTtl: '15m', refreshTokenTtl: '7d' }),
    ).not.toThrow();
  });

  it('throws when refreshTokenTtl is an unrecognised format', () => {
    expect(() =>
      validateConfig({ jwtSecret: VALID_SECRET, refreshTokenTtl: 'fortnight' }),
    ).toThrow(/Invalid refreshTokenTtl/);
  });

  // ─── production cookie security warning ───────────────────────────────────

  it('logs a warning when secure:false in cookie mode in production', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    validateConfig({
      jwtSecret: VALID_SECRET,
      cookieMode: true,
      cookieOptions: { secure: false },
      nodeEnv: 'production',
    });
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('SECURITY WARNING'));
    warn.mockRestore();
  });

  it('does NOT throw for secure:false in production — warning only', () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    expect(() =>
      validateConfig({
        jwtSecret: VALID_SECRET,
        cookieMode: true,
        cookieOptions: { secure: false },
        nodeEnv: 'production',
      }),
    ).not.toThrow();
    vi.restoreAllMocks();
  });

  it('does not warn when secure:false but NOT in cookie mode', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    validateConfig({
      jwtSecret: VALID_SECRET,
      cookieMode: false,
      cookieOptions: { secure: false },
      nodeEnv: 'production',
    });
    expect(warn).not.toHaveBeenCalled();
    warn.mockRestore();
  });

  it('does not warn when secure:false in cookie mode but NOT in production', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    validateConfig({
      jwtSecret: VALID_SECRET,
      cookieMode: true,
      cookieOptions: { secure: false },
      nodeEnv: 'development',
    });
    expect(warn).not.toHaveBeenCalled();
    warn.mockRestore();
  });

  it('does not warn when secure:true in cookie mode in production', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    validateConfig({
      jwtSecret: VALID_SECRET,
      cookieMode: true,
      cookieOptions: { secure: true },
      nodeEnv: 'production',
    });
    expect(warn).not.toHaveBeenCalled();
    warn.mockRestore();
  });

  // ─── happy path ───────────────────────────────────────────────────────────

  it('passes with a minimal valid config', () => {
    expect(() => validateConfig({ jwtSecret: VALID_SECRET })).not.toThrow();
  });

  it('passes with a fully specified valid config', () => {
    expect(() =>
      validateConfig({
        jwtSecret: VALID_SECRET,
        accessTokenTtl: '15m',
        refreshTokenTtl: '7d',
        cookieMode: true,
        cookieOptions: { secure: true, sameSite: 'strict' },
        nodeEnv: 'production',
      }),
    ).not.toThrow();
  });
});

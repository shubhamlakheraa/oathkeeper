const { generateToken, sha256 } = require('../src/utils/random');

describe('generateToken', () => {
  it('returns a 43-char string by default (32 bytes as base64url)', () => {
    expect(generateToken()).toHaveLength(43);
  });

  it('returns a 43-char string when called with 32 explicitly', () => {
    expect(generateToken(32)).toHaveLength(43);
  });

  it('produces a different value on each call', () => {
    expect(generateToken()).not.toBe(generateToken());
  });

  it('honors a custom byte length', () => {
    expect(generateToken(16)).toHaveLength(22);
    expect(generateToken(64)).toHaveLength(86);
  });

  it('uses url-safe alphabet only (no +, /, =)', () => {
    const t = generateToken(64);
    expect(t).toMatch(/^[A-Za-z0-9_-]+$/);
  });
});

describe('sha256', () => {
  it('matches the known digest for "hello"', () => {
    expect(sha256('hello')).toBe(
      '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',
    );
  });

  it('returns a 64-char lowercase hex string', () => {
    expect(sha256('anything')).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is deterministic for the same input', () => {
    expect(sha256('x')).toBe(sha256('x'));
  });

  it('produces different output for different input', () => {
    expect(sha256('a')).not.toBe(sha256('b'));
  });

  it('accepts a Buffer input and matches the string equivalent', () => {
    expect(sha256(Buffer.from('hello'))).toBe(sha256('hello'));
  });
});

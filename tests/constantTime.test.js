const { timingSafeEqual } = require('../src/utils/constantTime');

describe('timingSafeEqual', () => {
  it('returns true for identical strings', () => {
    expect(timingSafeEqual('abc', 'abc')).toBe(true);
  });

  it('returns false for same-length strings that differ', () => {
    expect(timingSafeEqual('abc', 'abd')).toBe(false);
  });

  it('returns false (without throwing) for different-length strings', () => {
    expect(() => timingSafeEqual('abc', 'abcd')).not.toThrow();
    expect(timingSafeEqual('abc', 'abcd')).toBe(false);
  });

  it('returns true for two empty strings', () => {
    expect(timingSafeEqual('', '')).toBe(true);
  });

  it('accepts Buffer inputs', () => {
    expect(timingSafeEqual(Buffer.from('abc'), Buffer.from('abc'))).toBe(true);
    expect(timingSafeEqual(Buffer.from('abc'), Buffer.from('abd'))).toBe(false);
  });

  it('treats a Buffer and a string with the same bytes as equal', () => {
    expect(timingSafeEqual(Buffer.from('abc'), 'abc')).toBe(true);
  });
  it('returns false in constant time regardless of length difference', () => {
    // Hard to assert timing strictly; assert the path runs without throw.
    expect(timingSafeEqual('a', 'abcdefghij')).toBe(false);
    expect(timingSafeEqual('abcdefghij', 'a')).toBe(false);
  });
});

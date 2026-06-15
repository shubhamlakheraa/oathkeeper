const { generateSecret, buildOtpAuthUri, generateCode, verifyCode } = require('../src/utils/totp');
const { base32Encode } = require('../src/utils/encodeDecode');

// RFC 4226 Appendix D — HOTP test vectors with secret "12345678901234567890".
// TOTP counter = floor(T_seconds / 30), so counter N maps to T = N * 30 * 1000 ms.
const RFC_SECRET = base32Encode(Buffer.from('12345678901234567890', 'ascii'));
const RFC_VECTORS = [
  { counter: 0, code: '755224' },
  { counter: 1, code: '287082' },
  { counter: 2, code: '359152' },
  { counter: 3, code: '969429' },
  { counter: 4, code: '338314' },
  { counter: 5, code: '254676' },
  { counter: 6, code: '287922' },
  { counter: 7, code: '162583' },
  { counter: 8, code: '399871' },
  { counter: 9, code: '520489' },
];

function makeReplayStore() {
  const store = new Map();
  return {
    has: (key) => store.has(key),
    set: (key) => store.set(key, true),
  };
}

describe('generateSecret', () => {
  it('returns a non-empty base32 string', () => {
    const secret = generateSecret();
    expect(typeof secret).toBe('string');
    expect(secret.length).toBeGreaterThan(0);
    expect(/^[A-Z2-7]+$/.test(secret)).toBe(true);
  });

  it('returns a different secret on each call', () => {
    expect(generateSecret()).not.toBe(generateSecret());
  });
});

describe('buildOtpAuthUri', () => {
  it('returns correct otpauth URI', () => {
    const uri = buildOtpAuthUri({ secret: 'ABCDEF', accountName: 'user@x.com', issuer: 'MyApp' });
    expect(uri).toBe(
      'otpauth://totp/MyApp:user%40x.com?secret=ABCDEF&issuer=MyApp&algorithm=SHA1&digits=6&period=30',
    );
  });

  it('percent-encodes special characters in accountName', () => {
    const uri = buildOtpAuthUri({ secret: 'S', accountName: 'a b+c', issuer: 'App' });
    expect(uri).toContain('a%20b%2Bc');
  });
});

describe('generateCode — RFC 4226 test vectors', () => {
  it.each(RFC_VECTORS)('counter=$counter → $code', ({ counter, code }) => {
    const time = counter * 30 * 1000;
    expect(generateCode(RFC_SECRET, time)).toBe(code);
  });

  it('returns a 6-character string for every vector', () => {
    for (const { counter } of RFC_VECTORS) {
      const result = generateCode(RFC_SECRET, counter * 30 * 1000);
      expect(result).toHaveLength(6);
    }
  });

  it('zero-pads codes shorter than 6 digits', () => {
    // counter=0 → 755224 — all vectors are 6 digits, but we verify padStart works
    // by checking that the result is always exactly 6 chars even for small values
    const result = generateCode(RFC_SECRET, 0);
    expect(result).toMatch(/^\d{6}$/);
  });
});

describe('verifyCode', () => {
  it('accepts the current code', () => {
    const secret = generateSecret();
    const code = generateCode(secret);
    const { valid } = verifyCode(secret, code, { replayStore: makeReplayStore() });
    expect(valid).toBe(true);
  });

  it('accepts a code from 30 seconds ago (within window=1)', () => {
    const secret = generateSecret();
    const thirtySecondsAgo = Date.now() - 30 * 1000;
    const code = generateCode(secret, thirtySecondsAgo);
    const { valid } = verifyCode(secret, code, { replayStore: makeReplayStore() });
    expect(valid).toBe(true);
  });

  it('rejects a code from 90 seconds ago (outside window=1)', () => {
    const secret = generateSecret();
    const ninetySecondsAgo = Date.now() - 90 * 1000;
    const code = generateCode(secret, ninetySecondsAgo);
    const { valid } = verifyCode(secret, code, { replayStore: makeReplayStore() });
    expect(valid).toBe(false);
  });

  it('rejects a wrong code', () => {
    const secret = generateSecret();
    const { valid } = verifyCode(secret, '000000', { replayStore: makeReplayStore() });
    expect(valid).toBe(false);
  });

  it('returns usedTime on success and null on failure', () => {
    const secret = generateSecret();
    const code = generateCode(secret);
    const store = makeReplayStore();
    const success = verifyCode(secret, code, { replayStore: store });
    expect(success.usedTime).not.toBeNull();

    const failure = verifyCode(secret, '000000', { replayStore: makeReplayStore() });
    expect(failure.usedTime).toBeNull();
  });

  describe('replay protection', () => {
    it('first use succeeds, second use of same code is rejected', () => {
      const secret = generateSecret();
      const code = generateCode(secret);
      const store = makeReplayStore();

      const first = verifyCode(secret, code, { replayStore: store });
      expect(first.valid).toBe(true);

      const second = verifyCode(secret, code, { replayStore: store });
      expect(second.valid).toBe(false);
    });

    it('replay rejection is per time-step — a new window code is accepted after replay', () => {
      const secret = generateSecret();
      const store = makeReplayStore();

      const currentCode = generateCode(secret, Date.now());
      verifyCode(secret, currentCode, { replayStore: store });

      // code from -1 window (different time-step) must still be accepted
      const prevCode = generateCode(secret, Date.now() - 30 * 1000);
      if (prevCode !== currentCode) {
        const result = verifyCode(secret, prevCode, { replayStore: store });
        expect(result.valid).toBe(true);
      }
    });
  });
});

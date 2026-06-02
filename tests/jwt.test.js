const jwtLib = require('jsonwebtoken');
const { sign, verify } = require('../src/utils/jwt');

const secret = 'test-secret-do-not-use-anywhere-else';

describe('jwt.sign + verify', () => {
  it('sign returns a verifiable JWT string', () => {
    const token = sign({ sub: '1' }, { secret, expiresIn: '5m' });
    expect(typeof token).toBe('string');
    expect(token.split('.')).toHaveLength(3);
    expect(verify(token, { secret })).toMatchObject({ sub: '1' });
  });

  it('verify with the correct secret succeeds', () => {
    const token = sign({ sub: '1' }, { secret, expiresIn: '5m' });
    const decoded = verify(token, { secret });
    expect(decoded.sub).toBe('1');
  });

  it('verify with the wrong secret throws', () => {
    const token = sign({ sub: '1' }, { secret, expiresIn: '5m' });
    expect(() => verify(token, { secret: 'wrong-secret' })).toThrow();
  });

  it('expired token throws with a message containing "expired"', () => {
    // Build an already-expired token via the raw lib so the test is deterministic.
    const expired = jwtLib.sign(
      { sub: '1', exp: Math.floor(Date.now() / 1000) - 60 },
      secret,
      { algorithm: 'HS256' },
    );
    expect(() => verify(expired, { secret })).toThrow(/expired/i);
  });

  it('rejects an "alg: none" token', () => {
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: '1' })).toString('base64url');
    const noneToken = `${header}.${payload}.`;
    expect(() => verify(noneToken, { secret })).toThrow();
  });

  it('payload round-trips (sign then verify returns original claims)', () => {
    const token = sign({ sub: '1', role: 'admin', email: 'a@b.com' }, { secret, expiresIn: '5m' });
    const decoded = verify(token, { secret });
    expect(decoded).toMatchObject({ sub: '1', role: 'admin', email: 'a@b.com' });
    expect(decoded.iat).toEqual(expect.any(Number));
    expect(decoded.exp).toEqual(expect.any(Number));
  });
});

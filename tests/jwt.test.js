const jwtLib = require('jsonwebtoken');
const { createJwtSigner } = require('../src/utils/jwt');

const secret = 'test-secret-do-not-use-anywhere-else';

describe('createJwtSigner (factory)', () => {
  it('throws when secret is missing', () => {
    expect(() => createJwtSigner()).toThrow(/secret/);
    expect(() => createJwtSigner({})).toThrow(/secret/);
  });
});

describe('jwtSigner.sign + verify', () => {
  const signer = createJwtSigner({ secret });

  it('sign returns a verifiable JWT string', () => {
    const token = signer.sign({ sub: '1' }, { expiresIn: '5m' });
    expect(typeof token).toBe('string');
    expect(token.split('.')).toHaveLength(3);
    expect(signer.verify(token)).toMatchObject({ sub: '1' });
  });

  it('verify with the correct secret succeeds', () => {
    const token = signer.sign({ sub: '1' }, { expiresIn: '5m' });
    expect(signer.verify(token).sub).toBe('1');
  });

  it('verify with the wrong secret throws', () => {
    const other = createJwtSigner({ secret: 'wrong-secret' });
    const token = signer.sign({ sub: '1' }, { expiresIn: '5m' });
    expect(() => other.verify(token)).toThrow();
  });

  it('expired token throws with a message containing "expired"', () => {
    const expired = jwtLib.sign(
      { sub: '1', exp: Math.floor(Date.now() / 1000) - 60 },
      secret,
      { algorithm: 'HS256' },
    );
    expect(() => signer.verify(expired)).toThrow(/expired/i);
  });

  it('rejects an "alg: none" token', () => {
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: '1' })).toString('base64url');
    const noneToken = `${header}.${payload}.`;
    expect(() => signer.verify(noneToken)).toThrow();
  });

  it('payload round-trips (sign then verify returns original claims)', () => {
    const token = signer.sign({ sub: '1', role: 'admin', email: 'a@b.com' }, { expiresIn: '5m' });
    const decoded = signer.verify(token);
    expect(decoded).toMatchObject({ sub: '1', role: 'admin', email: 'a@b.com' });
    expect(decoded.iat).toEqual(expect.any(Number));
    expect(decoded.exp).toEqual(expect.any(Number));
  });

  it('writes kid to the JWT header when provided', () => {
    const kidSigner = createJwtSigner({ secret, kid: 'k1' });
    const token = kidSigner.sign({ sub: '1' }, { expiresIn: '5m' });
    const [hdr] = token.split('.');
    const header = JSON.parse(Buffer.from(hdr, 'base64url').toString());
    expect(header.kid).toBe('k1');
  });

  it('rejects a token whose payload has been tampered with', () => {
    const token = signer.sign({ sub: '1', role: 'user' }, { expiresIn: '5m' });
    const [hdr, , sig] = token.split('.');
    const tamperedPayload = Buffer.from(JSON.stringify({ sub: '1', role: 'admin' })).toString(
      'base64url',
    );
    const tamperedToken = `${hdr}.${tamperedPayload}.${sig}`;
    expect(() => signer.verify(tamperedToken)).toThrow();
  });

  it('throws when expiresIn is missing', () => {
    expect(() => signer.sign({ sub: '1' }, {})).toThrow(/expiresIn/);
    expect(() => signer.sign({ sub: '1' })).toThrow(/expiresIn/);
  });
});

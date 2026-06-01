const { createArgon2Hasher } = require('../src/adapters/hasher/argon2Hasher');

const { hash, verify } = createArgon2Hasher();

describe('argon2Hasher.hash', () => {
  it('returns a string starting with "$argon2id$"', async () => {
    const h = await hash('hunter2');
    expect(typeof h).toBe('string');
    expect(h.startsWith('$argon2id$')).toBe(true);
  });

  it('produces a different hash on each call for the same input (random salt)', async () => {
    const h1 = await hash('hunter2');
    const h2 = await hash('hunter2');
    expect(h1).not.toBe(h2);
  });

  it('takes at least 100ms per call', async () => {
    const start = Date.now();
    await hash('hunter2');
    const elapsed = Date.now() - start;
    expect(elapsed).toBeGreaterThanOrEqual(100);
  });
});

describe('argon2Hasher.verify', () => {
  it('returns true when plaintext matches the stored hash', async () => {
    const stored = await hash('hunter2');
    expect(await verify('hunter2', stored)).toBe(true);
  });

  it('returns false when plaintext does not match the stored hash', async () => {
    const stored = await hash('hunter2');
    expect(await verify('hunter3', stored)).toBe(false);
  });

  it('rejects (or returns false) for a malformed hash string', async () => {
    await expect(verify('hunter2', 'not-a-hash')).rejects.toThrow();
  });

  it('handles empty plaintext consistently', async () => {
    const h = await hash('');
    expect(await verify('', h)).toBe(true);
    expect(await verify('x', h)).toBe(false);
  });
});

function createMemoryRateLimit() {
  const store = new Map();

  function isRateLimited(key, limit, windowMs) {
    const now = Date.now();
    const entry = store.get(key) || {
      currentCount: 0,
      prevCount: 0,
      windowStart: now,
    };

    const elapsed = now - entry.windowStart;
    if (elapsed >= windowMs) {
      entry.prevCount = elapsed < windowMs * 2 ? entry.currentCount : 0;
      entry.currentCount = 0;
      entry.windowStart = now;
    }

    const timeIntoWindow = now - entry.windowStart;
    const prevWindowWeight = (windowMs - timeIntoWindow) / windowMs;
    const estimated = Math.ceil(entry.prevCount * prevWindowWeight + entry.currentCount);

    if (estimated >= limit) {
      store.set(key, entry);
      return true;
    }

    entry.currentCount += 1;
    store.set(key, entry);
    return false;
  }

  function reset(key) {
    store.delete(key);
  }

  return { isRateLimited, reset };
}

module.exports = { createMemoryRateLimit };

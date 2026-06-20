// src/adapters/rateLimit/RateLimitAdapter.js

/**
 * @typedef {Object} RateLimitAdapter
 * 
 * @property {(key: string, limit: number, windowMs: number) => boolean} isRateLimited
 * Check if the given key has exceeded the limit within the window.
 * Returns true if rate limited, false if request should be allowed.
 * Must increment the counter on each call.
 * 
 * @property {(key: string) => void} reset
 * Reset the counter for a given key.
 * Used in tests and after successful auth events.
 */
function createMemoryReplayStore() {
    const used = new Map();
  
    function has(key) {
      const expiry = used.get(key);
      if (expiry === undefined) return false;
      if (Date.now() > expiry) {
        used.delete(key);
        return false;
      }
      return true;
    }
  
    function set(key, ttlSeconds) {
      used.set(key, Date.now() + ttlSeconds * 1000);
    }
  
    return { has, set };
  }
  
  module.exports = { createMemoryReplayStore };
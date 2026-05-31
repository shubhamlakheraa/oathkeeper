const crypto = require('node:crypto');

function timingSafeEqual(a, b) {
  const aBuf = Buffer.isBuffer(a) ? a : Buffer.from(a);
  const bBuf = Buffer.isBuffer(b) ? b : Buffer.from(b);
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

module.exports = { timingSafeEqual };

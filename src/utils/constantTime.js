const crypto = require('node:crypto');

/**
 * Constant-time equality check for strings or Buffers.
 * Pads inputs to equal length so the byte-comparison runs in constant time;
 * unequal original lengths return false. String inputs are compared as their
 * UTF-8 byte representation.
 * @param {string|Buffer} a First value.
 * @param {string|Buffer} b Second value.
 * @returns {boolean} True iff both inputs have identical bytes and length.
 */
function timingSafeEqual(a, b) {
  const aBuf = Buffer.isBuffer(a) ? a : Buffer.from(a);
  const bBuf = Buffer.isBuffer(b) ? b : Buffer.from(b);
  const len = Math.max(aBuf.length, bBuf.length);
  const aPad = Buffer.alloc(len);
  const bPad = Buffer.alloc(len);
  aBuf.copy(aPad);
  bBuf.copy(bPad);
  const sameLen = aBuf.length === bBuf.length;
  const sameBytes = crypto.timingSafeEqual(aPad, bPad);
  return sameLen && sameBytes;
}

module.exports = { timingSafeEqual };

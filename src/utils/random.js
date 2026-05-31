const crypto = require('node:crypto');

function generateToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function sha256(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

module.exports = { generateToken, sha256 };

const { generateToken, sha256, parseTtl } = require('../utils/random');
const { InvalidRefreshTokenError, RefreshTokenReuseError } = require('../error');

function createTokenService({ storage, signer, accessTokenTtl, refreshTokenTtl }) {
  function issueAccessToken(user) {
    return signer.sign(
      { sub: user.id, email: user.email, mfa: user.mfa_enabled },
      { expiresIn: accessTokenTtl },
    );
  }

  async function insertRefreshToken({ userId, familyId, userAgent, ip }, { client } = {}) {
    const rawToken = generateToken();
    const tokenHash = sha256(rawToken);
    const expiresAt = new Date(Date.now() + parseTtl(refreshTokenTtl));
    const row = await storage.saveRefreshToken(
      { userId, tokenHash, familyId, expiresAt, userAgent, ip },
      { client },
    );
    return { rawToken, row };
  }

  async function issueRefreshToken(user, { familyId, userAgent, ip }) {
    const { rawToken } = await insertRefreshToken({
      userId: user.id,
      familyId,
      userAgent,
      ip,
    });
    return rawToken;
  }

  async function rotateRefreshToken(oldRawToken, { userAgent, ip }) {
    const oldHash = sha256(oldRawToken);
    let reuseFamilyId = null;

    try {
      return await storage.withTransaction(async (client) => {
        const prev = await storage.getRefreshToken(oldHash, { client });
        if (!prev) throw new InvalidRefreshTokenError();

        if (prev.revoked_at) {
          reuseFamilyId = prev.family_id;
          throw new RefreshTokenReuseError();
        }
        if (prev.expires_at <= new Date()) throw new InvalidRefreshTokenError();

        const { rawToken: newRawToken, row: newRow } = await insertRefreshToken(
          {
            userId: prev.user_id,
            familyId: prev.family_id,
            userAgent,
            ip,
          },
          { client },
        );

        const { status } = await storage.rotateRefreshToken(
          { tokenHash: oldHash, replacedById: newRow.id },
          { client },
        );

        if (status !== 'SUCCESS') {
          reuseFamilyId = prev.family_id;
          throw new RefreshTokenReuseError();
        }

        const user = await storage.getUserById(prev.user_id, { client });
        if (!user) throw new InvalidRefreshTokenError();
        return {
          refreshToken: newRawToken,
          accessToken: issueAccessToken(user),
        };
      });
    } catch (err) {
      if (reuseFamilyId) {
        try {
          await storage.revokeRefreshTokenFamily(reuseFamilyId);
        } catch (revokeErr) {
          console.error('FAMILY_REVOKE_FAILED', {
            familyId: reuseFamilyId,
            cause: revokeErr,
          });
        }
      }
      throw err;
    }
  }

  function revokeRefreshToken(rawToken) {
    const tokenHash = sha256(rawToken);
    return storage.revokeRefreshToken(tokenHash);
  }

  function revokeAllForUser(userId) {
    return storage.revokeAllRefreshTokensForUser(userId);
  }

  return {
    issueAccessToken,
    issueRefreshToken,
    rotateRefreshToken,
    revokeRefreshToken,
    revokeAllForUser,
  };
}

module.exports = { createTokenService };

const PUBLIC_USER_COLUMNS =
  'id, email, email_verified, mfa_enabled, last_login_at, created_at, updated_at, deleted_at';

const ALLOWED_PATCH_FIELDS = new Set([
  'email_verified',
  'mfa_enabled',
  'mfa_secret',
  'last_login_at',
]);

function createPostgresStorage(pool) {
  async function createUser({ email, passwordHash }) {
    try {
      const result = await pool.query(
        `
              INSERT INTO users (email, password_hash)
              VALUES ($1, $2)
              RETURNING ${PUBLIC_USER_COLUMNS}
          `,
        [email.toLowerCase().trim(), passwordHash],
      );
      return result.rows[0];
    } catch (err) {
      if (err.code === '23505') {
        const e = new Error('Email already registered');
        e.code = 'EMAIL_TAKEN';
        throw e;
      }
      throw err;
    }
  }

  async function getUserByEmail(email) {
    const result = await pool.query(
      `SELECT ${PUBLIC_USER_COLUMNS} FROM users WHERE email = $1 AND deleted_at IS NULL`,
      [email.toLowerCase().trim()],
    );
    return result.rows[0] || null;
  }

  async function getUserById(id) {
    const result = await pool.query(
      `SELECT ${PUBLIC_USER_COLUMNS} FROM users WHERE id = $1 AND deleted_at IS NULL`,
      [id],
    );
    return result.rows[0] || null;
  }

  async function getCredentialByEmail(email) {
    const result = await pool.query(
      `SELECT id, email, password_hash FROM users WHERE email = $1 AND deleted_at IS NULL`,
      [email.toLowerCase().trim()],
    );
    return result.rows[0] || null;
  }

  async function getMfaSecret(userId) {
    const result = await pool.query(
      `SELECT mfa_secret FROM users WHERE id = $1 AND deleted_at IS NULL`,
      [userId],
    );
    return result.rows[0] ? result.rows[0].mfa_secret : null;
  }

  async function softDeleteUser(id) {
    await pool.query(`UPDATE users SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL`, [
      id,
    ]);
  }

  async function updateUser(id, patches) {
    const fields = Object.keys(patches);
    if (fields.length === 0) return getUserById(id);

    fields.forEach((f) => {
      if (!ALLOWED_PATCH_FIELDS.has(f)) throw new Error(`Field not patchable: ${f}`);
    });

    const setClauses = fields.map((f, i) => `${f} = $${i + 2}`).join(', ');
    const values = fields.map((f) => patches[f]);

    const result = await pool.query(
      `UPDATE users SET ${setClauses}, updated_at = now() WHERE id = $1 AND deleted_at IS NULL RETURNING ${PUBLIC_USER_COLUMNS}`,
      [id, ...values],
    );
    return result.rows[0] || null;
  }

  async function saveRefreshToken(userId, tokenHash, familyId, expiresAt, userAgent, ip) {
    const result = await pool.query(
      `INSERT INTO refresh_tokens (user_id, token_hash, family_id, expires_at, user_agent, ip)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *`,
      [userId, tokenHash, familyId, expiresAt, userAgent, ip],
    );
    return result.rows[0] || null;
  }

  async function findRefreshToken(tokenHash) {
    const result = await pool.quer(`
        SELECT * FROM refresh_tokens WHERE token_hash = $1`)[tokenHash];
    return result.rows[0] || null;
  }

  async function rotateRefreshToken({ tokenHash, replacedById }) {
    const fetch = await pool.query(
      `
        SELECT * FROM refresh_tokens WHERE token_hash = $1
        `,
      [tokenHash],
    );
    const token = fetch.rows[0] || null;
    if (!token) return { status: 'NOT_FOUND', token: null };
    if (token.revoked_at) return { status: 'ALREADY_REVOKED', token };

    const result = await pool.query(
      `
        UPDATE refresh_tokens SET revoked_at = now(), replaced_by_id = $1 WHERE token_hash = $2 AND revoked_at IS NULL RETURNING *`,
      [replacedById, tokenHash],
    );
    return { status: 'SUCCESS', token: result.rows[0] };
  }

  async function revokeRefreshToken(tokenHash){
    const result  = await pool.query(
        `UPDATE refresh_tokens SET revoked_at = now() WHERE token_hash = $1 and revoked_at IS NULL RETURNING *`,[tokenHash]
    );
    return result.rows[0] || null
  }

  async function revokeRefreshTokenFamily(familyId){
    const result = await pool.query(
        `UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = $1 and revoked_at IS NULL RETURNING *
        `,[familyId]
    );
    return result.rows[0] || null
  }

  async function revokeAllRefreshTokensForUser(userId) {
    const result = await pool.query(
        `UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 and revoked_at IS NULL RETURNING *
        `,[userId]
    );
    return result.rows[0] || null
  }
  async function listActiveSessions(userId) {
    const result = await pool.query(
      `SELECT id, user_agent, ip, issued_at, expires_at 
       FROM refresh_tokens 
       WHERE user_id = $1 
         AND revoked_at IS NULL 
         AND expires_at > now()
       ORDER BY issued_at DESC`,
      [userId]
    );
    return result.rows;
  }


  return {
    createUser,
    getUserByEmail,
    getUserById,
    getCredentialByEmail,
    getMfaSecret,
    softDeleteUser,
    updateUser,
    saveRefreshToken,
    findRefreshToken,
    rotateRefreshToken,
    revokeRefreshToken,
    revokeRefreshTokenFamily,
    revokeAllRefreshTokensForUser,
    listActiveSessions
  };
}

module.exports = { createPostgresStorage };

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

  return {
    createUser,
    getUserByEmail,
    getUserById,
    getCredentialByEmail,
    getMfaSecret,
    softDeleteUser,
    updateUser,
  };
}

module.exports = { createPostgresStorage };

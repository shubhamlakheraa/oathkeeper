function createPostgresStorage(pool) {
  async function createUser({ email, passwordHash }) {
    const result = await pool.query(
      `
            INSERT INTO users (email, password_hash)
            VALUES ($1, $2)
            RETURNING *
        `,
      [email.toLowerCase().trim(), passwordHash],
    );
    return sanitizeUser(result.rows[0]);
  }
  async function getUserByEmail(email) {
    const result = await pool.query(
      `
            SELECT * From users WHERE email = $1 AND deleted_at IS NULL
            `,
      [email.toLowerCase().trim()],
    );
    return result.rows[0] ? sanitizeUser(result.rows[0]) : null;
  }
  async function getUserById(id) {
    const result = await pool.query(`SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL`, [
      id,
    ]);
    return result.rows[0] ? sanitizeUser(result.rows[0]) : null;
  }
  async function softDeleteUser(id) {
    await pool.query(`UPDATE users SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL`, [
      id,
    ]);
  }
  const ALLOWED_PATCH_FIELDS = new Set([
    'email_verified',
    'mfa_enabled',
    'mfa_secret',
    'last_login_at',
  ]);

  async function updateUser(id, patches) {
    const fields = Object.keys(patches);
    fields.forEach((f) => {
      if (!ALLOWED_PATCH_FIELDS.has(f)) throw new Error(`Field not patchable: ${f}`);
    });

    const setClauses = fields.map((f, i) => `${f} = $${i + 2}`).join(', ');
    const values = fields.map((f) => patches[f]);

    const result = await pool.query(
      `UPDATE users SET ${setClauses}, updated_at = now() WHERE id = $1 AND deleted_at IS NULL RETURNING *`,
      [id, ...values],
    );
    return result.rows[0] ? sanitizeUser(result.rows[0]) : null;
  }

  return {
    createUser,
    getUserByEmail,
    getUserById,
    softDeleteUser,
    updateUser,
  };
}

module.exports = { createPostgresStorage };

function sanitizeUser(row) {
  const { password_hash, ...rest } = row;
  return rest;
}

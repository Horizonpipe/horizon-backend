'use strict';

function normalizeEmail(value) {
  return String(value || '')
    .trim()
    .toLowerCase();
}

function looksLikeEmail(s) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(s || '').trim());
}

function pickAccountSettings(user) {
  if (!user) return null;
  return {
    id: user.id,
    username: user.username,
    displayName: user.displayName,
    email: user.email || '',
    firstName: user.firstName || '',
    lastName: user.lastName || '',
    company: user.company || '',
    title: user.title || '',
    phone: user.phone || '',
    emailVerified: user.emailVerified !== false,
    mustChangePassword: user.mustChangePassword === true
  };
}

/**
 * @param {import('express').Express} app
 * @param {{
 *   pool: import('pg').Pool,
 *   requireAuth: import('express').RequestHandler,
 *   cleanString: (v: unknown) => string,
 *   readFreshUserFromPostgresById: (userId: string) => Promise<object | null>,
 *   tryWasabiStateWrite: (label: string, fn: (data: object) => void | Promise<void>) => Promise<boolean>,
 *   ensureSnapshotTable: (data: object, tableName: string) => unknown[],
 *   nowIso: () => string
 * }} deps
 */
function registerAccountRoutes(app, deps) {
  const { pool, requireAuth, cleanString, readFreshUserFromPostgresById, tryWasabiStateWrite, ensureSnapshotTable, nowIso } =
    deps;

  app.get('/account/settings', requireAuth, async (req, res) => {
    try {
      const fresh = await readFreshUserFromPostgresById(String(req.user?.id || ''));
      if (!fresh) {
        return res.status(404).json({ success: false, error: 'User not found' });
      }
      res.json({ success: true, settings: pickAccountSettings(fresh), user: fresh });
    } catch (error) {
      console.error('[account/settings GET]', error);
      res.status(500).json({ success: false, error: error.message || 'Server error' });
    }
  });

  app.put('/account/settings', requireAuth, async (req, res) => {
    const userId = String(req.user?.id || '').trim();
    if (!userId) {
      return res.status(400).json({ success: false, error: 'Missing user id' });
    }

    const emailRaw = req.body?.email;
    const hasEmail = Object.prototype.hasOwnProperty.call(req.body || {}, 'email');
    const email = hasEmail ? normalizeEmail(emailRaw) : null;
    const firstName = Object.prototype.hasOwnProperty.call(req.body || {}, 'firstName')
      ? cleanString(req.body?.firstName)
      : undefined;
    const lastName = Object.prototype.hasOwnProperty.call(req.body || {}, 'lastName')
      ? cleanString(req.body?.lastName)
      : undefined;
    const company = Object.prototype.hasOwnProperty.call(req.body || {}, 'company')
      ? cleanString(req.body?.company)
      : undefined;
    const title = Object.prototype.hasOwnProperty.call(req.body || {}, 'title')
      ? cleanString(req.body?.title)
      : undefined;
    const phone = Object.prototype.hasOwnProperty.call(req.body || {}, 'phone')
      ? cleanString(req.body?.phone)
      : undefined;

    if (hasEmail && email && !looksLikeEmail(email)) {
      return res.status(400).json({ success: false, error: 'Enter a valid email address' });
    }

    try {
      const currentResult = await pool.query(
        `SELECT id, username, display_name, email, first_name, last_name, company, title, phone, email_verified
         FROM users
         WHERE CAST(id AS text) = $1
         LIMIT 1`,
        [userId]
      );
      if (!currentResult.rows.length) {
        return res.status(404).json({ success: false, error: 'User not found' });
      }
      const current = currentResult.rows[0];

      if (hasEmail && email) {
        const dup = await pool.query(
          `SELECT id FROM users
           WHERE CAST(id AS text) <> $1
             AND email IS NOT NULL
             AND BTRIM(email) <> ''
             AND LOWER(TRIM(email)) = $2
           LIMIT 1`,
          [userId, email]
        );
        if (dup.rows.length) {
          return res.status(409).json({ success: false, error: 'That email is already linked to another account' });
        }
      }

      const nextFirst = firstName !== undefined ? firstName : cleanString(current.first_name);
      const nextLast = lastName !== undefined ? lastName : cleanString(current.last_name);
      const nextCompany = company !== undefined ? company : cleanString(current.company);
      const nextTitle = title !== undefined ? title : cleanString(current.title);
      const nextPhone = phone !== undefined ? phone : cleanString(current.phone);
      const nextEmail = hasEmail ? email || null : current.email || null;
      const emailChanged =
        hasEmail && String(nextEmail || '').toLowerCase() !== String(current.email || '').toLowerCase();
      const nextDisplayName =
        `${nextFirst} ${nextLast}`.trim() ||
        cleanString(current.display_name) ||
        cleanString(current.username);

      const wasabiWrote = await tryWasabiStateWrite('update-account-settings', async (data) => {
        const users = ensureSnapshotTable(data, 'users');
        const idx = users.findIndex((u) => String(u.id || '') === userId);
        if (idx < 0) return;
        users[idx] = {
          ...users[idx],
          email: nextEmail,
          first_name: nextFirst || null,
          last_name: nextLast || null,
          company: nextCompany || null,
          title: nextTitle || null,
          phone: nextPhone || null,
          display_name: nextDisplayName,
          email_verified: emailChanged ? true : users[idx].email_verified !== false,
          updated_at: nowIso()
        };
      });

      if (!wasabiWrote) {
        await pool.query(
          `UPDATE users
           SET email = $2,
               first_name = $3,
               last_name = $4,
               company = $5,
               title = $6,
               phone = $7,
               display_name = $8,
               email_verified = CASE WHEN $9 THEN true ELSE email_verified END,
               updated_at = NOW()
           WHERE CAST(id AS text) = $1`,
          [
            userId,
            nextEmail,
            nextFirst || null,
            nextLast || null,
            nextCompany || null,
            nextTitle || null,
            nextPhone || null,
            nextDisplayName,
            emailChanged
          ]
        );
      }

      const fresh = await readFreshUserFromPostgresById(userId);
      if (!fresh) {
        return res.status(404).json({ success: false, error: 'User not found after update' });
      }
      res.json({ success: true, settings: pickAccountSettings(fresh), user: fresh });
    } catch (error) {
      console.error('[account/settings PUT]', error);
      if (error.code === '23505') {
        return res.status(409).json({ success: false, error: 'That email is already linked to another account' });
      }
      res.status(500).json({ success: false, error: error.message || 'Server error' });
    }
  });
}

module.exports = { registerAccountRoutes };

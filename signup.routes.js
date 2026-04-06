'use strict';

const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const SIGNUP_PIN_TTL_MIN = Number(process.env.SIGNUP_PIN_TTL_MIN || 30);
const RESEND_COOLDOWN_SEC = Math.max(30, Number(process.env.SIGNUP_RESEND_COOLDOWN_SEC || 60));
const PASSWORD_MIN_LEN = Math.max(6, Number(process.env.SIGNUP_PASSWORD_MIN || 8));

function normalizeEmail(value) {
  return String(value || '')
    .trim()
    .toLowerCase();
}

function looksLikeEmail(s) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(s || '').trim());
}

/**
 * Build a Nodemailer transport. Use either:
 * - `SMTP_URL` — single string, e.g. `smtps://user:pass@smtp.host:465` (encode special chars in password)
 * - or `SMTP_HOST` (+ optional `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS`)
 */
function getMailer() {
  const url = (process.env.SMTP_URL || '').trim();
  if (url) {
    return nodemailer.createTransport(url);
  }
  const host = (process.env.SMTP_HOST || '').trim();
  if (!host) return null;
  const port = Number(process.env.SMTP_PORT || 587);
  const secure =
    String(process.env.SMTP_SECURE || '').toLowerCase() === 'true' || port === 465;
  const rejectUnauthorized =
    String(process.env.SMTP_TLS_REJECT_UNAUTHORIZED || 'true').toLowerCase() !== 'false';
  return nodemailer.createTransport({
    host,
    port,
    secure,
    requireTLS: !secure && port === 587,
    auth:
      process.env.SMTP_USER && process.env.SMTP_PASS
        ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
        : undefined,
    tls: { rejectUnauthorized }
  });
}

/**
 * @returns {Promise<{ ok: true } | { ok: false, reason: 'not_configured' | 'send_failed', message?: string }>}
 */
async function sendPinEmail(to, pin) {
  const from = (process.env.SMTP_FROM || process.env.SMTP_USER || 'Horizon Pipe').trim();
  const transporter = getMailer();
  const subject = 'Your Horizon Pipe verification code';
  const text = `Your verification code is: ${pin}\n\nEnter this code on the sign-up screen to finish creating your account. This code expires in ${SIGNUP_PIN_TTL_MIN} minutes.\n\nIf you did not request this, you can ignore this email.`;
  if (!transporter) {
    console.warn('[signup] SMTP is not configured (set SMTP_URL or SMTP_HOST).');
    return { ok: false, reason: 'not_configured' };
  }
  try {
    await transporter.sendMail({ from, to, subject, text });
    return { ok: true };
  } catch (err) {
    const message = err && typeof err.message === 'string' ? err.message : String(err);
    console.error('[signup] SMTP send failed:', message);
    return { ok: false, reason: 'send_failed', message };
  }
}

/**
 * @param {import('express').Express} app
 * @param {{ pool: import('pg').Pool, cleanString: (v: unknown) => string, normalizeRoles: (v: unknown) => object, normalizeUser: (row: object) => object }} deps
 */
function registerSignupRoutes(app, deps) {
  const { pool, cleanString, normalizeRoles, normalizeUser } = deps;

  app.post('/signup/request', async (req, res) => {
    const firstName = cleanString(req.body?.firstName);
    const lastName = cleanString(req.body?.lastName);
    const company = cleanString(req.body?.company);
    const title = cleanString(req.body?.title);
    const phone = cleanString(req.body?.phone);
    const email = normalizeEmail(req.body?.email);
    const password = cleanString(req.body?.password);

    if (!firstName || !lastName) {
      return res.status(400).json({ success: false, error: 'First and last name are required' });
    }
    if (!company) {
      return res.status(400).json({ success: false, error: 'Company is required' });
    }
    if (!email || !looksLikeEmail(email)) {
      return res.status(400).json({ success: false, error: 'A valid email address is required' });
    }
    if (password.length < PASSWORD_MIN_LEN) {
      return res.status(400).json({
        success: false,
        error: `Password must be at least ${PASSWORD_MIN_LEN} characters`
      });
    }

    try {
      const dup = await pool.query(
        `SELECT id FROM users
         WHERE LOWER(TRIM(username)) = $1
            OR (email IS NOT NULL AND BTRIM(email) <> '' AND LOWER(TRIM(email)) = $1)
         LIMIT 1`,
        [email]
      );
      if (dup.rows.length) {
        return res.status(409).json({ success: false, error: 'An account with this email already exists' });
      }

      const existing = await pool.query(
        `SELECT created_at FROM signup_verifications WHERE email_normalized = $1 LIMIT 1`,
        [email]
      );
      if (existing.rows.length) {
        const created = new Date(existing.rows[0].created_at).getTime();
        if (Date.now() - created < RESEND_COOLDOWN_SEC * 1000) {
          return res.status(429).json({
            success: false,
            error: `Please wait ${RESEND_COOLDOWN_SEC} seconds before requesting another code`
          });
        }
      }

      const pin = String(crypto.randomInt(100000, 1000000));
      const pinHash = await bcrypt.hash(pin, 10);
      const passwordHash = await bcrypt.hash(password, 10);

      await pool.query(`DELETE FROM signup_verifications WHERE email_normalized = $1`, [email]);
      await pool.query(
        `INSERT INTO signup_verifications (
           email_normalized, pin_hash, password_hash, first_name, last_name, company, title, phone, expires_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW() + ($9::int * INTERVAL '1 minute'))`,
        [
          email,
          pinHash,
          passwordHash,
          firstName,
          lastName,
          company,
          title || null,
          phone || null,
          SIGNUP_PIN_TTL_MIN
        ]
      );

      const sendResult = await sendPinEmail(email, pin);
      const devPin =
        String(process.env.SIGNUP_DEV_RETURN_PIN || '').trim() === '1' ? pin : undefined;

      if (!sendResult.ok && !devPin) {
        await pool.query(`DELETE FROM signup_verifications WHERE email_normalized = $1`, [email]);
        if (sendResult.reason === 'not_configured') {
          return res.status(503).json({
            success: false,
            error:
              'Email could not be sent: SMTP is not configured. On the backend host, set SMTP_URL or SMTP_HOST (and usually SMTP_USER, SMTP_PASS, SMTP_FROM). See deployment docs for your mail provider.'
          });
        }
        return res.status(503).json({
          success: false,
          error: `Email could not be sent: ${sendResult.message || 'SMTP error'}. Check SMTP credentials and SMTP_FROM.`
        });
      }

      res.json({
        success: true,
        message: sendResult.ok
          ? 'Check your email for a verification code.'
          : 'Verification code generated (dev only — configure SMTP for production).',
        ...(devPin ? { devPin } : {})
      });
    } catch (error) {
      console.error('SIGNUP REQUEST ERROR:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  });

  app.post('/signup/verify', async (req, res) => {
    const email = normalizeEmail(req.body?.email);
    const pin = cleanString(req.body?.pin).replace(/\D/g, '');

    if (!email || !looksLikeEmail(email)) {
      return res.status(400).json({ success: false, error: 'Valid email is required' });
    }
    if (pin.length !== 6) {
      return res.status(400).json({ success: false, error: 'Enter the 6-digit code from your email' });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const v = await client.query(
        `SELECT * FROM signup_verifications WHERE email_normalized = $1 LIMIT 1 FOR UPDATE`,
        [email]
      );
      if (!v.rows.length) {
        await client.query('ROLLBACK');
        return res.status(400).json({ success: false, error: 'No pending sign-up for this email. Start again.' });
      }
      const row = v.rows[0];
      if (new Date(row.expires_at).getTime() < Date.now()) {
        await client.query(`DELETE FROM signup_verifications WHERE email_normalized = $1`, [email]);
        await client.query('COMMIT');
        return res.status(400).json({ success: false, error: 'That code has expired. Request a new one.' });
      }

      const pinOk = await bcrypt.compare(pin, row.pin_hash);
      if (!pinOk) {
        await client.query('ROLLBACK');
        return res.status(400).json({ success: false, error: 'Invalid verification code' });
      }

      const displayName = `${row.first_name} ${row.last_name}`.trim() || email;
      /** New self-signup accounts start with no planner/report/email/file privileges until admin assigns access. */
      const roles = normalizeRoles({
        camera: false,
        vac: false,
        simpleVac: false,
        email: false,
        psrPlanner: false,
        pricingView: false,
        footageView: false
      });

      let inserted;
      try {
        inserted = await client.query(
          `INSERT INTO users (
             username, display_name, password, is_admin, roles, must_change_password,
             portal_files_client_id, portal_files_job_id, portal_files_access_granted, self_signup,
             email, first_name, last_name, company, title, phone, email_verified
           )
           VALUES ($1, $2, $3, false, $4::jsonb, false, NULL, NULL, false, true, $5, $6, $7, $8, $9, $10, true)
           RETURNING id, username, display_name, is_admin, roles, must_change_password,
                     portal_files_client_id, portal_files_job_id, portal_files_access_granted, self_signup,
                     email, first_name, last_name, company, title, phone, email_verified`,
          [
            email,
            displayName,
            row.password_hash,
            JSON.stringify(roles),
            email,
            row.first_name,
            row.last_name,
            row.company,
            row.title,
            row.phone
          ]
        );
      } catch (e) {
        await client.query('ROLLBACK');
        if (e.code === '23505') {
          return res.status(409).json({ success: false, error: 'An account with this email already exists' });
        }
        throw e;
      }

      await client.query(`DELETE FROM signup_verifications WHERE email_normalized = $1`, [email]);
      await client.query('COMMIT');

      const userRow = inserted.rows[0];
      const user = normalizeUser(userRow);
      res.json({
        success: true,
        user,
        requiresApproval: true,
        message: 'Account created. An administrator must grant access before you can sign in.'
      });
    } catch (error) {
      try {
        await client.query('ROLLBACK');
      } catch {
        /* ignore */
      }
      console.error('SIGNUP VERIFY ERROR:', error);
      res.status(500).json({ success: false, error: error.message });
    } finally {
      client.release();
    }
  });
}

module.exports = { registerSignupRoutes };

'use strict';

const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { isSaasSignupRequest } = require('./lib/saas-signup-context');
const { upsertTenantDraft } = require('./tenant-provisioning.service');
const { applySaasTenantOwnerPrivileges } = require('./lib/saas-tenant-owner');

const SIGNUP_PIN_TTL_MIN = Number(process.env.SIGNUP_PIN_TTL_MIN || 30);
const RESEND_COOLDOWN_SEC = Math.max(30, Number(process.env.SIGNUP_RESEND_COOLDOWN_SEC || 60));
const PASSWORD_MIN_LEN = Math.max(6, Number(process.env.SIGNUP_PASSWORD_MIN || 8));
const SIGNUP_MAIL_FROM_NAME = (process.env.SIGNUP_MAIL_FROM_NAME || process.env.SMTP_FROM_NAME || 'PipeShare').trim();

function publicSignupMailError(reason, detailMessage) {
  if (reason === 'not_configured') {
    return {
      code: 'smtp_not_configured',
      error:
        'We could not send a verification email right now. Account creation is temporarily unavailable — please try again later or contact support.'
    };
  }
  return {
    code: 'smtp_send_failed',
    error:
      'We could not send a verification email. Please confirm your email address and try again in a few minutes.'
  };
}

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
  const from = (process.env.SMTP_FROM || process.env.SMTP_USER || `${SIGNUP_MAIL_FROM_NAME} <EmailVerification@pipeshare.net>`).trim();
  const transporter = getMailer();
  const subject = `Your ${SIGNUP_MAIL_FROM_NAME} verification code`;
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

function approvalNotifyRecipients() {
  return (process.env.ACCOUNT_APPROVAL_NOTIFY_TO || process.env.SIGNUP_APPROVAL_NOTIFY_TO || '')
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean);
}

function hasAnyAssignedAccess(row, normalizeRoles) {
  if (row?.is_admin) return true;
  const roles = normalizeRoles(row?.roles);
  const hasRoleAccess = Object.values(roles).some((v) => v === true);
  const hasPortalFiles = row?.portal_files_access_granted === true;
  const hasPortalPermissions = row?.portal_permissions_access === true;
  return hasRoleAccess || hasPortalFiles || hasPortalPermissions;
}

/**
 * @returns {Promise<{ ok: true } | { ok: false, reason: 'not_configured' | 'send_failed', message?: string }>}
 */
async function sendApprovalRequestEmail(payload) {
  const transporter = getMailer();
  const to = approvalNotifyRecipients();
  if (!transporter || !to.length) {
    return { ok: false, reason: 'not_configured' };
  }
  const from = (process.env.SMTP_FROM || process.env.SMTP_USER || 'Horizon Pipe').trim();
  const subject = 'Horizon Pipe account approval request';
  const text = [
    'A user requested account approval.',
    '',
    `Identifier entered: ${payload.identifier || '(none)'}`,
    `Matched username: ${payload.username || '(not found)'}`,
    `Matched email: ${payload.email || '(not found)'}`,
    `Display name: ${payload.displayName || '(not found)'}`,
    `Requested at: ${new Date().toISOString()}`
  ].join('\n');
  try {
    await transporter.sendMail({ from, to, subject, text });
    return { ok: true };
  } catch (err) {
    const message = err && typeof err.message === 'string' ? err.message : String(err);
    console.error('[signup] approval request email failed:', message);
    return { ok: false, reason: 'send_failed', message };
  }
}

/**
 * @param {import('express').Express} app
 * @param {{ pool: import('pg').Pool, query?: (text: string, params?: unknown[]) => Promise<{rows: unknown[], rowCount?: number}>, createSignupUserWithWasabi?: (payload: {email: string, verificationRow: object, saasSignup?: boolean}) => Promise<{status: number, body: Record<string, unknown>} | null>, signupPrimaryStrict?: boolean, cleanString: (v: unknown) => string, normalizeRoles: (v: unknown) => object, normalizeUser: (row: object) => object, issueSession?: (userId: string|number, options?: {keepSession?: boolean}) => Promise<string>, attachScopesToUser?: (user: object) => Promise<object>, resolveCapabilities?: (user: object) => object }} deps
 */
function registerSignupRoutes(app, deps) {
  const {
    pool,
    query,
    createSignupUserWithWasabi,
    signupPrimaryStrict = false,
    cleanString,
    normalizeRoles,
    normalizeUser,
    issueSession,
    attachScopesToUser,
    resolveCapabilities
  } = deps;
  const dbQuery =
    typeof query === 'function'
      ? query
      : (pool && typeof pool.query === 'function' ? pool.query.bind(pool) : null);
  if (typeof dbQuery !== 'function') {
    throw new Error('registerSignupRoutes requires either pool.query or deps.query.');
  }

  const smtpConfigured = !!(process.env.SMTP_URL || '').trim() || !!(process.env.SMTP_HOST || '').trim();
  if (!smtpConfigured) {
    console.warn(
      '[signup] SMTP is not configured (set SMTP_URL or SMTP_HOST, and usually SMTP_FROM / credentials). /signup/request returns 503 until mail is configured.'
    );
  }

  app.post('/account/request-approval', async (req, res) => {
    const identifierRaw = cleanString(req.body?.emailOrUsername || req.body?.email || req.body?.username);
    const identifier = identifierRaw.toLowerCase();
    if (!identifier) {
      return res.status(400).json({ success: false, error: 'Email or username is required' });
    }

    try {
      const q = await dbQuery(
        `SELECT id, username, display_name, email, is_admin, roles, portal_files_access_granted, portal_permissions_access
           FROM users
          WHERE LOWER(TRIM(username)) = LOWER(TRIM($1))
             OR (email IS NOT NULL AND BTRIM(email) <> '' AND LOWER(TRIM(email)) = LOWER(TRIM($1)))
          LIMIT 1`,
        [identifier]
      );
      const row = q.rows[0] || null;

      // Avoid account enumeration: always return success-style response, even when account is missing.
      if (!row) {
        return res.json({
          success: true,
          message: 'If the account exists, your approval request has been sent to an administrator.'
        });
      }

      if (hasAnyAssignedAccess(row, normalizeRoles)) {
        return res.json({
          success: true,
          message: 'This account already has access. Try signing in again.'
        });
      }

      const sendResult = await sendApprovalRequestEmail({
        identifier,
        username: row.username,
        email: row.email,
        displayName: row.display_name
      });

      if (!sendResult.ok && sendResult.reason === 'send_failed') {
        return res.json({
          success: true,
          message:
            'Approval request captured, but admin notification email failed. Please contact your administrator directly.'
        });
      }

      if (!sendResult.ok && sendResult.reason === 'not_configured') {
        return res.json({
          success: true,
          message:
            'Approval request received. Admin email notifications are not configured yet, so please contact your administrator directly.'
        });
      }

      return res.json({
        success: true,
        message: 'Approval request sent. An administrator will review your account.'
      });
    } catch (error) {
      console.error('ACCOUNT APPROVAL REQUEST ERROR:', error);
      return res.status(500).json({ success: false, error: error.message });
    }
  });

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
      const dup = await dbQuery(
        `SELECT id FROM users
         WHERE LOWER(TRIM(username)) = $1
            OR (email IS NOT NULL AND BTRIM(email) <> '' AND LOWER(TRIM(email)) = $1)
         LIMIT 1`,
        [email]
      );
      if (dup.rows.length) {
        return res.status(409).json({ success: false, error: 'An account with this email already exists' });
      }

      /** Pending PINs stay in Postgres — Wasabi snapshot races lose short-lived verification rows. */
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
      const saasSignup = isSaasSignupRequest(req);
      const devPinAllowed =
        !saasSignup && String(process.env.SIGNUP_DEV_RETURN_PIN || '').trim() === '1';
      const devPin = devPinAllowed ? pin : undefined;

      if (!sendResult.ok && !devPin) {
        await pool.query(`DELETE FROM signup_verifications WHERE email_normalized = $1`, [email]);
        const pub = publicSignupMailError(sendResult.reason, sendResult.message);
        console.error('[signup] verification email failed:', sendResult.reason, sendResult.message || '');
        return res.status(503).json({ success: false, ...pub });
      }

      res.json({
        success: true,
        message: sendResult.ok
          ? 'Check your email for a verification code.'
          : saasSignup
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

    const saasSignup = isSaasSignupRequest(req);

    try {
      const v = await pool.query(
        `SELECT * FROM signup_verifications WHERE email_normalized = $1 LIMIT 1 FOR UPDATE`,
        [email]
      );
      if (!v.rows.length) {
        return res.status(400).json({ success: false, error: 'No pending sign-up for this email. Start again.' });
      }
      const row = v.rows[0];
      if (new Date(row.expires_at).getTime() < Date.now()) {
        await pool.query(`DELETE FROM signup_verifications WHERE email_normalized = $1`, [email]);
        return res.status(400).json({ success: false, error: 'That code has expired. Request a new one.' });
      }

      const pinOk = await bcrypt.compare(pin, row.pin_hash);
      if (!pinOk) {
        return res.status(400).json({ success: false, error: 'Invalid verification code' });
      }

      if (typeof createSignupUserWithWasabi === 'function') {
        try {
          const wasabiResult = await createSignupUserWithWasabi({
            email,
            verificationRow: row,
            saasSignup
          });
          if (wasabiResult && typeof wasabiResult === 'object') {
            await pool.query(`DELETE FROM signup_verifications WHERE email_normalized = $1`, [email]);
            return res.status(Number(wasabiResult.status || 200)).json(wasabiResult.body || {});
          }
          if (signupPrimaryStrict) {
            return res.status(500).json({
              success: false,
              error: 'Account could not be completed. Please try again or contact support.'
            });
          }
        } catch (error) {
          console.error('SIGNUP VERIFY WASABI PATH ERROR:', error);
          if (signupPrimaryStrict) {
            return res.status(500).json({ success: false, error: error.message });
          }
        }
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
        inserted = await dbQuery(
          `INSERT INTO users (
             username, display_name, password, is_admin, account_type, employee_role, roles, must_change_password,
             portal_files_client_id, portal_files_job_id, portal_files_access_granted, self_signup,
             email, first_name, last_name, company, title, phone, email_verified
           )
           VALUES ($1, $2, $3, false, 'customer', NULL, $4::jsonb, false, NULL, NULL, false, true, $5, $6, $7, $8, $9, $10, true)
           RETURNING id, username, display_name, is_admin, account_type, employee_role, roles, must_change_password,
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
        if (e.code === '23505') {
          return res.status(409).json({ success: false, error: 'An account with this email already exists' });
        }
        throw e;
      }

      const userRow = inserted.rows[0];

      /** pipeshare.net business sign-up → cPanel immediately; client portal sign-up waits for admin. */
      if (saasSignup) {
        if (typeof issueSession !== 'function' || typeof attachScopesToUser !== 'function') {
          console.error('[signup] SaaS verify missing issueSession/attachScopesToUser');
          await dbQuery(`DELETE FROM users WHERE CAST(id AS text) = $1`, [String(userRow.id)]);
          return res.status(500).json({
            success: false,
            error: 'Account could not be completed. Please try again or contact support.'
          });
        }
        const companyName = cleanString(row.company);
        if (!companyName) {
          await dbQuery(`DELETE FROM users WHERE CAST(id AS text) = $1`, [String(userRow.id)]);
          return res.status(400).json({ success: false, error: 'Company is required' });
        }
        try {
          await upsertTenantDraft(pool, userRow.id, {
            businessName: companyName,
            branding: { businessName: companyName }
          });
          await applySaasTenantOwnerPrivileges(pool, userRow.id);
        } catch (tenantError) {
          console.error('[signup] SaaS tenant draft failed:', tenantError);
          await dbQuery(`DELETE FROM users WHERE CAST(id AS text) = $1`, [String(userRow.id)]);
          return res.status(500).json({
            success: false,
            error: 'Could not set up your workspace. Please try again or contact support.'
          });
        }
        await pool.query(`DELETE FROM signup_verifications WHERE email_normalized = $1`, [email]);
        const refreshed = await dbQuery(
          `SELECT id, username, display_name, is_admin, account_type, employee_role, roles, must_change_password,
                  portal_files_client_id, portal_files_job_id, portal_files_access_granted, self_signup,
                  email, first_name, last_name, company, title, phone, email_verified
           FROM users WHERE CAST(id AS text) = $1 LIMIT 1`,
          [String(userRow.id)]
        );
        const user = await attachScopesToUser(
          normalizeUser(refreshed.rows[0] || userRow, { saasTenantOwner: true })
        );
        const token = await issueSession(userRow.id, { keepSession: false });
        return res.json({
          success: true,
          user,
          token,
          capabilities:
            typeof resolveCapabilities === 'function' ? resolveCapabilities(user) : undefined,
          message: 'Account created. Taking you to your control panel.'
        });
      }

      await pool.query(`DELETE FROM signup_verifications WHERE email_normalized = $1`, [email]);

      const user = normalizeUser(userRow);
      res.json({
        success: true,
        user,
        requiresApproval: true,
        message: 'Account created. An administrator must grant access before you can sign in.'
      });
    } catch (error) {
      console.error('SIGNUP VERIFY ERROR:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  });
}

module.exports = { registerSignupRoutes };

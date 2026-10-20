'use strict';

const nodemailer = require('nodemailer');
const {
  tenantKey,
  loadBundle,
  applyAction,
  readMedia,
  pipeScopesForUser,
  processDue
} = require('./lib/job-schedule-store');

function mailer() {
  const url = String(process.env.SMTP_URL || '').trim();
  if (url) return nodemailer.createTransport(url);
  const host = String(process.env.SMTP_HOST || '').trim();
  if (!host) return null;
  const port = Number(process.env.SMTP_PORT || 587);
  const secure = String(process.env.SMTP_SECURE || '').toLowerCase() === 'true' || port === 465;
  return nodemailer.createTransport({
    host,
    port,
    secure,
    auth:
      process.env.SMTP_USER && process.env.SMTP_PASS
        ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
        : undefined
  });
}

function mailApi() {
  const transporter = mailer();
  return {
    configured: !!transporter,
    async send({ to, subject, text }) {
      if (!transporter) {
        return { ok: false, message: 'Email is not configured on the server (SMTP_URL or SMTP_HOST).' };
      }
      const from = String(process.env.SMTP_FROM || process.env.SMTP_USER || 'Horizon Pipe').trim();
      try {
        await transporter.sendMail({ from, to, subject, text });
        return { ok: true };
      } catch (err) {
        return { ok: false, message: err instanceof Error ? err.message : 'Email send failed.' };
      }
    }
  };
}

/**
 * Job schedule, crews, contact book, and daily-report bodies.
 * Texts are stored. They are emailed when SMTP and an address exist.
 * There is no SMS provider in this repo, so phone-only notices stay queued then held.
 */
function registerJobScheduleRoutes(app, { pool, requireAuth }) {
  const mail = mailApi();
  const timer = setInterval(() => {
    processDue(pool, mail).catch((err) => {
      console.warn('[job-schedule] notify', err?.message || err);
    });
  }, 60_000);
  if (typeof timer.unref === 'function') timer.unref();

  app.get('/api/job-schedule/bootstrap', requireAuth, async (req, res) => {
    try {
      const bundle = await loadBundle(pool, req.user, tenantKey(req.user, req), mail);
      return res.json(bundle);
    } catch (err) {
      console.error('[job-schedule] bootstrap', err);
      return res.status(500).json({ error: 'Could not load the schedule.' });
    }
  });

  app.get('/api/job-schedule/pipe-scopes', requireAuth, (req, res) => {
    return res.json({ success: true, scopes: pipeScopesForUser(req.user) });
  });

  app.get('/api/job-schedule/media/:id', requireAuth, async (req, res) => {
    try {
      const media = await readMedia(pool, req.user, tenantKey(req.user, req), req.params.id);
      if (!media) return res.status(404).json({ error: 'Photo not found.' });
      res.set('Content-Type', media.mime || 'application/octet-stream');
      res.set('Cache-Control', 'private, max-age=300');
      return res.send(media.bytes);
    } catch (err) {
      console.error('[job-schedule] media', err);
      return res.status(500).json({ error: 'Could not load that photo.' });
    }
  });

  app.post('/api/job-schedule/action', requireAuth, async (req, res) => {
    try {
      const bundle = await applyAction(pool, req.user, tenantKey(req.user, req), req.body || {}, mail);
      return res.json(bundle);
    } catch (err) {
      const status = Number(err?.status) || 500;
      if (status >= 500) console.error('[job-schedule] action', err);
      return res.status(status).json({ error: err?.message || 'Could not save that change.' });
    }
  });
}

module.exports = { registerJobScheduleRoutes };

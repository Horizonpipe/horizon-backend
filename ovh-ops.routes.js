'use strict';

const express = require('express');
const {
  isOvhOpsEnabled,
  getOverview,
  getMetricsHistory,
  queryMetricsHistory,
  getMetricsMeta,
  listMetricsDates,
  readEvents,
  appendEvent,
  tailFile,
  resolveLogPath,
  deployFromGitHub,
  rollbackRepos,
  rollbackPlatformRelease,
  verifyGithubSignature,
  shouldDeployGithubPush,
  getActiveJob
} = require('./ovh-ops.service');

/** GitHub webhook — must register before express.json (raw body for HMAC). */
function registerOvhOpsWebhook(app) {
  app.post(
    '/ops/webhook/github',
    express.raw({ type: 'application/json', limit: '512kb' }),
    async (req, res) => {
      if (!isOvhOpsEnabled()) {
        return res.status(503).json({ ok: false, error: 'ops disabled' });
      }
      const secret = process.env.GITHUB_WEBHOOK_SECRET || '';
      if (!secret) {
        return res.status(503).json({ ok: false, error: 'GITHUB_WEBHOOK_SECRET not configured' });
      }
      const raw = req.body instanceof Buffer ? req.body : Buffer.from('');
      if (!verifyGithubSignature(raw, req.headers['x-hub-signature-256'], secret)) {
        appendEvent('webhook.rejected', 'GitHub webhook signature mismatch');
        return res.status(401).json({ ok: false, error: 'invalid signature' });
      }
      let payload;
      try {
        payload = JSON.parse(raw.toString('utf8'));
      } catch {
        return res.status(400).json({ ok: false, error: 'invalid json' });
      }
      const event = String(req.headers['x-github-event'] || '');
      if (event === 'ping') {
        appendEvent('webhook.ping', 'GitHub webhook ping received');
        return res.json({ ok: true, pong: true });
      }
      if (event !== 'push') {
        return res.json({ ok: true, ignored: true, event });
      }
      if (!shouldDeployGithubPush(payload)) {
        appendEvent('webhook.ignored', 'Push ignored (branch or repo filter)', {
          ref: payload?.ref,
          repo: payload?.repository?.full_name
        });
        return res.json({ ok: true, ignored: true });
      }
      if (getActiveJob()?.status === 'running') {
        appendEvent('webhook.skipped', 'Deploy skipped — job already running');
        return res.json({ ok: true, skipped: true, reason: 'busy' });
      }
      appendEvent('webhook.push', 'GitHub push accepted — starting deploy', {
        ref: payload?.ref,
        repo: payload?.repository?.full_name,
        pusher: payload?.pusher?.name
      });
      res.json({ ok: true, accepted: true });
      setImmediate(() => {
        deployFromGitHub(`github:${payload?.repository?.full_name || 'push'}`).catch((err) => {
          console.error('[ops/webhook/github] deploy failed:', err?.message || err);
        });
      });
    }
  );
}

/**
 * OVH server ops console API (Render-style metrics, logs, deploy, rollback).
 * @param {import('express').Express} app
 * @param {{ requireAuth: Function, requireAdmin: Function }} deps
 */
function registerOvhOpsRoutes(app, { requireAuth, requireAdmin }) {
  function gate(_req, res, next) {
    if (!isOvhOpsEnabled()) {
      return res.status(503).json({
        success: false,
        error: 'OVH ops console is only available on the production Linux host (set HP_OVH_OPS_ENABLED=1 to override).'
      });
    }
    return next();
  }

  function jsonError(res, status, message) {
    return res.status(status).json({ success: false, error: message });
  }

  app.get('/ops/status', requireAuth, requireAdmin, gate, async (_req, res) => {
    try {
      const overview = await getOverview();
      return res.json({ success: true, overview });
    } catch (err) {
      console.error('[ops/status]', err);
      return jsonError(res, 500, err.message || 'Server error');
    }
  });

  app.get('/ops/metrics/history', requireAuth, requireAdmin, gate, (req, res) => {
    const now = Date.now();
    const fromMs = req.query?.from != null ? Number(req.query.from) : now - 30 * 60 * 1000;
    const toMs = req.query?.to != null ? Number(req.query.to) : now;
    const maxPoints = Math.min(2000, Math.max(50, Number(req.query?.maxPoints) || 500));
    if (!Number.isFinite(fromMs) || !Number.isFinite(toMs) || fromMs >= toMs) {
      return jsonError(res, 400, 'Invalid from/to range');
    }
    const result = queryMetricsHistory({ fromMs, toMs, maxPoints });
    return res.json({
      success: true,
      fromMs,
      toMs,
      meta: getMetricsMeta(),
      ...result
    });
  });

  app.get('/ops/metrics/meta', requireAuth, requireAdmin, gate, (_req, res) => {
    return res.json({ success: true, meta: getMetricsMeta() });
  });

  app.get('/ops/metrics/dates', requireAuth, requireAdmin, gate, (req, res) => {
    const year = req.query?.year != null ? Number(req.query.year) : undefined;
    const month = req.query?.month != null ? Number(req.query.month) : undefined;
    return res.json({
      success: true,
      dates: listMetricsDates({ year, month })
    });
  });

  app.get('/ops/events', requireAuth, requireAdmin, gate, (req, res) => {
    const limit = Math.min(500, Math.max(1, Number(req.query?.limit) || 100));
    return res.json({ success: true, events: readEvents(limit) });
  });

  app.get('/ops/logs/:source', requireAuth, requireAdmin, gate, async (req, res) => {
    try {
      const filePath = await resolveLogPath(req.params.source);
      const lines = Math.min(2000, Math.max(20, Number(req.query?.lines) || 200));
      const result = tailFile(filePath, lines);
      return res.json({ success: true, ...result });
    } catch (err) {
      return jsonError(res, 500, err.message || 'Server error');
    }
  });

  app.get('/ops/deploy/active', requireAuth, requireAdmin, gate, (_req, res) => {
    return res.json({ success: true, job: getActiveJob() });
  });

  app.post('/ops/deploy', requireAuth, requireAdmin, gate, async (req, res) => {
    if (getActiveJob()?.status === 'running') {
      return jsonError(res, 409, 'A deploy or rollback is already running.');
    }
    try {
      const reason = String(req.body?.reason || 'manual').slice(0, 120);
      const result = await deployFromGitHub(reason);
      return res.json({ success: true, result });
    } catch (err) {
      console.error('[ops/deploy]', err);
      return jsonError(res, 500, err.message || 'Deploy failed');
    }
  });

  app.post('/ops/rollback', requireAuth, requireAdmin, gate, async (req, res) => {
    if (getActiveJob()?.status === 'running') {
      return jsonError(res, 409, 'A deploy or rollback is already running.');
    }
    const target = String(req.body?.target || 'both').toLowerCase();
    const ref = String(req.body?.ref || 'HEAD~1').trim();
    if (!['backend', 'frontend', 'both'].includes(target)) {
      return jsonError(res, 400, 'target must be backend, frontend, or both');
    }
    if (!ref || ref.length > 64) {
      return jsonError(res, 400, 'Invalid git ref');
    }
    try {
      const result = await rollbackRepos(target, ref);
      return res.json({ success: true, result });
    } catch (err) {
      console.error('[ops/rollback]', err);
      return jsonError(res, 500, err.message || 'Rollback failed');
    }
  });

  app.post('/ops/rollback/release', requireAuth, requireAdmin, gate, async (req, res) => {
    if (getActiveJob()?.status === 'running') {
      return jsonError(res, 409, 'A deploy or rollback is already running.');
    }
    const target = String(req.body?.target || '').toLowerCase();
    const version = String(req.body?.version || '').trim();
    if (!['backend', 'frontend'].includes(target)) {
      return jsonError(res, 400, 'target must be backend or frontend');
    }
    if (!/^\d+\.\d+\.\d+$/.test(version)) {
      return jsonError(res, 400, 'Invalid version (use semver like 0.0.1)');
    }
    try {
      const result = await rollbackPlatformRelease(target, version);
      return res.json({ success: true, result });
    } catch (err) {
      console.error('[ops/rollback/release]', err);
      return jsonError(res, 500, err.message || 'Platform rollback failed');
    }
  });

}

module.exports = { registerOvhOpsWebhook, registerOvhOpsRoutes };

'use strict';

const { tenantKey } = require('./lib/job-schedule-store');
const livingIndex = require('./lib/living-index');

/**
 * Thin index API. File bytes are not accepted and are not returned.
 * Customers use the same signed-in account. This does not add a second user system.
 */
function registerLivingIndexRoutes(app, { requireAuth }) {
  function scopeOf(req) {
    try {
      return tenantKey(req.user, req) || 'base';
    } catch {
      return 'base';
    }
  }

  app.get('/api/living-index/revision', requireAuth, async (req, res) => {
    try {
      const head = await livingIndex.head(scopeOf(req));
      return res.json({ ok: true, revision: head.revision });
    } catch (error) {
      console.error('[living-index] revision', error);
      return res.status(500).json({ ok: false, error: 'Could not read the index.' });
    }
  });

  app.get('/api/living-index/diff', requireAuth, async (req, res) => {
    try {
      const since = Math.max(0, Number(req.query.since || 0) || 0);
      const diff = await livingIndex.diffSince(scopeOf(req), since);
      return res.json({ ok: true, revision: diff.revision, since: diff.since, rows: diff.rows });
    } catch (error) {
      console.error('[living-index] diff', error);
      return res.status(500).json({ ok: false, error: 'Could not read the index diff.' });
    }
  });

  app.post('/api/living-index/ops', requireAuth, async (req, res) => {
    try {
      const ops = Array.isArray(req.body?.ops) ? req.body.ops : [];
      const result = await livingIndex.pushOps(scopeOf(req), ops);
      return res.json({ ok: true, revision: result.revision, applied: result.applied, skipped: result.skipped });
    } catch (error) {
      console.error('[living-index] ops', error);
      return res.status(500).json({ ok: false, error: 'Could not write the index.' });
    }
  });
}

module.exports = { registerLivingIndexRoutes };

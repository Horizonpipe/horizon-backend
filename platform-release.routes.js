'use strict';

const { resolveDeploymentProfile } = require('./lib/deployment-profile');
const {
  getPlatformReleaseStatus,
  listPlatformReleases,
  registerNonSaasHeartbeat,
  publishPlatformRelease,
  applyPlatformRelease,
  previewNextRelease
} = require('./platform-release.service');
const {
  isPlatformApplyPeerConfigured,
  pushPlatformReleaseToPeers,
  requirePlatformApplyPeerSecret,
  platformApplyLocalEnabled,
  defaultSaasPlatformRequestHost
} = require('./lib/platform-release-peers');

function requestHostFromReq(req) {
  return String(req?.headers?.['x-forwarded-host'] || req?.headers?.host || '').trim();
}

function isNonSaasRequest(req) {
  return resolveDeploymentProfile({ requestHost: requestHostFromReq(req) }).isPrivateBase;
}

function isSaasRequest(req) {
  return resolveDeploymentProfile({ requestHost: requestHostFromReq(req) }).isSaasPlatform;
}

function cleanString(v) {
  return String(v ?? '').trim();
}

/**
 * Platform release catalog — separates non-SaaS (private) deploys from SaaS tenant platform updates.
 * @param {import('express').Express} app
 * @param {{
 *   pool: import('pg').Pool,
 *   requireAuth: import('express').RequestHandler,
 *   requireAdmin: import('express').RequestHandler,
 *   wasabiClient: import('@aws-sdk/client-s3').S3Client | null,
 *   wasabiBucket: string
 * }} deps
 */
function registerPlatformReleaseRoutes(app, { pool, requireAuth, requireAdmin, wasabiClient, wasabiBucket }) {
  function jsonError(res, status, message) {
    return res.status(status).json({ success: false, error: message });
  }

  function wasabiReady(res) {
    if (wasabiClient && wasabiBucket) return true;
    jsonError(res, 503, 'Wasabi is not configured — platform releases require object storage');
    return false;
  }

  app.get('/saas/platform/releases/list', requireAuth, requireAdmin, async (req, res) => {
    try {
      if (!wasabiReady(res)) return;
      const catalog = await listPlatformReleases(wasabiClient, wasabiBucket);
      return res.json({ success: true, ...catalog });
    } catch (error) {
      console.error('[saas/platform/releases/list]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.get('/saas/platform/releases/status', requireAuth, requireAdmin, async (req, res) => {
    try {
      if (!wasabiReady(res)) return;
      const status = await getPlatformReleaseStatus(wasabiClient, wasabiBucket);
      const peersReady = isPlatformApplyPeerConfigured();
      return res.json({
        success: true,
        ...status,
        canPublish: isNonSaasRequest(req),
        canApply: isSaasRequest(req) || (isNonSaasRequest(req) && peersReady),
        canPushFromBase: isNonSaasRequest(req) && peersReady,
        deploymentProfile: resolveDeploymentProfile({ requestHost: requestHostFromReq(req) })
      });
    } catch (error) {
      console.error('[saas/platform/releases/status]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.get('/saas/platform/releases/preview', requireAuth, requireAdmin, async (req, res) => {
    try {
      if (!wasabiReady(res)) return;
      const preview = await previewNextRelease(wasabiClient, wasabiBucket, {
        title: cleanString(req.query?.title),
        description: cleanString(req.query?.description),
        forceDraft: req.query?.fromDraft === '1' || req.query?.forceDraft === '1'
      });
      return res.json({ success: true, preview });
    } catch (error) {
      console.error('[saas/platform/releases/preview]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.post('/saas/platform/releases/publish', requireAuth, requireAdmin, async (req, res) => {
    try {
      if (!wasabiReady(res)) return;
      if (!isNonSaasRequest(req)) {
        return jsonError(
          res,
          403,
          'Publish from your non-SaaS server only. SaaS tenants are updated via Apply in this panel.'
        );
      }
      const entry = await publishPlatformRelease(wasabiClient, wasabiBucket, {
        version: cleanString(req.body?.version),
        title: cleanString(req.body?.title),
        description: cleanString(req.body?.description),
        changeLog: Array.isArray(req.body?.changeLog) ? req.body.changeLog : undefined,
        publishedBy: cleanString(req.user?.username || req.user?.displayName),
        gitSha: cleanString(req.body?.gitSha),
        gitBranch: cleanString(req.body?.gitBranch),
        artifactKeys: req.body?.artifactKeys
      });
      if (pool) {
        await pool.query(
          `INSERT INTO platform_release_events (version, event_type, actor_user_id, deployment_mode, notes)
           VALUES ($1, 'published', $2, 'non-saas', $3)`,
          [entry.version, cleanString(req.user?.id), cleanString(entry.title)]
        );
      }
      return res.json({ success: true, release: entry });
    } catch (error) {
      console.error('[saas/platform/releases/publish]', error);
      return jsonError(res, 400, error.message || 'Publish failed');
    }
  });

  app.post('/saas/platform/releases/heartbeat', requireAuth, requireAdmin, async (req, res) => {
    try {
      if (!wasabiReady(res)) return;
      const result = await registerNonSaasHeartbeat(wasabiClient, wasabiBucket, {
        version: cleanString(req.body?.version),
        actor: cleanString(req.user?.username || req.user?.displayName),
        gitSha: cleanString(req.body?.gitSha),
        notes: cleanString(req.body?.notes)
      });
      return res.json({ success: true, ...result });
    } catch (error) {
      console.error('[saas/platform/releases/heartbeat]', error);
      return jsonError(res, 400, error.message || 'Heartbeat failed');
    }
  });

  app.post('/saas/platform/releases/apply', requireAuth, requireAdmin, async (req, res) => {
    try {
      if (!wasabiReady(res)) return;
      const version = cleanString(req.body?.version);
      if (!version) return jsonError(res, 400, 'version is required');
      const actor = cleanString(req.user?.username || req.user?.displayName);

      if (isSaasRequest(req)) {
        const result = await applyPlatformRelease(
          wasabiClient,
          wasabiBucket,
          { version, actor, requestHost: requestHostFromReq(req) },
          { pool }
        );
        return res.json({ success: true, ...result });
      }

      if (isNonSaasRequest(req) && isPlatformApplyPeerConfigured()) {
        const peers = await pushPlatformReleaseToPeers(version, { actor });
        let local = null;
        if (platformApplyLocalEnabled()) {
          local = await applyPlatformRelease(
            wasabiClient,
            wasabiBucket,
            { version, actor, requestHost: defaultSaasPlatformRequestHost() },
            { pool }
          );
        }
        if (pool) {
          await pool.query(
            `INSERT INTO platform_release_events (version, event_type, actor_user_id, deployment_mode, notes)
             VALUES ($1, 'applied', $2, 'non-saas', $3)`,
            [version, cleanString(req.user?.id), `Pushed to SaaS peers from BASE (${peers.length})`]
          );
        }
        return res.json({ success: true, version, pushedFromBase: true, peers, local });
      }

      return jsonError(
        res,
        403,
        'Configure HP_PLATFORM_APPLY_PEER_URLS and HP_PLATFORM_APPLY_PEER_SECRET on BASE to push from pipeshare.live.'
      );
    } catch (error) {
      console.error('[saas/platform/releases/apply]', error);
      return jsonError(res, 400, error.message || 'Apply failed');
    }
  });

  /** Server-to-server apply invoked by BASE (pipeshare.live) when pushing to SaaS platform hosts. */
  app.post('/internal/platform/releases/apply', requirePlatformApplyPeerSecret, async (req, res) => {
    try {
      if (!wasabiReady(res)) return;
      const version = cleanString(req.body?.version);
      if (!version) return jsonError(res, 400, 'version is required');
      const actor = cleanString(req.body?.actor) || 'BASE peer push';
      const result = await applyPlatformRelease(
        wasabiClient,
        wasabiBucket,
        { version, actor, requestHost: defaultSaasPlatformRequestHost() },
        { pool }
      );
      return res.json({ success: true, ...result });
    } catch (error) {
      console.error('[internal/platform/releases/apply]', error);
      return jsonError(res, 400, error.message || 'Peer apply failed');
    }
  });

  console.log('[platform-release] /saas/platform/releases/* routes mounted');
}

module.exports = { registerPlatformReleaseRoutes };

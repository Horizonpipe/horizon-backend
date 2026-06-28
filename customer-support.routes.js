'use strict';

const crypto = require('crypto');
const { canAccessAdminPanel, looksLikeMike, ACCOUNT_TYPES } = require('./capabilities');
const { loadUserCompanyMembership } = require('./company-permissions.service');

/** Shared Postgres pool for non-SaaS (OVH) presence when user has no saas_tenant_instances row. */
const NON_SAAS_GLOBAL_TENANT_ID = '00000000-0000-0000-0000-000000000001';
const DEPLOYMENT_GROUP_LABELS = Object.freeze({
  'non-saas': 'NON SAAS MODEL',
  saas: 'SAAS MODEL'
});

const PRESENCE_TTL_MS = Math.max(
  15_000,
  Math.min(300_000, Number(process.env.CP_SUPPORT_PRESENCE_TTL_MS || 90_000))
);
const HEARTBEAT_MIN_WRITE_MS = Math.max(
  0,
  Math.min(60_000, Number(process.env.CP_SUPPORT_HEARTBEAT_MIN_WRITE_MS || 8_000))
);

/** @type {Map<string, Set<import('http').ServerResponse>>} */
const sseByTenant = new Map();
/** @type {Map<string, number>} */
const lastPresenceWriteMs = new Map();
/** @type {Map<string, { id: number, at: number, fromUserId: string, type: string, payload: unknown }[]>} */
const remoteSignalsBySession = new Map();
const REMOTE_SIGNAL_BUFFER_MAX = 120;

function cleanString(v) {
  return String(v ?? '').trim();
}

function jsonError(res, status, message) {
  return res.status(status).json({ success: false, error: message });
}

function requireSupportAdmin(req, res, next) {
  if (!canAccessAdminPanel(req.user)) {
    return jsonError(res, 403, 'Admin access required');
  }
  return next();
}

function pushRemoteSignal(sessionId, fromUserId, type, payload) {
  const key = String(sessionId || '');
  if (!key) return null;
  let list = remoteSignalsBySession.get(key);
  if (!list) {
    list = [];
    remoteSignalsBySession.set(key, list);
  }
  const entry = {
    id: (list[list.length - 1]?.id || 0) + 1,
    at: Date.now(),
    fromUserId: String(fromUserId || ''),
    type: String(type || ''),
    payload
  };
  list.push(entry);
  while (list.length > REMOTE_SIGNAL_BUFFER_MAX) list.shift();
  return entry;
}

function clearRemoteSignals(sessionId) {
  remoteSignalsBySession.delete(String(sessionId || ''));
}

function broadcastTenant(tenantId, eventName, payload) {
  const key = String(tenantId || '');
  const set = sseByTenant.get(key);
  if (!set || !set.size) return;
  const body = `event: ${eventName}\ndata: ${JSON.stringify(payload)}\n\n`;
  for (const res of set) {
    try {
      res.write(body);
    } catch {
      set.delete(res);
    }
  }
}

async function initCustomerSupportSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS cp_support_presence (
      tenant_id UUID NOT NULL,
      user_id UUID NOT NULL,
      tab_id TEXT NOT NULL,
      display_name TEXT NOT NULL DEFAULT '',
      account_type TEXT NOT NULL DEFAULT 'employee',
      role_key TEXT NOT NULL DEFAULT '',
      company_name TEXT NOT NULL DEFAULT '',
      direct_client_label TEXT NOT NULL DEFAULT '',
      customer_group_label TEXT NOT NULL DEFAULT '',
      support_requested BOOLEAN NOT NULL DEFAULT false,
      page_path TEXT NOT NULL DEFAULT '',
      last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (tenant_id, user_id, tab_id)
    )
  `);
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_cp_support_presence_tenant_seen ON cp_support_presence (tenant_id, last_seen_at DESC)`
  );
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_cp_support_presence_support ON cp_support_presence (tenant_id, support_requested, last_seen_at DESC)`
  );
  await pool.query(`
    ALTER TABLE cp_support_presence
      ADD COLUMN IF NOT EXISTS deployment_model TEXT NOT NULL DEFAULT 'saas'
  `);
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_cp_support_presence_deployment ON cp_support_presence (deployment_model, last_seen_at DESC)`
  );

  await pool.query(`
    CREATE TABLE IF NOT EXISTS cp_support_chat_sessions (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id UUID NOT NULL,
      customer_user_id UUID NOT NULL,
      admin_user_id UUID,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_cp_support_chat_tenant ON cp_support_chat_sessions (tenant_id, updated_at DESC)`
  );

  await pool.query(`
    CREATE TABLE IF NOT EXISTS cp_support_chat_messages (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      session_id UUID NOT NULL REFERENCES cp_support_chat_sessions(id) ON DELETE CASCADE,
      sender_user_id UUID NOT NULL,
      body TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_cp_support_chat_messages_session ON cp_support_chat_messages (session_id, created_at ASC)`
  );

  await pool.query(`
    CREATE TABLE IF NOT EXISTS cp_support_remote_sessions (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id UUID NOT NULL,
      customer_user_id UUID NOT NULL,
      admin_user_id UUID NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      persist_token TEXT NOT NULL UNIQUE,
      customer_tab_id TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      ended_at TIMESTAMPTZ
    )
  `);
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_cp_support_remote_active ON cp_support_remote_sessions (tenant_id, status, updated_at DESC)`
  );
}

async function resolveTenantForUser(pool, user) {
  const userId = cleanString(user?.id);
  if (!userId) return null;

  const membership = await loadUserCompanyMembership(pool, userId);
  if (membership?.companyId) {
    const r = await pool.query(
      `SELECT id, company_id, portal_client_id, portal_job_id
       FROM saas_tenant_instances
       WHERE company_id = $1
       LIMIT 1`,
      [String(membership.companyId)]
    );
    if (r.rows[0]) {
      return {
        tenantId: r.rows[0].id,
        companyId: r.rows[0].company_id,
        portalClientId: r.rows[0].portal_client_id || '',
        portalJobId: r.rows[0].portal_job_id || '',
        companyName: membership.companyName || '',
        membershipRoleKey: membership.roleKey || ''
      };
    }
  }

  const portalClientId = cleanString(user.portalFilesClientId ?? user.portal_files_client_id);
  if (portalClientId) {
    const r = await pool.query(
      `SELECT id, company_id, portal_client_id, portal_job_id
       FROM saas_tenant_instances
       WHERE portal_client_id = $1
       LIMIT 1`,
      [portalClientId]
    );
    if (r.rows[0]) {
      return {
        tenantId: r.rows[0].id,
        companyId: r.rows[0].company_id,
        portalClientId: r.rows[0].portal_client_id || '',
        portalJobId: r.rows[0].portal_job_id || '',
        companyName: membership?.companyName || '',
        membershipRoleKey: membership?.roleKey || ''
      };
    }
  }

  return null;
}

async function resolveSupportScope(pool, user) {
  const saasScope = await resolveTenantForUser(pool, user);
  if (saasScope?.tenantId) {
    return {
      ...saasScope,
      deploymentModel: 'saas'
    };
  }
  return {
    tenantId: NON_SAAS_GLOBAL_TENANT_ID,
    companyId: null,
    portalClientId: '',
    portalJobId: '',
    companyName: cleanString(user?.company) || 'Horizon Pipe',
    membershipRoleKey: '',
    deploymentModel: 'non-saas'
  };
}

function resolveTargetTenantId(req, bodyTenantId) {
  const requested = cleanString(bodyTenantId);
  if (requested && looksLikeMike(req.user)) return requested;
  return req.supportTenant.tenantId;
}

function derivePresenceLabels(user, tenantScope) {
  const accountType = cleanString(user?.accountType ?? user?.account_type).toLowerCase() || 'employee';
  const companyName = tenantScope?.companyName || cleanString(user?.company) || 'Direct client';
  const directClientLabel = companyName || tenantScope?.portalClientId || 'Tenant';
  const customerGroupLabel =
    accountType === ACCOUNT_TYPES.CUSTOMER ? directClientLabel : cleanString(user?.displayName) || 'Customer';
  return {
    accountType,
    companyName,
    directClientLabel,
    customerGroupLabel,
    roleKey: tenantScope?.membershipRoleKey || ''
  };
}

async function upsertPresence(pool, user, tenantScope, body) {
  const tenantId = tenantScope.tenantId;
  const userId = cleanString(user.id);
  const tabId = cleanString(body?.tabId) || 'default';
  const labels = derivePresenceLabels(user, tenantScope);
  const supportRequested = body?.supportRequested === true;
  const pagePath = cleanString(body?.pagePath).slice(0, 500);

  const writeKey = `${tenantId}:${userId}:${tabId}`;
  const now = Date.now();
  const last = lastPresenceWriteMs.get(writeKey) || 0;
  if (now - last < HEARTBEAT_MIN_WRITE_MS) {
    return { skipped: true };
  }
  lastPresenceWriteMs.set(writeKey, now);

  const displayName =
    cleanString(user.displayName) || cleanString(user.username) || cleanString(user.email) || 'User';

  const deploymentModel = tenantScope?.deploymentModel === 'non-saas' ? 'non-saas' : 'saas';

  await pool.query(
    `INSERT INTO cp_support_presence (
        tenant_id, user_id, tab_id, display_name, account_type, role_key,
        company_name, direct_client_label, customer_group_label,
        support_requested, page_path, deployment_model, last_seen_at
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW())
      ON CONFLICT (tenant_id, user_id, tab_id) DO UPDATE SET
        display_name = EXCLUDED.display_name,
        account_type = EXCLUDED.account_type,
        role_key = EXCLUDED.role_key,
        company_name = EXCLUDED.company_name,
        direct_client_label = EXCLUDED.direct_client_label,
        customer_group_label = EXCLUDED.customer_group_label,
        deployment_model = EXCLUDED.deployment_model,
        support_requested = CASE
          WHEN EXCLUDED.support_requested THEN true
          ELSE cp_support_presence.support_requested
        END,
        page_path = EXCLUDED.page_path,
        last_seen_at = NOW()`,
    [
      tenantId,
      userId,
      tabId,
      displayName,
      labels.accountType,
      labels.roleKey,
      labels.companyName,
      labels.directClientLabel,
      labels.customerGroupLabel,
      supportRequested,
      pagePath,
      deploymentModel
    ]
  );

  broadcastTenant(tenantId, 'presence', { tenantId, userId, tabId });
  return { skipped: false };
}

function presenceSelectSql(whereClause) {
  return `
    SELECT p.*,
      EXISTS (
        SELECT 1 FROM cp_support_remote_sessions r
        WHERE r.tenant_id = p.tenant_id
          AND r.customer_user_id = p.user_id
          AND r.status = 'active'
          AND r.ended_at IS NULL
      ) AS remote_connected
    FROM cp_support_presence p
    WHERE ${whereClause}`;
}

async function listPresenceRows(pool, tenantId, { supportOnly = false, deploymentModel } = {}) {
  const cutoff = new Date(Date.now() - PRESENCE_TTL_MS).toISOString();
  const params = [tenantId, cutoff];
  let sql = presenceSelectSql(`p.tenant_id = $1 AND p.last_seen_at >= $2`);
  if (deploymentModel) {
    params.push(deploymentModel);
    sql += ` AND p.deployment_model = $${params.length}`;
  }
  if (supportOnly) {
    sql += ` AND p.support_requested = true`;
  }
  sql += ` ORDER BY p.display_name ASC`;
  const r = await pool.query(sql, params);
  return r.rows;
}

async function listAllPresenceRows(pool, { supportOnly = false } = {}) {
  const cutoff = new Date(Date.now() - PRESENCE_TTL_MS).toISOString();
  const params = [cutoff];
  let sql = presenceSelectSql(`p.last_seen_at >= $1`);
  if (supportOnly) {
    sql += ` AND p.support_requested = true`;
  }
  sql += ` ORDER BY p.deployment_model ASC, p.display_name ASC`;
  const r = await pool.query(sql, params);
  return r.rows;
}

function groupPresenceRows(rows) {
  const directClients = [];
  /** @type {Map<string, { directClientLabel: string, customers: object[] }>} */
  const customerGroups = new Map();

  for (const row of rows) {
    const entry = {
      tenantId: row.tenant_id,
      userId: row.user_id,
      tabId: row.tab_id,
      displayName: row.display_name,
      accountType: row.account_type,
      roleKey: row.role_key,
      companyName: row.company_name,
      directClientLabel: row.direct_client_label,
      customerGroupLabel: row.customer_group_label,
      deploymentModel: row.deployment_model === 'non-saas' ? 'non-saas' : 'saas',
      supportRequested: row.support_requested === true,
      pagePath: row.page_path || '',
      lastSeenAt: row.last_seen_at,
      remoteConnected: row.remote_connected === true
    };
    if (row.account_type === ACCOUNT_TYPES.CUSTOMER) {
      const key = row.direct_client_label || row.company_name || 'Customers';
      if (!customerGroups.has(key)) {
        customerGroups.set(key, { directClientLabel: key, customers: [] });
      }
      customerGroups.get(key).customers.push(entry);
    } else {
      directClients.push(entry);
    }
  }

  return {
    directClients,
    customerGroups: [...customerGroups.values()]
  };
}

function buildDeploymentGroup(deploymentModel, rows) {
  const grouped = groupPresenceRows(rows);
  return {
    deploymentModel,
    label: DEPLOYMENT_GROUP_LABELS[deploymentModel] || deploymentModel,
    ...grouped
  };
}

function buildPresenceListResponse(req, rows, { supportOnly = false } = {}) {
  const filter = supportOnly ? 'support' : 'all';
  if (looksLikeMike(req.user)) {
    const nonSaasRows = rows.filter((row) => row.deployment_model === 'non-saas');
    const saasRows = rows.filter((row) => row.deployment_model !== 'non-saas');
    return {
      success: true,
      scope: 'global',
      filter,
      deploymentGroups: [
        buildDeploymentGroup('non-saas', nonSaasRows),
        buildDeploymentGroup('saas', saasRows)
      ]
    };
  }

  const deploymentModel = req.supportTenant.deploymentModel === 'non-saas' ? 'non-saas' : 'saas';
  const grouped = groupPresenceRows(rows);
  return {
    success: true,
    scope: 'tenant',
    filter,
    deploymentModel,
    label: DEPLOYMENT_GROUP_LABELS[deploymentModel] || deploymentModel,
    ...grouped
  };
}

/**
 * @param {import('express').Express} app
 * @param {{
 *   pool: import('pg').Pool,
 *   requireAuth: import('express').RequestHandler,
 *   readSession: (token: string) => Promise<object | null>,
 *   currentToken: (req: import('express').Request) => string
 * }} deps
 */
function registerCustomerSupportRoutes(app, { pool, requireAuth, readSession, currentToken }) {
  let schemaReady = false;
  async function ensureSchema() {
    if (schemaReady) return;
    await initCustomerSupportSchema(pool);
    schemaReady = true;
  }

  async function tenantMiddleware(req, res, next) {
    try {
      await ensureSchema();
      const scope = await resolveSupportScope(pool, req.user);
      req.supportTenant = scope;
      return next();
    } catch (error) {
      console.error('[support] tenant scope', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  }

  app.post('/saas/support/presence', requireAuth, tenantMiddleware, async (req, res) => {
    try {
      const result = await upsertPresence(pool, req.user, req.supportTenant, req.body || {});
      return res.json({ success: true, skipped: result.skipped === true });
    } catch (error) {
      console.error('[saas/support/presence POST]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.get('/saas/support/presence', requireAuth, tenantMiddleware, requireSupportAdmin, async (req, res) => {
    try {
      const filter = cleanString(req.query?.filter).toLowerCase();
      const supportOnly = filter === 'support';
      let rows;
      if (looksLikeMike(req.user)) {
        rows = await listAllPresenceRows(pool, { supportOnly });
      } else if (req.supportTenant.deploymentModel === 'saas') {
        rows = await listPresenceRows(pool, req.supportTenant.tenantId, {
          supportOnly,
          deploymentModel: 'saas'
        });
      } else {
        rows = await listPresenceRows(pool, NON_SAAS_GLOBAL_TENANT_ID, {
          supportOnly,
          deploymentModel: 'non-saas'
        });
      }
      return res.json(buildPresenceListResponse(req, rows, { supportOnly }));
    } catch (error) {
      console.error('[saas/support/presence GET]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.post('/saas/support/request', requireAuth, tenantMiddleware, async (req, res) => {
    try {
      const tabId = cleanString(req.body?.tabId) || 'default';
      await upsertPresence(pool, req.user, req.supportTenant, {
        tabId,
        supportRequested: true,
        pagePath: req.body?.pagePath
      });
      await pool.query(
        `UPDATE cp_support_presence
         SET support_requested = true, last_seen_at = NOW()
         WHERE tenant_id = $1 AND user_id = $2 AND tab_id = $3`,
        [req.supportTenant.tenantId, req.user.id, tabId]
      );
      broadcastTenant(req.supportTenant.tenantId, 'support-request', {
        userId: req.user.id,
        tabId
      });
      return res.json({ success: true });
    } catch (error) {
      console.error('[saas/support/request]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.post('/saas/support/clear-request', requireAuth, tenantMiddleware, async (req, res) => {
    try {
      const tabId = cleanString(req.body?.tabId) || 'default';
      await pool.query(
        `UPDATE cp_support_presence
         SET support_requested = false, last_seen_at = NOW()
         WHERE tenant_id = $1 AND user_id = $2 AND tab_id = $3`,
        [req.supportTenant.tenantId, req.user.id, tabId]
      );
      broadcastTenant(req.supportTenant.tenantId, 'support-clear', { userId: req.user.id, tabId });
      return res.json({ success: true });
    } catch (error) {
      console.error('[saas/support/clear-request]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.post('/saas/support/admin/clear-request', requireAuth, tenantMiddleware, requireSupportAdmin, async (req, res) => {
    try {
      const customerUserId = cleanString(req.body?.customerUserId);
      const customerTabId = cleanString(req.body?.customerTabId) || 'default';
      if (!customerUserId) return jsonError(res, 400, 'customerUserId is required');
      const targetTenantId = resolveTargetTenantId(req, req.body?.tenantId);
      await pool.query(
        `UPDATE cp_support_presence
         SET support_requested = false, last_seen_at = NOW()
         WHERE tenant_id = $1 AND user_id = $2 AND tab_id = $3`,
        [targetTenantId, customerUserId, customerTabId]
      );
      broadcastTenant(targetTenantId, 'support-clear', {
        userId: customerUserId,
        tabId: customerTabId
      });
      return res.json({ success: true });
    } catch (error) {
      console.error('[saas/support/admin/clear-request]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.get('/saas/support/events', async (req, res) => {
    try {
      await ensureSchema();
      const token = cleanString(req.query?.access_token) || currentToken(req);
      const user = await readSession(token);
      if (!user) return jsonError(res, 401, 'Authentication required');

      const scope = await resolveSupportScope(pool, user);
      if (!scope?.tenantId) return jsonError(res, 403, 'No support scope for this account');

      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      res.flushHeaders?.();

      const tenantId = String(scope.tenantId);
      let set = sseByTenant.get(tenantId);
      if (!set) {
        set = new Set();
        sseByTenant.set(tenantId, set);
      }
      set.add(res);

      res.write(`event: hello\ndata: ${JSON.stringify({ tenantId, userId: user.id })}\n\n`);

      const ping = setInterval(() => {
        try {
          res.write(`event: ping\ndata: {}\n\n`);
        } catch {
          clearInterval(ping);
        }
      }, 25_000);

      req.on('close', () => {
        clearInterval(ping);
        set.delete(res);
        if (!set.size) sseByTenant.delete(tenantId);
      });
    } catch (error) {
      console.error('[saas/support/events]', error);
      if (!res.headersSent) return jsonError(res, 500, error.message || 'Server error');
      res.end();
    }
  });

  app.post('/saas/support/chat/start', requireAuth, tenantMiddleware, requireSupportAdmin, async (req, res) => {
    try {
      const customerUserId = cleanString(req.body?.customerUserId);
      const customerTabId = cleanString(req.body?.customerTabId) || 'default';
      if (!customerUserId) return jsonError(res, 400, 'customerUserId is required');
      const targetTenantId = resolveTargetTenantId(req, req.body?.tenantId);

      const existing = await pool.query(
        `SELECT id, status FROM cp_support_chat_sessions
         WHERE tenant_id = $1 AND customer_user_id = $2 AND status IN ('pending','active')
         ORDER BY updated_at DESC LIMIT 1`,
        [targetTenantId, customerUserId]
      );
      if (existing.rows[0]) {
        return res.json({ success: true, sessionId: existing.rows[0].id, status: existing.rows[0].status });
      }

      const r = await pool.query(
        `INSERT INTO cp_support_chat_sessions (tenant_id, customer_user_id, admin_user_id, status)
         VALUES ($1,$2,$3,'pending')
         RETURNING id, status`,
        [targetTenantId, customerUserId, req.user.id]
      );
      const sessionId = r.rows[0].id;
      broadcastTenant(targetTenantId, 'chat-invite', {
        sessionId,
        customerUserId,
        customerTabId,
        adminUserId: req.user.id
      });
      return res.json({ success: true, sessionId, status: 'pending' });
    } catch (error) {
      console.error('[saas/support/chat/start]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  async function loadChatSessionForUser(pool, sessionId, user, { preferredTenantId } = {}) {
    let row = null;
    if (preferredTenantId) {
      const r = await pool.query(
        `SELECT * FROM cp_support_chat_sessions WHERE id = $1 AND tenant_id = $2 LIMIT 1`,
        [sessionId, preferredTenantId]
      );
      row = r.rows[0];
    }
    if (!row && canAccessAdminPanel(user)) {
      const r = await pool.query(`SELECT * FROM cp_support_chat_sessions WHERE id = $1 LIMIT 1`, [sessionId]);
      row = r.rows[0];
    }
    if (!row) return { ok: false, status: 404, message: 'Chat session not found' };
    const uid = String(user.id);
    if (uid !== String(row.customer_user_id) && uid !== String(row.admin_user_id) && !canAccessAdminPanel(user)) {
      return { ok: false, status: 403, message: 'Not a participant in this chat' };
    }
    return { ok: true, row };
  }

  app.post('/saas/support/chat/respond', requireAuth, tenantMiddleware, async (req, res) => {
    try {
      const sessionId = cleanString(req.body?.sessionId);
      const accept = req.body?.accept === true;
      if (!sessionId) return jsonError(res, 400, 'sessionId is required');

      const r = await pool.query(
        `SELECT * FROM cp_support_chat_sessions WHERE id = $1 AND tenant_id = $2 LIMIT 1`,
        [sessionId, req.supportTenant.tenantId]
      );
      const row = r.rows[0];
      if (!row) return jsonError(res, 404, 'Chat session not found');
      if (String(row.customer_user_id) !== String(req.user.id)) {
        return jsonError(res, 403, 'Only the invited customer can respond');
      }
      if (row.status !== 'pending') {
        return res.json({ success: true, sessionId, status: row.status });
      }

      const status = accept ? 'active' : 'declined';
      await pool.query(
        `UPDATE cp_support_chat_sessions SET status = $2, updated_at = NOW() WHERE id = $1`,
        [sessionId, status]
      );
      broadcastTenant(row.tenant_id, 'chat-response', { sessionId, status, customerUserId: req.user.id });
      return res.json({ success: true, sessionId, status });
    } catch (error) {
      console.error('[saas/support/chat/respond]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.get('/saas/support/chat/:sessionId/messages', requireAuth, tenantMiddleware, async (req, res) => {
    try {
      const sessionId = cleanString(req.params.sessionId);
      const loaded = await loadChatSessionForUser(pool, sessionId, req.user, {
        preferredTenantId: req.supportTenant.tenantId
      });
      if (!loaded.ok) return jsonError(res, loaded.status, loaded.message);
      const row = loaded.row;
      const msgs = await pool.query(
        `SELECT id, session_id, sender_user_id, body, created_at
         FROM cp_support_chat_messages WHERE session_id = $1 ORDER BY created_at ASC`,
        [sessionId]
      );
      return res.json({
        success: true,
        session: {
          id: row.id,
          status: row.status,
          customerUserId: row.customer_user_id,
          adminUserId: row.admin_user_id
        },
        messages: msgs.rows.map((m) => ({
          id: m.id,
          sessionId: m.session_id,
          senderUserId: m.sender_user_id,
          body: m.body,
          createdAt: m.created_at
        }))
      });
    } catch (error) {
      console.error('[saas/support/chat/messages GET]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.post('/saas/support/chat/:sessionId/messages', requireAuth, tenantMiddleware, async (req, res) => {
    try {
      const sessionId = cleanString(req.params.sessionId);
      const body = cleanString(req.body?.body).slice(0, 4000);
      if (!body) return jsonError(res, 400, 'Message body is required');

      const loaded = await loadChatSessionForUser(pool, sessionId, req.user, {
        preferredTenantId: req.supportTenant.tenantId
      });
      if (!loaded.ok) return jsonError(res, loaded.status, loaded.message);
      const row = loaded.row;
      if (row.status !== 'active') return jsonError(res, 400, 'Chat is not active');
      const uid = String(req.user.id);
      if (uid !== String(row.customer_user_id) && uid !== String(row.admin_user_id)) {
        return jsonError(res, 403, 'Not a participant in this chat');
      }

      const ins = await pool.query(
        `INSERT INTO cp_support_chat_messages (session_id, sender_user_id, body)
         VALUES ($1,$2,$3)
         RETURNING id, session_id, sender_user_id, body, created_at`,
        [sessionId, req.user.id, body]
      );
      await pool.query(`UPDATE cp_support_chat_sessions SET updated_at = NOW() WHERE id = $1`, [sessionId]);
      const message = ins.rows[0];
      broadcastTenant(row.tenant_id, 'chat-message', {
        sessionId,
        message: {
          id: message.id,
          senderUserId: message.sender_user_id,
          body: message.body,
          createdAt: message.created_at
        }
      });
      return res.json({
        success: true,
        message: {
          id: message.id,
          sessionId: message.session_id,
          senderUserId: message.sender_user_id,
          body: message.body,
          createdAt: message.created_at
        }
      });
    } catch (error) {
      console.error('[saas/support/chat/messages POST]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  async function loadRemoteSessionForUser(pool, sessionId, user, { preferredTenantId } = {}) {
    let row = null;
    if (preferredTenantId) {
      const r = await pool.query(
        `SELECT * FROM cp_support_remote_sessions WHERE id = $1 AND tenant_id = $2 LIMIT 1`,
        [sessionId, preferredTenantId]
      );
      row = r.rows[0];
    }
    if (!row && canAccessAdminPanel(user)) {
      const r = await pool.query(`SELECT * FROM cp_support_remote_sessions WHERE id = $1 LIMIT 1`, [sessionId]);
      row = r.rows[0];
    }
    if (!row) return { ok: false, status: 404, message: 'Remote session not found' };
    const uid = String(user.id);
    if (
      uid !== String(row.customer_user_id) &&
      uid !== String(row.admin_user_id) &&
      !canAccessAdminPanel(user)
    ) {
      return { ok: false, status: 403, message: 'Not a participant in this remote session' };
    }
    return { ok: true, row };
  }

  app.post('/saas/support/remote/request', requireAuth, tenantMiddleware, requireSupportAdmin, async (req, res) => {
    try {
      const customerUserId = cleanString(req.body?.customerUserId);
      const customerTabId = cleanString(req.body?.customerTabId) || 'default';
      if (!customerUserId) return jsonError(res, 400, 'customerUserId is required');
      const targetTenantId = resolveTargetTenantId(req, req.body?.tenantId);

      const existing = await pool.query(
        `SELECT id, status FROM cp_support_remote_sessions
         WHERE tenant_id = $1 AND customer_user_id = $2 AND admin_user_id = $3 AND status IN ('pending','active')
         ORDER BY updated_at DESC LIMIT 1`,
        [targetTenantId, customerUserId, req.user.id]
      );
      if (existing.rows[0]) {
        const row = existing.rows[0];
        return res.json({
          success: true,
          sessionId: row.id,
          status: row.status,
          existing: true
        });
      }

      const persistToken = crypto.randomBytes(24).toString('base64url');
      const r = await pool.query(
        `INSERT INTO cp_support_remote_sessions (
            tenant_id, customer_user_id, admin_user_id, status, persist_token, customer_tab_id
          ) VALUES ($1,$2,$3,'pending',$4,$5)
          RETURNING id, status, persist_token`,
        [targetTenantId, customerUserId, req.user.id, persistToken, customerTabId]
      );
      const session = r.rows[0];
      broadcastTenant(targetTenantId, 'remote-request', {
        sessionId: session.id,
        customerUserId,
        customerTabId,
        adminUserId: req.user.id
      });
      return res.json({
        success: true,
        sessionId: session.id,
        status: session.status,
        persistToken: session.persist_token
      });
    } catch (error) {
      console.error('[saas/support/remote/request]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.post('/saas/support/remote/respond', requireAuth, tenantMiddleware, async (req, res) => {
    try {
      const sessionId = cleanString(req.body?.sessionId);
      const accept = req.body?.accept === true;
      if (!sessionId) return jsonError(res, 400, 'sessionId is required');

      const r = await pool.query(
        `SELECT * FROM cp_support_remote_sessions WHERE id = $1 AND tenant_id = $2 LIMIT 1`,
        [sessionId, req.supportTenant.tenantId]
      );
      const row = r.rows[0];
      if (!row) return jsonError(res, 404, 'Remote session not found');
      if (String(row.customer_user_id) !== String(req.user.id)) {
        return jsonError(res, 403, 'Only the customer can accept or decline remote control');
      }
      if (row.status !== 'pending') {
        return res.json({ success: true, sessionId, status: row.status, persistToken: row.persist_token });
      }

      const status = accept ? 'active' : 'declined';
      await pool.query(
        `UPDATE cp_support_remote_sessions SET status = $2, updated_at = NOW(), ended_at = CASE WHEN $2 = 'declined' THEN NOW() ELSE NULL END WHERE id = $1`,
        [sessionId, status]
      );
      broadcastTenant(req.supportTenant.tenantId, 'remote-response', {
        sessionId,
        status,
        customerUserId: req.user.id,
        persistToken: accept ? row.persist_token : null
      });
      return res.json({
        success: true,
        sessionId,
        status,
        persistToken: accept ? row.persist_token : null
      });
    } catch (error) {
      console.error('[saas/support/remote/respond]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.post('/saas/support/remote/end', requireAuth, tenantMiddleware, async (req, res) => {
    try {
      const sessionId = cleanString(req.body?.sessionId);
      if (!sessionId) return jsonError(res, 400, 'sessionId is required');

      const loaded = await loadRemoteSessionForUser(pool, sessionId, req.user, {
        preferredTenantId: req.supportTenant.tenantId
      });
      if (!loaded.ok) return jsonError(res, loaded.status, loaded.message);
      const row = loaded.row;
      const uid = String(req.user.id);
      if (
        uid !== String(row.customer_user_id) &&
        uid !== String(row.admin_user_id) &&
        !canAccessAdminPanel(req.user)
      ) {
        return jsonError(res, 403, 'Not allowed to end this session');
      }

      await pool.query(
        `UPDATE cp_support_remote_sessions SET status = 'ended', updated_at = NOW(), ended_at = NOW() WHERE id = $1`,
        [sessionId]
      );
      clearRemoteSignals(sessionId);
      broadcastTenant(row.tenant_id, 'remote-ended', {
        sessionId,
        customerUserId: row.customer_user_id
      });
      return res.json({ success: true, sessionId, status: 'ended' });
    } catch (error) {
      console.error('[saas/support/remote/end]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.post('/saas/support/remote/cancel-pending', requireAuth, tenantMiddleware, requireSupportAdmin, async (req, res) => {
    try {
      const customerUserId = cleanString(req.body?.customerUserId);
      if (!customerUserId) return jsonError(res, 400, 'customerUserId is required');
      const targetTenantId = resolveTargetTenantId(req, req.body?.tenantId);
      const r = await pool.query(
        `UPDATE cp_support_remote_sessions
         SET status = 'ended', updated_at = NOW(), ended_at = NOW()
         WHERE tenant_id = $1 AND customer_user_id = $2 AND admin_user_id = $3 AND status = 'pending'
         RETURNING id`,
        [targetTenantId, customerUserId, req.user.id]
      );
      for (const row of r.rows) {
        clearRemoteSignals(row.id);
        broadcastTenant(targetTenantId, 'remote-ended', {
          sessionId: row.id,
          customerUserId,
          reason: 'cancelled'
        });
      }
      return res.json({ success: true, cancelled: r.rows.length });
    } catch (error) {
      console.error('[saas/support/remote/cancel-pending]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.post('/saas/support/remote/:sessionId/signal', requireAuth, tenantMiddleware, async (req, res) => {
    try {
      const sessionId = cleanString(req.params.sessionId);
      const type = cleanString(req.body?.type).toLowerCase();
      const payload = req.body?.payload;
      if (!sessionId) return jsonError(res, 400, 'sessionId is required');
      if (!type || !['offer', 'answer', 'ice'].includes(type)) {
        return jsonError(res, 400, 'type must be offer, answer, or ice');
      }

      const loaded = await loadRemoteSessionForUser(pool, sessionId, req.user, {
        preferredTenantId: req.supportTenant.tenantId
      });
      if (!loaded.ok) return jsonError(res, loaded.status, loaded.message);
      const row = loaded.row;
      if (row.status !== 'active') return jsonError(res, 400, 'Remote session is not active');

      const entry = pushRemoteSignal(sessionId, req.user.id, type, payload);
      broadcastTenant(row.tenant_id, 'remote-signal', {
        sessionId,
        signalId: entry?.id,
        fromUserId: req.user.id,
        type,
        payload
      });
      return res.json({ success: true, signalId: entry?.id });
    } catch (error) {
      console.error('[saas/support/remote/signal POST]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.get('/saas/support/remote/:sessionId/signals', requireAuth, tenantMiddleware, async (req, res) => {
    try {
      const sessionId = cleanString(req.params.sessionId);
      const afterId = Math.max(0, Number(req.query?.after || 0));
      if (!sessionId) return jsonError(res, 400, 'sessionId is required');

      const loaded = await loadRemoteSessionForUser(pool, sessionId, req.user, {
        preferredTenantId: req.supportTenant.tenantId
      });
      if (!loaded.ok) return jsonError(res, loaded.status, loaded.message);
      const row = loaded.row;
      if (row.status !== 'active') return jsonError(res, 400, 'Remote session is not active');

      const list = remoteSignalsBySession.get(sessionId) || [];
      const signals = list.filter((s) => s.id > afterId);
      return res.json({ success: true, signals });
    } catch (error) {
      console.error('[saas/support/remote/signals GET]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.post('/saas/support/remote/:sessionId/virtual-call', requireAuth, tenantMiddleware, requireSupportAdmin, async (req, res) => {
    try {
      const sessionId = cleanString(req.params.sessionId);
      if (!sessionId) return jsonError(res, 400, 'sessionId is required');

      const loaded = await loadRemoteSessionForUser(pool, sessionId, req.user, {
        preferredTenantId: req.supportTenant.tenantId
      });
      if (!loaded.ok) return jsonError(res, loaded.status, loaded.message);
      const row = loaded.row;
      if (row.status !== 'active') return jsonError(res, 400, 'Remote session must be active');

      broadcastTenant(row.tenant_id, 'virtual-call-invite', {
        sessionId,
        customerUserId: row.customer_user_id,
        adminUserId: req.user.id
      });
      return res.json({ success: true });
    } catch (error) {
      console.error('[saas/support/remote/virtual-call]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.get('/saas/support/remote/active', requireAuth, tenantMiddleware, async (req, res) => {
    try {
      const uid = String(req.user.id);
      const r = await pool.query(
        `SELECT id, tenant_id, customer_user_id, admin_user_id, status, persist_token, customer_tab_id, created_at, updated_at
         FROM cp_support_remote_sessions
         WHERE status = 'active' AND ended_at IS NULL
           AND (customer_user_id = $1 OR admin_user_id = $1)
         ORDER BY updated_at DESC LIMIT 1`,
        [uid]
      );
      const row = r.rows[0];
      if (!row) return res.json({ success: true, session: null });
      return res.json({
        success: true,
        session: {
          id: row.id,
          status: row.status,
          customerUserId: row.customer_user_id,
          adminUserId: row.admin_user_id,
          persistToken: row.persist_token,
          customerTabId: row.customer_tab_id,
          createdAt: row.created_at,
          updatedAt: row.updated_at
        }
      });
    } catch (error) {
      console.error('[saas/support/remote/active]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });
}

module.exports = { registerCustomerSupportRoutes, initCustomerSupportSchema };

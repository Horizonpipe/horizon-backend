'use strict';

const crypto = require('crypto');
const { deploymentMode, canAccessAdminPanel, ACCOUNT_TYPES } = require('./capabilities');
const { loadUserCompanyMembership } = require('./company-permissions.service');

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

function cleanString(v) {
  return String(v ?? '').trim();
}

function jsonError(res, status, message) {
  return res.status(status).json({ success: false, error: message });
}

function requireSaas(_req, res, next) {
  if (deploymentMode() !== 'saas') {
    return jsonError(res, 404, 'Customer support is only available on SaaS deployments');
  }
  return next();
}

function requireSupportAdmin(req, res, next) {
  if (!canAccessAdminPanel(req.user)) {
    return jsonError(res, 403, 'Admin access required');
  }
  return next();
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

  await pool.query(
    `INSERT INTO cp_support_presence (
        tenant_id, user_id, tab_id, display_name, account_type, role_key,
        company_name, direct_client_label, customer_group_label,
        support_requested, page_path, last_seen_at
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW())
      ON CONFLICT (tenant_id, user_id, tab_id) DO UPDATE SET
        display_name = EXCLUDED.display_name,
        account_type = EXCLUDED.account_type,
        role_key = EXCLUDED.role_key,
        company_name = EXCLUDED.company_name,
        direct_client_label = EXCLUDED.direct_client_label,
        customer_group_label = EXCLUDED.customer_group_label,
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
      pagePath
    ]
  );

  broadcastTenant(tenantId, 'presence', { tenantId, userId, tabId });
  return { skipped: false };
}

async function listPresenceRows(pool, tenantId, { supportOnly = false } = {}) {
  const cutoff = new Date(Date.now() - PRESENCE_TTL_MS).toISOString();
  const params = [tenantId, cutoff];
  let sql = `
    SELECT p.*,
      EXISTS (
        SELECT 1 FROM cp_support_remote_sessions r
        WHERE r.tenant_id = p.tenant_id
          AND r.customer_user_id = p.user_id
          AND r.status = 'active'
          AND r.ended_at IS NULL
      ) AS remote_connected
    FROM cp_support_presence p
    WHERE p.tenant_id = $1 AND p.last_seen_at >= $2`;
  if (supportOnly) {
    sql += ` AND p.support_requested = true`;
  }
  sql += ` ORDER BY p.display_name ASC`;
  const r = await pool.query(sql, params);
  return r.rows;
}

function groupPresenceRows(rows) {
  const directClients = [];
  /** @type {Map<string, { directClientLabel: string, customers: object[] }>} */
  const customerGroups = new Map();

  for (const row of rows) {
    const entry = {
      userId: row.user_id,
      tabId: row.tab_id,
      displayName: row.display_name,
      accountType: row.account_type,
      roleKey: row.role_key,
      companyName: row.company_name,
      directClientLabel: row.direct_client_label,
      customerGroupLabel: row.customer_group_label,
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
      const scope = await resolveTenantForUser(pool, req.user);
      if (!scope?.tenantId) {
        return jsonError(res, 403, 'No SaaS tenant scope for this account');
      }
      req.supportTenant = scope;
      return next();
    } catch (error) {
      console.error('[saas/support] tenant scope', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  }

  app.post('/saas/support/presence', requireSaas, requireAuth, tenantMiddleware, async (req, res) => {
    try {
      const result = await upsertPresence(pool, req.user, req.supportTenant, req.body || {});
      return res.json({ success: true, skipped: result.skipped === true });
    } catch (error) {
      console.error('[saas/support/presence POST]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.get('/saas/support/presence', requireSaas, requireAuth, tenantMiddleware, requireSupportAdmin, async (req, res) => {
    try {
      const filter = cleanString(req.query?.filter).toLowerCase();
      const supportOnly = filter === 'support';
      const rows = await listPresenceRows(pool, req.supportTenant.tenantId, { supportOnly });
      const grouped = groupPresenceRows(rows);
      return res.json({ success: true, filter: supportOnly ? 'support' : 'all', ...grouped });
    } catch (error) {
      console.error('[saas/support/presence GET]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.post('/saas/support/request', requireSaas, requireAuth, tenantMiddleware, async (req, res) => {
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

  app.post('/saas/support/clear-request', requireSaas, requireAuth, tenantMiddleware, async (req, res) => {
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

  app.post('/saas/support/admin/clear-request', requireSaas, requireAuth, tenantMiddleware, requireSupportAdmin, async (req, res) => {
    try {
      const customerUserId = cleanString(req.body?.customerUserId);
      const customerTabId = cleanString(req.body?.customerTabId) || 'default';
      if (!customerUserId) return jsonError(res, 400, 'customerUserId is required');
      await pool.query(
        `UPDATE cp_support_presence
         SET support_requested = false, last_seen_at = NOW()
         WHERE tenant_id = $1 AND user_id = $2 AND tab_id = $3`,
        [req.supportTenant.tenantId, customerUserId, customerTabId]
      );
      broadcastTenant(req.supportTenant.tenantId, 'support-clear', {
        userId: customerUserId,
        tabId: customerTabId
      });
      return res.json({ success: true });
    } catch (error) {
      console.error('[saas/support/admin/clear-request]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.get('/saas/support/events', requireSaas, async (req, res) => {
    try {
      await ensureSchema();
      const token = cleanString(req.query?.access_token) || currentToken(req);
      const user = await readSession(token);
      if (!user) return jsonError(res, 401, 'Authentication required');

      const scope = await resolveTenantForUser(pool, user);
      if (!scope?.tenantId) return jsonError(res, 403, 'No SaaS tenant scope for this account');

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

  app.post('/saas/support/chat/start', requireSaas, requireAuth, tenantMiddleware, requireSupportAdmin, async (req, res) => {
    try {
      const customerUserId = cleanString(req.body?.customerUserId);
      const customerTabId = cleanString(req.body?.customerTabId) || 'default';
      if (!customerUserId) return jsonError(res, 400, 'customerUserId is required');

      const existing = await pool.query(
        `SELECT id, status FROM cp_support_chat_sessions
         WHERE tenant_id = $1 AND customer_user_id = $2 AND status IN ('pending','active')
         ORDER BY updated_at DESC LIMIT 1`,
        [req.supportTenant.tenantId, customerUserId]
      );
      if (existing.rows[0]) {
        return res.json({ success: true, sessionId: existing.rows[0].id, status: existing.rows[0].status });
      }

      const r = await pool.query(
        `INSERT INTO cp_support_chat_sessions (tenant_id, customer_user_id, admin_user_id, status)
         VALUES ($1,$2,$3,'pending')
         RETURNING id, status`,
        [req.supportTenant.tenantId, customerUserId, req.user.id]
      );
      const sessionId = r.rows[0].id;
      broadcastTenant(req.supportTenant.tenantId, 'chat-invite', {
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

  app.post('/saas/support/chat/respond', requireSaas, requireAuth, tenantMiddleware, async (req, res) => {
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
      broadcastTenant(req.supportTenant.tenantId, 'chat-response', { sessionId, status, customerUserId: req.user.id });
      return res.json({ success: true, sessionId, status });
    } catch (error) {
      console.error('[saas/support/chat/respond]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.get('/saas/support/chat/:sessionId/messages', requireSaas, requireAuth, tenantMiddleware, async (req, res) => {
    try {
      const sessionId = cleanString(req.params.sessionId);
      const session = await pool.query(
        `SELECT * FROM cp_support_chat_sessions WHERE id = $1 AND tenant_id = $2 LIMIT 1`,
        [sessionId, req.supportTenant.tenantId]
      );
      const row = session.rows[0];
      if (!row) return jsonError(res, 404, 'Chat session not found');
      const uid = String(req.user.id);
      if (uid !== String(row.customer_user_id) && uid !== String(row.admin_user_id) && !canAccessAdminPanel(req.user)) {
        return jsonError(res, 403, 'Not a participant in this chat');
      }
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

  app.post('/saas/support/chat/:sessionId/messages', requireSaas, requireAuth, tenantMiddleware, async (req, res) => {
    try {
      const sessionId = cleanString(req.params.sessionId);
      const body = cleanString(req.body?.body).slice(0, 4000);
      if (!body) return jsonError(res, 400, 'Message body is required');

      const session = await pool.query(
        `SELECT * FROM cp_support_chat_sessions WHERE id = $1 AND tenant_id = $2 LIMIT 1`,
        [sessionId, req.supportTenant.tenantId]
      );
      const row = session.rows[0];
      if (!row) return jsonError(res, 404, 'Chat session not found');
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
      broadcastTenant(req.supportTenant.tenantId, 'chat-message', {
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

  app.post('/saas/support/remote/request', requireSaas, requireAuth, tenantMiddleware, requireSupportAdmin, async (req, res) => {
    try {
      const customerUserId = cleanString(req.body?.customerUserId);
      const customerTabId = cleanString(req.body?.customerTabId) || 'default';
      if (!customerUserId) return jsonError(res, 400, 'customerUserId is required');

      const persistToken = crypto.randomBytes(24).toString('base64url');
      const r = await pool.query(
        `INSERT INTO cp_support_remote_sessions (
            tenant_id, customer_user_id, admin_user_id, status, persist_token, customer_tab_id
          ) VALUES ($1,$2,$3,'pending',$4,$5)
          RETURNING id, status, persist_token`,
        [req.supportTenant.tenantId, customerUserId, req.user.id, persistToken, customerTabId]
      );
      const session = r.rows[0];
      broadcastTenant(req.supportTenant.tenantId, 'remote-request', {
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

  app.post('/saas/support/remote/respond', requireSaas, requireAuth, tenantMiddleware, async (req, res) => {
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

  app.post('/saas/support/remote/end', requireSaas, requireAuth, tenantMiddleware, async (req, res) => {
    try {
      const sessionId = cleanString(req.body?.sessionId);
      if (!sessionId) return jsonError(res, 400, 'sessionId is required');

      const r = await pool.query(
        `SELECT * FROM cp_support_remote_sessions WHERE id = $1 AND tenant_id = $2 LIMIT 1`,
        [sessionId, req.supportTenant.tenantId]
      );
      const row = r.rows[0];
      if (!row) return jsonError(res, 404, 'Remote session not found');
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
      broadcastTenant(req.supportTenant.tenantId, 'remote-ended', {
        sessionId,
        customerUserId: row.customer_user_id
      });
      return res.json({ success: true, sessionId, status: 'ended' });
    } catch (error) {
      console.error('[saas/support/remote/end]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.get('/saas/support/remote/active', requireSaas, requireAuth, tenantMiddleware, async (req, res) => {
    try {
      const uid = String(req.user.id);
      const r = await pool.query(
        `SELECT id, tenant_id, customer_user_id, admin_user_id, status, persist_token, customer_tab_id, created_at, updated_at
         FROM cp_support_remote_sessions
         WHERE tenant_id = $1 AND status = 'active' AND ended_at IS NULL
           AND (customer_user_id = $2 OR admin_user_id = $2)
         ORDER BY updated_at DESC LIMIT 1`,
        [req.supportTenant.tenantId, uid]
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

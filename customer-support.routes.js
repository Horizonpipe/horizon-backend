'use strict';

const crypto = require('crypto');
const { canAccessAdminPanel, isSaasWorkspaceOwner, looksLikeMike, ACCOUNT_TYPES } = require('./capabilities');
const { loadUserCompanyMembership } = require('./company-permissions.service');
const {
  MAX_CHAT_UPLOAD_BYTES,
  buildChatUploadStorageKey,
  isValidChatUploadStorageKey,
  isChatUploadExpired,
  createChatUploadWasabiClient,
  chatUploadBucketName,
  presignChatUploadPut,
  presignChatUploadGet,
  headChatUploadObject
} = require('./chat-uploads-wasabi.js');

/** Lazy Wasabi client for support chat file uploads (same env as portal-files). */
let chatUploadWasabiClient = null;
function getChatUploadWasabi() {
  if (chatUploadWasabiClient !== null) return chatUploadWasabiClient;
  chatUploadWasabiClient = createChatUploadWasabiClient();
  return chatUploadWasabiClient;
}

/** Shared Postgres pool for non-SaaS (OVH) presence when user has no saas_tenant_instances row. */
const NON_SAAS_GLOBAL_TENANT_ID = '00000000-0000-0000-0000-000000000001';
const DEPLOYMENT_GROUP_LABELS = Object.freeze({
  'non-saas': 'NON SAAS MODEL',
  saas: 'SAAS MODEL'
});
function parsePresencePeerUrls() {
  const raw = cleanString(process.env.CP_SUPPORT_PRESENCE_PEER_URLS);
  if (!raw) return [];
  return raw
    .split(',')
    .map((u) => u.replace(/\/+$/, ''))
    .filter(Boolean);
}

function presencePeerSecret() {
  return cleanString(process.env.CP_SUPPORT_PRESENCE_PEER_SECRET);
}

function requirePresencePeerSecret(req, res, next) {
  const expected = presencePeerSecret();
  if (!expected) return jsonError(res, 503, 'Peer federation not configured');
  const got = cleanString(req.headers['x-cp-support-peer-secret']);
  if (!got || got !== expected) return jsonError(res, 403, 'Invalid peer secret');
  return next();
}

function presenceRowKey(row) {
  return `${row.tenant_id}:${row.user_id}:${row.tab_id}`;
}

function mergePresenceRowSets(...sets) {
  const byKey = new Map();
  for (const rows of sets) {
    for (const row of rows || []) {
      const key = presenceRowKey(row);
      const prev = byKey.get(key);
      if (!prev) {
        byKey.set(key, row);
        continue;
      }
      const prevAt = new Date(prev.last_seen_at).getTime();
      const nextAt = new Date(row.last_seen_at).getTime();
      if (nextAt >= prevAt) byKey.set(key, row);
    }
  }
  return [...byKey.values()];
}

async function fetchPeerPresenceRows(supportOnly) {
  const secret = presencePeerSecret();
  const peers = parsePresencePeerUrls();
  if (!secret || !peers.length) return [];

  const filter = supportOnly ? 'support' : 'all';
  const out = [];
  await Promise.all(
    peers.map(async (base) => {
      const url = `${base}/internal/support/presence-snapshot?filter=${encodeURIComponent(filter)}`;
      try {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 8000);
        const resp = await fetch(url, {
          method: 'GET',
          headers: { 'X-CP-Support-Peer-Secret': secret },
          signal: ctrl.signal
        });
        clearTimeout(timer);
        if (!resp.ok) {
          console.warn('[support] peer presence', base, resp.status);
          return;
        }
        const data = await resp.json();
        if (Array.isArray(data?.rows)) out.push(...data.rows);
      } catch (err) {
        console.warn('[support] peer presence fetch failed', base, err?.message || err);
      }
    })
  );
  return out;
}


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
/** Legacy in-process buffers (unused when Postgres relay tables are active). */
const remoteSignalsBySession = new Map();
const REMOTE_SIGNAL_BUFFER_MAX = 120;
const remoteFramesBySession = new Map();
const remoteInputBySession = new Map();
const REMOTE_INPUT_BUFFER_MAX = 240;
const REMOTE_FRAME_MAX_B64 = 1_200_000;
/** @type {Map<string, { id: string, sessionId: string, tenantId: string, fromUserId: string, toUserId: string, fileName: string, fileSize: number, mimeType: string, dataBase64: string, createdAt: number }>} */
const fileOffersById = new Map();
const FILE_OFFER_TTL_MS = 10 * 60 * 1000;
const MAX_CHAT_ATTACHMENT_BYTES = 8 * 1024 * 1024;

function cleanString(v) {
  return String(v ?? '').trim();
}

function authUserId(user) {
  return cleanString(user?.id ?? user?.userId);
}

function isChatParticipant(user, row) {
  const uid = authUserId(user);
  if (!uid || !row) return false;
  return uid === String(row.customer_user_id) || uid === String(row.admin_user_id);
}

function isRemoteParticipant(user, row) {
  return isChatParticipant(user, row);
}

function formatUserDisplayNameFromRow(row) {
  if (!row || typeof row !== 'object') return 'User';
  const displayName = cleanString(row.display_name ?? row.displayName);
  if (displayName) return displayName;
  const first = cleanString(row.first_name ?? row.firstName);
  const last = cleanString(row.last_name ?? row.lastName);
  if (first || last) return `${first} ${last}`.trim();
  return cleanString(row.username) || cleanString(row.email) || 'User';
}

function formatUserDisplayNameFromUser(user) {
  if (!user || typeof user !== 'object') return 'User';
  const displayName = cleanString(user.displayName ?? user.display_name);
  if (displayName) return displayName;
  const first = cleanString(user.firstName ?? user.first_name);
  const last = cleanString(user.lastName ?? user.last_name);
  if (first || last) return `${first} ${last}`.trim();
  return cleanString(user.username) || cleanString(user.email) || 'User';
}

async function lookupUserDisplayName(pool, userId) {
  const uid = cleanString(userId);
  if (!uid) return 'User';
  try {
    const r = await pool.query(
      `SELECT display_name, username, email, first_name, last_name FROM users WHERE CAST(id AS text) = $1 LIMIT 1`,
      [uid]
    );
    const row = r.rows[0];
    if (!row) return 'User';
    return formatUserDisplayNameFromRow(row);
  } catch {
    return 'User';
  }
}

function jsonError(res, status, message) {
  return res.status(status).json({ success: false, error: message });
}

function requireSupportAdmin(req, res, next) {
  if (canAccessAdminPanel(req.user) || isSaasWorkspaceOwner(req.user)) {
    return next();
  }
  return jsonError(res, 403, 'Admin access required');
}

async function insertRemoteSignalPg(pool, sessionId, fromUserId, type, payload) {
  const key = String(sessionId || '');
  if (!key) return null;
  const ins = await pool.query(
    `INSERT INTO cp_support_remote_signals (session_id, from_user_id, signal_type, payload)
     VALUES ($1, $2, $3, $4)
     RETURNING id, session_id, from_user_id, signal_type, payload, created_at`,
    [key, String(fromUserId || ''), String(type || ''), payload != null ? JSON.stringify(payload) : null]
  );
  const row = ins.rows[0];
  if (!row) return null;
  return {
    id: Number(row.id) || 0,
    at: row.created_at ? new Date(row.created_at).getTime() : Date.now(),
    fromUserId: String(row.from_user_id || ''),
    type: String(row.signal_type || ''),
    payload: row.payload
  };
}

async function fetchRemoteSignalsPg(pool, sessionId, afterId) {
  const key = String(sessionId || '');
  if (!key) return [];
  const r = await pool.query(
    `SELECT id, from_user_id, signal_type, payload, created_at
     FROM cp_support_remote_signals
     WHERE session_id = $1 AND id > $2
     ORDER BY id ASC
     LIMIT 64`,
    [key, Math.max(0, Number(afterId) || 0)]
  );
  return r.rows.map((row) => ({
    id: Number(row.id) || 0,
    fromUserId: String(row.from_user_id || ''),
    type: String(row.signal_type || ''),
    payload: row.payload,
    at: row.created_at ? new Date(row.created_at).getTime() : Date.now()
  }));
}

function clearRemoteSignals(sessionId) {
  remoteSignalsBySession.delete(String(sessionId || ''));
}

async function upsertRemoteFramePg(pool, sessionId, payload) {
  const key = String(sessionId || '');
  if (!key) return null;
  const dataBase64 = cleanString(payload?.dataBase64);
  if (!dataBase64 || dataBase64.length > REMOTE_FRAME_MAX_B64) return null;
  const seq = Math.max(1, Number(payload?.seq) || 0);
  await pool.query(
    `INSERT INTO cp_support_remote_frames (session_id, seq, mime_type, data_base64, w, h, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, NOW())
     ON CONFLICT (session_id) DO UPDATE SET
       seq = EXCLUDED.seq,
       mime_type = EXCLUDED.mime_type,
       data_base64 = EXCLUDED.data_base64,
       w = EXCLUDED.w,
       h = EXCLUDED.h,
       updated_at = NOW()`,
    [
      key,
      seq,
      cleanString(payload?.mimeType || 'image/jpeg') || 'image/jpeg',
      dataBase64,
      Math.max(0, Number(payload?.w) || 0),
      Math.max(0, Number(payload?.h) || 0)
    ]
  );
  return { seq, mimeType: cleanString(payload?.mimeType || 'image/jpeg'), dataBase64, w: Math.max(0, Number(payload?.w) || 0), h: Math.max(0, Number(payload?.h) || 0), at: Date.now() };
}

async function fetchRemoteFramePg(pool, sessionId, afterSeq) {
  const key = String(sessionId || '');
  if (!key) return null;
  const r = await pool.query(
    `SELECT seq, mime_type, data_base64, w, h, updated_at
     FROM cp_support_remote_frames
     WHERE session_id = $1 AND seq > $2
     LIMIT 1`,
    [key, Math.max(0, Number(afterSeq) || 0)]
  );
  const row = r.rows[0];
  if (!row) return null;
  return {
    seq: Number(row.seq) || 0,
    mimeType: String(row.mime_type || 'image/jpeg'),
    dataBase64: String(row.data_base64 || ''),
    w: Number(row.w) || 0,
    h: Number(row.h) || 0,
    at: row.updated_at ? new Date(row.updated_at).getTime() : Date.now()
  };
}

async function insertRemoteInputPg(pool, sessionId, fromUserId, payload) {
  const key = String(sessionId || '');
  if (!key || payload == null || typeof payload !== 'object') return null;
  const ins = await pool.query(
    `INSERT INTO cp_support_remote_inputs (session_id, from_user_id, payload)
     VALUES ($1, $2, $3)
     RETURNING id, from_user_id, payload, created_at`,
    [key, String(fromUserId || ''), JSON.stringify(payload)]
  );
  const row = ins.rows[0];
  if (!row) return null;
  return {
    id: Number(row.id) || 0,
    fromUserId: String(row.from_user_id || ''),
    payload: row.payload,
    at: row.created_at ? new Date(row.created_at).getTime() : Date.now()
  };
}

async function fetchRemoteInputsPg(pool, sessionId, afterId) {
  const key = String(sessionId || '');
  if (!key) return [];
  const r = await pool.query(
    `SELECT id, from_user_id, payload, created_at
     FROM cp_support_remote_inputs
     WHERE session_id = $1 AND id > $2
     ORDER BY id ASC
     LIMIT 64`,
    [key, Math.max(0, Number(afterId) || 0)]
  );
  return r.rows.map((row) => ({
    id: Number(row.id) || 0,
    fromUserId: String(row.from_user_id || ''),
    payload: row.payload,
    at: row.created_at ? new Date(row.created_at).getTime() : Date.now()
  }));
}

function clearRemoteRelay(sessionId) {
  const key = String(sessionId || '');
  remoteFramesBySession.delete(key);
  remoteInputBySession.delete(key);
}

async function clearRemoteRelayPg(pool, sessionId) {
  const key = String(sessionId || '');
  if (!key) return;
  clearRemoteSignals(key);
  clearRemoteRelay(key);
  await pool.query(`DELETE FROM cp_support_remote_signals WHERE session_id = $1`, [key]);
  await pool.query(`DELETE FROM cp_support_remote_frames WHERE session_id = $1`, [key]);
  await pool.query(`DELETE FROM cp_support_remote_inputs WHERE session_id = $1`, [key]);
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

/** Fan-out queue/presence/session events to global admin SSE (OVH Mike) as well as tenant channel. */
function broadcastSupportEvents(tenantId, eventName, payload) {
  broadcastTenant(tenantId, eventName, payload);
  const globalId = NON_SAAS_GLOBAL_TENANT_ID;
  if (String(tenantId) !== globalId) {
    broadcastTenant(globalId, eventName, payload);
  }
}

async function endChatSessionsForCustomer(pool, tenantId, customerUserId, { adminUserId } = {}) {
  const params = [tenantId, customerUserId];
  let sql = `
    UPDATE cp_support_chat_sessions
    SET status = 'closed', updated_at = NOW()
    WHERE tenant_id = $1 AND customer_user_id = $2
      AND status IN ('pending', 'active')`;
  if (adminUserId) {
    params.push(adminUserId);
    sql += ` AND admin_user_id = $${params.length}`;
  }
  sql += ` RETURNING id, customer_user_id, admin_user_id`;
  const r = await pool.query(sql, params);
  return r.rows;
}

async function endRemoteSessionsForCustomer(pool, tenantId, customerUserId, { adminUserId } = {}) {
  const params = [tenantId, customerUserId];
  let sql = `
    UPDATE cp_support_remote_sessions
    SET status = 'ended', updated_at = NOW(), ended_at = NOW()
    WHERE tenant_id = $1 AND customer_user_id = $2
      AND status IN ('pending', 'active') AND ended_at IS NULL`;
  if (adminUserId) {
    params.push(adminUserId);
    sql += ` AND admin_user_id = $${params.length}`;
  }
  sql += ` RETURNING id, customer_user_id, admin_user_id`;
  const r = await pool.query(sql, params);
  return r.rows;
}

async function broadcastEndedSessions(pool, tenantId, chatRows, remoteRows, reason) {
  for (const row of chatRows) {
    broadcastSupportEvents(tenantId, 'chat-ended', {
      sessionId: row.id,
      customerUserId: row.customer_user_id,
      adminUserId: row.admin_user_id,
      reason
    });
  }
  for (const row of remoteRows) {
    await clearRemoteRelayPg(pool, row.id);
    broadcastSupportEvents(tenantId, 'remote-ended', {
      sessionId: row.id,
      customerUserId: row.customer_user_id,
      adminUserId: row.admin_user_id,
      reason
    });
  }
}

async function terminateCustomerSessions(pool, tenantId, customerUserId, { adminUserId, reason } = {}) {
  const chatRows = await endChatSessionsForCustomer(pool, tenantId, customerUserId, { adminUserId });
  const remoteRows = await endRemoteSessionsForCustomer(pool, tenantId, customerUserId, { adminUserId });
  await broadcastEndedSessions(pool, tenantId, chatRows, remoteRows, reason || 'terminated');
  return { chatEnded: chatRows.length, remoteEnded: remoteRows.length };
}

/** OVH legacy users use numeric ids in Postgres (TEXT), not UUID — migrate support tables to match. */
async function migrateSupportUserIdColumnToText(pool, table, column) {
  const tbl = cleanString(table).replace(/[^a-z0-9_]/gi, '');
  const col = cleanString(column).replace(/[^a-z0-9_]/gi, '');
  if (!tbl || !col) return;
  await pool.query(`
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = '${tbl}'
          AND column_name = '${col}'
          AND data_type <> 'text'
      ) THEN
        EXECUTE 'ALTER TABLE ${tbl} ALTER COLUMN ${col} TYPE TEXT USING ${col}::text';
      END IF;
    END $$;
  `);
}

async function initCustomerSupportSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS cp_support_presence (
      tenant_id UUID NOT NULL,
      user_id TEXT NOT NULL,
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
  await pool.query(
    `ALTER TABLE cp_support_presence ADD COLUMN IF NOT EXISTS support_requested_at TIMESTAMPTZ`
  );
  await pool.query(
    `ALTER TABLE cp_support_presence ADD COLUMN IF NOT EXISTS support_assigned_admin_user_id TEXT`
  );
  await pool.query(
    `ALTER TABLE cp_support_presence ADD COLUMN IF NOT EXISTS support_assigned_admin_name TEXT`
  );
  await migrateSupportUserIdColumnToText(pool, 'cp_support_presence', 'user_id');

  await pool.query(`
    CREATE TABLE IF NOT EXISTS cp_support_chat_sessions (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id UUID NOT NULL,
      customer_user_id TEXT NOT NULL,
      admin_user_id TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_cp_support_chat_tenant ON cp_support_chat_sessions (tenant_id, updated_at DESC)`
  );
  await migrateSupportUserIdColumnToText(pool, 'cp_support_chat_sessions', 'customer_user_id');
  await migrateSupportUserIdColumnToText(pool, 'cp_support_chat_sessions', 'admin_user_id');

  await pool.query(`
    CREATE TABLE IF NOT EXISTS cp_support_chat_messages (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      session_id UUID NOT NULL REFERENCES cp_support_chat_sessions(id) ON DELETE CASCADE,
      sender_user_id TEXT NOT NULL,
      body TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_cp_support_chat_messages_session ON cp_support_chat_messages (session_id, created_at ASC)`
  );
  await migrateSupportUserIdColumnToText(pool, 'cp_support_chat_messages', 'sender_user_id');
  await pool.query(
    `ALTER TABLE cp_support_chat_messages ADD COLUMN IF NOT EXISTS message_type TEXT NOT NULL DEFAULT 'text'`
  );
  await pool.query(
    `ALTER TABLE cp_support_chat_messages ADD COLUMN IF NOT EXISTS attachment JSONB`
  );

  await pool.query(`
    CREATE TABLE IF NOT EXISTS cp_support_remote_sessions (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id UUID NOT NULL,
      customer_user_id TEXT NOT NULL,
      admin_user_id TEXT NOT NULL,
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
  await migrateSupportUserIdColumnToText(pool, 'cp_support_remote_sessions', 'customer_user_id');
  await migrateSupportUserIdColumnToText(pool, 'cp_support_remote_sessions', 'admin_user_id');
  await pool.query(
    `ALTER TABLE cp_support_remote_sessions ADD COLUMN IF NOT EXISTS initiated_by TEXT NOT NULL DEFAULT 'admin'`
  );
  await pool.query(
    `ALTER TABLE cp_support_remote_sessions ADD COLUMN IF NOT EXISTS chat_session_id UUID`
  );

  await pool.query(`
    CREATE TABLE IF NOT EXISTS cp_support_remote_signals (
      id BIGSERIAL PRIMARY KEY,
      session_id UUID NOT NULL REFERENCES cp_support_remote_sessions(id) ON DELETE CASCADE,
      from_user_id TEXT NOT NULL,
      signal_type TEXT NOT NULL,
      payload JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_cp_support_remote_signals_session ON cp_support_remote_signals (session_id, id ASC)`
  );

  await pool.query(`
    CREATE TABLE IF NOT EXISTS cp_support_remote_frames (
      session_id UUID PRIMARY KEY REFERENCES cp_support_remote_sessions(id) ON DELETE CASCADE,
      seq INT NOT NULL,
      mime_type TEXT NOT NULL DEFAULT 'image/jpeg',
      data_base64 TEXT NOT NULL,
      w INT NOT NULL DEFAULT 0,
      h INT NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS cp_support_remote_inputs (
      id BIGSERIAL PRIMARY KEY,
      session_id UUID NOT NULL REFERENCES cp_support_remote_sessions(id) ON DELETE CASCADE,
      from_user_id TEXT NOT NULL,
      payload JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_cp_support_remote_inputs_session ON cp_support_remote_inputs (session_id, id ASC)`
  );
}

function pruneExpiredFileOffers() {
  const now = Date.now();
  for (const [id, offer] of fileOffersById) {
    if (now - offer.createdAt > FILE_OFFER_TTL_MS) fileOffersById.delete(id);
  }
}

function decodeAttachmentBase64(dataBase64) {
  const raw = cleanString(dataBase64);
  if (!raw) return null;
  try {
    const buf = Buffer.from(raw, 'base64');
    if (!buf.length || buf.length > MAX_CHAT_ATTACHMENT_BYTES) return null;
    return buf;
  } catch {
    return null;
  }
}

async function insertChatMessageRow(pool, { sessionId, senderUserId, body, messageType = 'text', attachment = null }) {
  const ins = await pool.query(
    `INSERT INTO cp_support_chat_messages (session_id, sender_user_id, body, message_type, attachment)
     VALUES ($1,$2,$3,$4,$5)
     RETURNING id, session_id, sender_user_id, body, message_type, attachment, created_at`,
    [sessionId, senderUserId, body, messageType, attachment ? JSON.stringify(attachment) : null]
  );
  await pool.query(`UPDATE cp_support_chat_sessions SET updated_at = NOW() WHERE id = $1`, [sessionId]);
  return ins.rows[0];
}

function mapChatMessageRow(m, { senderDisplayName } = {}) {
  let attachment = m.attachment;
  if (typeof attachment === 'string') {
    try {
      attachment = JSON.parse(attachment);
    } catch {
      attachment = null;
    }
  }
  const mapped = {
    id: m.id,
    sessionId: m.session_id,
    senderUserId: m.sender_user_id,
    body: m.body,
    messageType: m.message_type || 'text',
    attachment,
    createdAt: m.created_at
  };
  if (senderDisplayName) mapped.senderDisplayName = senderDisplayName;
  return mapped;
}

async function mapChatMessageRowWithSender(pool, m) {
  const senderDisplayName = await lookupUserDisplayName(pool, m.sender_user_id);
  return mapChatMessageRow(m, { senderDisplayName });
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

async function resolveTargetTenantId(pool, req, bodyTenantId, customerUserId) {
  const requested = cleanString(bodyTenantId);
  const fallback = req.supportTenant.tenantId;
  if (requested && looksLikeMike(req.user)) return requested;
  const uid = cleanString(customerUserId);
  if (requested && uid) {
    const check = await pool.query(
      `SELECT 1 FROM cp_support_presence WHERE tenant_id = $1 AND user_id = $2 LIMIT 1`,
      [requested, uid]
    );
    if (check.rows[0]) return requested;
  }
  return fallback;
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

async function assignSupportAdmin(pool, tenantId, customerUserId, customerTabId, adminUser, adminDisplayName) {
  const tid = cleanString(tenantId);
  const uid = cleanString(customerUserId);
  const tab = cleanString(customerTabId) || 'default';
  const adminId = cleanString(adminUser?.id ?? adminUser?.userId);
  const adminName =
    cleanString(adminDisplayName) ||
    cleanString(adminUser?.displayName) ||
    cleanString(adminUser?.username) ||
    cleanString(adminUser?.email) ||
    'Support';
  if (!tid || !uid || !adminId) return;
  await pool.query(
    `UPDATE cp_support_presence
     SET support_assigned_admin_user_id = $4,
         support_assigned_admin_name = $5,
         last_seen_at = NOW()
     WHERE tenant_id = $1 AND user_id = $2 AND tab_id = $3`,
    [tid, uid, tab, adminId, adminName]
  );
}

async function upsertPresence(pool, user, tenantScope, body) {
  const tenantId = tenantScope.tenantId;
  const userId = cleanString(user?.id ?? user?.userId);
  if (!userId) {
    const err = new Error('Missing user id');
    err.code = 'SUPPORT_PRESENCE_NO_USER';
    throw err;
  }
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

  const displayName = formatUserDisplayNameFromUser(user);

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

  broadcastSupportEvents(tenantId, 'presence', { tenantId, userId, tabId });
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
      supportRequestedAt: row.support_requested_at || null,
      supportAssignedAdminUserId: row.support_assigned_admin_user_id || '',
      supportAssignedAdminName: row.support_assigned_admin_name || '',
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
         SET support_requested = true,
             support_requested_at = COALESCE(support_requested_at, NOW()),
             support_assigned_admin_user_id = NULL,
             support_assigned_admin_name = NULL,
             last_seen_at = NOW()
         WHERE tenant_id = $1 AND user_id = $2 AND tab_id = $3`,
        [req.supportTenant.tenantId, req.user.id, tabId]
      );
      const displayName =
        cleanString(req.user.displayName) ||
        cleanString(req.user.username) ||
        cleanString(req.user.email) ||
        'Customer';
      broadcastSupportEvents(req.supportTenant.tenantId, 'support-request', {
        userId: req.user.id,
        tabId,
        displayName,
        pagePath: cleanString(req.body?.pagePath).slice(0, 500)
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
         SET support_requested = false,
             support_requested_at = NULL,
             support_assigned_admin_user_id = NULL,
             support_assigned_admin_name = NULL,
             last_seen_at = NOW()
         WHERE tenant_id = $1 AND user_id = $2 AND tab_id = $3`,
        [req.supportTenant.tenantId, req.user.id, tabId]
      );
      broadcastSupportEvents(req.supportTenant.tenantId, 'support-clear', { userId: req.user.id, tabId });
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
      const targetTenantId = await resolveTargetTenantId(pool, req, req.body?.tenantId, customerUserId);
      const ended = await terminateCustomerSessions(pool, targetTenantId, customerUserId, {
        reason: 'clear-request'
      });
      await pool.query(
        `UPDATE cp_support_presence
         SET support_requested = false,
             support_requested_at = NULL,
             support_assigned_admin_user_id = NULL,
             support_assigned_admin_name = NULL,
             last_seen_at = NOW()
         WHERE tenant_id = $1 AND user_id = $2 AND tab_id = $3`,
        [targetTenantId, customerUserId, customerTabId]
      );
      broadcastSupportEvents(targetTenantId, 'support-clear', {
        userId: customerUserId,
        tabId: customerTabId
      });
      return res.json({ success: true, ...ended });
    } catch (error) {
      console.error('[saas/support/admin/clear-request]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.post('/saas/support/admin/terminate', requireAuth, tenantMiddleware, requireSupportAdmin, async (req, res) => {
    try {
      const customerUserId = cleanString(req.body?.customerUserId);
      if (!customerUserId) return jsonError(res, 400, 'customerUserId is required');
      const targetTenantId = await resolveTargetTenantId(pool, req, req.body?.tenantId, customerUserId);
      const adminUserId = req.body?.adminOnly === true ? cleanString(req.user?.id ?? req.user?.userId) : undefined;
      const ended = await terminateCustomerSessions(pool, targetTenantId, customerUserId, {
        adminUserId,
        reason: cleanString(req.body?.reason) || 'admin-terminate'
      });
      return res.json({ success: true, ...ended });
    } catch (error) {
      console.error('[saas/support/admin/terminate]', error);
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
      const targetTenantId = await resolveTargetTenantId(pool, req, req.body?.tenantId, customerUserId);
      const adminUserId = cleanString(req.user?.id ?? req.user?.userId);

      await terminateCustomerSessions(pool, targetTenantId, customerUserId, {
        reason: 'superseded'
      });

      const r = await pool.query(
        `INSERT INTO cp_support_chat_sessions (tenant_id, customer_user_id, admin_user_id, status)
         VALUES ($1,$2,$3,'pending')
         RETURNING id, status`,
        [targetTenantId, customerUserId, adminUserId]
      );
      const sessionId = r.rows[0].id;
      await assignSupportAdmin(
        pool,
        targetTenantId,
        customerUserId,
        customerTabId,
        req.user,
        cleanString(req.user.displayName) ||
          cleanString(req.user.username) ||
          cleanString(req.user.email) ||
          'Support'
      );
      broadcastSupportEvents(targetTenantId, 'chat-invite', {
        sessionId,
        customerUserId,
        customerTabId,
        adminUserId: adminUserId,
        adminDisplayName: formatUserDisplayNameFromUser(req.user)
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
    if (!row) {
      const uid = cleanString(user?.id ?? user?.userId);
      if (uid) {
        const r = await pool.query(
          `SELECT * FROM cp_support_chat_sessions
           WHERE id = $1 AND (customer_user_id = $2 OR admin_user_id = $2)
           LIMIT 1`,
          [sessionId, uid]
        );
        row = r.rows[0];
      }
    }
    if (!row && canAccessAdminPanel(user)) {
      const r = await pool.query(`SELECT * FROM cp_support_chat_sessions WHERE id = $1 LIMIT 1`, [sessionId]);
      row = r.rows[0];
    }
    if (!row) return { ok: false, status: 404, message: 'Chat session not found' };
    if (!isChatParticipant(user, row) && !canAccessAdminPanel(user)) {
      return { ok: false, status: 403, message: 'Not a participant in this chat' };
    }
    return { ok: true, row };
  }

  app.post('/saas/support/chat/respond', requireAuth, tenantMiddleware, async (req, res) => {
    try {
      const sessionId = cleanString(req.body?.sessionId);
      const accept = req.body?.accept === true;
      if (!sessionId) return jsonError(res, 400, 'sessionId is required');

      const loaded = await loadChatSessionForUser(pool, sessionId, req.user, {
        preferredTenantId: req.supportTenant.tenantId
      });
      if (!loaded.ok) return jsonError(res, loaded.status, loaded.message);
      const row = loaded.row;
      if (String(row.customer_user_id) !== authUserId(req.user)) {
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
      broadcastSupportEvents(row.tenant_id, 'chat-response', {
        sessionId,
        status,
        customerUserId: authUserId(req.user),
        adminUserId: row.admin_user_id,
        customerDisplayName: formatUserDisplayNameFromUser(req.user),
        adminDisplayName: await lookupUserDisplayName(pool, row.admin_user_id)
      });
      return res.json({ success: true, sessionId, status });
    } catch (error) {
      console.error('[saas/support/chat/respond]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  /** Static chat/remote lookup routes must register before /:sessionId/ param routes. */
  app.get('/saas/support/chat/pending', requireAuth, tenantMiddleware, async (req, res) => {
    try {
      const r = await pool.query(
        `SELECT id, tenant_id, customer_user_id, admin_user_id, status, created_at, updated_at
         FROM cp_support_chat_sessions
         WHERE tenant_id = $1 AND customer_user_id = $2 AND status = 'pending'
         ORDER BY updated_at DESC LIMIT 1`,
        [req.supportTenant.tenantId, authUserId(req.user)]
      );
      const row = r.rows[0];
      if (!row) return res.json({ success: true, session: null });
      return res.json({
        success: true,
        session: {
          id: row.id,
          tenantId: row.tenant_id,
          status: row.status,
          customerUserId: row.customer_user_id,
          adminUserId: row.admin_user_id,
          createdAt: row.created_at,
          updatedAt: row.updated_at
        }
      });
    } catch (error) {
      console.error('[saas/support/chat/pending]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.get('/saas/support/chat/active', requireAuth, tenantMiddleware, async (req, res) => {
    try {
      const uid = authUserId(req.user);
      const sessionId = cleanString(req.query?.sessionId);
      let row = null;

      const customerParams = [req.supportTenant.tenantId, uid];
      let customerSql = `
          SELECT id, tenant_id, customer_user_id, admin_user_id, status, created_at, updated_at
          FROM cp_support_chat_sessions
          WHERE tenant_id = $1 AND customer_user_id = $2
            AND status IN ('pending', 'active')`;
      if (sessionId) {
        customerParams.push(sessionId);
        customerSql += ` AND id = $${customerParams.length}`;
      }
      customerSql += `
          ORDER BY CASE status WHEN 'active' THEN 0 WHEN 'pending' THEN 1 ELSE 2 END, updated_at DESC
          LIMIT 1`;
      const customerHit = await pool.query(customerSql, customerParams);
      row = customerHit.rows[0];

      if (!row && canAccessAdminPanel(req.user)) {
        const params = [uid];
        let sql = `
          SELECT id, tenant_id, customer_user_id, admin_user_id, status, created_at, updated_at
          FROM cp_support_chat_sessions
          WHERE admin_user_id = $1 AND status IN ('pending', 'active')`;
        if (sessionId) {
          params.push(sessionId);
          sql += ` AND id = $${params.length}`;
        }
        sql += `
          ORDER BY CASE status WHEN 'active' THEN 0 WHEN 'pending' THEN 1 ELSE 2 END, updated_at DESC
          LIMIT 1`;
        const r = await pool.query(sql, params);
        row = r.rows[0];
      }

      if (!row && uid) {
        const params = [uid];
        let sql = `
          SELECT id, tenant_id, customer_user_id, admin_user_id, status, created_at, updated_at
          FROM cp_support_chat_sessions
          WHERE (customer_user_id = $1 OR admin_user_id = $1) AND status IN ('pending', 'active')`;
        if (sessionId) {
          params.push(sessionId);
          sql += ` AND id = $${params.length}`;
        }
        sql += `
          ORDER BY CASE status WHEN 'active' THEN 0 WHEN 'pending' THEN 1 ELSE 2 END, updated_at DESC
          LIMIT 1`;
        const participantHit = await pool.query(sql, params);
        row = participantHit.rows[0];
      }

      if (!row) return res.json({ success: true, session: null });
      const [customerDisplayName, adminDisplayName] = await Promise.all([
        lookupUserDisplayName(pool, row.customer_user_id),
        lookupUserDisplayName(pool, row.admin_user_id)
      ]);
      return res.json({
        success: true,
        session: {
          id: row.id,
          tenantId: row.tenant_id,
          status: row.status,
          customerUserId: row.customer_user_id,
          adminUserId: row.admin_user_id,
          customerDisplayName,
          adminDisplayName,
          createdAt: row.created_at,
          updatedAt: row.updated_at
        }
      });
    } catch (error) {
      console.error('[saas/support/chat/active]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.get('/saas/support/remote/active', requireAuth, tenantMiddleware, async (req, res) => {
    try {
      const uid = authUserId(req.user);
      const r = await pool.query(
        `SELECT id, tenant_id, customer_user_id, admin_user_id, status, persist_token, customer_tab_id, initiated_by, chat_session_id, created_at, updated_at
         FROM cp_support_remote_sessions
         WHERE ended_at IS NULL
           AND (
             (status = 'active' AND (customer_user_id = $1 OR admin_user_id = $1))
             OR (status = 'pending' AND customer_user_id = $1 AND initiated_by = 'admin')
             OR (status = 'pending' AND customer_user_id = $1 AND initiated_by = 'customer')
             OR (status = 'pending' AND admin_user_id = $1 AND initiated_by = 'customer')
           )
         ORDER BY CASE status WHEN 'pending' THEN 0 WHEN 'active' THEN 1 ELSE 2 END, updated_at DESC LIMIT 1`,
        [uid]
      );
      const row = r.rows[0];
      if (!row) return res.json({ success: true, session: null });
      let customerDisplayName = '';
      if (row.status === 'pending' && row.initiated_by === 'customer') {
        customerDisplayName = await lookupUserDisplayName(pool, row.customer_user_id);
      }
      return res.json({
        success: true,
        session: {
          id: row.id,
          tenantId: row.tenant_id,
          status: row.status,
          customerUserId: row.customer_user_id,
          adminUserId: row.admin_user_id,
          persistToken: row.persist_token,
          customerTabId: row.customer_tab_id,
          initiatedBy: row.initiated_by || 'admin',
          chatSessionId: row.chat_session_id || null,
          customerDisplayName: customerDisplayName || undefined,
          createdAt: row.created_at,
          updatedAt: row.updated_at
        }
      });
    } catch (error) {
      console.error('[saas/support/remote/active]', error);
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
      const [customerDisplayName, adminDisplayName] = await Promise.all([
        lookupUserDisplayName(pool, row.customer_user_id),
        lookupUserDisplayName(pool, row.admin_user_id)
      ]);
      const msgs = await pool.query(
        `SELECT id, session_id, sender_user_id, body, message_type, attachment, created_at
         FROM cp_support_chat_messages WHERE session_id = $1 ORDER BY created_at ASC`,
        [sessionId]
      );
      const messages = await Promise.all(msgs.rows.map((m) => mapChatMessageRowWithSender(pool, m)));
      return res.json({
        success: true,
        session: {
          id: row.id,
          tenantId: row.tenant_id,
          status: row.status,
          customerUserId: row.customer_user_id,
          adminUserId: row.admin_user_id,
          customerDisplayName,
          adminDisplayName
        },
        messages
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
      const messageType = cleanString(req.body?.messageType || 'text') || 'text';
      const attachment = req.body?.attachment && typeof req.body.attachment === 'object' ? req.body.attachment : null;
      if (!body && !attachment) return jsonError(res, 400, 'Message body or attachment is required');

      const loaded = await loadChatSessionForUser(pool, sessionId, req.user, {
        preferredTenantId: req.supportTenant.tenantId
      });
      if (!loaded.ok) return jsonError(res, loaded.status, loaded.message);
      const row = loaded.row;
      if (row.status !== 'active') return jsonError(res, 400, 'Chat is not active');
      if (!isChatParticipant(req.user, row) && !canAccessAdminPanel(req.user)) {
        return jsonError(res, 403, 'Not a participant in this chat');
      }

      const message = await insertChatMessageRow(pool, {
        sessionId,
        senderUserId: authUserId(req.user),
        body: body || (attachment?.name ? `Sent ${attachment.name}` : 'Attachment'),
        messageType,
        attachment
      });
      const mapped = await mapChatMessageRowWithSender(pool, message);
      broadcastSupportEvents(row.tenant_id, 'chat-message', {
        sessionId: String(sessionId),
        message: mapped
      });
      return res.json({
        success: true,
        message: mapped
      });
    } catch (error) {
      console.error('[saas/support/chat/messages POST]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.post('/saas/support/chat/:sessionId/attachment', requireAuth, tenantMiddleware, async (req, res) => {
    try {
      const sessionId = cleanString(req.params.sessionId);
      const messageType = cleanString(req.body?.messageType || 'image') || 'image';
      const name = cleanString(req.body?.name || req.body?.attachment?.name || 'attachment').slice(0, 255);
      const mimeType = cleanString(req.body?.mimeType || req.body?.attachment?.mimeType || 'application/octet-stream').slice(0, 128);
      const dataBase64 = cleanString(req.body?.dataBase64 || req.body?.attachment?.dataBase64);
      const caption = cleanString(req.body?.body || req.body?.caption).slice(0, 4000);
      const buf = decodeAttachmentBase64(dataBase64);
      if (!buf) return jsonError(res, 400, 'Valid attachment data is required (max 8 MB)');

      const loaded = await loadChatSessionForUser(pool, sessionId, req.user, {
        preferredTenantId: req.supportTenant.tenantId
      });
      if (!loaded.ok) return jsonError(res, loaded.status, loaded.message);
      const row = loaded.row;
      if (row.status !== 'active') return jsonError(res, 400, 'Chat is not active');
      if (!isChatParticipant(req.user, row) && !canAccessAdminPanel(req.user)) {
        return jsonError(res, 403, 'Not a participant in this chat');
      }

      const attachment = {
        name,
        mimeType,
        size: buf.length,
        dataBase64: buf.toString('base64')
      };
      const message = await insertChatMessageRow(pool, {
        sessionId,
        senderUserId: authUserId(req.user),
        body: caption || (messageType === 'image' ? 'Screenshot' : `File: ${name}`),
        messageType,
        attachment
      });
      const mapped = await mapChatMessageRowWithSender(pool, message);
      broadcastSupportEvents(row.tenant_id, 'chat-message', {
        sessionId: String(sessionId),
        message: mapped
      });
      return res.json({ success: true, message: mapped });
    } catch (error) {
      console.error('[saas/support/chat/attachment POST]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  /** Presign PUT to Wasabi chat-uploads/{tenantId}/{sessionId}/{fileId}-{filename}. */
  app.post('/saas/support/chat/:sessionId/file-upload/init', requireAuth, tenantMiddleware, async (req, res) => {
    try {
      const s3 = getChatUploadWasabi();
      const bucket = chatUploadBucketName();
      if (!s3 || !bucket) {
        return jsonError(res, 503, 'Chat file storage is not configured (Wasabi env missing)');
      }

      const sessionId = cleanString(req.params.sessionId);
      const fileName = cleanString(req.body?.fileName || req.body?.name).slice(0, 255);
      const mimeType = cleanString(req.body?.mimeType || 'application/octet-stream').slice(0, 128);
      const fileSize = Number(req.body?.fileSize ?? req.body?.size);
      if (!fileName) return jsonError(res, 400, 'fileName is required');
      if (!Number.isFinite(fileSize) || fileSize <= 0) return jsonError(res, 400, 'fileSize must be a positive number');
      if (fileSize > MAX_CHAT_UPLOAD_BYTES) {
        return jsonError(res, 400, `File exceeds ${MAX_CHAT_UPLOAD_BYTES} byte limit`);
      }

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

      const built = buildChatUploadStorageKey(row.tenant_id, sessionId, fileName);
      const presigned = await presignChatUploadPut(s3, bucket, built.wasabiKey, mimeType, built.expiresAt);
      return res.json({
        success: true,
        fileId: built.fileId,
        wasabiKey: built.wasabiKey,
        uploadUrl: presigned.url,
        uploadMethod: presigned.method,
        uploadHeaders: presigned.headers,
        uploadExpiresIn: presigned.expiresIn,
        expiresAt: built.expiresAt,
        maxBytes: MAX_CHAT_UPLOAD_BYTES
      });
    } catch (error) {
      console.error('[saas/support/chat/file-upload/init POST]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  /** After browser PUT to Wasabi, persist chat message and notify both peers. */
  app.post('/saas/support/chat/:sessionId/file-upload/complete', requireAuth, tenantMiddleware, async (req, res) => {
    try {
      const s3 = getChatUploadWasabi();
      const bucket = chatUploadBucketName();
      if (!s3 || !bucket) {
        return jsonError(res, 503, 'Chat file storage is not configured (Wasabi env missing)');
      }

      const sessionId = cleanString(req.params.sessionId);
      const wasabiKey = cleanString(req.body?.wasabiKey);
      const fileName = cleanString(req.body?.fileName || req.body?.name).slice(0, 255);
      const mimeType = cleanString(req.body?.mimeType || 'application/octet-stream').slice(0, 128);
      const expiresAt = cleanString(req.body?.expiresAt);
      const reportedSize = Number(req.body?.fileSize ?? req.body?.size);
      if (!wasabiKey || !fileName) return jsonError(res, 400, 'wasabiKey and fileName are required');
      if (!expiresAt) return jsonError(res, 400, 'expiresAt is required');
      if (isChatUploadExpired(expiresAt)) return jsonError(res, 410, 'Upload slot expired');

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
      if (!isValidChatUploadStorageKey(wasabiKey, row.tenant_id, sessionId)) {
        return jsonError(res, 400, 'Invalid wasabiKey for this chat session');
      }

      let head;
      try {
        head = await headChatUploadObject(s3, bucket, wasabiKey);
      } catch {
        return jsonError(res, 400, 'Uploaded file not found in storage — finish PUT before complete');
      }
      const storedSize = Number(head.ContentLength || 0);
      if (!storedSize || storedSize > MAX_CHAT_UPLOAD_BYTES) {
        return jsonError(res, 400, 'Uploaded file size is invalid');
      }
      if (Number.isFinite(reportedSize) && reportedSize > 0 && Math.abs(storedSize - reportedSize) > 4096) {
        return jsonError(res, 400, 'Uploaded file size mismatch');
      }

      const attachment = {
        name: fileName,
        mimeType,
        size: storedSize,
        wasabiKey,
        expiresAt
      };
      const message = await insertChatMessageRow(pool, {
        sessionId,
        senderUserId: req.user.id,
        body: `Shared file: ${fileName}`,
        messageType: 'file',
        attachment
      });
      const mapped = mapChatMessageRow(message);
      broadcastSupportEvents(row.tenant_id, 'chat-message', {
        sessionId: String(sessionId),
        message: mapped
      });
      broadcastSupportEvents(row.tenant_id, 'chat-file-uploaded', {
        sessionId: String(sessionId),
        message: mapped
      });
      return res.json({ success: true, message: mapped });
    } catch (error) {
      console.error('[saas/support/chat/file-upload/complete POST]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  /** Presign GET for a stored chat file (checks DB message + retention). */
  app.post('/saas/support/chat/:sessionId/file-download/presign', requireAuth, tenantMiddleware, async (req, res) => {
    try {
      const s3 = getChatUploadWasabi();
      const bucket = chatUploadBucketName();
      if (!s3 || !bucket) {
        return jsonError(res, 503, 'Chat file storage is not configured (Wasabi env missing)');
      }

      const sessionId = cleanString(req.params.sessionId);
      const messageId = cleanString(req.body?.messageId);
      const wasabiKeyBody = cleanString(req.body?.wasabiKey);
      if (!messageId && !wasabiKeyBody) return jsonError(res, 400, 'messageId or wasabiKey is required');

      const loaded = await loadChatSessionForUser(pool, sessionId, req.user, {
        preferredTenantId: req.supportTenant.tenantId
      });
      if (!loaded.ok) return jsonError(res, loaded.status, loaded.message);
      const row = loaded.row;
      const uid = String(req.user.id);
      if (uid !== String(row.customer_user_id) && uid !== String(row.admin_user_id)) {
        return jsonError(res, 403, 'Not a participant in this chat');
      }

      let attachment = null;
      let fileName = 'download';
      if (messageId) {
        const msgRow = await pool.query(
          `SELECT id, message_type, attachment FROM cp_support_chat_messages
           WHERE id = $1 AND session_id = $2 LIMIT 1`,
          [messageId, sessionId]
        );
        const m = msgRow.rows[0];
        if (!m) return jsonError(res, 404, 'Message not found');
        if (String(m.message_type || '') !== 'file') return jsonError(res, 400, 'Message is not a file');
        attachment = m.attachment;
        if (typeof attachment === 'string') {
          try {
            attachment = JSON.parse(attachment);
          } catch {
            attachment = null;
          }
        }
      } else {
        attachment = { wasabiKey: wasabiKeyBody };
      }

      const wasabiKey = cleanString(attachment?.wasabiKey);
      if (!wasabiKey) return jsonError(res, 400, 'File is not stored in object storage');
      if (!isValidChatUploadStorageKey(wasabiKey, row.tenant_id, sessionId)) {
        return jsonError(res, 403, 'Invalid file key for this session');
      }
      const expiresAt = cleanString(attachment?.expiresAt);
      if (isChatUploadExpired(expiresAt)) {
        return jsonError(res, 410, 'File has expired and is no longer available');
      }
      fileName = cleanString(attachment?.name || attachment?.fileName || fileName).slice(0, 255) || 'download';

      const presigned = await presignChatUploadGet(s3, bucket, wasabiKey);
      return res.json({
        success: true,
        url: presigned.url,
        expiresIn: presigned.expiresIn,
        fileName,
        mimeType: cleanString(attachment?.mimeType || 'application/octet-stream'),
        size: Number(attachment?.size || 0) || null
      });
    } catch (error) {
      console.error('[saas/support/chat/file-download/presign POST]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.post('/saas/support/chat/:sessionId/file-offer', requireAuth, tenantMiddleware, async (req, res) => {
    try {
      pruneExpiredFileOffers();
      const sessionId = cleanString(req.params.sessionId);
      const fileName = cleanString(req.body?.fileName || req.body?.name).slice(0, 255);
      const mimeType = cleanString(req.body?.mimeType || 'application/octet-stream').slice(0, 128);
      const dataBase64 = cleanString(req.body?.dataBase64);
      if (!fileName) return jsonError(res, 400, 'fileName is required');
      const buf = decodeAttachmentBase64(dataBase64);
      if (!buf) return jsonError(res, 400, 'Valid file data is required (max 8 MB)');

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
      const toUserId =
        uid === String(row.customer_user_id) ? String(row.admin_user_id) : String(row.customer_user_id);
      const offerId = crypto.randomUUID();
      fileOffersById.set(offerId, {
        id: offerId,
        sessionId,
        tenantId: row.tenant_id,
        fromUserId: uid,
        toUserId,
        fileName,
        fileSize: buf.length,
        mimeType,
        dataBase64: buf.toString('base64'),
        createdAt: Date.now()
      });
      const fromDisplayName = await lookupUserDisplayName(pool, uid);
      broadcastSupportEvents(row.tenant_id, 'chat-file-offer', {
        sessionId,
        offerId,
        fromUserId: uid,
        toUserId,
        fileName,
        fileSize: buf.length,
        mimeType,
        fromDisplayName
      });
      return res.json({ success: true, offerId });
    } catch (error) {
      console.error('[saas/support/chat/file-offer POST]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.post('/saas/support/chat/:sessionId/file-respond', requireAuth, tenantMiddleware, async (req, res) => {
    try {
      pruneExpiredFileOffers();
      const sessionId = cleanString(req.params.sessionId);
      const offerId = cleanString(req.body?.offerId);
      const accept = req.body?.accept === true;
      if (!offerId) return jsonError(res, 400, 'offerId is required');

      const offer = fileOffersById.get(offerId);
      if (!offer || offer.sessionId !== sessionId) {
        return jsonError(res, 404, 'File offer not found or expired');
      }
      const uid = String(req.user.id);
      if (uid !== offer.toUserId) return jsonError(res, 403, 'Only the recipient can respond to this offer');

      const loaded = await loadChatSessionForUser(pool, sessionId, req.user, {
        preferredTenantId: req.supportTenant.tenantId
      });
      if (!loaded.ok) return jsonError(res, loaded.status, loaded.message);
      const row = loaded.row;
      if (row.status !== 'active') return jsonError(res, 400, 'Chat is not active');

      fileOffersById.delete(offerId);
      const senderName = await lookupUserDisplayName(pool, offer.fromUserId);
      const responderName = await lookupUserDisplayName(pool, uid);

      if (accept) {
        const attachment = {
          name: offer.fileName,
          mimeType: offer.mimeType,
          size: offer.fileSize,
          dataBase64: offer.dataBase64
        };
        const fileMsg = await insertChatMessageRow(pool, {
          sessionId,
          senderUserId: offer.fromUserId,
          body: `Shared file: ${offer.fileName}`,
          messageType: 'file',
          attachment
        });
        const confirmMsg = await insertChatMessageRow(pool, {
          sessionId,
          senderUserId: uid,
          body: `${responderName} accepted ${offer.fileName}`,
          messageType: 'system',
          attachment: { variant: 'info' }
        });
        broadcastSupportEvents(row.tenant_id, 'chat-message', {
          sessionId: String(sessionId),
          message: mapChatMessageRow(fileMsg)
        });
        broadcastSupportEvents(row.tenant_id, 'chat-message', {
          sessionId: String(sessionId),
          message: mapChatMessageRow(confirmMsg)
        });
        return res.json({
          success: true,
          accepted: true,
          message: mapChatMessageRow(fileMsg)
        });
      }

      const declineForRequester = await insertChatMessageRow(pool, {
        sessionId,
        senderUserId: uid,
        body: `${responderName} declined your file transfer (${offer.fileName})`,
        messageType: 'system',
        attachment: { variant: 'warning', targetUserId: offer.fromUserId }
      });
      const declineForDecliner = await insertChatMessageRow(pool, {
        sessionId,
        senderUserId: uid,
        body: `You declined the file transfer from ${senderName}`,
        messageType: 'system',
        attachment: { variant: 'warning', targetUserId: uid }
      });
      broadcastSupportEvents(row.tenant_id, 'chat-message', {
        sessionId: String(sessionId),
        message: mapChatMessageRow(declineForRequester)
      });
      broadcastSupportEvents(row.tenant_id, 'chat-message', {
        sessionId: String(sessionId),
        message: mapChatMessageRow(declineForDecliner)
      });
      return res.json({ success: true, accepted: false });
    } catch (error) {
      console.error('[saas/support/chat/file-respond POST]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.post('/saas/support/chat/end', requireAuth, tenantMiddleware, async (req, res) => {
    try {
      const sessionId = cleanString(req.body?.sessionId);
      if (!sessionId) return jsonError(res, 400, 'sessionId is required');

      const loaded = await loadChatSessionForUser(pool, sessionId, req.user, {
        preferredTenantId: req.supportTenant.tenantId
      });
      if (!loaded.ok) return jsonError(res, loaded.status, loaded.message);
      const row = loaded.row;
      if (row.status === 'closed' || row.status === 'declined') {
        return res.json({ success: true, sessionId, status: row.status });
      }

      await pool.query(
        `UPDATE cp_support_chat_sessions SET status = 'closed', updated_at = NOW() WHERE id = $1`,
        [sessionId]
      );
      broadcastSupportEvents(row.tenant_id, 'chat-ended', {
        sessionId,
        customerUserId: row.customer_user_id,
        adminUserId: row.admin_user_id,
        reason: 'ended'
      });
      return res.json({ success: true, sessionId, status: 'closed' });
    } catch (error) {
      console.error('[saas/support/chat/end]', error);
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
    if (!row) {
      const uid = authUserId(user);
      if (uid) {
        const r = await pool.query(
          `SELECT * FROM cp_support_remote_sessions
           WHERE id = $1 AND (customer_user_id = $2 OR admin_user_id = $2)
           LIMIT 1`,
          [sessionId, uid]
        );
        row = r.rows[0];
      }
    }
    if (!row && canAccessAdminPanel(user)) {
      const r = await pool.query(`SELECT * FROM cp_support_remote_sessions WHERE id = $1 LIMIT 1`, [sessionId]);
      row = r.rows[0];
    }
    if (!row) return { ok: false, status: 404, message: 'Remote session not found' };
    if (!isRemoteParticipant(user, row) && !canAccessAdminPanel(user)) {
      return { ok: false, status: 403, message: 'Not a participant in this remote session' };
    }
    return { ok: true, row };
  }

  app.post('/saas/support/remote/request', requireAuth, tenantMiddleware, requireSupportAdmin, async (req, res) => {
    try {
      const customerUserId = cleanString(req.body?.customerUserId);
      const customerTabId = cleanString(req.body?.customerTabId) || 'default';
      const chatSessionId = cleanString(req.body?.chatSessionId);
      if (!customerUserId) return jsonError(res, 400, 'customerUserId is required');
      const adminUserId = cleanString(req.user?.id ?? req.user?.userId);

      // Prefer the live chat's tenant — BASE admin + SaaS customer must land on the customer channel.
      let targetTenantId = await resolveTargetTenantId(pool, req, req.body?.tenantId, customerUserId);
      let linkedChatSessionId = chatSessionId || '';
      if (linkedChatSessionId) {
        const chatHit = await pool.query(
          `SELECT id, tenant_id, customer_user_id, admin_user_id, status
           FROM cp_support_chat_sessions
           WHERE id = $1
           LIMIT 1`,
          [linkedChatSessionId]
        );
        const chatRow = chatHit.rows[0];
        if (!chatRow) return jsonError(res, 404, 'Chat session not found');
        if (String(chatRow.status) !== 'active') return jsonError(res, 400, 'Chat must be active');
        if (String(chatRow.customer_user_id) !== customerUserId) {
          return jsonError(res, 400, 'Customer does not match this chat');
        }
        targetTenantId = String(chatRow.tenant_id);
      }

      // Only supersede prior remote sessions — never tear down the live support chat.
      const priorRemote = await endRemoteSessionsForCustomer(pool, targetTenantId, customerUserId, {
        adminUserId
      });
      await broadcastEndedSessions(pool, targetTenantId, [], priorRemote, 'superseded');

      const persistToken = crypto.randomBytes(24).toString('base64url');
      const r = await pool.query(
        `INSERT INTO cp_support_remote_sessions (
            tenant_id, customer_user_id, admin_user_id, status, persist_token, customer_tab_id,
            initiated_by, chat_session_id
          ) VALUES ($1,$2,$3,'pending',$4,$5,'admin',$6)
          RETURNING id, status, persist_token`,
        [
          targetTenantId,
          customerUserId,
          adminUserId,
          persistToken,
          customerTabId,
          linkedChatSessionId || null
        ]
      );
      const session = r.rows[0];
      const invitePayload = {
        sessionId: session.id,
        customerUserId,
        customerTabId,
        adminUserId,
        initiatedBy: 'admin',
        chatSessionId: linkedChatSessionId || null
      };
      broadcastSupportEvents(targetTenantId, 'remote-request', invitePayload);

      // Also post into the live chat so SaaS customers receive the invite via message poll
      // even when SSE is on a different tenant channel than the admin.
      if (linkedChatSessionId) {
        const message = await insertChatMessageRow(pool, {
          sessionId: linkedChatSessionId,
          senderUserId: adminUserId,
          body: 'Remote desktop request — accept to share your screen with support.',
          messageType: 'remote-invite',
          attachment: {
            remoteSessionId: session.id,
            status: 'pending',
            initiatedBy: 'admin'
          }
        });
        const mapped = await mapChatMessageRowWithSender(pool, message);
        broadcastSupportEvents(targetTenantId, 'chat-message', {
          sessionId: String(linkedChatSessionId),
          message: mapped
        });
      }

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

      const loaded = await loadRemoteSessionForUser(pool, sessionId, req.user, {
        preferredTenantId: req.supportTenant.tenantId
      });
      if (!loaded.ok) return jsonError(res, loaded.status, loaded.message);
      const row = loaded.row;
      if (String(row.customer_user_id) !== authUserId(req.user)) {
        return jsonError(res, 403, 'Only the customer can accept or decline remote control');
      }
      if (row.status !== 'pending') {
        return res.json({ success: true, sessionId, status: row.status, persistToken: row.persist_token });
      }
      if (String(row.initiated_by || 'admin') !== 'admin') {
        return jsonError(res, 400, 'This remote session is waiting for admin response');
      }

      const status = accept ? 'active' : 'declined';
      await pool.query(
        `UPDATE cp_support_remote_sessions SET status = $2, updated_at = NOW(), ended_at = CASE WHEN $2 = 'declined' THEN NOW() ELSE NULL END WHERE id = $1`,
        [sessionId, status]
      );
      broadcastSupportEvents(row.tenant_id, 'remote-response', {
        sessionId,
        status,
        customerUserId: authUserId(req.user),
        adminUserId: row.admin_user_id,
        initiatedBy: row.initiated_by || 'admin',
        chatSessionId: row.chat_session_id || null,
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

  app.post('/saas/support/remote/customer-request', requireAuth, tenantMiddleware, async (req, res) => {
    try {
      const chatSessionId = cleanString(req.body?.chatSessionId);
      const customerTabId = cleanString(req.body?.tabId) || 'default';
      if (!chatSessionId) return jsonError(res, 400, 'chatSessionId is required');

      const loaded = await loadChatSessionForUser(pool, chatSessionId, req.user, {
        preferredTenantId: req.supportTenant.tenantId
      });
      if (!loaded.ok) return jsonError(res, loaded.status, loaded.message);
      const chatRow = loaded.row;
      if (chatRow.status !== 'active') return jsonError(res, 400, 'Chat must be active');
      if (String(chatRow.customer_user_id) !== String(req.user.id)) {
        return jsonError(res, 403, 'Only the customer can request remote help');
      }
      if (!chatRow.admin_user_id) return jsonError(res, 400, 'No admin connected to this chat');

      const pendingRemote = await pool.query(
        `SELECT id FROM cp_support_remote_sessions
         WHERE tenant_id = $1 AND customer_user_id = $2 AND status = 'pending' AND initiated_by = 'customer'
         LIMIT 1`,
        [chatRow.tenant_id, req.user.id]
      );
      if (pendingRemote.rows[0]) {
        return res.json({
          success: true,
          sessionId: pendingRemote.rows[0].id,
          status: 'pending',
          alreadyPending: true
        });
      }

      await pool.query(
        `UPDATE cp_support_remote_sessions
         SET status = 'declined', ended_at = NOW(), updated_at = NOW()
         WHERE tenant_id = $1 AND customer_user_id = $2 AND status = 'pending' AND initiated_by = 'admin'`,
        [chatRow.tenant_id, chatRow.customer_user_id]
      );

      const persistToken = crypto.randomBytes(24).toString('base64url');
      const r = await pool.query(
        `INSERT INTO cp_support_remote_sessions (
            tenant_id, customer_user_id, admin_user_id, status, persist_token, customer_tab_id, initiated_by, chat_session_id
          ) VALUES ($1,$2,$3,'pending',$4,$5,'customer',$6)
          RETURNING id, status, persist_token`,
        [
          chatRow.tenant_id,
          chatRow.customer_user_id,
          chatRow.admin_user_id,
          persistToken,
          customerTabId,
          chatSessionId
        ]
      );
      const session = r.rows[0];
      const customerDisplayName = await lookupUserDisplayName(pool, chatRow.customer_user_id);
      broadcastSupportEvents(chatRow.tenant_id, 'remote-help-request', {
        sessionId: session.id,
        chatSessionId,
        customerUserId: chatRow.customer_user_id,
        adminUserId: chatRow.admin_user_id,
        customerDisplayName,
        customerTabId
      });
      return res.json({
        success: true,
        sessionId: session.id,
        status: session.status
      });
    } catch (error) {
      console.error('[saas/support/remote/customer-request]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.post('/saas/support/remote/admin-respond', requireAuth, tenantMiddleware, requireSupportAdmin, async (req, res) => {
    try {
      const sessionId = cleanString(req.body?.sessionId);
      const accept = req.body?.accept === true;
      if (!sessionId) return jsonError(res, 400, 'sessionId is required');

      const r = await pool.query(
        `SELECT * FROM cp_support_remote_sessions WHERE id = $1 LIMIT 1`,
        [sessionId]
      );
      const row = r.rows[0];
      if (!row) return jsonError(res, 404, 'Remote session not found');
      if (String(row.admin_user_id) !== String(req.user.id)) {
        return jsonError(res, 403, 'Only the assigned admin can respond');
      }
      if (row.initiated_by !== 'customer') {
        return jsonError(res, 400, 'This remote session was not customer-initiated');
      }
      if (row.status !== 'pending') {
        return res.json({
          success: true,
          sessionId,
          status: row.status,
          persistToken: row.persist_token
        });
      }

      const adminDisplayName = await lookupUserDisplayName(pool, req.user.id);
      const chatSessionId = cleanString(row.chat_session_id);

      if (accept) {
        await pool.query(
          `UPDATE cp_support_remote_sessions SET status = 'active', updated_at = NOW(), ended_at = NULL WHERE id = $1`,
          [sessionId]
        );
        await assignSupportAdmin(
          pool,
          row.tenant_id,
          row.customer_user_id,
          cleanString(row.customer_tab_id) || 'default',
          req.user,
          adminDisplayName
        );
        broadcastSupportEvents(row.tenant_id, 'remote-response', {
          sessionId,
          status: 'active',
          customerUserId: row.customer_user_id,
          adminUserId: row.admin_user_id,
          persistToken: row.persist_token,
          initiatedBy: 'customer'
        });
        if (chatSessionId) {
          const sysMsg = await insertChatMessageRow(pool, {
            sessionId: chatSessionId,
            senderUserId: req.user.id,
            body: `${adminDisplayName} accepted your remote support request`,
            messageType: 'system',
            attachment: { variant: 'info' }
          });
          broadcastSupportEvents(row.tenant_id, 'chat-message', {
            sessionId: chatSessionId,
            message: mapChatMessageRow(sysMsg)
          });
        }
        return res.json({
          success: true,
          sessionId,
          status: 'active',
          persistToken: row.persist_token
        });
      }

      await pool.query(
        `UPDATE cp_support_remote_sessions SET status = 'declined', updated_at = NOW(), ended_at = NOW() WHERE id = $1`,
        [sessionId]
      );
      if (chatSessionId) {
        const forCustomer = await insertChatMessageRow(pool, {
          sessionId: chatSessionId,
          senderUserId: req.user.id,
          body: `${adminDisplayName} has declined your request for Remote support`,
          messageType: 'system',
          attachment: { variant: 'warning', targetUserId: row.customer_user_id }
        });
        const forAdmin = await insertChatMessageRow(pool, {
          sessionId: chatSessionId,
          senderUserId: req.user.id,
          body: 'You have declined the request.',
          messageType: 'system',
          attachment: { variant: 'warning', targetUserId: row.admin_user_id }
        });
        broadcastSupportEvents(row.tenant_id, 'chat-message', {
          sessionId: chatSessionId,
          message: mapChatMessageRow(forCustomer)
        });
        broadcastSupportEvents(row.tenant_id, 'chat-message', {
          sessionId: chatSessionId,
          message: mapChatMessageRow(forAdmin)
        });
      }
      broadcastSupportEvents(row.tenant_id, 'remote-help-declined', {
        sessionId,
        customerUserId: row.customer_user_id,
        adminUserId: row.admin_user_id
      });
      return res.json({ success: true, sessionId, status: 'declined' });
    } catch (error) {
      console.error('[saas/support/remote/admin-respond]', error);
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
      await clearRemoteRelayPg(pool, sessionId);
      broadcastSupportEvents(row.tenant_id, 'remote-ended', {
        sessionId,
        customerUserId: row.customer_user_id,
        adminUserId: row.admin_user_id
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
      const targetTenantId = await resolveTargetTenantId(pool, req, req.body?.tenantId, customerUserId);
      const ended = await terminateCustomerSessions(pool, targetTenantId, customerUserId, {
        reason: 'cancelled'
      });
      return res.json({ success: true, ...ended });
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
      if (!type || !['offer', 'answer', 'ice', 'screen-ready'].includes(type)) {
        return jsonError(res, 400, 'type must be offer, answer, ice, or screen-ready');
      }

      const loaded = await loadRemoteSessionForUser(pool, sessionId, req.user, {
        preferredTenantId: req.supportTenant.tenantId
      });
      if (!loaded.ok) return jsonError(res, loaded.status, loaded.message);
      const row = loaded.row;
      if (row.status !== 'active') return jsonError(res, 400, 'Remote session is not active');

      const entry = await insertRemoteSignalPg(pool, sessionId, req.user.id, type, payload);
      if (!entry) return jsonError(res, 500, 'Failed to store signal');
      if (type !== 'ice') {
        broadcastSupportEvents(row.tenant_id, 'remote-signal', {
          sessionId,
          signalId: entry?.id,
          fromUserId: req.user.id,
          type,
          payload
        });
      }
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

      const signals = await fetchRemoteSignalsPg(pool, sessionId, afterId);
      return res.json({ success: true, signals });
    } catch (error) {
      console.error('[saas/support/remote/signals GET]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.post('/saas/support/remote/:sessionId/frame', requireAuth, tenantMiddleware, async (req, res) => {
    try {
      const sessionId = cleanString(req.params.sessionId);
      if (!sessionId) return jsonError(res, 400, 'sessionId is required');

      const loaded = await loadRemoteSessionForUser(pool, sessionId, req.user, {
        preferredTenantId: req.supportTenant.tenantId
      });
      if (!loaded.ok) return jsonError(res, loaded.status, loaded.message);
      const row = loaded.row;
      if (row.status !== 'active') return jsonError(res, 400, 'Remote session is not active');
      if (String(row.customer_user_id) !== String(req.user.id)) {
        return jsonError(res, 403, 'Only the customer can upload viewport frames');
      }

      const stored = await upsertRemoteFramePg(pool, sessionId, req.body || {});
      if (!stored) return jsonError(res, 400, 'Valid frame data is required');
      return res.json({ success: true, seq: stored.seq });
    } catch (error) {
      console.error('[saas/support/remote/frame POST]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.get('/saas/support/remote/:sessionId/frame', requireAuth, tenantMiddleware, async (req, res) => {
    try {
      const sessionId = cleanString(req.params.sessionId);
      const afterSeq = Math.max(0, Number(req.query?.afterSeq || 0));
      if (!sessionId) return jsonError(res, 400, 'sessionId is required');

      const loaded = await loadRemoteSessionForUser(pool, sessionId, req.user, {
        preferredTenantId: req.supportTenant.tenantId
      });
      if (!loaded.ok) return jsonError(res, loaded.status, loaded.message);
      const row = loaded.row;
      if (row.status !== 'active') return jsonError(res, 400, 'Remote session is not active');
      if (String(row.admin_user_id) !== String(req.user.id) && !canAccessAdminPanel(req.user)) {
        return jsonError(res, 403, 'Only the assigned admin can view viewport frames');
      }

      const frame = await fetchRemoteFramePg(pool, sessionId, afterSeq);
      if (!frame) {
        return res.json({ success: true, frame: null });
      }
      return res.json({
        success: true,
        frame: {
          seq: frame.seq,
          mimeType: frame.mimeType,
          dataBase64: frame.dataBase64,
          w: frame.w,
          h: frame.h,
          at: frame.at
        }
      });
    } catch (error) {
      console.error('[saas/support/remote/frame GET]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.post('/saas/support/remote/:sessionId/input', requireAuth, tenantMiddleware, async (req, res) => {
    try {
      const sessionId = cleanString(req.params.sessionId);
      const payload = req.body?.payload;
      if (!sessionId) return jsonError(res, 400, 'sessionId is required');
      if (payload == null || typeof payload !== 'object') {
        return jsonError(res, 400, 'payload object is required');
      }

      const loaded = await loadRemoteSessionForUser(pool, sessionId, req.user, {
        preferredTenantId: req.supportTenant.tenantId
      });
      if (!loaded.ok) return jsonError(res, loaded.status, loaded.message);
      const row = loaded.row;
      if (row.status !== 'active') return jsonError(res, 400, 'Remote session is not active');

      const uid = String(req.user.id);
      const isAdminSender =
        uid === String(row.admin_user_id) || (canAccessAdminPanel(req.user) && uid !== String(row.customer_user_id));
      const isCustomerSender = uid === String(row.customer_user_id);
      const msgType = cleanString(payload?.t);
      if (msgType === 'viewport') {
        if (!isCustomerSender) return jsonError(res, 403, 'Only the customer can publish viewport size');
      } else if (!isAdminSender) {
        return jsonError(res, 403, 'Only the admin can send control input');
      }

      const entry = await insertRemoteInputPg(pool, sessionId, req.user.id, payload);
      if (!entry) return jsonError(res, 500, 'Failed to store input');
      return res.json({ success: true, inputId: entry?.id });
    } catch (error) {
      console.error('[saas/support/remote/input POST]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });

  app.get('/saas/support/remote/:sessionId/input', requireAuth, tenantMiddleware, async (req, res) => {
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
      if (String(row.customer_user_id) !== String(req.user.id)) {
        return jsonError(res, 403, 'Only the customer can poll control input');
      }

      const messages = await fetchRemoteInputsPg(pool, sessionId, afterId);
      return res.json({ success: true, messages });
    } catch (error) {
      console.error('[saas/support/remote/input GET]', error);
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


  app.get('/internal/support/presence-snapshot', requirePresencePeerSecret, async (req, res) => {
    try {
      await ensureSchema();
      const filter = cleanString(req.query?.filter).toLowerCase();
      const supportOnly = filter === 'support';
      const rows = await listAllPresenceRows(pool, { supportOnly });
      return res.json({ success: true, rows });
    } catch (error) {
      console.error('[internal/support/presence-snapshot]', error);
      return jsonError(res, 500, error.message || 'Server error');
    }
  });


}

module.exports = { registerCustomerSupportRoutes, initCustomerSupportSchema };

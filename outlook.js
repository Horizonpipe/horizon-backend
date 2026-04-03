const crypto = require('crypto');

const DEFAULT_SCOPES = 'offline_access openid profile email Mail.Read Mail.ReadWrite Mail.Send User.Read';

function configured() {
  return !!(process.env.OUTLOOK_CLIENT_ID && process.env.OUTLOOK_CLIENT_SECRET && process.env.OUTLOOK_REDIRECT_URI);
}

function tenantId() {
  return process.env.OUTLOOK_TENANT_ID || 'common';
}

function scopes() {
  return process.env.OUTLOOK_SCOPES || DEFAULT_SCOPES;
}

function authSecret() {
  return process.env.OUTLOOK_STATE_SECRET || process.env.OUTLOOK_CLIENT_SECRET || 'horizon-outlook-dev-secret';
}

function clean(value) {
  return String(value || '').trim();
}

function base64url(value) {
  return Buffer.from(value).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64urlDecode(value) {
  const padded = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(padded + '='.repeat((4 - (padded.length % 4 || 4)) % 4), 'base64').toString('utf8');
}

function signState(payload) {
  const raw = JSON.stringify(payload);
  const body = base64url(raw);
  const sig = crypto.createHmac('sha256', authSecret()).update(body).digest('hex');
  return `${body}.${sig}`;
}

function verifyState(value) {
  const [body, sig] = String(value || '').split('.');
  if (!body || !sig) return null;
  const expected = crypto.createHmac('sha256', authSecret()).update(body).digest('hex');
  if (sig.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  try {
    return JSON.parse(base64urlDecode(body));
  } catch {
    return null;
  }
}

function tokenEndpoint() {
  return `https://login.microsoftonline.com/${tenantId()}/oauth2/v2.0/token`;
}

function authorizeEndpoint() {
  return `https://login.microsoftonline.com/${tenantId()}/oauth2/v2.0/authorize`;
}

async function postForm(url, params) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params)
  });
  const text = await response.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = { error_description: text, message: text }; }
  if (!response.ok) {
    throw new Error(data?.error_description || data?.error?.message || data?.message || `HTTP ${response.status}`);
  }
  return data;
}

async function exchangeCodeForToken(code) {
  return postForm(tokenEndpoint(), {
    client_id: process.env.OUTLOOK_CLIENT_ID,
    client_secret: process.env.OUTLOOK_CLIENT_SECRET,
    redirect_uri: process.env.OUTLOOK_REDIRECT_URI,
    grant_type: 'authorization_code',
    code,
    scope: scopes()
  });
}

async function refreshAccessToken(refreshToken) {
  return postForm(tokenEndpoint(), {
    client_id: process.env.OUTLOOK_CLIENT_ID,
    client_secret: process.env.OUTLOOK_CLIENT_SECRET,
    redirect_uri: process.env.OUTLOOK_REDIRECT_URI,
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    scope: scopes()
  });
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  const text = await response.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = { message: text }; }
  if (!response.ok) {
    throw new Error(data?.error?.message || data?.message || `HTTP ${response.status}`);
  }
  return data;
}

async function graphRequest(accessToken, path, options = {}) {
  const headers = {
    Authorization: `Bearer ${accessToken}`,
    ...(options.body ? { 'Content-Type': 'application/json' } : {}),
    ...(options.headers || {})
  };
  return fetchJson(`https://graph.microsoft.com/v1.0${path}`, { ...options, headers });
}

async function ensureOutlookSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_outlook_tokens (
      user_id TEXT PRIMARY KEY,
      email_address TEXT NOT NULL DEFAULT '',
      display_name TEXT NOT NULL DEFAULT '',
      access_token TEXT NOT NULL DEFAULT '',
      refresh_token TEXT NOT NULL DEFAULT '',
      token_type TEXT NOT NULL DEFAULT 'Bearer',
      scope TEXT NOT NULL DEFAULT '',
      expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

async function readStoredToken(pool, userId) {
  const result = await pool.query('SELECT * FROM user_outlook_tokens WHERE user_id = $1 LIMIT 1', [String(userId)]);
  return result.rows[0] || null;
}

async function saveTokenRecord(pool, userId, tokenData, profile = {}) {
  const expiresAt = new Date(Date.now() + ((Number(tokenData.expires_in) || 3600) - 60) * 1000).toISOString();
  await pool.query(
    `INSERT INTO user_outlook_tokens
      (user_id, email_address, display_name, access_token, refresh_token, token_type, scope, expires_at, updated_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
     ON CONFLICT (user_id)
     DO UPDATE SET
       email_address = EXCLUDED.email_address,
       display_name = EXCLUDED.display_name,
       access_token = EXCLUDED.access_token,
       refresh_token = CASE WHEN EXCLUDED.refresh_token = '' THEN user_outlook_tokens.refresh_token ELSE EXCLUDED.refresh_token END,
       token_type = EXCLUDED.token_type,
       scope = EXCLUDED.scope,
       expires_at = EXCLUDED.expires_at,
       updated_at = NOW()`,
    [
      String(userId),
      clean(profile.mail || profile.userPrincipalName),
      clean(profile.displayName),
      clean(tokenData.access_token),
      clean(tokenData.refresh_token),
      clean(tokenData.token_type || 'Bearer'),
      clean(tokenData.scope || scopes()),
      expiresAt
    ]
  );
}

async function getValidAccessToken(pool, userId) {
  const row = await readStoredToken(pool, userId);
  if (!row) return null;
  const expiresAt = row.expires_at ? new Date(row.expires_at).getTime() : 0;
  if (expiresAt > Date.now() + 30 * 1000 && row.access_token) return row.access_token;
  if (!row.refresh_token) return null;
  const refreshed = await refreshAccessToken(row.refresh_token);
  const profile = { mail: row.email_address, userPrincipalName: row.email_address, displayName: row.display_name };
  await saveTokenRecord(pool, userId, refreshed, profile);
  return clean(refreshed.access_token);
}

function postConnectRedirect(corsOrigins = []) {
  if (process.env.OUTLOOK_POST_LOGIN_REDIRECT) return process.env.OUTLOOK_POST_LOGIN_REDIRECT;
  const base = corsOrigins[0] || '';
  return base ? `${base.replace(/\/$/, '')}/index.html?email=connected` : '';
}

function buildAuthUrl(user) {
  const state = signState({ userId: String(user.id), at: Date.now() });
  const url = new URL(authorizeEndpoint());
  url.searchParams.set('client_id', process.env.OUTLOOK_CLIENT_ID);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('redirect_uri', process.env.OUTLOOK_REDIRECT_URI);
  url.searchParams.set('response_mode', 'query');
  url.searchParams.set('scope', scopes());
  url.searchParams.set('state', state);
  url.searchParams.set('prompt', 'select_account');
  return url.toString();
}

function registerOutlookRoutes(app, { pool, requireAuth, corsOrigins = [] }) {
  const prefixes = ['/outlook', '/api/outlook'];
  const mountGet = (path, ...handlers) => prefixes.forEach((prefix) => app.get(`${prefix}${path}`, ...handlers));
  const mountPost = (path, ...handlers) => prefixes.forEach((prefix) => app.post(`${prefix}${path}`, ...handlers));
  const mountDelete = (path, ...handlers) => prefixes.forEach((prefix) => app.delete(`${prefix}${path}`, ...handlers));

  mountGet('/status', requireAuth, async (req, res) => {
    try {
      if (!configured()) return res.json({ success: true, configured: false, connected: false });
      const row = await readStoredToken(pool, req.user.id);
      res.json({
        success: true,
        configured: true,
        connected: !!row,
        email: row?.email_address || '',
        displayName: row?.display_name || '',
        expiresAt: row?.expires_at || null
      });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  });

  mountGet('/auth-url', requireAuth, async (req, res) => {
    if (!configured()) return res.status(400).json({ success: false, error: 'Outlook integration is not configured' });
    res.json({ success: true, url: buildAuthUrl(req.user) });
  });

  mountGet('/callback', async (req, res) => {
    try {
      if (!configured()) return res.status(400).send('Outlook integration is not configured.');
      const code = clean(req.query.code);
      const state = verifyState(req.query.state);
      if (!code || !state?.userId) return res.status(400).send('Invalid Outlook callback state.');
      const tokenData = await exchangeCodeForToken(code);
      const profile = await graphRequest(tokenData.access_token, '/me');
      await saveTokenRecord(pool, state.userId, tokenData, profile || {});
      const redirectUrl = postConnectRedirect(corsOrigins);
      if (redirectUrl) {
        const safeRedirect = JSON.stringify(redirectUrl);
        return res.send(`<!DOCTYPE html><html><body><script>
          (function(){
            var target = ${safeRedirect};
            if (window.opener && !window.opener.closed) {
              try { window.opener.location = target; } catch (e) {}
              try { window.close(); return; } catch (e) {}
            }
            window.location.replace(target);
          })();
        </script><p>Outlook connected. You can close this window.</p></body></html>`);
      }
      return res.send('<html><body><h1>Outlook connected.</h1><p>You can close this window and return to Horizon Pipe.</p></body></html>');
    } catch (error) {
      console.error('OUTLOOK CALLBACK ERROR:', error);
      res.status(500).send(`Outlook connect failed: ${error.message}`);
    }
  });

  mountGet('/messages', requireAuth, async (req, res) => {
    try {
      if (!configured()) return res.status(400).json({ success: false, error: 'Outlook integration is not configured' });
      const token = await getValidAccessToken(pool, req.user.id);
      if (!token) return res.status(401).json({ success: false, error: 'Outlook is not connected for this user' });
      const data = await graphRequest(token, `/me/mailFolders/inbox/messages?$top=25&$orderby=receivedDateTime desc&$select=id,subject,receivedDateTime,bodyPreview,from,toRecipients`);
      const messages = Array.isArray(data.value) ? data.value.map((item) => ({
        id: item.id,
        subject: item.subject || '',
        preview: item.bodyPreview || '',
        from: clean(item.from?.emailAddress?.name || item.from?.emailAddress?.address),
        to: (item.toRecipients || []).map((r) => clean(r.emailAddress?.address || r.emailAddress?.name)).filter(Boolean).join(', '),
        receivedAt: item.receivedDateTime ? new Date(item.receivedDateTime).toLocaleString() : ''
      })) : [];
      res.json({ success: true, messages });
    } catch (error) {
      console.error('OUTLOOK MESSAGES ERROR:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  });

  mountGet('/messages/:id', requireAuth, async (req, res) => {
    try {
      const token = await getValidAccessToken(pool, req.user.id);
      if (!token) return res.status(401).json({ success: false, error: 'Outlook is not connected for this user' });
      const item = await graphRequest(token, `/me/messages/${encodeURIComponent(req.params.id)}?$select=id,subject,receivedDateTime,body,bodyPreview,from,toRecipients,ccRecipients,bccRecipients`);
      res.json({
        success: true,
        message: {
          id: item.id,
          subject: item.subject || '',
          from: clean(item.from?.emailAddress?.name || item.from?.emailAddress?.address),
          to: (item.toRecipients || []).map((r) => clean(r.emailAddress?.address || r.emailAddress?.name)).filter(Boolean).join(', '),
          cc: (item.ccRecipients || []).map((r) => clean(r.emailAddress?.address || r.emailAddress?.name)).filter(Boolean).join(', '),
          bcc: (item.bccRecipients || []).map((r) => clean(r.emailAddress?.address || r.emailAddress?.name)).filter(Boolean).join(', '),
          receivedAt: item.receivedDateTime ? new Date(item.receivedDateTime).toLocaleString() : '',
          bodyHtml: item.body?.contentType === 'html' ? item.body.content : '',
          bodyText: item.body?.contentType === 'text' ? item.body.content : item.bodyPreview || ''
        }
      });
    } catch (error) {
      console.error('OUTLOOK MESSAGE ERROR:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  });

  mountPost('/send', requireAuth, async (req, res) => {
    try {
      const token = await getValidAccessToken(pool, req.user.id);
      if (!token) return res.status(401).json({ success: false, error: 'Outlook is not connected for this user' });
      const to = clean(req.body?.to);
      const subject = clean(req.body?.subject);
      const body = String(req.body?.body || '');
      if (!to || !subject) return res.status(400).json({ success: false, error: 'To and subject are required' });
      const parseRecipients = (value) => clean(value).split(',').map((item) => item.trim()).filter(Boolean).map((address) => ({ emailAddress: { address } }));
      await graphRequest(token, '/me/sendMail', {
        method: 'POST',
        body: JSON.stringify({
          message: {
            subject,
            body: { contentType: 'Text', content: body },
            toRecipients: parseRecipients(req.body?.to),
            ccRecipients: parseRecipients(req.body?.cc),
            bccRecipients: parseRecipients(req.body?.bcc)
          },
          saveToSentItems: true
        })
      });
      res.json({ success: true });
    } catch (error) {
      console.error('OUTLOOK SEND ERROR:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  });

  mountDelete('/disconnect', requireAuth, async (req, res) => {
    try {
      await pool.query('DELETE FROM user_outlook_tokens WHERE user_id = $1', [String(req.user.id)]);
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  });
}

module.exports = {
  ensureOutlookSchema,
  registerOutlookRoutes
};

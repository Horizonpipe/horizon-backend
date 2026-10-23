'use strict';

const crypto = require('crypto');

const DEFAULT_FROM = '+19049251267';
const PUBLIC_BASE = 'https://pipeshare.live';
const INBOUND_PATH = '/api/sms/twilio/inbound';

const STOP_REPLY =
  'PipeShare: You are opted out and will not receive any more operational schedule texts. Reply START to opt back in.';
const START_REPLY =
  'PipeShare: You are opted back in and will receive operational schedule texts. Reply STOP to opt out.';
const START_NEEDS_ACCOUNT_REPLY =
  'PipeShare: START received. Operational schedule texts stay off until you agree on your PipeShare employee account. Reply STOP to opt out.';
const HELP_REPLY =
  'PipeShare: Help with operational schedule texts. Message frequency varies. Message and data rates may apply. Reply STOP to opt out. https://pipeshare.live/sms-opt-in';
const YES_CONSENT_REPLY =
  'PipeShare: Your employee account is set for operational schedule texts. Reply STOP to opt out.';
const YES_OPTED_OUT_REPLY =
  'PipeShare: You are opted out of operational schedule texts. Reply START to opt back in.';
const YES_NO_KEYWORD_REPLY =
  'PipeShare: Texting YES does not opt you in. Agree with the checkbox on your PipeShare employee account if you want operational schedule texts. Reply STOP to opt out.';
const OTHER_REPLY =
  'PipeShare: This number sends operational schedule texts only. Reply HELP for help or STOP to opt out.';

const SMS_CONSENT_LABEL =
  'I agree to receive operational text messages from PipeShare about my work schedule, job site, and shift time. Message frequency varies. Message and data rates may apply. Reply HELP for help or STOP to opt out. Consent is not required to keep my employee account.';

let schemaPromise = null;
let secretCache = { value: '', at: 0 };

function phoneDigits(value) {
  return String(value || '').replace(/\D/g, '');
}

/** Last 10 digits of a US number, or empty when it is not one. */
function phoneKey(value) {
  let digits = phoneDigits(value);
  if (digits.length === 11 && digits.startsWith('1')) digits = digits.slice(1);
  if (digits.length > 11) digits = digits.slice(-10);
  return digits.length === 10 ? digits : '';
}

function e164(value) {
  const key = phoneKey(value);
  return key ? `+1${key}` : '';
}

function classifyKeyword(body) {
  const word =
    String(body || '')
      .trim()
      .toUpperCase()
      .replace(/[^A-Z]/g, ' ')
      .split(/\s+/)
      .filter(Boolean)[0] || '';
  if (['STOP', 'STOPALL', 'UNSUBSCRIBE', 'CANCEL', 'END', 'QUIT'].includes(word)) return 'stop';
  if (word === 'START' || word === 'UNSTOP') return 'start';
  if (word === 'HELP' || word === 'INFO') return 'help';
  if (word === 'YES') return 'yes';
  return 'other';
}

function isOptedOut(row) {
  if (!row || !row.opted_out_at) return false;
  if (!row.started_at) return true;
  return new Date(row.opted_out_at).getTime() > new Date(row.started_at).getTime();
}

function employeeMayReceiveSms(row, optOutRow) {
  if (!row) return false;
  if (String(row.account_type || row.accountType || 'employee').toLowerCase() === 'customer') return false;
  if (row.sms_consent !== true && row.smsConsent !== true) return false;
  if (row.sms_opted_out_at || row.smsOptedOutAt) return false;
  if (!e164(row.phone)) return false;
  if (isOptedOut(optOutRow)) return false;
  return true;
}

function oneLine(value, max) {
  return String(value || '').replace(/\s+/g, ' ').trim().slice(0, max);
}

function buildCrewText(kind, parts) {
  const project = oneLine(parts?.project, 80) || 'your job';
  const when = oneLine(parts?.when, 80) || 'the scheduled time';
  const place = oneLine(parts?.place, 80);
  const where = place ? ` in ${place}` : '';
  let map = oneLine(parts?.map, 220);
  if (map.length > 180) map = '';
  const mapBit = map ? ` Map: ${map}.` : '';
  const stop = ' Reply STOP to opt out.';
  let core;
  if (kind === 'reminder') {
    core = `PipeShare: Reminder: ${project} starts ${when}.${place ? ` ${place}.` : ''}`;
  } else if (kind === 'change') {
    core = `PipeShare: Schedule change for ${project}${where}. ${when}.`;
  } else if (kind === 'cancel') {
    core = `PipeShare: Canceled: ${project} on ${when} is off your schedule.`;
  } else {
    core = `PipeShare: Schedule: ${project}${where}. ${when}.`;
  }
  let text = `${core}${mapBit}${stop}`.replace(/\s+/g, ' ').trim();
  if (text.length > 640) text = `${core}${stop}`.replace(/\s+/g, ' ').trim();
  if (!text.startsWith('PipeShare:')) text = `PipeShare: ${text}`;
  if (!text.includes('Reply STOP to opt out.')) text = `${text} Reply STOP to opt out.`;
  return text;
}

function withStopFooter(body) {
  let text = oneLine(body, 600);
  if (!text) return 'PipeShare: Operational schedule text. Reply STOP to opt out.';
  if (!/^PipeShare:/i.test(text)) text = `PipeShare: ${text}`;
  if (!/reply stop/i.test(text)) text = `${text} Reply STOP to opt out.`;
  return text;
}

function replyFor(keyword, ctx) {
  const hadConsent = ctx?.hadConsent === true;
  const optedOut = ctx?.optedOut === true;
  if (keyword === 'stop') return STOP_REPLY;
  if (keyword === 'help') return HELP_REPLY;
  if (keyword === 'start') return hadConsent ? START_REPLY : START_NEEDS_ACCOUNT_REPLY;
  if (keyword === 'yes') {
    if (optedOut) return YES_OPTED_OUT_REPLY;
    if (hadConsent) return YES_CONSENT_REPLY;
    return YES_NO_KEYWORD_REPLY;
  }
  return OTHER_REPLY;
}

function xmlEscape(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function twimlMessage(text) {
  return `<?xml version="1.0" encoding="UTF-8"?><Response><Message>${xmlEscape(text)}</Message></Response>`;
}

function twilioAuth() {
  const accountSid = String(process.env.TWILIO_ACCOUNT_SID || '').trim();
  const apiKey = String(process.env.TWILIO_API_KEY || '').trim();
  const apiSecret = String(process.env.TWILIO_API_SECRET || '').trim();
  const authToken = String(process.env.TWILIO_AUTH_TOKEN || '').trim();
  if (!accountSid) return null;
  if (apiKey && apiSecret) return { accountSid, user: apiKey, pass: apiSecret, authToken };
  if (authToken) return { accountSid, user: accountSid, pass: authToken, authToken };
  return null;
}

function fromNumber() {
  return e164(process.env.TWILIO_PHONE_NUMBER || DEFAULT_FROM);
}

function twilioReady() {
  return !!(twilioAuth() && fromNumber());
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a || ''));
  const right = Buffer.from(String(b || ''));
  if (!left.length || left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function formParams(body) {
  const out = {};
  if (!body || typeof body !== 'object') return out;
  for (const [key, value] of Object.entries(body)) {
    if (value == null) continue;
    out[key] = Array.isArray(value) ? String(value[0] ?? '') : String(value);
  }
  return out;
}

function validTwilioSignature(authToken, signature, url, params) {
  const token = String(authToken || '');
  const sig = String(signature || '');
  if (!token || !sig || !url) return false;
  const data =
    url +
    Object.keys(params || {})
      .sort()
      .map((key) => key + String(params[key] ?? ''))
      .join('');
  const expected = crypto.createHmac('sha1', token).update(data, 'utf8').digest('base64');
  return safeEqual(expected, sig);
}

function candidateUrls(req) {
  const original = String(req?.originalUrl || req?.url || INBOUND_PATH);
  const host = String(req?.headers?.['x-forwarded-host'] || req?.headers?.host || 'pipeshare.live')
    .split(',')[0]
    .trim();
  const proto = String(req?.headers?.['x-forwarded-proto'] || req?.protocol || 'https')
    .split(',')[0]
    .trim();
  const urls = [`${proto}://${host}${original}`, `${PUBLIC_BASE}${original}`];
  return [...new Set(urls)];
}

async function ensureOperationalSmsSchema(pool) {
  if (!schemaPromise) {
    schemaPromise = (async () => {
      await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS sms_consent BOOLEAN NOT NULL DEFAULT false`);
      await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS sms_consent_at TIMESTAMPTZ`);
      await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS sms_opted_out_at TIMESTAMPTZ`);
      await pool.query(`
        CREATE TABLE IF NOT EXISTS sms_opt_outs (
          phone_key TEXT PRIMARY KEY,
          opted_out_at TIMESTAMPTZ,
          started_at TIMESTAMPTZ,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )`);
      await pool.query(`
        CREATE TABLE IF NOT EXISTS sms_inbound_messages (
          message_sid TEXT PRIMARY KEY,
          phone_key TEXT NOT NULL DEFAULT '',
          keyword TEXT NOT NULL DEFAULT '',
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )`);
      await pool.query(`
        CREATE TABLE IF NOT EXISTS sms_runtime (
          id TEXT PRIMARY KEY,
          webhook_secret TEXT NOT NULL,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )`);
    })().catch((err) => {
      schemaPromise = null;
      throw err;
    });
  }
  return schemaPromise;
}

async function usersForPhone(pool, key) {
  if (!key) return [];
  const found = await pool.query(
    `SELECT id, account_type, phone, sms_consent, sms_opted_out_at
     FROM users
     WHERE RIGHT(regexp_replace(COALESCE(phone, ''), '\\D', '', 'g'), 10) = $1`,
    [key]
  );
  return found.rows || [];
}

async function optOutRow(pool, key) {
  if (!key) return null;
  const found = await pool.query(`SELECT phone_key, opted_out_at, started_at FROM sms_opt_outs WHERE phone_key = $1`, [
    key
  ]);
  return found.rows[0] || null;
}

async function markOptOut(pool, phone) {
  const key = phoneKey(phone);
  if (!key) return;
  await ensureOperationalSmsSchema(pool);
  await pool.query(
    `INSERT INTO sms_opt_outs (phone_key, opted_out_at, started_at, updated_at)
     VALUES ($1, NOW(), NULL, NOW())
     ON CONFLICT (phone_key) DO UPDATE
       SET opted_out_at = NOW(), started_at = NULL, updated_at = NOW()`,
    [key]
  );
  await pool.query(
    `UPDATE users
     SET sms_opted_out_at = NOW(), updated_at = NOW()
     WHERE RIGHT(regexp_replace(COALESCE(phone, ''), '\\D', '', 'g'), 10) = $1`,
    [key]
  );
}

async function clearOptOut(pool, phone) {
  const key = phoneKey(phone);
  if (!key) return;
  await ensureOperationalSmsSchema(pool);
  await pool.query(
    `INSERT INTO sms_opt_outs (phone_key, opted_out_at, started_at, updated_at)
     VALUES ($1, NULL, NOW(), NOW())
     ON CONFLICT (phone_key) DO UPDATE
       SET opted_out_at = NULL, started_at = NOW(), updated_at = NOW()`,
    [key]
  );
  await pool.query(
    `UPDATE users
     SET sms_opted_out_at = NULL, updated_at = NOW()
     WHERE RIGHT(regexp_replace(COALESCE(phone, ''), '\\D', '', 'g'), 10) = $1`,
    [key]
  );
}

async function evaluateEmployeeSms(pool, { userId, phone }) {
  await ensureOperationalSmsSchema(pool);
  let user = null;
  if (userId) {
    const found = await pool.query(
      `SELECT id, account_type, phone, sms_consent, sms_opted_out_at
       FROM users WHERE CAST(id AS text) = $1 LIMIT 1`,
      [String(userId)]
    );
    user = found.rows[0] || null;
    if (user && String(user.account_type || '').toLowerCase() === 'customer') {
      return { ok: false, reason: 'Customers do not receive schedule texts.' };
    }
  } else {
    const key = phoneKey(phone);
    if (!key) return { ok: false, reason: 'No mobile number is stored on an employee account.' };
    const rows = await usersForPhone(pool, key);
    const employees = rows.filter((row) => String(row.account_type || 'employee').toLowerCase() !== 'customer');
    if (!employees.length) {
      if (rows.length) return { ok: false, reason: 'Customers do not receive schedule texts.' };
      return { ok: false, reason: 'No employee account with this phone has agreed to operational texts.' };
    }
    user = employees.find((row) => row.sms_consent === true) || null;
    if (!user) return { ok: false, reason: 'That employee has not agreed to operational texts.' };
  }
  if (!user) return { ok: false, reason: 'No employee account with this phone has agreed to operational texts.' };
  if (!e164(user.phone)) return { ok: false, reason: 'That employee account has no mobile number.' };
  if (user.sms_consent !== true) return { ok: false, reason: 'That employee has not agreed to operational texts.' };
  if (user.sms_opted_out_at) return { ok: false, reason: 'That employee replied STOP and is opted out.' };
  const key = phoneKey(user.phone);
  const opt = await optOutRow(pool, key);
  if (isOptedOut(opt)) return { ok: false, reason: 'That number replied STOP and is opted out.' };
  return { ok: true, to: e164(user.phone) };
}

function consentContext(rows, optRow) {
  const employees = (rows || []).filter((row) => String(row.account_type || 'employee').toLowerCase() !== 'customer');
  return {
    hadConsent: employees.some((row) => row.sms_consent === true),
    optedOut: isOptedOut(optRow) || employees.some((row) => !!row.sms_opted_out_at)
  };
}

async function handleInboundSms(pool, fields) {
  await ensureOperationalSmsSchema(pool);
  const keyword = classifyKeyword(fields?.Body);
  const from = String(fields?.From || '');
  const key = phoneKey(from);
  const sid = String(fields?.MessageSid || '').trim();
  if (sid) {
    const inserted = await pool.query(
      `INSERT INTO sms_inbound_messages (message_sid, phone_key, keyword)
       VALUES ($1, $2, $3)
       ON CONFLICT (message_sid) DO NOTHING
       RETURNING message_sid`,
      [sid.slice(0, 80), key, keyword]
    );
    if (!inserted.rows.length) {
      const rows = key ? await usersForPhone(pool, key) : [];
      const opt = key ? await optOutRow(pool, key) : null;
      return { keyword, text: replyFor(keyword, consentContext(rows, opt)) };
    }
  }
  const rows = key ? await usersForPhone(pool, key) : [];
  const opt = key ? await optOutRow(pool, key) : null;
  const before = consentContext(rows, opt);
  if (keyword === 'stop' && key) await markOptOut(pool, from);
  if (keyword === 'start' && key) await clearOptOut(pool, from);
  return { keyword, text: replyFor(keyword, before) };
}

async function sendOperationalSms({ to, body }) {
  const auth = twilioAuth();
  const from = fromNumber();
  if (!auth || !from) return { ok: false, code: 'not_configured', message: 'Texting service is not configured on the server.' };
  const dest = e164(to);
  if (!dest) return { ok: false, code: 'bad_phone', message: 'That employee account has no US mobile number.' };
  const form = { To: dest, Body: withStopFooter(body).slice(0, 1000) };
  const serviceSid = String(process.env.TWILIO_MESSAGING_SERVICE_SID || '').trim();
  if (serviceSid) form.MessagingServiceSid = serviceSid;
  else form.From = from;
  const url = `https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(auth.accountSid)}/Messages.json`;
  let res;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Basic ${Buffer.from(`${auth.user}:${auth.pass}`).toString('base64')}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams(form)
    });
  } catch {
    return { ok: false, code: 'network', message: 'Texting service could not be reached.' };
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    return {
      ok: false,
      code: String(data?.code || res.status),
      message: String(data?.code) === '21610' ? 'That number is opted out.' : 'Text was not sent.'
    };
  }
  return { ok: true };
}

function smsSender() {
  return {
    configured: twilioReady(),
    send: sendOperationalSms
  };
}

async function webhookSecret(pool) {
  const envSecret = String(process.env.TWILIO_WEBHOOK_SECRET || '').trim();
  if (envSecret) return envSecret;
  if (secretCache.value && Date.now() - secretCache.at < 30000) return secretCache.value;
  if (!pool) return '';
  try {
    await ensureOperationalSmsSchema(pool);
    const row = await pool.query(`SELECT webhook_secret FROM sms_runtime WHERE id = 'inbound'`);
    const value = String(row.rows[0]?.webhook_secret || '').trim();
    secretCache = { value, at: Date.now() };
    return value;
  } catch {
    return '';
  }
}

async function inboundRequestAllowed(req, pool) {
  const hookKey = String(req?.params?.hookKey || '');
  const authToken = String(process.env.TWILIO_AUTH_TOKEN || '').trim();
  const secret = await webhookSecret(pool);
  if (hookKey && (!secret || !safeEqual(hookKey, secret))) return false;
  if (authToken) {
    const signature = String(req?.get?.('x-twilio-signature') || req?.headers?.['x-twilio-signature'] || '');
    const params = formParams(req?.body);
    return candidateUrls(req).some((url) => validTwilioSignature(authToken, signature, url, params));
  }
  return !!(hookKey && secret && safeEqual(hookKey, secret));
}

async function twilioRequest(auth, url, { method = 'GET', form } = {}) {
  const headers = {
    Authorization: `Basic ${Buffer.from(`${auth.user}:${auth.pass}`).toString('base64')}`
  };
  let body;
  if (form) {
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
    body = new URLSearchParams(form);
  }
  const res = await fetch(url, { method, headers, body });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(`Twilio request failed (${res.status})`);
    err.code = data?.code || res.status;
    throw err;
  }
  return data;
}

async function loadOrCreateWebhookSecret(pool) {
  const envSecret = String(process.env.TWILIO_WEBHOOK_SECRET || '').trim();
  if (envSecret) return envSecret;
  await ensureOperationalSmsSchema(pool);
  const existing = await pool.query(`SELECT webhook_secret FROM sms_runtime WHERE id = 'inbound'`);
  if (existing.rows[0]?.webhook_secret) {
    const value = String(existing.rows[0].webhook_secret);
    secretCache = { value, at: Date.now() };
    return value;
  }
  const created = crypto.randomBytes(24).toString('hex');
  await pool.query(
    `INSERT INTO sms_runtime (id, webhook_secret) VALUES ('inbound', $1)
     ON CONFLICT (id) DO NOTHING`,
    [created]
  );
  const again = await pool.query(`SELECT webhook_secret FROM sms_runtime WHERE id = 'inbound'`);
  const value = String(again.rows[0]?.webhook_secret || '');
  secretCache = { value, at: Date.now() };
  return value;
}

function inboundWebhookUrl(secret) {
  const base = String(process.env.PUBLIC_BASE_URL || PUBLIC_BASE).replace(/\/$/, '');
  if (secret) return `${base}${INBOUND_PATH}/${secret}`;
  return `${base}${INBOUND_PATH}`;
}

async function findPipeShareNumber(auth) {
  const target = fromNumber();
  const data = await twilioRequest(
    auth,
    `https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(auth.accountSid)}/IncomingPhoneNumbers.json?PhoneNumber=${encodeURIComponent(target)}&PageSize=20`
  );
  const rows = Array.isArray(data.incoming_phone_numbers) ? data.incoming_phone_numbers : [];
  return rows.find((row) => e164(row.phone_number) === target) || null;
}

async function messagingServiceForNumber(auth, numberSid) {
  const configured = String(process.env.TWILIO_MESSAGING_SERVICE_SID || '').trim();
  if (configured) return configured;
  let url = 'https://messaging.twilio.com/v1/Services?PageSize=20';
  for (let page = 0; page < 5 && url; page += 1) {
    const data = await twilioRequest(auth, url);
    const services = Array.isArray(data.services) ? data.services : [];
    for (const service of services) {
      if (!service?.sid) continue;
      const phones = await twilioRequest(
        auth,
        `https://messaging.twilio.com/v1/Services/${encodeURIComponent(service.sid)}/PhoneNumbers?PageSize=50`
      );
      const list = Array.isArray(phones.phone_numbers) ? phones.phone_numbers : [];
      if (list.some((row) => row.sid === numberSid || e164(row.phone_number) === fromNumber())) return service.sid;
    }
    const next = String(data.meta?.next_page_url || '');
    url = next.startsWith('https://messaging.twilio.com/') ? next : '';
  }
  return '';
}

/**
 * Point the PipeShare number and its messaging service at the inbound webhook.
 * Does nothing — and makes no Twilio request — until API credentials are in the environment.
 */
async function ensureTwilioInboundWebhook(pool) {
  const auth = twilioAuth();
  if (!auth || !fromNumber()) {
    console.log('[sms] Twilio credentials are not set. No inbound webhook was changed.');
    return { updated: false, reason: 'credentials-missing' };
  }
  const useSignature = !!auth.authToken;
  const secret = useSignature ? '' : await loadOrCreateWebhookSecret(pool);
  if (!useSignature && !secret) {
    console.warn('[sms] Inbound webhook was not changed because no webhook key could be stored.');
    return { updated: false, reason: 'secret-missing' };
  }
  const webhookUrl = inboundWebhookUrl(useSignature ? '' : secret);
  const number = await findPipeShareNumber(auth);
  if (!number?.sid) {
    console.warn('[sms] The PipeShare number was not found on the Twilio account. No webhook was changed.');
    return { updated: false, reason: 'number-not-found' };
  }
  await twilioRequest(
    auth,
    `https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(auth.accountSid)}/IncomingPhoneNumbers/${encodeURIComponent(number.sid)}.json`,
    {
      method: 'POST',
      form: {
        SmsUrl: webhookUrl,
        SmsMethod: 'POST',
        SmsFallbackUrl: webhookUrl,
        SmsFallbackMethod: 'POST'
      }
    }
  );
  const serviceSid = await messagingServiceForNumber(auth, number.sid);
  if (serviceSid) {
    await twilioRequest(auth, `https://messaging.twilio.com/v1/Services/${encodeURIComponent(serviceSid)}`, {
      method: 'POST',
      form: {
        InboundRequestUrl: webhookUrl,
        InboundMethod: 'POST',
        FallbackUrl: webhookUrl,
        FallbackMethod: 'POST'
      }
    });
  }
  console.log('[sms] Inbound webhook set for operational schedule texts.');
  return { updated: true, reason: serviceSid ? 'number-and-service' : 'number-only' };
}

module.exports = {
  DEFAULT_FROM,
  INBOUND_PATH,
  PUBLIC_BASE,
  SMS_CONSENT_LABEL,
  STOP_REPLY,
  START_REPLY,
  START_NEEDS_ACCOUNT_REPLY,
  HELP_REPLY,
  YES_CONSENT_REPLY,
  YES_OPTED_OUT_REPLY,
  YES_NO_KEYWORD_REPLY,
  OTHER_REPLY,
  phoneKey,
  e164,
  classifyKeyword,
  isOptedOut,
  employeeMayReceiveSms,
  buildCrewText,
  withStopFooter,
  replyFor,
  twimlMessage,
  twilioReady,
  validTwilioSignature,
  ensureOperationalSmsSchema,
  evaluateEmployeeSms,
  handleInboundSms,
  markOptOut,
  sendOperationalSms,
  smsSender,
  inboundRequestAllowed,
  ensureTwilioInboundWebhook
};

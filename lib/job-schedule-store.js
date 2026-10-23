'use strict';

const crypto = require('crypto');
const { isAdminUser, isSaasWorkspaceOwner, deriveAccountModel, ACCOUNT_TYPES } = require('../capabilities');
const { tenantUsersWhereSql } = require('./saas-tenant-scope');
const { parseSaasTenantSlugFromHost } = require('./saas-tenant-access-urls');
const {
  buildCrewText,
  ensureOperationalSmsSchema,
  evaluateEmployeeSms,
  markOptOut,
  smsSender,
  twilioReady,
  withStopFooter
} = require('./operational-sms');

const MAX_CLIP_SEC = 30;
const MAX_IMAGE_BYTES = 4 * 1024 * 1024;
const BUILTIN_LABELS = ['Crew', 'Foreman', 'Superintendent', 'Owner'];

let schemaPromise = null;

function clean(value, max = 500) {
  return String(value == null ? '' : value).replace(/\s+/g, ' ').trim().slice(0, max);
}

function cleanThumb(value) {
  const s = String(value || '').replace(/\s/g, '');
  if (!s.startsWith('data:image/jpeg;base64,')) return '';
  if (s.length > 160000) return '';
  if (!/^data:image\/jpeg;base64,[A-Za-z0-9+/=]+$/.test(s)) return '';
  return s;
}

function cleanMultiline(value, max = 8000) {
  return String(value == null ? '' : value).replace(/\r\n/g, '\n').trim().slice(0, max);
}

function digits(value) {
  return String(value || '').replace(/\D/g, '');
}

function normName(value) {
  return String(value || '').trim().toLowerCase().replace(/\s+/g, ' ');
}

function looksLikeEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || '').trim());
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function round1(n) {
  return Math.round(Number(n) * 10) / 10;
}

/** Keep a problem clip at or under 30 seconds. */
function clampClip(start, end) {
  let s = Math.max(0, Number(start) || 0);
  let e = Math.max(s, Number(end) || s);
  if (e - s > MAX_CLIP_SEC) e = s + MAX_CLIP_SEC;
  return { start: round1(s), end: round1(e) };
}

function tenantKey(user, req) {
  const host = String(req?.headers?.['x-forwarded-host'] || req?.headers?.host || '')
    .split(',')[0]
    .trim();
  const slug = parseSaasTenantSlugFromHost(host);
  if (slug) return `saas:${slug}`.slice(0, 160);
  const hostOnly = host.toLowerCase().split(':')[0];
  if (hostOnly === 'pipeshare.net' || hostOnly.endsWith('.pipeshare.net')) return 'saas:apex';
  return 'base';
}

function isManager(user) {
  if (!user) return false;
  if (isAdminUser(user) || isSaasWorkspaceOwner(user)) return true;
  const model = deriveAccountModel(user);
  if (model.accountType !== ACCOUNT_TYPES.EMPLOYEE) return false;
  return model.employeeRole === 'admin' || model.employeeRole === 'superadmin';
}

function isCustomer(user) {
  return deriveAccountModel(user || {}).accountType === ACCOUNT_TYPES.CUSTOMER;
}

function userMatchesMember(user, member) {
  if (!user || !member) return false;
  if (member.user_id && String(member.user_id) === String(user.id || '')) return true;
  const names = [user.displayName, user.username, `${user.firstName || ''} ${user.lastName || ''}`]
    .map(normName)
    .filter(Boolean);
  if (names.includes(normName(member.name))) return true;
  const phone = digits(user.phone);
  const memberPhone = digits(member.phone);
  if (phone.length >= 7 && memberPhone.length >= 7) {
    const a = phone.slice(-10);
    const b = memberPhone.slice(-10);
    if (a === b) return true;
  }
  return false;
}

function customerSeesJob(user, job, contacts, clients) {
  const names = [user.displayName, user.username, `${user.firstName || ''} ${user.lastName || ''}`]
    .map(normName)
    .filter(Boolean);
  const phone = digits(user.phone);
  const email = normName(user.email);
  const company = normName(user.company);
  const client = clients.find((c) => c.id === job.clientId);
  if (company && client && normName(client.name) === company) return true;
  const ids = new Set(asArray(job.contactIds).map(String));
  return contacts.some((c) => {
    if (!ids.has(String(c.id))) return false;
    if (names.includes(normName(c.name))) return true;
    if (email && normName(c.phone) === email) return true;
    const cp = digits(c.phone);
    return phone.length >= 7 && cp.length >= 7 && phone.slice(-10) === cp.slice(-10);
  });
}

async function ensureSchema(pool) {
  if (!schemaPromise) {
    schemaPromise = (async () => {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS job_sched_clients (
          id UUID PRIMARY KEY,
          tenant_key TEXT NOT NULL,
          name TEXT NOT NULL,
          created_by TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )`);
      await pool.query(`CREATE INDEX IF NOT EXISTS idx_job_sched_clients_tenant ON job_sched_clients (tenant_key)`);
      await pool.query(`
        CREATE TABLE IF NOT EXISTS job_sched_labels (
          id UUID PRIMARY KEY,
          tenant_key TEXT NOT NULL,
          name TEXT NOT NULL,
          UNIQUE (tenant_key, name)
        )`);
      await pool.query(`
        CREATE TABLE IF NOT EXISTS job_sched_contacts (
          id UUID PRIMARY KEY,
          tenant_key TEXT NOT NULL,
          client_id UUID NOT NULL,
          name TEXT NOT NULL,
          phone TEXT NOT NULL DEFAULT '',
          labels JSONB NOT NULL DEFAULT '[]'::jsonb,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )`);
      await pool.query(`CREATE INDEX IF NOT EXISTS idx_job_sched_contacts_tenant ON job_sched_contacts (tenant_key, client_id)`);
      await pool.query(`
        CREATE TABLE IF NOT EXISTS job_sched_jobs (
          id UUID PRIMARY KEY,
          tenant_key TEXT NOT NULL,
          client_id UUID NOT NULL,
          city TEXT NOT NULL DEFAULT '',
          state TEXT NOT NULL DEFAULT '',
          county TEXT NOT NULL DEFAULT '',
          project_name TEXT NOT NULL,
          description TEXT NOT NULL DEFAULT '',
          map_query TEXT NOT NULL DEFAULT '',
          map_lat DOUBLE PRECISION,
          map_lng DOUBLE PRECISION,
          map_url TEXT NOT NULL DEFAULT '',
          pdfs JSONB NOT NULL DEFAULT '[]'::jsonb,
          contact_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )`);
      await pool.query(`CREATE INDEX IF NOT EXISTS idx_job_sched_jobs_tenant ON job_sched_jobs (tenant_key, client_id)`);
      await pool.query(`
        CREATE TABLE IF NOT EXISTS job_sched_crews (
          id UUID PRIMARY KEY,
          tenant_key TEXT NOT NULL,
          name TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )`);
      await pool.query(`
        CREATE TABLE IF NOT EXISTS job_sched_crew_members (
          id UUID PRIMARY KEY,
          crew_id UUID NOT NULL REFERENCES job_sched_crews(id) ON DELETE CASCADE,
          name TEXT NOT NULL,
          phone TEXT NOT NULL DEFAULT '',
          is_lead BOOLEAN NOT NULL DEFAULT false,
          user_id TEXT
        )`);
      await pool.query(`
        CREATE TABLE IF NOT EXISTS job_sched_assignments (
          id UUID PRIMARY KEY,
          tenant_key TEXT NOT NULL,
          job_id UUID NOT NULL,
          crew_id UUID NOT NULL,
          start_date DATE NOT NULL,
          arrival_time TEXT NOT NULL DEFAULT '',
          end_date DATE,
          end_time TEXT NOT NULL DEFAULT '',
          notify_hours NUMERIC NOT NULL DEFAULT 24,
          created_by TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )`);
      await pool.query(`CREATE INDEX IF NOT EXISTS idx_job_sched_assign_tenant ON job_sched_assignments (tenant_key, start_date)`);
      await pool.query(`
        CREATE TABLE IF NOT EXISTS job_sched_reports (
          id UUID PRIMARY KEY,
          tenant_key TEXT NOT NULL,
          job_id UUID NOT NULL,
          report_date DATE NOT NULL,
          body JSONB NOT NULL DEFAULT '{}'::jsonb,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_by TEXT,
          UNIQUE (tenant_key, job_id, report_date)
        )`);
      await pool.query(`
        CREATE TABLE IF NOT EXISTS job_sched_media (
          id UUID PRIMARY KEY,
          tenant_key TEXT NOT NULL,
          job_id UUID NOT NULL,
          name TEXT NOT NULL DEFAULT '',
          mime TEXT NOT NULL DEFAULT 'application/octet-stream',
          bytes BYTEA NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )`);
      await pool.query(`
        CREATE TABLE IF NOT EXISTS job_sched_chat (
          id UUID PRIMARY KEY,
          tenant_key TEXT NOT NULL,
          job_id UUID NOT NULL,
          author_id TEXT,
          author_name TEXT NOT NULL DEFAULT '',
          body TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )`);
      await pool.query(`CREATE INDEX IF NOT EXISTS idx_job_sched_chat_job ON job_sched_chat (tenant_key, job_id, created_at)`);
      await pool.query(`
        CREATE TABLE IF NOT EXISTS job_sched_notifications (
          id UUID PRIMARY KEY,
          tenant_key TEXT NOT NULL,
          assignment_id UUID,
          recipient_name TEXT NOT NULL DEFAULT '',
          recipient_phone TEXT NOT NULL DEFAULT '',
          recipient_email TEXT NOT NULL DEFAULT '',
          channel TEXT NOT NULL,
          body TEXT NOT NULL,
          map_link TEXT NOT NULL DEFAULT '',
          send_at TIMESTAMPTZ NOT NULL,
          sent_at TIMESTAMPTZ,
          status TEXT NOT NULL,
          detail TEXT NOT NULL DEFAULT ''
        )`);
      await pool.query(
        `CREATE INDEX IF NOT EXISTS idx_job_sched_notify_due ON job_sched_notifications (status, send_at)`
      );
      await pool.query(
        `ALTER TABLE job_sched_notifications ADD COLUMN IF NOT EXISTS notice_kind TEXT NOT NULL DEFAULT ''`
      );
      await pool.query(
        `ALTER TABLE job_sched_notifications ADD COLUMN IF NOT EXISTS recipient_user_id TEXT NOT NULL DEFAULT ''`
      );
      await ensureOperationalSmsSchema(pool);
    })().catch((err) => {
      schemaPromise = null;
      throw err;
    });
  }
  return schemaPromise;
}

function mapClient(row) {
  return { id: row.id, name: row.name || '', createdAt: row.created_at };
}

function mapContact(row) {
  return {
    id: row.id,
    clientId: row.client_id,
    name: row.name || '',
    phone: row.phone || '',
    labels: asArray(row.labels).map((x) => clean(x, 40)).filter(Boolean)
  };
}

function mapJob(row) {
  return {
    id: row.id,
    clientId: row.client_id,
    city: row.city || '',
    state: row.state || '',
    county: row.county || '',
    projectName: row.project_name || '',
    description: row.description || '',
    mapQuery: row.map_query || '',
    mapLat: row.map_lat == null ? null : Number(row.map_lat),
    mapLng: row.map_lng == null ? null : Number(row.map_lng),
    mapUrl: row.map_url || '',
    pdfs: asArray(row.pdfs),
    contactIds: asArray(row.contact_ids).map(String),
    updatedAt: row.updated_at
  };
}

function mapCrew(row, members) {
  return {
    id: row.id,
    name: row.name || '',
    members: members.map((m) => ({
      id: m.id,
      name: m.name || '',
      phone: m.phone || '',
      isLead: m.is_lead === true,
      userId: m.user_id || ''
    }))
  };
}

function isoDate(value) {
  if (!value) return '';
  if (value instanceof Date) {
    const z = (n) => String(n).padStart(2, '0');
    return `${value.getUTCFullYear()}-${z(value.getUTCMonth() + 1)}-${z(value.getUTCDate())}`;
  }
  return String(value).slice(0, 10);
}

function mapAssignment(row) {
  return {
    id: row.id,
    jobId: row.job_id,
    crewId: row.crew_id,
    startDate: isoDate(row.start_date),
    arrivalTime: row.arrival_time || '',
    endDate: isoDate(row.end_date) || isoDate(row.start_date),
    endTime: row.end_time || '',
    notifyHours: Number(row.notify_hours) || 0,
    createdAt: row.created_at
  };
}

function emptyBody() {
  return { logs: [], images: [], problems: [], notified: { checked: false, who: '', at: '' } };
}

function sanitizeBody(raw) {
  const src = raw && typeof raw === 'object' ? raw : {};
  const logs = asArray(src.logs)
    .slice(0, 300)
    .map((log) => ({
      id: clean(log?.id, 80) || crypto.randomUUID(),
      label: clean(log?.label, 20),
      text: cleanMultiline(log?.text, 4000),
      flag: clean(log?.flag, 80),
      createdAt: clean(log?.createdAt, 40)
    }))
    .filter((log) => log.label || log.text || log.flag);
  const images = asArray(src.images)
    .slice(0, 40)
    .map((img) => ({ id: clean(img?.id, 80), name: clean(img?.name, 180) }))
    .filter((img) => img.id);
  const problems = asArray(src.problems)
    .slice(0, 40)
    .map((p) => {
      const clip = clampClip(p?.clipStart, p?.clipEnd);
      return {
        id: clean(p?.id, 80) || crypto.randomUUID(),
        videoId: clean(p?.videoId, 200),
        videoName: clean(p?.videoName, 240),
        pipeClientId: clean(p?.pipeClientId, 120),
        pipeJobId: clean(p?.pipeJobId, 120),
        remarkId: clean(p?.remarkId, 80),
        remarkText: clean(p?.remarkText, 500),
        code: clean(p?.code, 40),
        footage: clean(p?.footage, 40),
        thumb: cleanThumb(p?.thumb),
        remarkTimeSec: round1(p?.remarkTimeSec),
        pipeT: Number.isFinite(Number(p?.pipeT)) ? Number(p.pipeT) : null,
        clipStart: clip.start,
        clipEnd: clip.end,
        note: cleanMultiline(p?.note, 2000),
        videoPath: clean(p?.videoPath, 500).replace(/\\/g, '/'),
        projectId: clean(p?.projectId, 80)
      };
    })
    .filter((p) => p.videoId || p.videoPath || p.note);
  const notified = {
    checked: src.notified?.checked === true,
    who: clean(src.notified?.who, 200),
    at: clean(src.notified?.at, 40)
  };
  return { logs, images, problems, notified };
}

function mapReport(row) {
  return {
    id: row.id,
    jobId: row.job_id,
    reportDate: isoDate(row.report_date),
    body: sanitizeBody(row.body),
    updatedAt: row.updated_at,
    updatedBy: row.updated_by || ''
  };
}

function mapChat(row) {
  return {
    id: row.id,
    jobId: row.job_id,
    authorId: row.author_id || '',
    authorName: row.author_name || '',
    body: row.body || '',
    createdAt: row.created_at
  };
}

function mapNotice(row) {
  return {
    id: row.id,
    assignmentId: row.assignment_id,
    recipientName: row.recipient_name || '',
    recipientPhone: row.recipient_phone || '',
    recipientEmail: row.recipient_email || '',
    channel: row.channel,
    body: row.body || '',
    mapLink: row.map_link || '',
    sendAt: row.send_at,
    sentAt: row.sent_at,
    status: row.status,
    detail: row.detail || ''
  };
}

async function readAll(pool, tenant) {
  const [clients, labels, contacts, jobs, crews, members, assignments, reports, chat, notifications] = await Promise.all([
    pool.query(`SELECT * FROM job_sched_clients WHERE tenant_key = $1 ORDER BY name`, [tenant]),
    pool.query(`SELECT * FROM job_sched_labels WHERE tenant_key = $1 ORDER BY name`, [tenant]),
    pool.query(`SELECT * FROM job_sched_contacts WHERE tenant_key = $1 ORDER BY name`, [tenant]),
    pool.query(`SELECT * FROM job_sched_jobs WHERE tenant_key = $1 ORDER BY project_name`, [tenant]),
    pool.query(`SELECT * FROM job_sched_crews WHERE tenant_key = $1 ORDER BY name`, [tenant]),
    pool.query(
      `SELECT m.* FROM job_sched_crew_members m
       JOIN job_sched_crews c ON c.id = m.crew_id
       WHERE c.tenant_key = $1
       ORDER BY m.name`,
      [tenant]
    ),
    pool.query(`SELECT * FROM job_sched_assignments WHERE tenant_key = $1 ORDER BY start_date`, [tenant]),
    pool.query(
      `SELECT * FROM job_sched_reports WHERE tenant_key = $1 ORDER BY report_date DESC LIMIT 500`,
      [tenant]
    ),
    pool.query(
      `SELECT * FROM job_sched_chat WHERE tenant_key = $1 ORDER BY created_at DESC LIMIT 400`,
      [tenant]
    ),
    pool.query(
      `SELECT * FROM job_sched_notifications WHERE tenant_key = $1 ORDER BY send_at DESC LIMIT 200`,
      [tenant]
    )
  ]);
  const membersByCrew = new Map();
  for (const m of members.rows) {
    const list = membersByCrew.get(m.crew_id) || [];
    list.push(m);
    membersByCrew.set(m.crew_id, list);
  }
  return {
    clients: clients.rows.map(mapClient),
    labels: labels.rows.map((r) => ({ id: r.id, name: r.name })),
    contacts: contacts.rows.map(mapContact),
    jobs: jobs.rows.map(mapJob),
    crews: crews.rows.map((r) => mapCrew(r, membersByCrew.get(r.id) || [])),
    assignments: assignments.rows.map(mapAssignment),
    reports: reports.rows.map(mapReport),
    chat: chat.rows.map(mapChat).reverse(),
    notifications: notifications.rows.map(mapNotice)
  };
}

function visibleSlice(user, data, extras) {
  const myCrewIds = data.crews.filter((c) => c.members.some((m) => userMatchesMember(user, m))).map((c) => c.id);
  let role = 'employee';
  if (isCustomer(user)) role = 'customer';
  else if (isManager(user)) role = 'manager';
  else if (myCrewIds.length) role = 'crew';

  let jobs = data.jobs;
  if (role === 'customer') {
    jobs = data.jobs.filter((j) => customerSeesJob(user, j, data.contacts, data.clients));
  } else if (role === 'crew') {
    const ids = new Set(data.assignments.filter((a) => myCrewIds.includes(a.crewId)).map((a) => a.jobId));
    jobs = data.jobs.filter((j) => ids.has(j.id));
  } else if (role === 'employee') {
    jobs = [];
  }
  const jobIds = new Set(jobs.map((j) => j.id));
  const clientIds = new Set(jobs.map((j) => j.clientId));
  const contactIds = new Set(jobs.flatMap((j) => j.contactIds));
  const manager = role === 'manager';
  return {
    role,
    myCrewIds,
    smsConfigured: extras?.smsConfigured === true,
    clients: manager ? data.clients : data.clients.filter((c) => clientIds.has(c.id)),
    labels: manager ? data.labels : [],
    builtinLabels: BUILTIN_LABELS,
    contacts: manager
      ? data.contacts
      : data.contacts.filter((c) => (role === 'customer' ? contactIds.has(c.id) : contactIds.has(c.id) || clientIds.has(c.clientId))),
    jobs,
    crews: manager ? data.crews : data.crews.filter((c) => myCrewIds.includes(c.id)),
    assignments: data.assignments.filter((a) => (manager ? true : jobIds.has(a.jobId) && myCrewIds.includes(a.crewId))),
    reports: data.reports.filter((r) => jobIds.has(r.jobId)),
    chat: data.chat.filter((m) => jobIds.has(m.jobId)),
    notifications: manager ? data.notifications : []
  };
}

function mapEmployee(row) {
  return {
    id: String(row.id),
    username: row.username || '',
    displayName: row.display_name || row.username || '',
    phone: row.phone || '',
    title: row.title || '',
    employeeRole: row.employee_role || '',
    accountType: row.account_type || 'employee'
  };
}

async function listEmployeeAccounts(pool, tenant) {
  const base = `SELECT id, username, display_name, phone, title, employee_role, account_type
    FROM users
    WHERE LOWER(COALESCE(account_type, 'employee')) <> 'customer'`;
  try {
    if (!String(tenant || '').startsWith('saas:')) {
      const rows = await pool.query(`${base} ORDER BY LOWER(username)`);
      return rows.rows.map(mapEmployee);
    }
    const slug = String(tenant).slice(5).trim().toLowerCase();
    if (!slug) return null;
    const inst = await pool.query(
      `SELECT company_id, portal_client_id
       FROM saas_tenant_instances
       WHERE LOWER(wasabi_root_prefix) LIKE $1
          OR LOWER(portal_client_id) = $2
       LIMIT 1`,
      [`tenants/${slug}/%`, `tenant-${slug}`]
    );
    if (!inst.rows.length) return null;
    const where = tenantUsersWhereSql(1);
    const rows = await pool.query(
      `${base} AND ${where} ORDER BY LOWER(username)`,
      [inst.rows[0].portal_client_id || '', inst.rows[0].company_id]
    );
    return rows.rows.map(mapEmployee);
  } catch (error) {
    console.warn('[job-schedule] employee list skipped:', error?.message || error);
    return null;
  }
}

async function loadBundle(pool, user, tenant, mail, sms) {
  await ensureSchema(pool);
  const data = await readAll(pool, tenant);
  const slice = visibleSlice(user, data, {
    smsConfigured: sms?.configured === true || twilioReady()
  });
  if (slice.role === 'manager') {
    const employees = await listEmployeeAccounts(pool, tenant);
    if (Array.isArray(employees)) slice.employees = employees;
  }
  return { success: true, ...slice, smtpConfigured: !!(mail && mail.configured) };
}

function assertManager(user) {
  if (!isManager(user)) {
    const err = new Error('Managers and admins can change the schedule.');
    err.status = 403;
    throw err;
  }
}

async function jobVisible(pool, user, tenant, jobId) {
  const bundle = await loadBundle(pool, user, tenant, { configured: false });
  return bundle.jobs.some((j) => String(j.id) === String(jobId));
}

function parseClock(label) {
  const m = String(label || '').trim().match(/^(\d{1,2}):(\d{2})\s*(AM|PM)$/i);
  if (!m) return null;
  let h = Number(m[1]);
  const min = Number(m[2]);
  const ap = m[3].toUpperCase();
  if (h < 1 || h > 12 || min < 0 || min > 59) return null;
  if (ap === 'AM') h = h === 12 ? 0 : h;
  else h = h === 12 ? 12 : h + 12;
  return { h, min };
}

function zonedToUtc(isoDate, hours, minutes, timeZone) {
  const y = Number(isoDate.slice(0, 4));
  const mo = Number(isoDate.slice(5, 7));
  const d = Number(isoDate.slice(8, 10));
  const desired = Date.UTC(y, mo - 1, d, hours, minutes, 0);
  const dtf = new Intl.DateTimeFormat('en-US', {
    timeZone,
    hourCycle: 'h23',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
  const utcGuess = new Date(desired);
  const map = {};
  for (const p of dtf.formatToParts(utcGuess)) map[p.type] = p.value;
  const asUtc = Date.UTC(+map.year, +map.month - 1, +map.day, +map.hour, +map.minute, +map.second);
  return new Date(desired - (asUtc - utcGuess.getTime()));
}

function notifyInstant(startDate, arrivalTime, hours) {
  const tz = process.env.JOB_SCHEDULE_TZ || 'America/New_York';
  const clock = parseClock(arrivalTime) || { h: 7, min: 0 };
  const when = zonedToUtc(startDate, clock.h, clock.min, tz);
  return new Date(when.getTime() - Math.max(0, Number(hours) || 0) * 3600000);
}

async function lookupEmail(pool, member) {
  if (looksLikeEmail(member.phone)) return String(member.phone).trim();
  const phone = digits(member.phone).slice(-10);
  if (phone.length >= 7) {
    const byPhone = await pool.query(
      `SELECT email FROM users
       WHERE regexp_replace(COALESCE(phone, ''), '\\D', '', 'g') LIKE '%' || $1
         AND btrim(COALESCE(email, '')) <> ''
       LIMIT 1`,
      [phone]
    );
    if (byPhone.rows[0]?.email) return String(byPhone.rows[0].email).trim();
  }
  const name = normName(member.name);
  if (!name) return '';
  const byName = await pool.query(
    `SELECT email FROM users
     WHERE (lower(trim(COALESCE(display_name, ''))) = $1 OR lower(trim(COALESCE(username, ''))) = $1)
       AND btrim(COALESCE(email, '')) <> ''
     LIMIT 1`,
    [name]
  );
  return byName.rows[0]?.email ? String(byName.rows[0].email).trim() : '';
}

function mapsUrl(job) {
  if (job.mapUrl) return job.mapUrl;
  if (job.mapLat != null && job.mapLng != null) {
    return `https://www.google.com/maps/search/?api=1&query=${job.mapLat},${job.mapLng}`;
  }
  if (job.mapQuery) return `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(job.mapQuery)}`;
  const q = [job.city, job.state].filter(Boolean).join(', ');
  return q ? `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(q)}` : '';
}

function shiftWhen(assignment) {
  const start = `${assignment.startDate || ''}${assignment.arrivalTime ? ` ${assignment.arrivalTime}` : ''}`.trim();
  const endDifferent = assignment.endDate && assignment.endDate !== assignment.startDate;
  const end = endDifferent
    ? ` through ${assignment.endDate}${assignment.endTime ? ` ${assignment.endTime}` : ''}`
    : assignment.endTime
      ? ` until ${assignment.endTime}`
      : '';
  return `${start}${end}`.trim();
}

async function insertNotice(pool, row) {
  await pool.query(
    `INSERT INTO job_sched_notifications
      (id, tenant_key, assignment_id, recipient_name, recipient_phone, recipient_email, recipient_user_id, channel, notice_kind, body, map_link, send_at, status, detail)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'queued','')`,
    [
      crypto.randomUUID(),
      row.tenant,
      row.assignmentId,
      row.name || '',
      row.phone || '',
      row.email || '',
      row.userId || '',
      row.channel,
      row.kind || '',
      row.body,
      row.link || '',
      row.sendAt
    ]
  );
}

async function queueAssignmentNotices(pool, tenant, assignment, job, client, contacts, crew, noticeKind) {
  await pool.query(
    `DELETE FROM job_sched_notifications WHERE assignment_id = $1 AND status = 'queued'`,
    [assignment.id]
  );
  const link = mapsUrl(job);
  const poc = contacts.filter((c) => asArray(job.contactIds).includes(String(c.id)));
  const pocLine = poc.map((c) => `${c.name}${c.phone ? ` ${c.phone}` : ''}`).join('; ');
  const whenLine = [
    `Start ${assignment.startDate}${assignment.arrivalTime ? `, arrive ${assignment.arrivalTime}` : ''}`,
    `End ${assignment.endDate || assignment.startDate}${assignment.endTime ? ` ${assignment.endTime}` : ''}`
  ].join('. ');
  const leadBody = [
    `New job: ${job.projectName} for ${client?.name || 'client'}.`,
    [job.city, job.state, job.county].filter(Boolean).join(', '),
    whenLine,
    pocLine ? `Point of contact: ${pocLine}.` : '',
    link ? `Map: ${link}` : ''
  ]
    .filter(Boolean)
    .join('\n');
  const memberBody = [
    `You have a new job: ${job.projectName} for ${client?.name || 'client'}.`,
    link ? `Map: ${link}` : ''
  ]
    .filter(Boolean)
    .join('\n');
  const leads = crew.members.filter((m) => m.isLead);
  const emailAt = notifyInstant(assignment.startDate, assignment.arrivalTime, assignment.notifyHours);
  const remindAt = emailAt;
  const kind = noticeKind === 'change' ? 'change' : 'schedule';
  const place = [job.city, job.state].filter(Boolean).join(', ');
  const when = shiftWhen(assignment);
  const nowIso = new Date().toISOString();
  for (const member of crew.members) {
    const full = member.isLead || !leads.length;
    const email = await lookupEmail(pool, member);
    if (email) {
      await insertNotice(pool, {
        tenant,
        assignmentId: assignment.id,
        name: member.name,
        phone: member.phone || '',
        email,
        userId: member.userId || '',
        channel: 'email',
        kind: '',
        body: full ? leadBody : memberBody,
        link,
        sendAt: emailAt.toISOString()
      });
    }
    const smsBody = buildCrewText(kind, { project: job.projectName, when, place, map: link });
    await insertNotice(pool, {
      tenant,
      assignmentId: assignment.id,
      name: member.name,
      phone: member.phone || '',
      email: '',
      userId: member.userId || '',
      channel: 'sms',
      kind,
      body: smsBody,
      link,
      sendAt: nowIso
    });
    if ((Number(assignment.notifyHours) || 0) > 0 && remindAt.getTime() > Date.now() + 60_000) {
      await insertNotice(pool, {
        tenant,
        assignmentId: assignment.id,
        name: member.name,
        phone: member.phone || '',
        email: '',
        userId: member.userId || '',
        channel: 'sms',
        kind: 'reminder',
        body: buildCrewText('reminder', { project: job.projectName, when, place, map: link }),
        link,
        sendAt: remindAt.toISOString()
      });
    }
  }
}

async function queueCancelNotices(pool, tenant, assignment, job, crew) {
  const place = [job.city, job.state].filter(Boolean).join(', ');
  const when = shiftWhen(assignment);
  const body = buildCrewText('cancel', { project: job.projectName, when, place });
  const nowIso = new Date().toISOString();
  for (const member of crew.members || []) {
    await insertNotice(pool, {
      tenant,
      assignmentId: assignment.id,
      name: member.name,
      phone: member.phone || '',
      email: '',
      userId: member.userId || '',
      channel: 'sms',
      kind: 'cancel',
      body,
      link: '',
      sendAt: nowIso
    });
  }
}

async function ensureReport(pool, tenant, jobId, reportDate, userId) {
  const id = crypto.randomUUID();
  await pool.query(
    `INSERT INTO job_sched_reports (id, tenant_key, job_id, report_date, body, updated_by)
     VALUES ($1,$2,$3,$4,$5::jsonb,$6)
     ON CONFLICT (tenant_key, job_id, report_date) DO NOTHING`,
    [id, tenant, jobId, reportDate, JSON.stringify(emptyBody()), userId || '']
  );
}

function parseDataUrl(dataUrl) {
  const m = String(dataUrl || '').match(/^data:([^;,]+)(;base64)?,(.*)$/is);
  if (!m) return null;
  const mime = m[1].toLowerCase();
  if (!/^image\/(jpeg|png|webp|gif)$/.test(mime)) return null;
  const buf = Buffer.from(m[3].replace(/\s/g, ''), 'base64');
  if (!buf.length || buf.length > MAX_IMAGE_BYTES) return null;
  return { mime, buf };
}

async function applyAction(pool, user, tenant, body, mail, sms) {
  await ensureSchema(pool);
  const op = clean(body?.op, 40);
  const managerOps = new Set([
    'save-client',
    'delete-client',
    'save-contact',
    'delete-contact',
    'save-label',
    'save-job',
    'delete-job',
    'save-crew',
    'delete-crew',
    'save-member',
    'delete-member',
    'save-assignment',
    'delete-assignment'
  ]);
  if (managerOps.has(op)) assertManager(user);

  if (op === 'save-client') {
    const name = clean(body.name, 80);
    if (!name) throw Object.assign(new Error('Client name is required.'), { status: 400 });
    const id = clean(body.id, 80) || crypto.randomUUID();
    await pool.query(
      `INSERT INTO job_sched_clients (id, tenant_key, name, created_by)
       VALUES ($1,$2,$3,$4)
       ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name
       WHERE job_sched_clients.tenant_key = $2`,
      [id, tenant, name, String(user.id || '')]
    );
  } else if (op === 'delete-client') {
    const id = clean(body.id, 80);
    await pool.query(`DELETE FROM job_sched_contacts WHERE tenant_key = $1 AND client_id = $2`, [tenant, id]);
    const jobs = await pool.query(`SELECT id FROM job_sched_jobs WHERE tenant_key = $1 AND client_id = $2`, [tenant, id]);
    for (const row of jobs.rows) {
      await pool.query(`DELETE FROM job_sched_assignments WHERE tenant_key = $1 AND job_id = $2`, [tenant, row.id]);
      await pool.query(`DELETE FROM job_sched_reports WHERE tenant_key = $1 AND job_id = $2`, [tenant, row.id]);
      await pool.query(`DELETE FROM job_sched_chat WHERE tenant_key = $1 AND job_id = $2`, [tenant, row.id]);
      await pool.query(`DELETE FROM job_sched_media WHERE tenant_key = $1 AND job_id = $2`, [tenant, row.id]);
    }
    await pool.query(`DELETE FROM job_sched_jobs WHERE tenant_key = $1 AND client_id = $2`, [tenant, id]);
    await pool.query(`DELETE FROM job_sched_clients WHERE tenant_key = $1 AND id = $2`, [tenant, id]);
  } else if (op === 'save-label') {
    const name = clean(body.name, 40);
    if (!name) throw Object.assign(new Error('Label name is required.'), { status: 400 });
    await pool.query(
      `INSERT INTO job_sched_labels (id, tenant_key, name) VALUES ($1,$2,$3) ON CONFLICT (tenant_key, name) DO NOTHING`,
      [crypto.randomUUID(), tenant, name]
    );
  } else if (op === 'save-contact') {
    const name = clean(body.name, 120);
    const clientId = clean(body.clientId, 80);
    if (!name || !clientId) throw Object.assign(new Error('Pick a client and enter a name.'), { status: 400 });
    const labels = asArray(body.labels).map((x) => clean(x, 40)).filter(Boolean).slice(0, 12);
    const id = clean(body.id, 80) || crypto.randomUUID();
    await pool.query(
      `INSERT INTO job_sched_contacts (id, tenant_key, client_id, name, phone, labels)
       VALUES ($1,$2,$3,$4,$5,$6::jsonb)
       ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, phone = EXCLUDED.phone, labels = EXCLUDED.labels, client_id = EXCLUDED.client_id
       WHERE job_sched_contacts.tenant_key = $2`,
      [id, tenant, clientId, name, clean(body.phone, 40), JSON.stringify(labels)]
    );
  } else if (op === 'delete-contact') {
    await pool.query(`DELETE FROM job_sched_contacts WHERE tenant_key = $1 AND id = $2`, [tenant, clean(body.id, 80)]);
  } else if (op === 'save-job') {
    const clientId = clean(body.clientId, 80);
    const projectName = clean(body.projectName, 160);
    if (!clientId || !projectName) {
      throw Object.assign(new Error('A job needs a client and a project name.'), { status: 400 });
    }
    const id = clean(body.id, 80) || crypto.randomUUID();
    const pdfs = asArray(body.pdfs)
      .slice(0, 40)
      .map((p) => ({
        id: clean(p?.id, 80) || crypto.randomUUID(),
        name: clean(p?.name, 180),
        legacyDocId: clean(p?.legacyDocId, 80),
        storageKey: clean(p?.storageKey, 800),
        folderName: clean(p?.folderName, 120)
      }));
    const contactIds = asArray(body.contactIds).map((x) => clean(x, 80)).filter(Boolean).slice(0, 40);
    const lat = body.mapLat == null || body.mapLat === '' ? null : Number(body.mapLat);
    const lng = body.mapLng == null || body.mapLng === '' ? null : Number(body.mapLng);
    await pool.query(
      `INSERT INTO job_sched_jobs
        (id, tenant_key, client_id, city, state, county, project_name, description, map_query, map_lat, map_lng, map_url, pdfs, contact_ids)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14::jsonb)
       ON CONFLICT (id) DO UPDATE SET
         client_id = EXCLUDED.client_id,
         city = EXCLUDED.city,
         state = EXCLUDED.state,
         county = EXCLUDED.county,
         project_name = EXCLUDED.project_name,
         description = EXCLUDED.description,
         map_query = EXCLUDED.map_query,
         map_lat = EXCLUDED.map_lat,
         map_lng = EXCLUDED.map_lng,
         map_url = EXCLUDED.map_url,
         pdfs = EXCLUDED.pdfs,
         contact_ids = EXCLUDED.contact_ids,
         updated_at = NOW()
       WHERE job_sched_jobs.tenant_key = $2`,
      [
        id,
        tenant,
        clientId,
        clean(body.city, 80),
        clean(body.state, 40),
        clean(body.county, 80),
        projectName,
        cleanMultiline(body.description, 8000),
        clean(body.mapQuery, 300),
        Number.isFinite(lat) ? lat : null,
        Number.isFinite(lng) ? lng : null,
        clean(body.mapUrl, 600),
        JSON.stringify(pdfs),
        JSON.stringify(contactIds)
      ]
    );
  } else if (op === 'delete-job') {
    const id = clean(body.id, 80);
    await pool.query(`DELETE FROM job_sched_assignments WHERE tenant_key = $1 AND job_id = $2`, [tenant, id]);
    await pool.query(`DELETE FROM job_sched_reports WHERE tenant_key = $1 AND job_id = $2`, [tenant, id]);
    await pool.query(`DELETE FROM job_sched_chat WHERE tenant_key = $1 AND job_id = $2`, [tenant, id]);
    await pool.query(`DELETE FROM job_sched_media WHERE tenant_key = $1 AND job_id = $2`, [tenant, id]);
    await pool.query(`DELETE FROM job_sched_jobs WHERE tenant_key = $1 AND id = $2`, [tenant, id]);
  } else if (op === 'save-crew') {
    const name = clean(body.name, 80);
    if (!name) throw Object.assign(new Error('Crew name is required.'), { status: 400 });
    const id = clean(body.id, 80) || crypto.randomUUID();
    await pool.query(
      `INSERT INTO job_sched_crews (id, tenant_key, name) VALUES ($1,$2,$3)
       ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name WHERE job_sched_crews.tenant_key = $2`,
      [id, tenant, name]
    );
  } else if (op === 'delete-crew') {
    const id = clean(body.id, 80);
    await pool.query(`DELETE FROM job_sched_assignments WHERE tenant_key = $1 AND crew_id = $2`, [tenant, id]);
    await pool.query(`DELETE FROM job_sched_crews WHERE tenant_key = $1 AND id = $2`, [tenant, id]);
  } else if (op === 'save-member') {
    const crewId = clean(body.crewId, 80);
    const userId = clean(body.userId, 80);
    const memberId = clean(body.id, 80);
    if (!crewId) throw Object.assign(new Error('Pick a crew first.'), { status: 400 });
    if (!userId && !memberId) throw Object.assign(new Error('Choose an employee account.'), { status: 400 });
    const owns = await pool.query(`SELECT id FROM job_sched_crews WHERE tenant_key = $1 AND id = $2`, [tenant, crewId]);
    if (!owns.rows.length) throw Object.assign(new Error('Crew not found.'), { status: 404 });
    let account = null;
    if (userId) {
      const found = await pool.query(
        `SELECT id, username, display_name, phone, account_type FROM users WHERE CAST(id AS text) = $1 LIMIT 1`,
        [userId]
      );
      account = found.rows[0] || null;
      if (!account) throw Object.assign(new Error('That employee account was not found.'), { status: 404 });
      if (String(account.account_type || 'employee').toLowerCase() === 'customer') {
        throw Object.assign(new Error('Choose an employee account.'), { status: 400 });
      }
      const dup = await pool.query(
        `SELECT m.id FROM job_sched_crew_members m
         JOIN job_sched_crews c ON c.id = m.crew_id
         WHERE c.tenant_key = $1 AND m.crew_id = $2 AND m.user_id = $3 AND ($4 = '' OR CAST(m.id AS text) <> $4)
         LIMIT 1`,
        [tenant, crewId, userId, memberId]
      );
      if (dup.rows.length) throw Object.assign(new Error('That employee is already on this crew.'), { status: 400 });
    }
    const phone = Object.prototype.hasOwnProperty.call(body, 'phone')
      ? clean(body.phone, 40)
      : account
        ? clean(account.phone, 40)
        : '';
    const name = account ? clean(account.display_name || account.username, 120) : clean(body.name, 120);
    if (!name) throw Object.assign(new Error('Choose an employee account.'), { status: 400 });
    if (account && phone !== clean(account.phone, 40)) {
      await pool.query(`UPDATE users SET phone = $2, updated_at = NOW() WHERE CAST(id AS text) = $1`, [
        String(account.id),
        phone || null
      ]);
    }
    if (memberId) {
      await pool.query(
        `UPDATE job_sched_crew_members m
         SET name = $3, phone = $4, is_lead = $5, user_id = COALESCE(NULLIF($6, ''), m.user_id)
         FROM job_sched_crews c
         WHERE m.id = $1 AND m.crew_id = c.id AND c.tenant_key = $2`,
        [memberId, tenant, name, phone, body.isLead === true, userId]
      );
    } else {
      await pool.query(
        `INSERT INTO job_sched_crew_members (id, crew_id, name, phone, is_lead, user_id) VALUES ($1,$2,$3,$4,$5,$6)`,
        [crypto.randomUUID(), crewId, name, phone, body.isLead === true, userId || null]
      );
    }
  } else if (op === 'delete-member') {
    await pool.query(
      `DELETE FROM job_sched_crew_members m USING job_sched_crews c
       WHERE m.id = $1 AND m.crew_id = c.id AND c.tenant_key = $2`,
      [clean(body.id, 80), tenant]
    );
  } else if (op === 'save-assignment') {
    const jobId = clean(body.jobId, 80);
    const crewId = clean(body.crewId, 80);
    const startDate = clean(body.startDate, 10);
    if (!jobId || !crewId || !/^\d{4}-\d{2}-\d{2}$/.test(startDate)) {
      throw Object.assign(new Error('Pick a job, a crew, and a start date.'), { status: 400 });
    }
    const endDate = /^\d{4}-\d{2}-\d{2}$/.test(clean(body.endDate, 10)) ? clean(body.endDate, 10) : startDate;
    const id = clean(body.id, 80) || crypto.randomUUID();
    const prior = await pool.query(
      `SELECT id FROM job_sched_assignments WHERE tenant_key = $1 AND id = $2 LIMIT 1`,
      [tenant, id]
    );
    const noticeKind = prior.rows.length ? 'change' : 'schedule';
    const notifyHours = Math.max(0, Math.min(336, Number(body.notifyHours) || 0));
    await pool.query(
      `INSERT INTO job_sched_assignments
        (id, tenant_key, job_id, crew_id, start_date, arrival_time, end_date, end_time, notify_hours, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       ON CONFLICT (id) DO UPDATE SET
         job_id = EXCLUDED.job_id,
         crew_id = EXCLUDED.crew_id,
         start_date = EXCLUDED.start_date,
         arrival_time = EXCLUDED.arrival_time,
         end_date = EXCLUDED.end_date,
         end_time = EXCLUDED.end_time,
         notify_hours = EXCLUDED.notify_hours`,
      [
        id,
        tenant,
        jobId,
        crewId,
        startDate,
        clean(body.arrivalTime, 20),
        endDate,
        clean(body.endTime, 20),
        notifyHours,
        String(user.id || '')
      ]
    );
    await ensureReport(pool, tenant, jobId, startDate, String(user.id || ''));
    const data = await readAll(pool, tenant);
    const assignment = data.assignments.find((a) => a.id === id);
    const job = data.jobs.find((j) => j.id === jobId);
    const client = data.clients.find((c) => c.id === job?.clientId);
    const crew = data.crews.find((c) => c.id === crewId);
    if (assignment && job && crew) {
      await queueAssignmentNotices(pool, tenant, assignment, job, client, data.contacts, crew, noticeKind);
    }
  } else if (op === 'delete-assignment') {
    const id = clean(body.id, 80);
    const data = await readAll(pool, tenant);
    const assignment = data.assignments.find((a) => a.id === id);
    const job = data.jobs.find((j) => j.id === assignment?.jobId);
    const crew = data.crews.find((c) => c.id === assignment?.crewId);
    await pool.query(`DELETE FROM job_sched_notifications WHERE assignment_id = $1 AND status = 'queued'`, [id]);
    await pool.query(`DELETE FROM job_sched_assignments WHERE tenant_key = $1 AND id = $2`, [tenant, id]);
    if (assignment && job && crew) await queueCancelNotices(pool, tenant, assignment, job, crew);
  } else if (op === 'save-report') {
    const jobId = clean(body.jobId, 80);
    const reportDate = clean(body.reportDate, 10);
    if (!jobId || !/^\d{4}-\d{2}-\d{2}$/.test(reportDate)) {
      throw Object.assign(new Error('A report needs a job and a date.'), { status: 400 });
    }
    if (!(await jobVisible(pool, user, tenant, jobId))) {
      throw Object.assign(new Error('You cannot edit this daily report.'), { status: 403 });
    }
    const saved = sanitizeBody(body.body);
    await pool.query(
      `INSERT INTO job_sched_reports (id, tenant_key, job_id, report_date, body, updated_by)
       VALUES ($1,$2,$3,$4,$5::jsonb,$6)
       ON CONFLICT (tenant_key, job_id, report_date)
       DO UPDATE SET body = EXCLUDED.body, updated_at = NOW(), updated_by = EXCLUDED.updated_by`,
      [crypto.randomUUID(), tenant, jobId, reportDate, JSON.stringify(saved), String(user.displayName || user.username || '')]
    );
  } else if (op === 'add-image') {
    const jobId = clean(body.jobId, 80);
    const reportDate = clean(body.reportDate, 10);
    if (!(await jobVisible(pool, user, tenant, jobId))) {
      throw Object.assign(new Error('You cannot add a photo to this report.'), { status: 403 });
    }
    const parsed = parseDataUrl(body.dataUrl);
    if (!parsed) throw Object.assign(new Error('Use a JPEG, PNG, WEBP, or GIF under 4 MB.'), { status: 400 });
    const mediaId = crypto.randomUUID();
    await pool.query(
      `INSERT INTO job_sched_media (id, tenant_key, job_id, name, mime, bytes) VALUES ($1,$2,$3,$4,$5,$6)`,
      [mediaId, tenant, jobId, clean(body.name, 180) || 'photo', parsed.mime, parsed.buf]
    );
    await ensureReport(pool, tenant, jobId, reportDate, String(user.id || ''));
    const existing = await pool.query(
      `SELECT body FROM job_sched_reports WHERE tenant_key = $1 AND job_id = $2 AND report_date = $3`,
      [tenant, jobId, reportDate]
    );
    const next = sanitizeBody(existing.rows[0]?.body);
    next.images.push({ id: mediaId, name: clean(body.name, 180) || 'photo' });
    await pool.query(
      `UPDATE job_sched_reports SET body = $4::jsonb, updated_at = NOW(), updated_by = $5
       WHERE tenant_key = $1 AND job_id = $2 AND report_date = $3`,
      [tenant, jobId, reportDate, JSON.stringify(next), String(user.displayName || user.username || '')]
    );
  } else if (op === 'chat') {
    const jobId = clean(body.jobId, 80);
    const text = cleanMultiline(body.text, 4000);
    if (!text) throw Object.assign(new Error('Write a message first.'), { status: 400 });
    if (!(await jobVisible(pool, user, tenant, jobId))) {
      throw Object.assign(new Error('You cannot post on this job.'), { status: 403 });
    }
    await pool.query(
      `INSERT INTO job_sched_chat (id, tenant_key, job_id, author_id, author_name, body)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [
        crypto.randomUUID(),
        tenant,
        jobId,
        String(user.id || ''),
        clean(user.displayName || user.username || 'Someone', 120),
        text
      ]
    );
  } else {
    throw Object.assign(new Error('Unknown schedule action.'), { status: 400 });
  }

  await processDue(pool, mail, sms);
  return loadBundle(pool, user, tenant, mail, sms);
}

async function readMedia(pool, user, tenant, id) {
  await ensureSchema(pool);
  const row = await pool.query(`SELECT * FROM job_sched_media WHERE id = $1 AND tenant_key = $2`, [id, tenant]);
  const media = row.rows[0];
  if (!media) return null;
  if (!(await jobVisible(pool, user, tenant, media.job_id))) return null;
  return media;
}

function pipeScopesForUser(user) {
  const out = [];
  const seen = new Set();
  const push = (clientId, jobId) => {
    const c = clean(clientId, 120);
    const j = clean(jobId, 120);
    if (!c || !j) return;
    const key = `${c}\n${j}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ clientId: c, jobId: j });
  };
  for (const s of asArray(user?.portalScopes)) push(s.clientId || s.client_id, s.jobId || s.job_id);
  push(user?.portalFilesClientId, user?.portalFilesJobId);
  return out.slice(0, 80);
}

async function claimNotice(pool, id) {
  const claim = await pool.query(
    `UPDATE job_sched_notifications
     SET status = 'sending', detail = 'Sending.'
     WHERE id = $1 AND status = 'queued'
     RETURNING id`,
    [id]
  );
  return claim.rows.length > 0;
}

async function holdNotice(pool, id, detail) {
  await pool.query(`UPDATE job_sched_notifications SET status = 'held', detail = $2 WHERE id = $1`, [
    id,
    clean(detail || 'Not sent.', 300)
  ]);
}

async function processDue(pool, mail, sms) {
  await ensureSchema(pool);
  const sender = sms || smsSender();
  const due = await pool.query(
    `SELECT * FROM job_sched_notifications
     WHERE status = 'queued' AND send_at <= NOW()
     ORDER BY send_at
     LIMIT 30`
  );
  for (const row of due.rows) {
    if (!(await claimNotice(pool, row.id))) continue;
    try {
      if (row.channel === 'email' && row.recipient_email && mail?.send) {
        const result = await mail.send({
          to: row.recipient_email,
          subject: 'Horizon job assignment',
          text: row.body
        });
        if (result?.ok) {
          await pool.query(
            `UPDATE job_sched_notifications SET status = 'sent', sent_at = NOW(), detail = 'Sent by email.' WHERE id = $1`,
            [row.id]
          );
          continue;
        }
        await holdNotice(pool, row.id, result?.message || 'Email could not be sent.');
        continue;
      }
      if (row.channel === 'sms') {
        if (!sender?.configured || typeof sender.send !== 'function') {
          await holdNotice(pool, row.id, 'Texting service is not configured on the server.');
          continue;
        }
        const gate = await evaluateEmployeeSms(pool, {
          userId: row.recipient_user_id,
          phone: row.recipient_phone
        });
        if (!gate.ok) {
          await holdNotice(pool, row.id, gate.reason);
          continue;
        }
        const result = await sender.send({ to: gate.to, body: withStopFooter(row.body) });
        if (result?.ok) {
          await pool.query(
            `UPDATE job_sched_notifications SET status = 'sent', sent_at = NOW(), detail = 'Sent as an operational schedule text.' WHERE id = $1`,
            [row.id]
          );
          continue;
        }
        if (String(result?.code) === '21610') await markOptOut(pool, gate.to);
        await holdNotice(pool, row.id, result?.message || 'Text was not sent.');
        continue;
      }
      await holdNotice(
        pool,
        row.id,
        'No email address was found for this person, and this row is not an operational text.'
      );
    } catch (err) {
      await holdNotice(pool, row.id, 'That notice could not be sent.');
      console.warn('[job-schedule] notice', err?.message || err);
    }
  }
}

/**
 * Index Misc/Docu/Problems/problems.json onto the daily report for each problem's job and date.
 * Matches a video that is already in the uploaded tree. Does not download video bytes.
 */
async function mergeWincanProblems(pool, tenant, doc, ctx) {
  await ensureSchema(pool);
  const incoming = Array.isArray(doc?.problems) ? doc.problems : [];
  const projectId = clean(doc?.projectId, 80);
  const root = String(ctx?.projectRoot || '')
    .replace(/\\/g, '/')
    .replace(/\/+$/, '');
  const fileIndex = ctx?.fileIndex instanceof Map ? ctx.fileIndex : new Map();
  const groups = new Map();
  for (const raw of incoming) {
    const jobId = clean(raw?.jobId, 80);
    const reportDate = isoDate(raw?.reportDate);
    if (!jobId || !/^\d{4}-\d{2}-\d{2}$/.test(reportDate)) continue;
    const videoPath = clean(raw?.videoPath, 500).replace(/\\/g, '/').replace(/^\/+/, '');
    const full = root && videoPath ? `${root}/${videoPath}`.replace(/\/+/g, '/') : videoPath;
    const videoId = full ? fileIndex.get(full.toLowerCase()) || '' : '';
    const key = `${jobId}\n${reportDate}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push({
      ...raw,
      videoPath,
      videoId,
      projectId: clean(raw?.projectId, 80) || projectId
    });
  }
  for (const [key, rows] of groups) {
    const split = key.indexOf('\n');
    const jobId = key.slice(0, split);
    const reportDate = key.slice(split + 1);
    await ensureReport(pool, tenant, jobId, reportDate, 'wincan-problems');
    const found = await pool.query(
      `SELECT body FROM job_sched_reports WHERE tenant_key = $1 AND job_id = $2 AND report_date = $3`,
      [tenant, jobId, reportDate]
    );
    const current = found.rows[0]?.body && typeof found.rows[0].body === 'object' ? found.rows[0].body : {};
    const problems = Array.isArray(current.problems) ? current.problems.slice() : [];
    for (const row of rows) {
      const id = clean(row.id, 80);
      const idx = id ? problems.findIndex((item) => clean(item?.id, 80) === id) : -1;
      const prior = idx >= 0 ? problems[idx] : {};
      const next = {
        ...prior,
        ...row,
        videoId: row.videoId || prior.videoId || ''
      };
      if (idx >= 0) problems[idx] = next;
      else problems.push(next);
    }
    const cleanBody = sanitizeBody({ ...current, problems });
    await pool.query(
      `UPDATE job_sched_reports SET body = $4::jsonb, updated_at = NOW(), updated_by = $5
       WHERE tenant_key = $1 AND job_id = $2 AND report_date = $3`,
      [tenant, jobId, reportDate, JSON.stringify(cleanBody), 'wincan-problems']
    );
  }
}

module.exports = {
  BUILTIN_LABELS,
  MAX_CLIP_SEC,
  clampClip,
  tenantKey,
  ensureSchema,
  loadBundle,
  applyAction,
  readMedia,
  pipeScopesForUser,
  processDue,
  mergeWincanProblems
};

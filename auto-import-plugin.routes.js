const express = require('express');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');
const initSqlJs = require('sql.js');
const {
  extractCustomerFromDb3,
  resolveCityForAutosyncPsr
} = require('./lib/autosync-psr-ingest');

function createAutoImportPlugin(options = {}) {
  const {
    pool: poolOption,
    query,
    requireMike,
    /** Optional; when set, used only for desktop heartbeat routes (align with portal Data Auto Sync users). */
    requireDesktopHeartbeat,
    requireAuth,
    writeSegment,
    buildVersion,
    /** Load a normalized planner record (same shape as {@code fetchRecordById}) for segment matching during DB3 sync. */
    fetchPlannerRecord,
    /** Optional: list known PipeSync cities for AutoSync city matching. */
    listKnownPlannerCities,
    /** Optional: find planner records by client/city/jobsite. */
    findPlannerRecordsByScope,
    /** Optional: create a planner record when AutoSync has no target jobsite yet. */
    createPlannerRecord,
    /** Optional: normalize jobsite names the same way PipeSync does. */
    normalizeJobsiteName,
    uid = () => crypto.randomUUID(),
    nowIso = () => new Date().toISOString(),
    uploadDir = path.join(process.cwd(), 'uploads', 'auto-import-plugin'),
    logger = console
  } = options;

  const dbQuery =
    typeof query === 'function'
      ? query
      : (poolOption && typeof poolOption.query === 'function' ? poolOption.query.bind(poolOption) : null);
  if (typeof dbQuery !== 'function') {
    throw new Error('createAutoImportPlugin requires either pool.query or options.query.');
  }
  const pool = { query: dbQuery };
  /**
   * Heartbeats, init DDL, and **portal DAS monitor reads** must hit live Postgres when `options.query` is the
   * Wasabi auto-import adapter (snapshot can lag or omit rows that uploads/heartbeat just wrote).
   */
  const directPgQuery =
    poolOption && typeof poolOption.query === 'function' ? poolOption.query.bind(poolOption) : null;
  async function runPostgresAutoImportSql(text, params = []) {
    if (directPgQuery) return directPgQuery(text, params);
    return pool.query(text, params);
  }

  /**
   * DAS monitor reads: live Postgres first (matches heartbeat + immediate writes). If the table is empty there
   * but Wasabi-primary has populated the snapshot adapter, fall back to `pool.query` so the UI is not blank.
   */
  async function readAutoImportMonitorSql(text, params = []) {
    const pg = await runPostgresAutoImportSql(text, params);
    if (pg && Array.isArray(pg.rows) && pg.rows.length > 0) return pg;
    try {
      const viaAdapter = await pool.query(text, params);
      if (viaAdapter && Array.isArray(viaAdapter.rows) && viaAdapter.rows.length > 0) return viaAdapter;
    } catch {
      /* ignore */
    }
    return pg || { rows: [] };
  }
  if (typeof requireMike !== 'function') throw new Error('createAutoImportPlugin requires requireMike middleware.');
  const desktopHeartbeatGate =
    typeof requireDesktopHeartbeat === 'function' ? requireDesktopHeartbeat : requireMike;
  if (typeof requireAuth !== 'function') throw new Error('createAutoImportPlugin requires requireAuth middleware.');
  if (typeof writeSegment !== 'function') throw new Error('createAutoImportPlugin requires writeSegment(jobsiteId, payload, savedBy).');
  if (typeof buildVersion !== 'function') throw new Error('createAutoImportPlugin requires buildVersion(payload).');
  if (typeof fetchPlannerRecord !== 'function') {
    throw new Error('createAutoImportPlugin requires fetchPlannerRecord(jobsiteId) for structure-aware DB3 sync.');
  }

  fs.mkdirSync(uploadDir, { recursive: true });

  const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => {
      const safe = String(file.originalname || 'file').replace(/[^a-zA-Z0-9._-]/g, '_');
      cb(null, `${Date.now()}_${crypto.randomUUID()}_${safe}`);
    }
  });
  const upload = multer({ storage, limits: { fileSize: 60 * 1024 * 1024 } });

  const router = express.Router();
  const HEARTBEAT_TTL_MS = (() => {
    const raw = Number(process.env.AUTO_IMPORT_HEARTBEAT_TTL_MS);
    /** Default 90s so slower desktop poll intervals do not flash "offline" while uploads still work. */
    if (!Number.isFinite(raw)) return 90_000;
    return Math.max(10_000, Math.min(300_000, Math.floor(raw)));
  })();
  /** GET /monitor-snapshot: coalesce identical viewers (0 disables). */
  const MONITOR_SNAPSHOT_CACHE_MS = Math.max(
    0,
    Math.min(60_000, Number(process.env.AUTO_IMPORT_MONITOR_SNAPSHOT_CACHE_MS ?? 3500))
  );
  const monitorSnapshotCache = new Map();
  /** POST /desktop-heartbeat: min interval between Postgres upserts per user_key (0 = every POST). */
  const HEARTBEAT_MIN_WRITE_MS = Math.max(
    0,
    Math.min(300_000, Number(process.env.AUTO_IMPORT_HEARTBEAT_MIN_WRITE_MS ?? 10_000))
  );
  const lastHeartbeatWriteMs = new Map();

  function rememberMonitorSnapshot(cacheKey, body) {
    if (MONITOR_SNAPSHOT_CACHE_MS <= 0) return;
    monitorSnapshotCache.set(cacheKey, { exp: Date.now() + MONITOR_SNAPSHOT_CACHE_MS, body });
    if (monitorSnapshotCache.size > 500) {
      const drop = Math.ceil(monitorSnapshotCache.size / 2);
      let n = 0;
      for (const k of monitorSnapshotCache.keys()) {
        monitorSnapshotCache.delete(k);
        if (++n >= drop) break;
      }
    }
  }

  /**
   * Desktop JWT and browser session must resolve the same logical user; some clients only have
   * numeric `id`, others only `username` in the persisted session. We read/write heartbeats under
   * every stable key so GET sees POSTs regardless of which field the gateway attached first.
   * @returns {string[]}
   */
  function heartbeatKeys(req) {
    const u = req?.user;
    if (!u) return ['anon'];
    const keys = [];
    const pushKey = (raw) => {
      const k = String(raw || '').trim();
      if (!k) return;
      if (!keys.includes(k)) keys.push(k);
    };
    const id = u.id != null ? String(u.id).trim() : '';
    const un = u.username != null ? String(u.username).trim().toLowerCase() : '';
    const em = u.email != null ? String(u.email).trim().toLowerCase() : '';
    pushKey(id);
    if (un) pushKey(un);
    if (em) pushKey(em);
    return keys.length ? keys : ['anon'];
  }

  async function initSchema() {
    await runPostgresAutoImportSql(`
      CREATE TABLE IF NOT EXISTS auto_import_projects (
        id TEXT PRIMARY KEY,
        source_key TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL,
        db3_path TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'idle',
        detection_mode TEXT NOT NULL DEFAULT 'auto',
        detected_job_client TEXT DEFAULT '',
        detected_job_city TEXT DEFAULT '',
        detected_jobsite TEXT DEFAULT '',
        last_seen_at TIMESTAMPTZ,
        last_scan_at TIMESTAMPTZ,
        last_switch_at TIMESTAMPTZ,
        last_error TEXT DEFAULT '',
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS auto_import_runs (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL REFERENCES auto_import_projects(id) ON DELETE CASCADE,
        started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        completed_at TIMESTAMPTZ,
        active_db3_path TEXT NOT NULL,
        switch_reason TEXT DEFAULT '',
        rows_found INTEGER NOT NULL DEFAULT 0,
        rows_changed INTEGER NOT NULL DEFAULT 0,
        rows_inserted INTEGER NOT NULL DEFAULT 0,
        rows_updated INTEGER NOT NULL DEFAULT 0,
        notes TEXT DEFAULT '',
        payload JSONB NOT NULL DEFAULT '{}'::jsonb
      );

      CREATE TABLE IF NOT EXISTS auto_import_row_cache (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL REFERENCES auto_import_projects(id) ON DELETE CASCADE,
        row_key TEXT NOT NULL,
        row_hash TEXT NOT NULL,
        system_type TEXT NOT NULL DEFAULT 'storm',
        reference TEXT NOT NULL,
        upstream TEXT DEFAULT '',
        downstream TEXT DEFAULT '',
        dia TEXT DEFAULT '',
        material TEXT DEFAULT '',
        length NUMERIC(12,3) DEFAULT 0,
        footage NUMERIC(12,3) DEFAULT 0,
        source_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
        first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(project_id, row_key)
      );

      CREATE TABLE IF NOT EXISTS auto_import_bindings (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL REFERENCES auto_import_projects(id) ON DELETE CASCADE,
        client TEXT NOT NULL,
        city TEXT NOT NULL,
        jobsite TEXT NOT NULL,
        system_type TEXT NOT NULL DEFAULT 'storm',
        pinned BOOLEAN NOT NULL DEFAULT FALSE,
        created_by TEXT DEFAULT '',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(project_id)
      );

      CREATE INDEX IF NOT EXISTS idx_auto_import_projects_seen ON auto_import_projects(last_seen_at DESC);
      CREATE INDEX IF NOT EXISTS idx_auto_import_runs_project_started ON auto_import_runs(project_id, started_at DESC);
      CREATE INDEX IF NOT EXISTS idx_auto_import_row_cache_project_seen ON auto_import_row_cache(project_id, last_seen_at DESC);

      CREATE TABLE IF NOT EXISTS auto_import_logs (
        id TEXT PRIMARY KEY,
        project_id TEXT REFERENCES auto_import_projects(id) ON DELETE CASCADE,
        source TEXT NOT NULL DEFAULT 'server',
        level TEXT NOT NULL DEFAULT 'info',
        message TEXT NOT NULL,
        payload JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_auto_import_logs_project_created ON auto_import_logs(project_id, created_at DESC);

      CREATE TABLE IF NOT EXISTS auto_import_desktop_heartbeats (
        user_key TEXT PRIMARY KEY,
        at_ms BIGINT NOT NULL,
        state TEXT NOT NULL DEFAULT 'connected',
        source TEXT NOT NULL DEFAULT 'desktop',
        detail TEXT NOT NULL DEFAULT '',
        username TEXT NOT NULL DEFAULT '',
        display_name TEXT NOT NULL DEFAULT '',
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_auto_import_desktop_hb_updated ON auto_import_desktop_heartbeats(updated_at DESC);
    `);
  }

  function clean(value) {
    return String(value || '').trim();
  }

  function normalizeMode(value) {
    const mode = clean(value).toLowerCase();
    if (mode === 'pinned') return 'pinned';
    if (mode === 'suggest') return 'suggest';
    return 'auto';
  }

  function diaFromShape(shape, size1, size2) {
    const s1 = clean(size1);
    const s2 = clean(size2);
    const shapeText = clean(shape).toLowerCase();
    if (s1 && s2 && s1 !== s2) return `${s1}x${s2}`;
    if (s1) return s1;
    if (shapeText.includes('ellipse') && s1 && s2) return `${s1}x${s2}`;
    return s1 || s2 || clean(shape);
  }

  function sha(value) {
    return crypto.createHash('sha1').update(value).digest('hex');
  }

  async function logEvent(projectId, source, level, message, payload = {}) {
    try {
      const rawPid = projectId == null ? '' : String(projectId).trim();
      const pid = !rawPid || rawPid === '__global__' ? null : clean(rawPid);
      // Use Wasabi-primary adapter (pool.query), not direct Postgres — projects may exist only in snapshot.
      await pool.query(
        `INSERT INTO auto_import_logs (id, project_id, source, level, message, payload)
         VALUES ($1,$2,$3,$4,$5,$6::jsonb)`,
        [
          uid(),
          pid,
          clean(source || 'server') || 'server',
          clean(level || 'info') || 'info',
          clean(message),
          JSON.stringify(payload || {})
        ]
      );
    } catch (e) {
      logger.warn?.('AUTO IMPORT LOG WRITE FAILED:', e?.message || e);
    }
  }

  function rowKeyFor(row) {
    return `${clean(row.system || 'storm')}|${clean(row.reference).toLowerCase()}`;
  }

  /** Order-independent key for matching ST-204–ST-402 with ST-402–ST-204. */
  function structurePairKey(upstream, downstream) {
    const u = clean(upstream).toLowerCase();
    const d = clean(downstream).toLowerCase();
    if (!u || !d) return null;
    return u <= d ? `${u}\u0001${d}` : `${d}\u0001${u}`;
  }

  function rowHashFor(row) {
    const pair = structurePairKey(row.upstream, row.downstream);
    return sha(JSON.stringify({
      reference: clean(row.reference).toLowerCase(),
      structurePair: pair || '',
      dia: clean(row.dia),
      material: clean(row.material),
      length: Number(row.length || 0),
      footage: Number(row.footage || row.length || 0)
    }));
  }

  function systemKeyFromBinding(binding) {
    const st = clean(binding.system_type || 'storm').toLowerCase();
    return st === 'sanitary' ? 'sanitary' : 'storm';
  }

  function findExistingSegment(segments, row) {
    if (!Array.isArray(segments) || !segments.length) return null;
    const ref = clean(row.reference).toLowerCase();
    if (ref) {
      const byRef = segments.find((s) => clean(s.reference).toLowerCase() === ref);
      if (byRef) return byRef;
    }
    const pair = structurePairKey(row.upstream, row.downstream);
    if (!pair) return null;
    return segments.find((s) => structurePairKey(s.upstream, s.downstream) === pair) || null;
  }

  function cloneJson(value) {
    try {
      return JSON.parse(JSON.stringify(value));
    } catch {
      return null;
    }
  }

  function numFootage(seg, row) {
    const n = Number(seg?.footage ?? seg?.length ?? row?.footage ?? row?.length ?? 0);
    return Number.isFinite(n) ? n : 0;
  }

  function buildPayloadForRow(project, binding, row, existing, username) {
    const system = binding.system_type || 'storm';
    const nextLen = Number(row.length || 0);
    const nextFoot = Number(row.footage || row.length || 0);
    const savedBy = username || 'System';
    const today = nowIso().slice(0, 10);

    if (!existing) {
      return {
        id: uid(),
        system,
        reference: row.reference,
        upstream: row.upstream || '',
        downstream: row.downstream || '',
        dia: row.dia || '',
        material: row.material || '',
        length: nextLen,
        footage: nextFoot,
        versions: [
          buildVersion({
            status: 'neutral',
            notes: 'Auto Sync',
            recordedDate: today,
            savedBy
          }),
          buildVersion({
            status: 'complete',
            notes: 'autosync complete',
            recordedDate: today,
            savedBy
          })
        ]
      };
    }

    const versions = cloneJson(existing.versions) || [];
    const prevFoot = numFootage(existing, null);
    const footageChanged = Math.abs(prevFoot - nextFoot) > 0.0001;
    const diaChanged = clean(existing.dia) !== clean(row.dia);
    const matChanged = clean(existing.material) !== clean(row.material);
    const last = versions.length ? versions[versions.length - 1] : {};
    const carryStatus = clean(last.status || 'complete') || 'complete';

    if (footageChanged) {
      versions.push(
        buildVersion({
          status: carryStatus,
          notes: 'footage added from auto sync',
          recordedDate: today,
          savedBy
        })
      );
    } else if (diaChanged || matChanged) {
      versions.push(
        buildVersion({
          status: carryStatus,
          notes: 'Auto sync: DB3 metadata updated.',
          recordedDate: today,
          savedBy
        })
      );
    }

    return {
      id: existing.id,
      system,
      reference: existing.reference,
      upstream: existing.upstream || '',
      downstream: existing.downstream || '',
      dia: row.dia || existing.dia || '',
      material: row.material || existing.material || '',
      length: nextLen,
      footage: nextFoot,
      versions: versions.length ? versions : [
        buildVersion({
          status: 'neutral',
          notes: `Auto imported from ${project.display_name}`,
          recordedDate: today,
          savedBy
        })
      ]
    };
  }

  /**
   * Desktop AUTOSYNC sends Windows absolute DB3 paths. Those files are not on this Linux host —
   * never try to open them here (was flooding 500s → nginx 502 / broken uploads).
   */
  function isClientLocalDb3Path(filePath) {
    const p = String(filePath || '').trim();
    if (!p) return false;
    if (/^[A-Za-z]:[\\/]/.test(p)) return true;
    if (p.startsWith('\\\\')) return true;
    return false;
  }

  function normalizeDb3SourcePath(filePath) {
    const p = String(filePath || '').trim();
    if (!p) return '';
    if (isClientLocalDb3Path(p)) {
      return p.replace(/\//g, '\\');
    }
    try {
      return path.resolve(p);
    } catch {
      return p;
    }
  }

  async function parseDb3(filePath) {
    const abs = String(filePath || '').trim();
    if (!abs) throw new Error('DB3 path is empty.');
    if (isClientLocalDb3Path(abs)) {
      const err = new Error(
        'DB3 path is on the crew PC, not this server. Send rows from Desktop Auto Sync (registerOnly discover + sync with rows).'
      );
      err.status = 400;
      throw err;
    }
    try {
      await fsp.access(abs);
    } catch {
      const err = new Error(`DB3 not readable on server: ${abs}`);
      err.status = 400;
      throw err;
    }
    const SQL = await initSqlJs({ locateFile: (file) => require.resolve(`sql.js/dist/${file}`) });
    const buffer = await fsp.readFile(abs);
    const db = new SQL.Database(buffer);
    const tablesResult = db.exec("SELECT name FROM sqlite_master WHERE type='table'");
    const tables = new Set((tablesResult[0]?.values || []).map((row) => row[0]));
    if (!tables.has('SECTION')) throw new Error('SECTION table not found in DB3 file.');

    const result = db.exec(`
      SELECT
        COALESCE(s.OBJ_Key, '') AS reference,
        COALESCE(s.OBJ_FromNode_REF, '') AS upstream,
        COALESCE(s.OBJ_ToNode_REF, '') AS downstream,
        COALESCE(s.OBJ_Material, '') AS material,
        COALESCE(s.OBJ_Shape, '') AS shape,
        COALESCE(s.OBJ_Size1, '') AS size1,
        COALESCE(s.OBJ_Size2, '') AS size2,
        COALESCE(si.INS_InspectedLength, s.OBJ_Length, 0) AS length,
        COALESCE(s.OBJ_City, '') AS city,
        COALESCE(s.OBJ_Street, '') AS street,
        COALESCE(s.OBJ_Project, '') AS project_name
      FROM SECTION s
      LEFT JOIN SECINSP si ON si.OBJ_ID = s.OBJ_ID
    `);

    if (!result[0]) return [];
    const columns = result[0].columns;
    return result[0].values.map((values) => {
      const raw = Object.fromEntries(columns.map((column, index) => [column, values[index]]));
      const dia = diaFromShape(raw.shape, raw.size1, raw.size2);
      const length = Number(raw.length || 0);
      return {
        system: 'storm',
        reference: clean(raw.reference),
        upstream: clean(raw.upstream),
        downstream: clean(raw.downstream),
        material: clean(raw.material),
        dia,
        length,
        footage: length,
        city: clean(raw.city),
        street: clean(raw.street),
        projectName: clean(raw.project_name)
      };
    }).filter((row) => row.reference);
  }

  async function ensureProject({ db3Path, displayName = '' }) {
    const normalizedPath = normalizeDb3SourcePath(db3Path);
    const sourceKey = sha(normalizedPath.toLowerCase());
    const existing = await pool.query('SELECT * FROM auto_import_projects WHERE source_key = $1 LIMIT 1', [sourceKey]);
    let project;
    if (existing.rows[0]) {
      const updated = await pool.query(`
        UPDATE auto_import_projects
        SET display_name = $2,
            db3_path = $3,
            last_seen_at = NOW(),
            updated_at = NOW()
        WHERE source_key = $1
        RETURNING *
      `, [sourceKey, displayName || path.basename(normalizedPath), normalizedPath]);
      project = updated.rows[0];
    } else {
      const inserted = await pool.query(`
        INSERT INTO auto_import_projects (
          id, source_key, display_name, db3_path, status, last_seen_at, metadata
        ) VALUES ($1,$2,$3,$4,'idle',NOW(),'{}'::jsonb)
        RETURNING *
      `, [uid(), sourceKey, displayName || path.basename(normalizedPath), normalizedPath]);
      project = inserted.rows[0];
    }
    // Wasabi-primary writes never land in Postgres; mirror so log FK + monitor stay valid.
    if (project && directPgQuery) {
      try {
        await runPostgresAutoImportSql(
          `INSERT INTO auto_import_projects (
             id, source_key, display_name, db3_path, status, detection_mode,
             detected_job_client, detected_job_city, detected_jobsite,
             last_seen_at, last_scan_at, last_switch_at, last_error, metadata, created_at, updated_at
           ) VALUES (
             $1,$2,$3,$4,COALESCE($5,'idle'),COALESCE($6,'auto'),
             COALESCE($7,''),COALESCE($8,''),COALESCE($9,''),
             $10,$11,$12,COALESCE($13,''),COALESCE($14::jsonb,'{}'::jsonb),
             COALESCE($15,NOW()),COALESCE($16,NOW())
           )
           ON CONFLICT (id) DO UPDATE SET
             source_key = EXCLUDED.source_key,
             display_name = EXCLUDED.display_name,
             db3_path = EXCLUDED.db3_path,
             status = EXCLUDED.status,
             last_seen_at = EXCLUDED.last_seen_at,
             last_scan_at = COALESCE(EXCLUDED.last_scan_at, auto_import_projects.last_scan_at),
             metadata = EXCLUDED.metadata,
             updated_at = EXCLUDED.updated_at`,
          [
            project.id,
            project.source_key,
            project.display_name,
            project.db3_path,
            project.status || 'idle',
            project.detection_mode || 'auto',
            project.detected_job_client || '',
            project.detected_job_city || '',
            project.detected_jobsite || '',
            project.last_seen_at || nowIso(),
            project.last_scan_at || null,
            project.last_switch_at || null,
            project.last_error || '',
            JSON.stringify(project.metadata && typeof project.metadata === 'object' ? project.metadata : {}),
            project.created_at || nowIso(),
            project.updated_at || nowIso()
          ]
        );
      } catch (e) {
        logger.warn?.('AUTO IMPORT PROJECT PG MIRROR FAILED:', e?.message || e);
      }
    }
    return project;
  }

  async function upsertBinding(projectId, body, username) {
    const client = clean(body.client);
    const city = clean(body.city);
    const jobsite = clean(body.jobsite);
    const systemType = clean(body.systemType || 'storm') || 'storm';
    const pinned = !!body.pinned;
    if (!client || !city || !jobsite) throw new Error('Client, city, and jobsite are required.');

    const existing = await pool.query('SELECT id FROM auto_import_bindings WHERE project_id = $1 LIMIT 1', [projectId]);
    let binding;
    if (existing.rows[0]) {
      const updated = await pool.query(`
        UPDATE auto_import_bindings
        SET client = $2,
            city = $3,
            jobsite = $4,
            system_type = $5,
            pinned = $6,
            created_by = COALESCE(NULLIF(created_by,''), $7),
            updated_at = NOW()
        WHERE project_id = $1
        RETURNING *
      `, [projectId, client, city, jobsite, systemType, pinned, username || 'System']);
      binding = updated.rows[0];
    } else {
      const inserted = await pool.query(`
        INSERT INTO auto_import_bindings (id, project_id, client, city, jobsite, system_type, pinned, created_by)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        RETURNING *
      `, [uid(), projectId, client, city, jobsite, systemType, pinned, username || 'System']);
      binding = inserted.rows[0];
    }
    if (binding && directPgQuery) {
      try {
        await runPostgresAutoImportSql(
          `INSERT INTO auto_import_bindings (
             id, project_id, client, city, jobsite, system_type, pinned, created_by, created_at, updated_at
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,COALESCE($9,NOW()),COALESCE($10,NOW()))
           ON CONFLICT (project_id) DO UPDATE SET
             client = EXCLUDED.client,
             city = EXCLUDED.city,
             jobsite = EXCLUDED.jobsite,
             system_type = EXCLUDED.system_type,
             pinned = EXCLUDED.pinned,
             updated_at = EXCLUDED.updated_at`,
          [
            binding.id,
            binding.project_id,
            binding.client,
            binding.city,
            binding.jobsite,
            binding.system_type || 'storm',
            !!binding.pinned,
            binding.created_by || username || 'System',
            binding.created_at || nowIso(),
            binding.updated_at || nowIso()
          ]
        );
      } catch (e) {
        logger.warn?.('AUTO IMPORT BINDING PG MIRROR FAILED:', e?.message || e);
      }
    }
    return binding;
  }

  /**
   * Desktop AutoSync often registers a project before anyone binds it in the UI.
   * Infer client/city/jobsite from DB3 rows (same rules as PSR ingest) and create binding + planner target.
   * @returns {{ binding: object, plannerRecord: object|null }}
   */
  async function ensureAutoBindingFromRows(project, rows, username) {
    const list = Array.isArray(rows) ? rows : [];
    const sample = list[0] || {};
    const projectName =
      clean(sample.projectName || sample.project || project?.display_name || path.basename(String(project?.db3_path || ''), '.db3')) ||
      'NOT SET';
    let customer = '';
    for (const row of list) {
      customer = extractCustomerFromDb3(row?.db3Imported, projectName);
      if (customer) break;
    }
    if (!customer) customer = extractCustomerFromDb3(sample?.db3Imported, projectName);
    if (!customer) {
      throw new Error(
        'Bind this DB3 project to a client/city/jobsite before syncing (could not infer Customer from DB3).'
      );
    }
    let knownCities = [];
    if (typeof listKnownPlannerCities === 'function') {
      try {
        knownCities = await listKnownPlannerCities();
      } catch {
        knownCities = [];
      }
    }
    const cityInfo = resolveCityForAutosyncPsr(projectName, sample.city || project?.detected_job_city || '', knownCities);
    const city = clean(cityInfo?.city || sample.city || project?.detected_job_city) || 'NOT SET';
    const street = clean(sample.street || '');
    const jobsite =
      typeof normalizeJobsiteName === 'function'
        ? clean(normalizeJobsiteName(projectName, street)) || clean(projectName)
        : clean(projectName);
    const binding = await upsertBinding(
      project.id,
      { client: customer, city, jobsite, systemType: 'storm', pinned: false },
      username || 'AutoSync'
    );
    let plannerRecord = null;
    if (typeof findPlannerRecordsByScope === 'function') {
      try {
        const matches = await findPlannerRecordsByScope(customer, city, jobsite, { latestOnly: true });
        plannerRecord = matches?.[0] || null;
      } catch {
        plannerRecord = null;
      }
    }
    if (!plannerRecord && typeof createPlannerRecord === 'function') {
      plannerRecord = await createPlannerRecord(
        {
          record_date: new Date().toISOString().slice(0, 10),
          client: customer,
          city,
          street,
          jobsite,
          status: '',
          saved_by: username || 'AutoSync',
          systems: { storm: [], sanitary: [] }
        },
        { user: { displayName: username || 'AutoSync', username: 'autosync' } }
      );
    }
    await logEvent(project.id, 'server', 'info', 'Auto-bound Desktop AutoSync project from DB3 fields.', {
      client: customer,
      city,
      jobsite,
      plannerId: plannerRecord?.id || null
    });
    return { binding, plannerRecord };
  }

  async function syncProjectRows(project, rows, username) {
    let bindingResult = await pool.query('SELECT * FROM auto_import_bindings WHERE project_id = $1 LIMIT 1', [project.id]);
    let binding = bindingResult.rows[0];
    let plannerRecord = null;
    if (!binding) {
      const auto = await ensureAutoBindingFromRows(project, rows, username);
      binding = auto?.binding || null;
      plannerRecord = auto?.plannerRecord || null;
    }
    if (!binding) throw new Error('Bind this DB3 project to a client/city/jobsite before syncing.');

    if (!plannerRecord && typeof findPlannerRecordsByScope === 'function') {
      try {
        const matches = await findPlannerRecordsByScope(binding.client, binding.city, binding.jobsite, {
          latestOnly: true
        });
        plannerRecord = matches?.[0] || null;
      } catch {
        plannerRecord = null;
      }
    }

    let targetJobsiteId = plannerRecord?.id ? String(plannerRecord.id) : '';
    if (!targetJobsiteId) {
      const targetJobsiteResult = await pool.query(
        `SELECT id FROM planner_records
         WHERE LOWER(client) = LOWER($1) AND LOWER(city) = LOWER($2) AND LOWER(jobsite) = LOWER($3)
         ORDER BY updated_at DESC
         LIMIT 1`,
        [binding.client, binding.city, binding.jobsite]
      );
      targetJobsiteId = targetJobsiteResult.rows[0]?.id ? String(targetJobsiteResult.rows[0].id) : '';
    }
    if (!targetJobsiteId && typeof createPlannerRecord === 'function') {
      plannerRecord = await createPlannerRecord(
        {
          record_date: new Date().toISOString().slice(0, 10),
          client: binding.client,
          city: binding.city,
          street: '',
          jobsite: binding.jobsite,
          status: '',
          saved_by: username || 'AutoSync',
          systems: { storm: [], sanitary: [] }
        },
        { user: { displayName: username || 'AutoSync', username: 'autosync' } }
      );
      targetJobsiteId = plannerRecord?.id ? String(plannerRecord.id) : '';
    }
    if (!targetJobsiteId) {
      throw new Error(
        'Selected target jobsite was not found. Create a planner record with the same client, city, and jobsite first.'
      );
    }

    let changed = 0;
    let inserted = 0;
    let updated = 0;
    let omitted = 0;

    const systemKey = systemKeyFromBinding(binding);

    for (const row of rows) {
      const rowKey = rowKeyFor(row);
      const rowHash = rowHashFor(row);
      const cacheResult = await pool.query(
        'SELECT id, row_hash FROM auto_import_row_cache WHERE project_id = $1 AND row_key = $2 LIMIT 1',
        [project.id, rowKey]
      );
      const cache = cacheResult.rows[0] || null;

      if (cache && cache.row_hash === rowHash) {
        await pool.query(
          'UPDATE auto_import_row_cache SET last_seen_at = NOW() WHERE id = $1',
          [cache.id]
        );
        omitted += 1;
        continue;
      }

      const record =
        plannerRecord && String(plannerRecord.id) === String(targetJobsiteId)
          ? plannerRecord
          : await fetchPlannerRecord(String(targetJobsiteId));
      if (!record || !record.systems) {
        throw new Error(`Planner record not found for jobsite id ${targetJobsiteId}`);
      }
      // Keep in-memory record fresh across segment writes in this sync pass.
      plannerRecord = record;
      const segments = record.systems[systemKey] || [];
      const existing = findExistingSegment(segments, row);
      const payload = buildPayloadForRow(project, binding, row, existing, username || 'System');
      await writeSegment(targetJobsiteId, payload, username || 'System', record);
      // Prefer the record writeSegment just persisted when available.
      if (record && record.systems) plannerRecord = record;
      changed += 1;

      if (cache) updated += 1;
      else inserted += 1;

      if (cache) {
        await pool.query(`
          UPDATE auto_import_row_cache
          SET row_hash = $3,
              system_type = $4,
              reference = $5,
              upstream = $6,
              downstream = $7,
              dia = $8,
              material = $9,
              length = $10,
              footage = $11,
              source_payload = $12::jsonb,
              last_seen_at = NOW()
          WHERE project_id = $1 AND row_key = $2
        `, [
          project.id,
          rowKey,
          rowHash,
          binding.system_type || 'storm',
          row.reference,
          row.upstream || '',
          row.downstream || '',
          row.dia || '',
          row.material || '',
          Number(row.length || 0),
          Number(row.footage || row.length || 0),
          JSON.stringify(row)
        ]);
      } else {
        await pool.query(`
          INSERT INTO auto_import_row_cache (
            id, project_id, row_key, row_hash, system_type, reference, upstream, downstream, dia, material, length, footage, source_payload
          ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb)
        `, [
          uid(),
          project.id,
          rowKey,
          rowHash,
          binding.system_type || 'storm',
          row.reference,
          row.upstream || '',
          row.downstream || '',
          row.dia || '',
          row.material || '',
          Number(row.length || 0),
          Number(row.footage || row.length || 0),
          JSON.stringify(row)
        ]);
      }
    }

    return { changed, inserted, updated, omitted };
  }

  async function latestHeartbeatRow(keys) {
    const r = await runPostgresAutoImportSql(
      `SELECT at_ms, state, source, detail FROM auto_import_desktop_heartbeats
       WHERE user_key = ANY($1::text[])
       ORDER BY at_ms DESC NULLS LAST
       LIMIT 1`,
      [keys]
    );
    return r.rows[0] || null;
  }

  function summarizeHeartbeat(rec, nowMs) {
    const atMs = rec ? Number(rec.at_ms) : NaN;
    const ageMs = rec && Number.isFinite(atMs) ? Math.max(0, nowMs - atMs) : Number.POSITIVE_INFINITY;
    const connected = !!(rec && ageMs <= HEARTBEAT_TTL_MS && String(rec.state || '').toLowerCase() !== 'offline');
    return {
      connected,
      state: connected ? rec.state || 'connected' : 'offline',
      lastSeenAt: rec && Number.isFinite(atMs) ? new Date(atMs).toISOString() : null,
      ageMs: Number.isFinite(ageMs) ? ageMs : null,
      ttlMs: HEARTBEAT_TTL_MS,
      source: rec?.source || null,
      detail: rec?.detail || ''
    };
  }

  /**
   * Single low-churn JSON for the portal DAS monitor: **live Postgres only** (no Wasabi snapshot adapter).
   */
  router.get('/monitor-snapshot', desktopHeartbeatGate, async (req, res) => {
    const keys = heartbeatKeys(req);
    const cacheKey = keys.join('|');
    const nowMs = Date.now();
    if (MONITOR_SNAPSHOT_CACHE_MS > 0) {
      const hit = monitorSnapshotCache.get(cacheKey);
      if (hit && hit.exp > nowMs) {
        res.set('X-Monitor-Snapshot-Cache', 'hit');
        return res.json(hit.body);
      }
    }
    try {
      const [rec, projR, logR] = await Promise.all([
        latestHeartbeatRow(keys),
        runPostgresAutoImportSql(
          `SELECT id, display_name, status, detection_mode, last_seen_at, last_scan_at, updated_at, created_at
           FROM auto_import_projects
           ORDER BY COALESCE(last_seen_at, created_at) DESC NULLS LAST
           LIMIT 12`
        ),
        runPostgresAutoImportSql(
          `SELECT id, project_id, source, level, message, created_at
           FROM auto_import_logs
           WHERE project_id IS NULL
           ORDER BY created_at DESC NULLS LAST
           LIMIT 40`
        )
      ]);
      const hb = summarizeHeartbeat(rec, nowMs);
      let projects = (projR.rows || []).map((p) => ({ ...p, binding: null }));
      if ((!projects || projects.length === 0) && hb.connected) {
        const u = req?.user || {};
        const label = clean(u.displayName || u.username || u.email || 'Auto sync desktop');
        const atIso = hb.lastSeenAt || new Date(nowMs).toISOString();
        projects = [
          {
            id: '__autosync_desktop__',
            display_name: label || 'Auto sync desktop',
            status: String(hb.state || 'online').toUpperCase(),
            detection_mode: 'DATA_AUTOSYNC',
            last_seen_at: atIso,
            last_scan_at: atIso,
            updated_at: atIso,
            created_at: atIso,
            binding: null
          }
        ];
      }
      let logs = logR.rows || [];
      const hbDetail = String(hb.detail || '').trim();
      if (hbDetail) {
        const atIso = hb.lastSeenAt || new Date(nowMs).toISOString();
        const dup =
          logs.length > 0 &&
          String(logs[0]?.message || '').trim() === hbDetail &&
          Math.abs(Date.parse(String(logs[0]?.created_at || '')) - Date.parse(atIso)) < 5000;
        if (!dup) {
          logs = [
            {
              id: 'heartbeat-detail',
              project_id: null,
              source: 'desktop',
              level: 'info',
              message: hbDetail,
              created_at: atIso
            },
            ...logs
          ].slice(0, 40);
        }
      }
      let desktopRecent = false;
      for (const r of logs) {
        const src = String(r?.source || '').toLowerCase();
        if (src !== 'desktop' && src !== 'java-desktop') continue;
        const t = Date.parse(String(r?.created_at || ''));
        if (Number.isFinite(t) && nowMs - t <= 90000) {
          desktopRecent = true;
          break;
        }
      }
      let newestProjectTs = 0;
      for (const p of projects) {
        for (const k of ['last_seen_at', 'last_scan_at', 'updated_at', 'created_at']) {
          const t = Date.parse(String(p[k] || ''));
          if (Number.isFinite(t)) newestProjectTs = Math.max(newestProjectTs, t);
        }
      }
      const projectRecent = newestProjectTs > 0 && nowMs - newestProjectTs <= 120000;
      const monitorConnected = hb.connected || desktopRecent || projectRecent;
      const body = {
        success: true,
        store: 'postgres',
        heartbeat: hb,
        monitor: {
          connected: monitorConnected,
          projectCount: projects.length,
          logCount: logs.length
        },
        projects,
        logs
      };
      rememberMonitorSnapshot(cacheKey, body);
      res.json(body);
    } catch (error) {
      logger.error?.('auto-import monitor-snapshot:', error?.code || '', error?.message || error);
      return res.status(500).json({ success: false, error: 'Monitor snapshot failed.' });
    }
  });

  router.get('/health', desktopHeartbeatGate, async (req, res) => {
    res.json({
      success: true,
      service: 'auto-import-plugin',
      connected: true,
      now: nowIso()
    });
  });

  router.post('/desktop-heartbeat', desktopHeartbeatGate, express.json(), async (req, res) => {
    const keys = heartbeatKeys(req);
    const nowMs = Date.now();
    const state = clean(req.body?.state || 'connected').toLowerCase() || 'connected';
    let source = clean(req.body?.source || 'desktop') || 'desktop';
    if (String(source).toLowerCase() === 'java-desktop') source = 'desktop';
    const detail = clean(req.body?.detail || req.body?.message || '');
    const username = clean(req.user?.username || '');
    const displayName = clean(req.user?.displayName || '');
    try {
      for (const key of keys) {
        if (HEARTBEAT_MIN_WRITE_MS > 0) {
          const prev = lastHeartbeatWriteMs.get(key) || 0;
          if (nowMs - prev < HEARTBEAT_MIN_WRITE_MS) {
            continue;
          }
          lastHeartbeatWriteMs.set(key, nowMs);
        }
        await runPostgresAutoImportSql(
          `INSERT INTO auto_import_desktop_heartbeats (user_key, at_ms, state, source, detail, username, display_name, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
           ON CONFLICT (user_key) DO UPDATE SET
             at_ms = EXCLUDED.at_ms,
             state = EXCLUDED.state,
             source = EXCLUDED.source,
             detail = EXCLUDED.detail,
             username = EXCLUDED.username,
             display_name = EXCLUDED.display_name,
             updated_at = NOW()`,
          [key, nowMs, state, source, detail, username, displayName]
        );
      }
      if (lastHeartbeatWriteMs.size > 5000) {
        const drop = Math.ceil(lastHeartbeatWriteMs.size / 2);
        let n = 0;
        for (const k of lastHeartbeatWriteMs.keys()) {
          lastHeartbeatWriteMs.delete(k);
          if (++n >= drop) break;
        }
      }
    } catch (error) {
      logger.error?.(
        'auto-import desktop-heartbeat UPSERT failed:',
        error?.code || '',
        error?.message || error,
        error?.detail || ''
      );
      return res.status(500).json({ success: false, error: 'Heartbeat persistence failed.' });
    }
    res.json({
      success: true,
      connected: true,
      state,
      lastSeenAt: new Date(nowMs).toISOString()
    });
  });

  router.get('/desktop-heartbeat', desktopHeartbeatGate, async (req, res) => {
    const keys = heartbeatKeys(req);
    const nowMs = Date.now();
    try {
      const rec = await latestHeartbeatRow(keys);
      res.json({ success: true, ...summarizeHeartbeat(rec, nowMs) });
    } catch (error) {
      logger.error?.('auto-import desktop-heartbeat SELECT failed:', error?.code || '', error?.message || error);
      return res.status(500).json({ success: false, error: 'Heartbeat read failed.' });
    }
  });

  /** Same gate as desktop heartbeat + portal DAS monitor (not only `dataAutoSyncEmployee`). */
  router.get('/projects', desktopHeartbeatGate, async (req, res, next) => {
    try {
      const [projects, bindings] = await Promise.all([
        readAutoImportMonitorSql(
          'SELECT * FROM auto_import_projects ORDER BY COALESCE(last_seen_at, created_at) DESC, display_name ASC'
        ),
        readAutoImportMonitorSql('SELECT * FROM auto_import_bindings ORDER BY updated_at DESC')
      ]);
      const bindingMap = new Map(bindings.rows.map((row) => [row.project_id, row]));
      res.json({
        success: true,
        projects: projects.rows.map((project) => ({
          ...project,
          binding: bindingMap.get(project.id) || null
        }))
      });
    } catch (error) {
      next(error);
    }
  });

  router.post('/discover', requireMike, express.json({ limit: '12mb' }), async (req, res, next) => {
    try {
      const db3Path = clean(req.body.db3Path);
      if (!db3Path) return res.status(400).json({ error: 'db3Path is required.' });
      // Desktop Auto Sync: register the project from a client-side path; rows come later via /sync.
      const registerOnly =
        Boolean(req.body.registerOnly) ||
        isClientLocalDb3Path(db3Path) ||
        (Array.isArray(req.body.rows) && req.body.rows.length > 0);
      let rows = Array.isArray(req.body.rows) ? req.body.rows : [];
      if (!registerOnly) {
        rows = await parseDb3(db3Path);
      }
      const project = await ensureProject({ db3Path, displayName: clean(req.body.displayName) });
      const sample = rows[0] || {};
      await pool.query(`
        UPDATE auto_import_projects
        SET detected_job_city = COALESCE(NULLIF($2, ''), detected_job_city),
            detected_jobsite = COALESCE(NULLIF($3, ''), detected_jobsite),
            metadata = $4::jsonb,
            last_scan_at = CASE WHEN $5::int > 0 THEN NOW() ELSE last_scan_at END,
            status = CASE WHEN $5::int > 0 THEN 'discovered' ELSE status END,
            updated_at = NOW()
        WHERE id = $1
      `, [
        project.id,
        clean(sample.city),
        clean(sample.projectName || sample.street || project.display_name),
        JSON.stringify({
          sampleRowCount: rows.length,
          source: registerOnly ? 'desktop-register' : 'manual-discover',
          clientPath: isClientLocalDb3Path(db3Path)
        }),
        rows.length
      ]);
      await logEvent(project.id, 'web', 'info', registerOnly
        ? 'Project registered from Desktop Auto Sync (client DB3 path).'
        : 'Preview discovered from DB3 path.', {
        db3Path,
        rowCount: rows.length,
        registerOnly: Boolean(registerOnly)
      });
      res.json({ success: true, project: { ...project, rowCount: rows.length }, rows: rows.slice(0, 50) });
    } catch (error) {
      next(error);
    }
  });

  router.get('/status/:projectId', requireMike, async (req, res, next) => {
    try {
      const projectResult = await pool.query('SELECT * FROM auto_import_projects WHERE id = $1 LIMIT 1', [req.params.projectId]);
      const project = projectResult.rows[0];
      if (!project) return res.status(404).json({ error: 'Project not found.' });
      const runResult = await pool.query(
        'SELECT * FROM auto_import_runs WHERE project_id = $1 ORDER BY started_at DESC LIMIT 1',
        [req.params.projectId]
      );
      res.json({
        success: true,
        status: {
          projectId: project.id,
          state: project.status || 'idle',
          detectionMode: project.detection_mode || 'auto',
          db3Path: project.db3_path || '',
          lastScanAt: project.last_scan_at || null,
          lastError: project.last_error || '',
          activeRun: runResult.rows[0] || null
        }
      });
    } catch (error) {
      next(error);
    }
  });

  router.post('/start/:projectId', requireMike, express.json(), async (req, res, next) => {
    try {
      const result = await pool.query(
        `UPDATE auto_import_projects
         SET status = 'running',
             last_error = '',
             updated_at = NOW()
         WHERE id = $1
         RETURNING *`,
        [req.params.projectId]
      );
      const project = result.rows[0];
      if (!project) return res.status(404).json({ error: 'Project not found.' });
      await logEvent(project.id, 'web', 'info', 'Start requested from web UI.', {
        requestedBy: req.user?.username || 'System'
      });
      res.json({ success: true, project });
    } catch (error) {
      next(error);
    }
  });

  router.post('/stop/:projectId', requireMike, express.json(), async (req, res, next) => {
    try {
      const result = await pool.query(
        `UPDATE auto_import_projects
         SET status = 'idle',
             updated_at = NOW()
         WHERE id = $1
         RETURNING *`,
        [req.params.projectId]
      );
      const project = result.rows[0];
      if (!project) return res.status(404).json({ error: 'Project not found.' });
      await logEvent(project.id, 'web', 'warn', 'Stop requested from web UI.', {
        requestedBy: req.user?.username || 'System'
      });
      res.json({ success: true, project });
    } catch (error) {
      next(error);
    }
  });

  router.post('/bind/:projectId', requireMike, express.json(), async (req, res, next) => {
    try {
      const binding = await upsertBinding(req.params.projectId, req.body, req.user?.username || 'System');
      res.json({ success: true, binding });
    } catch (error) {
      next(error);
    }
  });

  router.post('/mode/:projectId', requireMike, express.json(), async (req, res, next) => {
    try {
      const mode = normalizeMode(req.body.mode);
      const result = await pool.query(`
        UPDATE auto_import_projects
        SET detection_mode = $2,
            updated_at = NOW()
        WHERE id = $1
        RETURNING *
      `, [req.params.projectId, mode]);
      if (!result.rows[0]) return res.status(404).json({ error: 'Project not found.' });
      res.json({ success: true, project: result.rows[0] });
    } catch (error) {
      next(error);
    }
  });

  router.post('/preview', requireMike, upload.single('file'), async (req, res, next) => {
    try {
      const explicitPath = clean(req.body.db3Path);
      const filePath = req.file?.path || explicitPath;
      if (!filePath) return res.status(400).json({ error: 'DB3 file or db3Path is required.' });
      if (!req.file?.path && isClientLocalDb3Path(explicitPath)) {
        return res.status(400).json({
          error: 'Upload the .db3 file (multipart) for preview — client PC paths are not readable on the server.'
        });
      }
      const rows = await parseDb3(filePath);
      const project = await ensureProject({ db3Path: explicitPath || filePath, displayName: clean(req.body.displayName) || path.basename(filePath) });
      res.json({ success: true, project, rows: rows.slice(0, 500), totalRows: rows.length });
    } catch (error) {
      next(error);
    }
  });

  router.post('/sync/:projectId', requireMike, express.json({ limit: '10mb' }), async (req, res, next) => {
    try {
      const projectResult = await pool.query('SELECT * FROM auto_import_projects WHERE id = $1 LIMIT 1', [req.params.projectId]);
      const project = projectResult.rows[0];
      if (!project) return res.status(404).json({ error: 'Project not found.' });
      let rows = Array.isArray(req.body.rows) && req.body.rows.length ? req.body.rows : null;
      if (!rows) {
        if (isClientLocalDb3Path(project.db3_path)) {
          return res.status(400).json({
            error: 'Sync requires rows[] for Desktop Auto Sync projects (DB3 lives on the crew PC).'
          });
        }
        rows = await parseDb3(project.db3_path);
      }
      await logEvent(project.id, 'web', 'info', 'Sync started.', {
        requestedBy: req.user?.username || 'System',
        rowCount: rows.length,
        reason: clean(req.body.switchReason || 'manual sync')
      });
      const sync = await syncProjectRows(project, rows, req.user?.username || 'System');
      const runId = uid();
      await pool.query(`
        INSERT INTO auto_import_runs (
          id, project_id, completed_at, active_db3_path, switch_reason, rows_found, rows_changed, rows_inserted, rows_updated, payload
        ) VALUES ($1,$2,NOW(),$3,$4,$5,$6,$7,$8,$9::jsonb)
      `, [
        runId,
        project.id,
        project.db3_path,
        clean(req.body.switchReason || 'manual sync'),
        rows.length,
        sync.changed,
        sync.inserted,
        sync.updated,
        JSON.stringify({ mode: project.detection_mode })
      ]);
      await pool.query(`
        UPDATE auto_import_projects
        SET status = 'synced',
            last_scan_at = NOW(),
            last_error = '',
            updated_at = NOW()
        WHERE id = $1
      `, [project.id]);
      await logEvent(project.id, 'server', 'info', 'Sync completed.', {
        changed: sync.changed,
        inserted: sync.inserted,
        updated: sync.updated,
        omitted: sync.omitted,
        totalRows: rows.length
      });
      res.json({ success: true, sync, totalRows: rows.length });
    } catch (error) {
      logger.error('AUTO IMPORT SYNC ERROR:', error);
      try {
        await pool.query(`
          UPDATE auto_import_projects
          SET status = 'error',
              last_error = $2,
              updated_at = NOW()
          WHERE id = $1
        `, [req.params.projectId, String(error.message || error)]);
      } catch {}
      await logEvent(req.params.projectId, 'server', 'error', 'Sync failed.', {
        error: String(error.message || error)
      });
      next(error);
    }
  });

  router.post('/sync-current/:projectId', requireMike, express.json(), async (req, res, next) => {
    try {
      const projectResult = await pool.query('SELECT * FROM auto_import_projects WHERE id = $1 LIMIT 1', [req.params.projectId]);
      const project = projectResult.rows[0];
      if (!project) return res.status(404).json({ error: 'Project not found.' });
      const rows = await parseDb3(project.db3_path);
      await logEvent(project.id, 'web', 'info', 'Manual import current DB3 requested.', {
        requestedBy: req.user?.username || 'System',
        db3Path: project.db3_path,
        rowCount: rows.length
      });
      const sync = await syncProjectRows(project, rows, req.user?.username || 'System');
      await pool.query(
        `UPDATE auto_import_projects
         SET status = 'synced',
             last_scan_at = NOW(),
             last_error = '',
             updated_at = NOW()
         WHERE id = $1`,
        [project.id]
      );
      await logEvent(project.id, 'server', 'info', 'Manual import current DB3 completed.', {
        changed: sync.changed,
        inserted: sync.inserted,
        updated: sync.updated,
        omitted: sync.omitted,
        totalRows: rows.length
      });
      res.json({ success: true, sync, totalRows: rows.length });
    } catch (error) {
      await logEvent(req.params.projectId, 'server', 'error', 'Manual import current DB3 failed.', {
        error: String(error.message || error)
      });
      next(error);
    }
  });

  router.get('/jobsite-options', requireMike, async (req, res, next) => {
    try {
      const result = await pool.query(`
        SELECT id, client, city, jobsite
        FROM planner_records
        ORDER BY LOWER(client), LOWER(city), LOWER(jobsite)
      `);
      res.json({ success: true, jobsites: result.rows });
    } catch (error) {
      next(error);
    }
  });

  router.get('/runs/:projectId', requireMike, async (req, res, next) => {
    try {
      const result = await pool.query(
        'SELECT * FROM auto_import_runs WHERE project_id = $1 ORDER BY started_at DESC LIMIT 100',
        [req.params.projectId]
      );
      res.json({ success: true, runs: result.rows });
    } catch (error) {
      next(error);
    }
  });

  /** Same gate as `/projects` monitor reads — must match `requireDataAutoSyncDesktopHeartbeatAccess` on the server. */
  router.get('/logs/:projectId', desktopHeartbeatGate, async (req, res, next) => {
    try {
      const limit = Math.max(20, Math.min(500, Number(req.query.limit || 200)));
      const projectId = clean(req.params.projectId) || '__global__';
      let result;
      if (projectId === '__global__') {
        result = await readAutoImportMonitorSql(
          `SELECT * FROM auto_import_logs
           WHERE project_id IS NULL
           ORDER BY created_at DESC
           LIMIT $1`,
          [limit]
        );
      } else {
        result = await readAutoImportMonitorSql(
          `SELECT * FROM auto_import_logs
           WHERE project_id = $1 OR project_id IS NULL
           ORDER BY created_at DESC
           LIMIT $2`,
          [projectId, limit]
        );
      }
      res.json({ success: true, logs: result.rows.reverse() });
    } catch (error) {
      next(error);
    }
  });

  /** Data Auto Sync / Java desktop: append portal-visible monitor lines (`project_id` null). Same auth as heartbeat. */
  router.post('/logs/__global__', desktopHeartbeatGate, express.json({ limit: '32kb' }), async (req, res) => {
    try {
      let source = clean(req.body?.source || 'desktop') || 'desktop';
      if (String(source).toLowerCase() === 'java-desktop') source = 'desktop';
      const level = clean(req.body?.level || 'info').toLowerCase() || 'info';
      const message = clean(req.body?.message || '');
      if (!message) return res.status(400).json({ success: false, error: 'message is required.' });
      if (message.length > 8000) return res.status(400).json({ success: false, error: 'message too long.' });
      await logEvent(null, source, level, message, req.body?.payload && typeof req.body.payload === 'object' ? req.body.payload : {});
      res.json({ success: true });
    } catch (error) {
      logger.error?.('auto-import logs __global__ POST:', error?.message || error);
      return res.status(500).json({ success: false, error: 'Log write failed.' });
    }
  });

  // Optional endpoint for desktop helper/EXE to push connection/activity logs.
  router.post('/logs/:projectId', requireMike, express.json({ limit: '128kb' }), async (req, res, next) => {
    try {
      const source = clean(req.body?.source || 'desktop');
      const level = clean(req.body?.level || 'info').toLowerCase();
      const message = clean(req.body?.message || '');
      if (!message) return res.status(400).json({ error: 'message is required.' });
      await logEvent(req.params.projectId, source, level, message, req.body?.payload || {});
      res.json({ success: true });
    } catch (error) {
      next(error);
    }
  });

  return { router, initSchema, parseDb3 };
}

module.exports = { createAutoImportPlugin };

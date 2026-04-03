#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const initSqlJs = require('sql.js');

const CONFIG_PATH = process.env.AUTO_IMPORT_PLUGIN_CONFIG || path.join(process.cwd(), 'auto-import-plugin.config.json');

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function clean(value) {
  return String(value || '').trim();
}

function sha(input) {
  return crypto.createHash('sha1').update(input).digest('hex');
}

function normalizeMode(value) {
  const mode = clean(value).toLowerCase();
  if (mode === 'suggest') return 'suggest';
  if (mode === 'pinned') return 'pinned';
  return 'auto';
}

function diaFromShape(shape, size1, size2) {
  const a = clean(size1);
  const b = clean(size2);
  if (a && b && a !== b) return `${a}x${b}`;
  return a || b || clean(shape);
}

async function loadConfig() {
  const raw = await fs.promises.readFile(CONFIG_PATH, 'utf8');
  const parsed = JSON.parse(raw);
  return {
    apiBase: clean(parsed.apiBase).replace(/\/$/, ''),
    token: clean(parsed.token),
    roots: Array.isArray(parsed.roots) ? parsed.roots.map((item) => path.resolve(String(item))) : [],
    pollMs: Math.max(3000, Number(parsed.pollMs || 8000)),
    switchDebounceMs: Math.max(5000, Number(parsed.switchDebounceMs || 20000)),
    mode: normalizeMode(parsed.mode),
    pinnedPath: clean(parsed.pinnedPath) ? path.resolve(String(parsed.pinnedPath)) : '',
    allowCreateProjects: parsed.allowCreateProjects !== false,
    minimumScore: Number(parsed.minimumScore || 2)
  };
}

async function walkForDb3Files(dir, out) {
  let entries = [];
  try {
    entries = await fs.promises.readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      await walkForDb3Files(full, out);
      continue;
    }
    if (/\.db3$/i.test(entry.name)) out.push(full);
  }
}

async function collectCandidates(roots) {
  const files = [];
  for (const root of roots) {
    await walkForDb3Files(root, files);
  }
  const stats = [];
  for (const file of files) {
    try {
      const stat = await fs.promises.stat(file);
      stats.push({ file, mtimeMs: stat.mtimeMs, size: stat.size });
    } catch {}
  }
  return stats;
}

async function parseDb3(filePath) {
  const SQL = await initSqlJs({ locateFile: (file) => require.resolve(`sql.js/dist/${file}`) });
  const buffer = await fs.promises.readFile(filePath);
  const db = new SQL.Database(buffer);
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
    const row = Object.fromEntries(columns.map((column, index) => [column, values[index]]));
    const length = Number(row.length || 0);
    return {
      system: 'storm',
      reference: clean(row.reference),
      upstream: clean(row.upstream),
      downstream: clean(row.downstream),
      material: clean(row.material),
      dia: diaFromShape(row.shape, row.size1, row.size2),
      length,
      footage: length,
      city: clean(row.city),
      street: clean(row.street),
      projectName: clean(row.project_name)
    };
  }).filter((row) => row.reference);
}

async function api(config, pathname, options = {}) {
  const response = await fetch(`${config.apiBase}${pathname}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${config.token}`,
      ...(options.headers || {})
    }
  });
  const text = await response.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { raw: text };
  }
  if (!response.ok) {
    throw new Error(data?.error || data?.message || `HTTP ${response.status}`);
  }
  return data;
}

function computeScore(candidate, previousState) {
  let score = 0;
  if (candidate.changed) score += 3;
  if (candidate.sizeChanged) score += 1;
  if (candidate.mtimeMs >= Date.now() - 60_000) score += 2;
  if (previousState && previousState.file === candidate.file) score += 1;
  return score;
}

async function ensureRemoteProject(config, filePath) {
  const displayName = path.basename(filePath);
  const response = await api(config, '/auto-import-plugin/discover', {
    method: 'POST',
    body: JSON.stringify({ db3Path: filePath, displayName })
  });
  return response.project;
}

async function syncRemoteProject(config, projectId, rows, reason) {
  return api(config, `/auto-import-plugin/sync/${projectId}`, {
    method: 'POST',
    body: JSON.stringify({ rows, switchReason: reason })
  });
}

async function main() {
  const config = await loadConfig();
  if (!config.apiBase || !config.token || !config.roots.length) {
    throw new Error('Missing config values. Required: apiBase, token, roots[].');
  }

  console.log(`[AUTO IMPORT AGENT] Watching ${config.roots.join(', ')}`);
  let active = null;
  const previousStats = new Map();
  const remoteProjectMap = new Map();

  while (true) {
    try {
      const candidates = await collectCandidates(config.roots);
      const enriched = candidates.map((item) => {
        const prev = previousStats.get(item.file);
        const changed = !!prev && prev.mtimeMs !== item.mtimeMs;
        const sizeChanged = !!prev && prev.size !== item.size;
        const score = computeScore({ ...item, changed, sizeChanged }, active);
        previousStats.set(item.file, item);
        return { ...item, changed, sizeChanged, score };
      }).sort((a, b) => b.score - a.score || b.mtimeMs - a.mtimeMs);

      let winner = null;
      if (config.mode === 'pinned' && config.pinnedPath) {
        winner = enriched.find((item) => path.resolve(item.file) === path.resolve(config.pinnedPath)) || null;
      } else {
        winner = enriched[0] || null;
      }

      if (winner && winner.score >= config.minimumScore) {
        const now = Date.now();
        const shouldSwitch = !active
          || active.file !== winner.file && (now - active.since) >= config.switchDebounceMs;

        if (!active || shouldSwitch) {
          active = { file: winner.file, since: now, score: winner.score };
          console.log(`[AUTO IMPORT AGENT] Active DB3 => ${winner.file}`);
        }

        if (active.file === winner.file && (winner.changed || !remoteProjectMap.has(winner.file))) {
          const rows = await parseDb3(winner.file);
          let remote = remoteProjectMap.get(winner.file) || null;
          if (!remote && config.allowCreateProjects) {
            remote = await ensureRemoteProject(config, winner.file);
            remoteProjectMap.set(winner.file, remote);
          }
          if (remote?.id) {
            const sync = await syncRemoteProject(config, remote.id, rows, winner.changed ? 'active db3 changed' : 'initial sync');
            console.log(`[AUTO IMPORT AGENT] Synced ${rows.length} rows from ${path.basename(winner.file)} => changed ${sync.sync?.changed ?? 0}`);
          }
        }
      }
    } catch (error) {
      console.error('[AUTO IMPORT AGENT] ERROR:', error.message || error);
    }

    await sleep(config.pollMs);
  }
}

main().catch((error) => {
  console.error('[AUTO IMPORT AGENT] FATAL:', error.message || error);
  process.exit(1);
});

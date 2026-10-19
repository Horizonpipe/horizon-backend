'use strict';

const initSqlJs = require('sql.js');
const {
  evaluateSectionReviewStatus,
  fetchSectionObservationOpcodes
} = require('./autosync-psr-ingest');

function cleanString(value) {
  return String(value || '').trim();
}

const sqlJsPromise = initSqlJs();

function shapeLabel(code, size1, size2) {
  const primary = size1 ? String(size1).replace(/\.0+$/, '') : '';
  const secondary = size2 ? String(size2).replace(/\.0+$/, '') : '';
  const base = (() => {
    const upper = String(code || '').trim().toUpperCase();
    if (upper === 'C') return 'Circular';
    if (upper === 'O') return 'Oval';
    if (upper === 'R') return 'Rectangular';
    if (upper === 'E') return 'Egg';
    return upper || 'Unknown';
  })();
  if (!primary) return base;
  if (secondary) return `${base} ${primary}/${secondary}in`;
  return `${base} ${primary}in`;
}

function materialLabel(code) {
  const upper = String(code || '').trim().toUpperCase();
  const map = {
    PE: 'Polyethylene',
    PVC: 'Polyvinyl Chloride',
    PP: 'Polypropylene',
    RCP: 'Reinforced Concrete Pipe',
    VC: 'Vitrified Clay Pipe',
    SP: 'Steel Pipe'
  };
  return map[upper] || upper || '';
}

function sqliteTableList(db) {
  try {
    const r = db.exec("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name");
    return (r[0]?.values || []).map((row) => String(row[0] || '')).filter(Boolean);
  } catch {
    return [];
  }
}

function sqliteObjectType(db, objectName) {
  const target = cleanString(objectName);
  if (!target) return '';
  let stmt;
  try {
    stmt = db.prepare("SELECT type FROM sqlite_master WHERE lower(name) = lower(?) LIMIT 1");
    stmt.bind([target]);
    if (stmt.step()) {
      const row = stmt.getAsObject();
      return cleanString(row.type).toLowerCase();
    }
  } catch {
    return '';
  } finally {
    try {
      stmt?.free();
    } catch {
      /* ignore */
    }
  }
  return '';
}

function pickSqliteTable(actualNames, ...wanted) {
  const set = new Set(actualNames);
  const byLower = new Map(actualNames.map((n) => [n.toLowerCase(), n]));
  for (const w of wanted) {
    if (set.has(w)) return w;
    const hit = byLower.get(String(w).toLowerCase());
    if (hit) return hit;
  }
  return '';
}

function sqlIdentQuoted(name) {
  return `"${String(name).replace(/"/g, '""')}"`;
}

/**
 * When SECTION is missing, infer common mis-uploads (WinCan catalog / META DB vs pipe project DB).
 * @param {string[]} tables
 */
function explainMissingSectionDb3(tables) {
  const lower = new Set(tables.map((t) => String(t).toLowerCase()));
  const hasMeta = [...lower].some((t) => t.startsWith('meta'));
  const hasDirectory = lower.has('directory');
  const hasRehab = lower.has('rehabilitation');
  const hasEquipment = lower.has('equipment');
  const hasWorkgroup = lower.has('workgroup');
  const looksCatalogOrSupport =
    (hasMeta && (hasDirectory || lower.has('metaclass') || lower.has('metaobj'))) ||
    (hasEquipment && hasRehab && !lower.has('node')) ||
    (hasWorkgroup && hasEquipment && !lower.has('node'));

  if (looksCatalogOrSupport) {
    return (
      ' This file looks like a WinCan catalog, workgroup, equipment, or support database (META*, DIRECTORY, REHABILITATION, etc.) — not a pipe inspection project. ' +
      'Use the WinCan **project** .db3 for the jobsite run (the database that opens with your pipe sections; it must contain SECTION and NODE tables). ' +
      'That file is usually beside your inspection videos in the job folder, not the global WinCan catalog database.'
    );
  }
  return '';
}

/** WinCan SECTION columns already surfaced on the main import row — omit from `db3Imported` to avoid duplication. */
const DB3_SECTION_CORE_PHYSICAL_COLS = new Set(
  [
    'OBJ_KEY',
    'OBJ_LENGTH',
    'OBJ_CITY',
    'OBJ_STREET',
    'OBJ_FROMNODE_REF',
    'OBJ_TONODE_REF',
    'OBJ_MATERIAL',
    'OBJ_SHAPE',
    'OBJ_SIZE1',
    'OBJ_SIZE2',
    'OBJ_PK',
    'OBJ_ID',
    'OBJ_GUID'
  ].map((s) => s.toUpperCase())
);

const DB3_INSPECTOR_HINT_KEYS = new Set(
  [
    'INS_OPERATOR_REF',
    'INS_Operator_REF',
    'OP_KEY',
    'OP_Key',
    'OBJ_SURVEYEDBY',
    'OBJ_SURVEYOR',
    'OBJ_SURVEYORNAME',
    'OBJ_INSPECTOR',
    'OBJ_INSPECTORNAME',
    'OBJ_INSPECTIONBY',
    'OBJ_INSPECTEDBY',
    'INS_INSPECTOR',
    'INS_INSPECTORNAME',
    'INS_INSPECTOR_NAME',
    'INS_INSPECTIONBY',
    'INS_INSPECTEDBY',
    'INS_SURVEYOR',
    'INS_SURVEYORNAME',
    'INS_OPERATOR',
    'INS_OPERATORNAME',
    'INS_OPERATOR_NAME',
    'INS_TECHNICIAN',
    'INS_TECHNICIANNAME',
    'INS_CREWLEADER',
    'INS_CREW_LEADER',
    'INS_FIELDLEAD',
    'INS_FIELD_LEAD',
    'INS_COMPLETEDBY'
  ].map((k) => String(k).toUpperCase())
);

const DB3_INSPECTOR_ALIAS_MAP = new Map([
  ['thomas', 'Mike Thomas'],
  ['m thomas', 'Mike Thomas'],
  ['mike thomas', 'Mike Thomas'],
  ['mike s', 'Mike Strickland'],
  ['m strickland', 'Mike Strickland'],
  ['strickland', 'Mike Strickland'],
  ['mike strickland', 'Mike Strickland'],
  ['alec beck', 'Alec Beck']
]);

/** Guard against extremely wide SECINSP schemas generating huge OR predicates in sql.js. */
const DB3_SECINSP_MAX_FK_COLUMNS = 32;
const DB3_SECINSP_MAX_KEY_COLUMNS = 24;
const DB3_SECINSP_SPLIT_QUERY_LIMIT = 6;
const DB3_SECINSP_DIAG_ONCE = new Set();
const DB3_PREVIEW_STRATEGY_VERSION = 'secinsp-split-only-v2';

function db3InspectorAliasKey(value) {
  return String(value == null ? '' : value)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function db3InspectorDisplay(value) {
  return String(value == null ? '' : value)
    .trim()
    .replace(/\s+/g, ' ')
    .replace(/\b\w/g, (m) => m.toUpperCase());
}

/** sql.js may return WinCan UNIQUEIDENTIFIER as string or 16-byte Uint8Array. */
function db3NormalizeSqlId(value) {
  if (value == null || value === '') return '';
  if (typeof value === 'string') return value.trim();
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  const asBytes =
    value instanceof Uint8Array
      ? value
      : typeof Buffer !== 'undefined' && Buffer.isBuffer?.(value)
        ? new Uint8Array(value)
        : typeof value === 'object' &&
            value &&
            typeof value.length === 'number' &&
            value.length === 16 &&
            typeof value[0] === 'number'
          ? Uint8Array.from(/** @type {ArrayLike<number>} */ (value))
          : null;
  if (asBytes && asBytes.length === 16) {
    const h = [...asBytes].map((b) => b.toString(16).padStart(2, '0')).join('');
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`.toLowerCase();
  }
  const s = String(value).trim();
  if (!s || s === '[object Object]' || s === '[object Uint8Array]') return '';
  return s;
}

function db3GuidHex(value) {
  const hex = String(value || '')
    .trim()
    .replace(/[^0-9a-f]/gi, '')
    .toLowerCase();
  return hex.length === 32 ? hex : '';
}

function db3ValueLooksLikeGuidToken(value) {
  return Boolean(db3GuidHex(value));
}

function db3ValueLooksLikeOperatorDisplayName(value) {
  const s = cleanString(value);
  if (!s) return false;
  if (/^\d+$/.test(s)) return false;
  if (db3ValueLooksLikeGuidToken(s)) return false;
  if (!/[A-Za-z]/.test(s)) return false;
  // Reject comma-joined byte dumps from String(Uint8Array).
  if (/^\d+(,\d+){8,}$/.test(s)) return false;
  return true;
}

/**
 * Resolve WinCan "Inspected By" from SECINSP.INS_Operator_REF → companion META OPERATOR
 * (OP_Key / OP_PK → OP_Name1 / OP_Name / …). Prefer Meta DB3; primary is fallback.
 * @param {any} db
 * @param {string[]} tables
 * @param {Record<string, string>} imported
 */
function enrichDb3ImportedOperatorFromWcmeta(db, tables, imported) {
  const out = imported && typeof imported === 'object' ? { ...imported } : {};
  const existing = cleanString(out.HP_INSPECTOR_DISPLAY) || cleanString(out.HP_INSPECTOR_RAW);
  if (db3ValueLooksLikeOperatorDisplayName(existing)) return out;

  const operatorTable =
    pickSqliteTable(tables, 'OPERATOR') ||
    tables.find((t) => String(t || '').toUpperCase() === 'WCMETA.OPERATOR') ||
    tables.find((t) => /OPERATOR$/i.test(String(t || '')) && !/SECINSP|SECTION/i.test(String(t || ''))) ||
    '';
  if (!operatorTable || sqliteObjectType(db, operatorTable) === 'view') return out;

  const refKeys = ['INS_Operator_REF', 'INS_OPERATOR_REF', 'OP_Key', 'OP_KEY', 'INS_OPERATOR'];
  let bindVal = '';
  for (const k of refKeys) {
    const ku = String(k).toUpperCase();
    const hit = Object.keys(out).find((key) => String(key).toUpperCase() === ku);
    const v = hit ? out[hit] : '';
    const s = db3NormalizeSqlId(v);
    if (s) {
      bindVal = s;
      break;
    }
  }
  if (!bindVal) return out;

  // Some WinCan exports store the operator display name directly on the REF field.
  if (db3ValueLooksLikeOperatorDisplayName(bindVal)) {
    const resolved = db3InspectorDisplay(bindVal);
    out.HP_INSPECTOR_RAW = resolved;
    out.HP_INSPECTOR_DISPLAY = resolved;
    out.HP_INSPECTOR_KEY = db3InspectorAliasKey(resolved);
    out.OPERATOR_NAME = resolved.slice(0, 4000);
    return out;
  }

  const cols = sqlitePragmaColumns(db, operatorTable);
  if (!cols.length) return out;
  const colNames = cols.map((c) => c.name);
  const colSet = new Set(colNames.map((n) => String(n).toUpperCase()));

  /** Lookup columns: WinCan Meta typically keys OPERATOR by OP_Key (GUID); OP_PK is fallback. */
  const keyColCandidates = ['OP_Key', 'OP_KEY', 'OP_PK', 'OPERATOR_PK', 'OPERATOR_KEY', 'OBJ_PK', 'OBJ_ID'];
  /** @type {string[]} */
  const keyCols = [];
  for (const want of keyColCandidates) {
    const hit = colNames.find((n) => String(n).toUpperCase() === want.toUpperCase());
    if (hit && !keyCols.includes(hit)) keyCols.push(hit);
  }
  if (!keyCols.length) {
    const pkish = colNames.find((n) => /_PK$/i.test(String(n)) || /_KEY$/i.test(String(n)));
    if (pkish) keyCols.push(pkish);
  }
  if (!keyCols.length) return out;

  const nameCandidates = [
    'OP_Name1',
    'OP_NAME1',
    'OP_Name',
    'OP_NAME',
    'OP_DisplayName',
    'OP_DISPLAYNAME',
    'OP_Description',
    'OP_DESCRIPTION',
    'NAME',
    'OPERATOR_NAME',
    'OPERATOR'
  ];
  /** @type {string[]} */
  const nameCols = [];
  for (const want of nameCandidates) {
    const hit = colNames.find((n) => String(n).toUpperCase() === want.toUpperCase());
    if (hit && !nameCols.includes(hit)) nameCols.push(hit);
  }
  if (!nameCols.length) {
    const fuzzy = colNames.find((n) => /NAME|LABEL|DESCRIPTION/i.test(String(n)));
    if (fuzzy) nameCols.push(fuzzy);
  }
  if (!nameCols.length) return out;

  const OT = sqlIdentQuoted(operatorTable);
  const selectList = nameCols.map((c) => sqlIdentQuoted(c)).join(', ');
  const hex = db3GuidHex(bindVal);

  const tryLookup = (sql, params) => {
    let stmt;
    try {
      stmt = db.prepare(sql);
      stmt.bind(params);
      if (!stmt.step()) {
        stmt.free();
        return '';
      }
      const row = stmt.getAsObject();
      stmt.free();
      for (const col of nameCols) {
        const resolved = db3InspectorDisplay(row[col]);
        if (db3ValueLooksLikeOperatorDisplayName(resolved)) return resolved;
      }
      // Also accept first aliased/unknown property that looks like a name.
      for (const v of Object.values(row)) {
        const resolved = db3InspectorDisplay(v);
        if (db3ValueLooksLikeOperatorDisplayName(resolved)) return resolved;
      }
    } catch {
      try {
        stmt?.free();
      } catch {
        /* ignore */
      }
    }
    return '';
  };

  let resolvedName = '';
  for (const keyCol of keyCols) {
    if (!colSet.has(String(keyCol).toUpperCase())) continue;
    const KC = sqlIdentQuoted(keyCol);
    resolvedName = tryLookup(
      `SELECT ${selectList} FROM ${OT} WHERE ${KC} = ? LIMIT 1`,
      [bindVal]
    );
    if (resolvedName) break;
    if (hex) {
      resolvedName = tryLookup(
        `SELECT ${selectList} FROM ${OT} WHERE lower(hex(${KC})) = ? LIMIT 1`,
        [hex]
      );
      if (resolvedName) break;
    }
  }

  if (db3ValueLooksLikeOperatorDisplayName(resolvedName)) {
    out.HP_INSPECTOR_RAW = resolvedName;
    out.HP_INSPECTOR_DISPLAY = resolvedName;
    out.HP_INSPECTOR_KEY = db3InspectorAliasKey(resolvedName);
    out.OPERATOR_NAME = resolvedName.slice(0, 4000);
  }
  return out;
}

function db3InspectorIdentityFromImported(imported) {
  const imp = imported && typeof imported === 'object' && !Array.isArray(imported) ? imported : {};
  const read = (k) => {
    const v = imp[k];
    return typeof v === 'number' && Number.isFinite(v) ? String(v) : cleanString(v);
  };
  let raw = read('HP_INSPECTOR_RAW') || read('HP_EDIT_INSPECTED_BY') || read('HP_INSPECTOR_DISPLAY') || read('OPERATOR_NAME');
  if (!raw) {
    for (const [k, v] of Object.entries(imp)) {
      const ku = String(k || '').toUpperCase();
      const vv = typeof v === 'number' && Number.isFinite(v) ? String(v) : cleanString(v);
      if (!vv) continue;
      if (DB3_INSPECTOR_HINT_KEYS.has(ku)) {
        if ((ku === 'INS_OPERATOR_REF' || ku === 'INS_Operator_REF'.toUpperCase() || ku === 'OP_KEY') && !db3ValueLooksLikeOperatorDisplayName(vv)) {
          continue;
        }
        raw = vv;
        break;
      }
    }
  }
  if (!raw) {
    for (const [k, v] of Object.entries(imp)) {
      const ku = String(k || '').toUpperCase();
      const vv = typeof v === 'number' && Number.isFinite(v) ? String(v) : cleanString(v);
      if (!vv) continue;
      if (/^INS_(PK|ID)$/.test(ku)) continue;
      if (/INSPECT|SURVEY|OPERATOR|TECHNICIAN|CREW|FIELD.?LEAD|COMPLETEDBY/.test(ku)) {
        raw = vv;
        break;
      }
    }
  }
  raw = db3InspectorDisplay(raw);
  if (!raw) return null;
  const alias = db3InspectorAliasKey(raw);
  const canonical = db3InspectorDisplay(DB3_INSPECTOR_ALIAS_MAP.get(alias) || raw);
  const key = db3InspectorAliasKey(canonical) || alias;
  return { raw, canonical, key };
}

/**
 * @param {any} db sql.js Database
 * @param {string} tableName
 * @returns {{ name: string, type: string }[]}
 */
function sqlitePragmaColumns(db, tableName) {
  const out = [];
  let stmt;
  try {
    stmt = db.prepare(`PRAGMA table_info(${sqlIdentQuoted(tableName)})`);
    while (stmt.step()) {
      const o = stmt.getAsObject();
      const name = String(o.name || '');
      const type = String(o.type || '').toUpperCase();
      if (!name) continue;
      if (type.includes('BLOB')) continue;
      out.push({ name, type });
    }
  } catch {
    return [];
  } finally {
    try {
      stmt?.free();
    } catch {
      /* ignore */
    }
  }
  return out;
}

/**
 * Extra SECTION columns as SQL select list + parallel original column names for alias decode.
 * @param {any} db sql.js Database
 * @param {string} sectionTable
 * @returns {{ sql: string, aliasNames: string[] }}
 */
function buildDb3SectionExtraSelect(db, sectionTable) {
  const cols = sqlitePragmaColumns(db, sectionTable);
  const parts = [];
  /** @type {string[]} */
  const aliasNames = [];
  for (const { name } of cols) {
    if (DB3_SECTION_CORE_PHYSICAL_COLS.has(name.toUpperCase())) continue;
    const idx = aliasNames.length;
    parts.push(`s.${sqlIdentQuoted(name)} AS ${sqlIdentQuoted(`__db3_${idx}`)}`);
    aliasNames.push(name);
  }
  if (!parts.length) return { sql: '', aliasNames: [] };
  return { sql: parts.join(', '), aliasNames };
}

/**
 * @param {Record<string, unknown>} raw
 * @param {string[]} aliasNames
 * @returns {Record<string, string>}
 */
function extractDb3ImportedFromRow(raw, aliasNames) {
  if (!raw || !Array.isArray(aliasNames) || !aliasNames.length) return {};
  const out = {};
  const keys = Object.keys(raw);
  for (let i = 0; i < aliasNames.length; i++) {
    const want = `__db3_${i}`;
    const hit = keys.find((k) => k.toLowerCase() === want.toLowerCase());
    if (!hit) continue;
    const v = raw[hit];
    if (v == null || v === '') continue;
    const col = aliasNames[i];
    const key = String(col).toUpperCase();
    const str =
      typeof v === 'number' && Number.isFinite(v)
        ? String(v)
        : db3NormalizeSqlId(v) || (typeof v === 'string' ? v.trim() : '');
    if (!str) continue;
    out[key] = str.slice(0, 4000);
  }
  return out;
}

/**
 * SECTION.OBJ_Key → primary key for joining SECINSP (WinCan variants).
 * @param {any} db
 * @param {string} sectionTable
 * @param {string} reference
 * @returns {string|number|null}
 */
function resolveSectionPrimaryKeyForReference(db, sectionTable, reference) {
  const S = sqlIdentQuoted(sectionTable);
  const ref = cleanString(reference);
  if (!ref) return null;
  const secCols = sqlitePragmaColumns(db, sectionTable).map((c) => c.name.toUpperCase());
  const pkCol = secCols.includes('OBJ_PK') ? 'OBJ_PK' : secCols.includes('OBJ_ID') ? 'OBJ_ID' : '';
  if (!pkCol) return null;
  let stmt;
  try {
    stmt = db.prepare(`SELECT ${sqlIdentQuoted(pkCol)} AS spk FROM ${S} WHERE OBJ_Key = ? LIMIT 1`);
    stmt.bind([ref]);
    if (stmt.step()) {
      const v = stmt.getAsObject().spk;
      stmt.free();
      if (v != null && String(v).trim() !== '') return v;
    } else {
      stmt.free();
    }
  } catch {
    try {
      stmt?.free();
    } catch {
      /* ignore */
    }
  }
  return null;
}

/**
 * Merge first matching SECINSP row into db3Imported (inspector, certificate, etc. often live here).
 * Does not overwrite keys already populated from SECTION extras.
 * @param {any} db
 * @param {string} sectionTable
 * @param {string} secinspTable
 * @param {string} reference SECTION.OBJ_Key
 * @param {Record<string, string>} imported
 */
function mergeSecinspRowIntoDb3Imported(db, sectionTable, secinspTable, reference, imported) {
  const out = imported && typeof imported === 'object' ? { ...imported } : {};
  if (!secinspTable) return out;
  const spk = resolveSectionPrimaryKeyForReference(db, sectionTable, reference);
  if (spk == null) return out;
  const cols = sqlitePragmaColumns(db, secinspTable);
  if (!cols.length) return out;
  const wantFks = [
    'INS_Section_FK',
    'INS_SECTION_FK',
    'INS_SectionId',
    'INS_SECTION_ID',
    'INS_SECTION_OBJ_PK',
    'INS_SEC_FK',
    'INS_SECTIONREF',
    'INS_SECTION_REF',
    'OBJ_ID',
    'OBJ_PK',
    'INS_ObjectId',
    'INS_OBJECTID'
  ];
  /** @type {string[]} */
  const fkCols = [];
  for (const w of wantFks) {
    const hit = cols.find((c) => String(c.name).toUpperCase() === w.toUpperCase());
    if (hit && !fkCols.includes(hit.name)) fkCols.push(hit.name);
  }
  if (!fkCols.length) {
    for (const c of cols) {
      const u = String(c.name).toUpperCase();
      if (u.includes('SECTION') && (u.includes('FK') || u.includes('REF'))) fkCols.push(c.name);
    }
  }
  if (!fkCols.length) return out;
  if (fkCols.length > DB3_SECINSP_MAX_FK_COLUMNS) {
    fkCols.splice(DB3_SECINSP_MAX_FK_COLUMNS);
  }
  const SI = sqlIdentQuoted(secinspTable);
  const ref = cleanString(reference);

  /**
   * @param {Record<string, unknown>} row
   */
  const applyRow = (row) => {
    for (const [k, v] of Object.entries(row)) {
      if (v == null || v === '') continue;
      const ku = String(k).toUpperCase();
      if (out[ku] && String(out[ku]).trim() !== '') continue;
      // Preserve GUID/BLOB FKs (INS_Operator_REF) so Meta OPERATOR lookup can join later.
      const str =
        typeof v === 'number' && Number.isFinite(v)
          ? String(v)
          : db3NormalizeSqlId(v) || (typeof v === 'string' ? v.trim() : '');
      if (!str) continue;
      out[ku] = str.slice(0, 4000);
    }
  };

  function logSecinspStrategyOnce(strategy, detail = {}) {
    const key = `${String(secinspTable || '').toLowerCase()}|${strategy}|${fkCols.length}`;
    if (DB3_SECINSP_DIAG_ONCE.has(key)) return;
    DB3_SECINSP_DIAG_ONCE.add(key);
    console.warn('[db3-preview][secinsp-probe]', {
      table: secinspTable,
      strategy,
      fkColumns: fkCols.length,
      ...detail
    });
  }

  /**
   * @param {string|number|null|undefined} bindVal
   */
  const mergeForBindSplit = (bindVal) => {
    if (bindVal == null || bindVal === '') return;
    logSecinspStrategyOnce('split-only', { reason: 'or-disabled-hardening', strategyVersion: DB3_PREVIEW_STRATEGY_VERSION });
    for (const fkCol of fkCols) {
      let stmt;
      try {
        stmt = db.prepare(`SELECT * FROM ${SI} WHERE ${sqlIdentQuoted(fkCol)} = ? LIMIT ${DB3_SECINSP_SPLIT_QUERY_LIMIT}`);
        stmt.bind([bindVal]);
        while (stmt.step()) {
          applyRow(stmt.getAsObject());
        }
        stmt.free();
      } catch (error) {
        const msg = String(error?.message || error || '');
        logSecinspStrategyOnce('split-column-error', {
          reason: 'column-query-error',
          fkColumn: String(fkCol || ''),
          message: msg.slice(0, 220),
          strategyVersion: DB3_PREVIEW_STRATEGY_VERSION
        });
        try {
          stmt?.free();
        } catch {
          /* ignore */
        }
      }
    }
  };

  try {
    mergeForBindSplit(spk);
    /* Some WinCan builds store the section OBJ_Key string in SECINSP FK columns instead of OBJ_PK. */
    if (ref && String(spk) !== String(ref)) mergeForBindSplit(ref);
  } catch {
    /* ignore */
  }
  return out;
}

/**
 * Merge SECINSP rows where a text column holds SECTION.OBJ_Key (string link).
 * @param {any} db
 * @param {string} secinspTable
 * @param {string} reference SECTION.OBJ_Key
 * @param {Record<string, string>} imported
 */
function mergeSecinspBySectionObjKeyColumn(db, secinspTable, reference, imported) {
  const out = imported && typeof imported === 'object' ? { ...imported } : {};
  const ref = cleanString(reference);
  if (!ref || !secinspTable) return out;
  const cols = sqlitePragmaColumns(db, secinspTable);
  const keyCols = cols
    .map((c) => c.name)
    .filter((name) => {
      const u = String(name).toUpperCase();
      if (u === 'SECTION_KEY' || u === 'INS_SECTIONKEY' || u === 'SECTION_OBJ_KEY') return true;
      if (u.includes('SECTION') && u.includes('KEY') && !u.includes('FOREIGN') && !u.includes('PRIM')) return true;
      return false;
    });
  if (!keyCols.length) return out;
  if (keyCols.length > DB3_SECINSP_MAX_KEY_COLUMNS) {
    keyCols.splice(DB3_SECINSP_MAX_KEY_COLUMNS);
  }
  const SI = sqlIdentQuoted(secinspTable);
  for (const kcol of keyCols) {
    let stmt;
    try {
      stmt = db.prepare(`SELECT * FROM ${SI} WHERE ${sqlIdentQuoted(kcol)} = ?`);
      stmt.bind([ref]);
      while (stmt.step()) {
        const row = stmt.getAsObject();
        for (const [k, v] of Object.entries(row)) {
          if (v == null || v === '') continue;
          const ku = String(k).toUpperCase();
          if (out[ku] && String(out[ku]).trim() !== '') continue;
          const str = typeof v === 'number' && Number.isFinite(v) ? String(v) : String(v).trim();
          if (!str) continue;
          out[ku] = str.slice(0, 4000);
        }
      }
      stmt.free();
    } catch {
      try {
        stmt?.free();
      } catch {
        /* ignore */
      }
    }
  }
  return out;
}

function injectDb3ExtrasBeforeOrderBy(sql, extraSql) {
  if (!extraSql) return sql;
  const trimmed = String(sql || '').trimEnd();
  const m = /\sORDER\s+BY\s/i.exec(trimmed);
  if (m && m.index >= 0) {
    return `${trimmed.slice(0, m.index)}, ${extraSql}${trimmed.slice(m.index)}`;
  }
  return `${trimmed}, ${extraSql}`;
}

function mapDb3SectionRow(row, projectName) {
  const dia = row.size2
    ? `${String(row.size1).replace(/\.0+$/, '')}/${String(row.size2).replace(/\.0+$/, '')}`
    : String(row.size1 || '').replace(/\.0+$/, '');
  return {
    project: projectName || 'NOT SET',
    reference: cleanString(row.reference),
    length: Number(row.length || 0).toFixed(3),
    city: cleanString(row.city),
    street: cleanString(row.street),
    upstream: cleanString(row.upstream),
    downstream: cleanString(row.downstream),
    material: materialLabel(row.material_code),
    shape: shapeLabel(row.shape_code, row.size1, row.size2),
    dia
  };
}

/**
 * Attach observation opcodes + AutoSync review status (MSA / ending access codes) onto parsed DB3 rows.
 * Must run before the sql.js Database is closed.
 */
function attachObservationReviewToDb3Rows(db, tableCtx, rows) {
  if (!db || !Array.isArray(rows) || !rows.length) return rows;
  const secobsTable =
    pickSqliteTable(sqliteTableList(db), 'SECOBS') ||
    (sqliteTableList(db).find((t) => String(t).toUpperCase() === 'SECOBS') || '');
  if (!secobsTable) {
    for (const row of rows) {
      if (!row || typeof row !== 'object') continue;
      row.observationOpcodes = [];
      row.suggestedStatus = 'complete';
      row.reviewReasons = [];
    }
    return rows;
  }
  const ctx = {
    sectionTable: tableCtx?.sectionTable || 'SECTION',
    secinspTable: tableCtx?.secinspTable || 'SECINSP',
    secobsTable
  };
  for (const row of rows) {
    if (!row || typeof row !== 'object') continue;
    const opcodes = fetchSectionObservationOpcodes(db, ctx, row.reference);
    const review = evaluateSectionReviewStatus(opcodes);
    row.observationOpcodes = opcodes;
    row.suggestedStatus = review.status;
    row.reviewReasons = review.reasons;
  }
  return rows;
}

function isDb3FromClauseOverflowError(error) {
  const msg = String(error?.message || error || '');
  return /too many from clause terms/i.test(msg) || /from clause terms,\s*max:\s*200/i.test(msg);
}

function resolveDb3NodeKeyByRef(db, nodeTable, rawRef) {
  const ref = rawRef == null ? '' : String(rawRef).trim();
  if (!ref || !nodeTable) return '';
  const cols = sqlitePragmaColumns(db, nodeTable).map((c) => String(c.name || '').toUpperCase());
  const hasPk = cols.includes('OBJ_PK');
  const hasId = cols.includes('OBJ_ID');
  if (!hasPk && !hasId) return '';
  const N = sqlIdentQuoted(nodeTable);
  const readObjKey = (colName) => {
    let stmt;
    try {
      stmt = db.prepare(`SELECT COALESCE(OBJ_Key, '') AS obj_key FROM ${N} WHERE ${sqlIdentQuoted(colName)} = ? LIMIT 1`);
      stmt.bind([ref]);
      if (stmt.step()) {
        const row = stmt.getAsObject();
        const key = cleanString(row.obj_key);
        stmt.free();
        return key;
      }
      stmt.free();
    } catch {
      try {
        stmt?.free();
      } catch {
        /* ignore */
      }
    }
    return '';
  };
  if (hasPk) {
    const key = readObjKey('OBJ_PK');
    if (key) return key;
  }
  if (hasId) {
    const key = readObjKey('OBJ_ID');
    if (key) return key;
  }
  return '';
}

function enrichDb3ImportedOperatorPreferMeta(primaryDb, primaryTables, metaDb, metaTables, imported) {
  let out = imported && typeof imported === 'object' ? { ...imported } : {};
  if (metaDb && Array.isArray(metaTables) && metaTables.length) {
    out = enrichDb3ImportedOperatorFromWcmeta(metaDb, metaTables, out);
  }
  const have =
    db3ValueLooksLikeOperatorDisplayName(cleanString(out.HP_INSPECTOR_DISPLAY)) ||
    db3ValueLooksLikeOperatorDisplayName(cleanString(out.HP_INSPECTOR_RAW));
  if (!have) {
    out = enrichDb3ImportedOperatorFromWcmeta(primaryDb, primaryTables, out);
  }
  return out;
}

async function parseDb3(buffer, metaBuffer = null) {
  const SQL = await sqlJsPromise;
  const db = new SQL.Database(new Uint8Array(buffer));
  /** @type {any} */
  let metaDb = null;
  /** @type {string[]} */
  let metaTables = [];
  let metaWarning = '';
  if (metaBuffer && metaBuffer.length) {
    try {
      metaDb = new SQL.Database(new Uint8Array(metaBuffer));
      metaTables = sqliteTableList(metaDb);
    } catch {
      metaDb = null;
      metaTables = [];
      metaWarning = 'META DB3 could not be opened. Mapping from the project DB3 only.';
    }
  } else {
    metaWarning =
      'META DB3 was not provided. Inspected by / operator names may be missing until you upload *_Meta.db3.';
  }
  const closeMeta = () => {
    try {
      metaDb?.close();
    } catch {
      /* ignore */
    }
    metaDb = null;
  };
  const finishRows = (rows) => {
    closeMeta();
    if (metaWarning) {
      try {
        Object.defineProperty(rows, 'metaWarning', { value: metaWarning, enumerable: false });
      } catch {
        /* ignore */
      }
    }
    return rows;
  };
  const tables = sqliteTableList(db);
  const preferredSection = pickSqliteTable(tables, 'SECTION');
  let sectionT = preferredSection;
  const preferredSectionType = sectionT ? sqliteObjectType(db, sectionT) : '';
  if (sectionT && preferredSectionType === 'view') {
    console.warn('[db3-preview][section-source]', {
      strategyVersion: DB3_PREVIEW_STRATEGY_VERSION,
      branch: 'reject-preferred-view',
      preferredSection,
      preferredSectionType
    });
    sectionT = '';
  }
  if (!sectionT) {
    /** @type {{ name: string, score: number }[]} */
    const candidates = [];
    for (const tableName of tables) {
      if (!tableName) continue;
      if (tableName === preferredSection) continue;
      if (sqliteObjectType(db, tableName) !== 'table') continue;
      const cols = sqlitePragmaColumns(db, tableName).map((c) => String(c.name || '').toUpperCase());
      const set = new Set(cols);
      if (!set.has('OBJ_KEY')) continue;
      let score = 0;
      if (String(tableName).toUpperCase().includes('SECTION')) score += 6;
      if (set.has('OBJ_LENGTH')) score += 3;
      if (set.has('OBJ_FROMNODE_REF')) score += 2;
      if (set.has('OBJ_TONODE_REF')) score += 2;
      if (set.has('OBJ_MATERIAL')) score += 1;
      if (set.has('OBJ_SHAPE')) score += 1;
      if (set.has('OBJ_SIZE1')) score += 1;
      if (set.has('OBJ_SIZE2')) score += 1;
      candidates.push({ name: tableName, score });
    }
    candidates.sort((a, b) => {
      if (b.score !== a.score) return b.score - a.score;
      return String(a.name || '').localeCompare(String(b.name || ''), undefined, { sensitivity: 'base' });
    });
    if (candidates.length) sectionT = candidates[0].name;
  }
  if (!sectionT) {
    db.close();
    closeMeta();
    const preview = tables.slice(0, 40).join(', ') || '(none)';
    const hint = explainMissingSectionDb3(tables);
    throw new Error(
      `Not a WinCan-style pipe DB3: missing SECTION table.${hint} Tables in file: ${preview}${tables.length > 40 ? ' …' : ''}`
    );
  }
  const extraFrag = buildDb3SectionExtraSelect(db, sectionT);
  console.warn('[db3-preview][section-source]', {
    strategyVersion: DB3_PREVIEW_STRATEGY_VERSION,
    branch: 'selected-section-source',
    selectedSection: sectionT,
    preferredSection: preferredSection || '',
    preferredSectionType: preferredSectionType || ''
  });
  const nodeT = pickSqliteTable(tables, 'NODE');
  const nodeType = nodeT ? sqliteObjectType(db, nodeT) : '';
  const nodeRuntimeTable = nodeT && nodeType !== 'view' ? nodeT : '';
  const secinspT = pickSqliteTable(tables, 'SECINSP');
  const secinspType = secinspT ? sqliteObjectType(db, secinspT) : '';
  const secinspSafeForJoin = !!secinspT && secinspType !== 'view';
  const secinspRuntimeTable = secinspSafeForJoin ? secinspT : '';
  const projectT = pickSqliteTable(tables, 'PROJECT');

  let projectName = '';
  if (projectT) {
    try {
      const projectStmt = db.prepare(
        `SELECT COALESCE(MAX(PRJ_Key), '') AS project_name FROM ${sqlIdentQuoted(projectT)}`
      );
      if (projectStmt.step()) {
        const row = projectStmt.getAsObject();
        projectName = cleanString(row.project_name);
      }
      projectStmt.free();
    } catch {
      projectName = '';
    }
  }

  const S = sqlIdentQuoted(sectionT);
  const N = nodeRuntimeTable ? sqlIdentQuoted(nodeRuntimeTable) : '';

  const coreCols = `
      s.OBJ_Key AS reference,
      COALESCE(si.inspected_length, s.OBJ_Length, 0) AS length,
      COALESCE(s.OBJ_City, '') AS city,
      COALESCE(s.OBJ_Street, '') AS street,
      COALESCE(n1.OBJ_Key, '') AS upstream,
      COALESCE(n2.OBJ_Key, '') AS downstream,
      COALESCE(s.OBJ_Material, '') AS material_code,
      COALESCE(s.OBJ_Shape, '') AS shape_code,
      COALESCE(s.OBJ_Size1, '') AS size1,
      COALESCE(s.OBJ_Size2, '') AS size2`;

  const coreColsNoInsp = `
      s.OBJ_Key AS reference,
      COALESCE(s.OBJ_Length, 0) AS length,
      COALESCE(s.OBJ_City, '') AS city,
      COALESCE(s.OBJ_Street, '') AS street,
      COALESCE(n1.OBJ_Key, '') AS upstream,
      COALESCE(n2.OBJ_Key, '') AS downstream,
      COALESCE(s.OBJ_Material, '') AS material_code,
      COALESCE(s.OBJ_Shape, '') AS shape_code,
      COALESCE(s.OBJ_Size1, '') AS size1,
      COALESCE(s.OBJ_Size2, '') AS size2`;

  const coreColsBare = `
      s.OBJ_Key AS reference,
      COALESCE(s.OBJ_Length, 0) AS length,
      COALESCE(s.OBJ_City, '') AS city,
      COALESCE(s.OBJ_Street, '') AS street,
      '' AS upstream,
      '' AS downstream,
      COALESCE(s.OBJ_Material, '') AS material_code,
      COALESCE(s.OBJ_Shape, '') AS shape_code,
      COALESCE(s.OBJ_Size1, '') AS size1,
      COALESCE(s.OBJ_Size2, '') AS size2`;

  /** @type {string[]} */
  const sqlVariants = [];
  if (secinspSafeForJoin && nodeRuntimeTable) {
    const SI = sqlIdentQuoted(secinspT);
    sqlVariants.push(`
    SELECT ${coreCols}
    FROM ${S} s
    LEFT JOIN (
      SELECT INS_Section_FK AS si_fk, MAX(COALESCE(INS_InspectedLength, INS_EstimatedLength, 0)) AS inspected_length
      FROM ${SI}
      GROUP BY INS_Section_FK
    ) si ON si.si_fk = s.OBJ_PK
    LEFT JOIN ${N} n1 ON n1.OBJ_PK = s.OBJ_FromNode_REF
    LEFT JOIN ${N} n2 ON n2.OBJ_PK = s.OBJ_ToNode_REF
    ORDER BY s.OBJ_Key`);
    sqlVariants.push(`
    SELECT ${coreCols}
    FROM ${S} s
    LEFT JOIN (
      SELECT OBJ_ID AS si_fk, MAX(COALESCE(INS_InspectedLength, INS_EstimatedLength, 0)) AS inspected_length
      FROM ${SI}
      GROUP BY OBJ_ID
    ) si ON si.si_fk = s.OBJ_ID
    LEFT JOIN ${N} n1 ON n1.OBJ_PK = s.OBJ_FromNode_REF
    LEFT JOIN ${N} n2 ON n2.OBJ_PK = s.OBJ_ToNode_REF
    ORDER BY s.OBJ_Key`);
    sqlVariants.push(`
    SELECT ${coreCols}
    FROM ${S} s
    LEFT JOIN (
      SELECT OBJ_ID AS si_fk, MAX(COALESCE(INS_InspectedLength, INS_EstimatedLength, 0)) AS inspected_length
      FROM ${SI}
      GROUP BY OBJ_ID
    ) si ON si.si_fk = s.OBJ_PK
    LEFT JOIN ${N} n1 ON n1.OBJ_PK = s.OBJ_FromNode_REF
    LEFT JOIN ${N} n2 ON n2.OBJ_PK = s.OBJ_ToNode_REF
    ORDER BY s.OBJ_Key`);
  }
  if (nodeRuntimeTable) {
    sqlVariants.push(`
    SELECT ${coreColsNoInsp}
    FROM ${S} s
    LEFT JOIN ${N} n1 ON n1.OBJ_PK = s.OBJ_FromNode_REF
    LEFT JOIN ${N} n2 ON n2.OBJ_PK = s.OBJ_ToNode_REF
    ORDER BY s.OBJ_Key`);
  }
  sqlVariants.push(`
    SELECT ${coreColsBare}
    FROM ${S} s
    ORDER BY s.OBJ_Key`);

  let lastErr = 'no query variant succeeded';
  let sawFromClauseOverflow = false;
  for (const sql of sqlVariants) {
    const sqlWithExtras = injectDb3ExtrasBeforeOrderBy(sql, extraFrag.sql);
    let stmt;
    try {
      stmt = db.prepare(sqlWithExtras);
    } catch (e) {
      lastErr = e instanceof Error ? e.message : String(e);
      if (isDb3FromClauseOverflowError(e)) {
        sawFromClauseOverflow = true;
        console.warn('[db3-preview][variant-overflow]', {
          strategyVersion: DB3_PREVIEW_STRATEGY_VERSION,
          branch: 'variant-prepare',
          hasNodeTable: !!nodeRuntimeTable,
          hasSecinspTable: !!secinspRuntimeTable,
          message: String(lastErr || '').slice(0, 220)
        });
      }
      continue;
    }
    try {
      const rows = [];
      while (stmt.step()) {
        const raw = stmt.getAsObject();
        const mapped = mapDb3SectionRow(raw, projectName);
        let imported = extractDb3ImportedFromRow(raw, extraFrag.aliasNames);
        if (secinspRuntimeTable) {
          imported = mergeSecinspRowIntoDb3Imported(db, sectionT, secinspRuntimeTable, mapped.reference, imported);
          imported = mergeSecinspBySectionObjKeyColumn(db, secinspRuntimeTable, mapped.reference, imported);
        }
        imported = enrichDb3ImportedOperatorPreferMeta(db, tables, metaDb, metaTables, imported);
        const inspector = db3InspectorIdentityFromImported(imported);
        if (inspector) {
          imported.HP_INSPECTOR_RAW = inspector.raw;
          imported.HP_INSPECTOR_DISPLAY = inspector.canonical;
          imported.HP_INSPECTOR_KEY = inspector.key;
          mapped.inspectorRaw = inspector.raw;
          mapped.inspector = inspector.canonical;
          mapped.inspectorKey = inspector.key;
        }
        if (Object.keys(imported).length) {
          mapped.db3Imported = imported;
        }
        rows.push(mapped);
      }
      stmt.free();
      console.warn('[db3-preview][strategy-select]', {
        strategyVersion: DB3_PREVIEW_STRATEGY_VERSION,
        strategy: 'sql-variant-v1',
        hasNodeTable: !!nodeRuntimeTable,
        hasSecinspTable: !!secinspRuntimeTable,
        usesSectionExtras: !!extraFrag.sql
      });
      attachObservationReviewToDb3Rows(db, {
        sectionTable: sectionT,
        secinspTable: secinspRuntimeTable || 'SECINSP'
      }, rows);
      db.close();
      return finishRows(rows);
    } catch (e) {
      lastErr = e instanceof Error ? e.message : String(e);
      if (isDb3FromClauseOverflowError(e)) {
        sawFromClauseOverflow = true;
        console.warn('[db3-preview][variant-overflow]', {
          strategyVersion: DB3_PREVIEW_STRATEGY_VERSION,
          branch: 'variant-step',
          hasNodeTable: !!nodeRuntimeTable,
          hasSecinspTable: !!secinspRuntimeTable,
          message: String(lastErr || '').slice(0, 220)
        });
      }
      try {
        stmt.free();
      } catch {
        /* ignore */
      }
    }
  }
  if (sawFromClauseOverflow) {
    let splitStmt;
    try {
      const splitCoreCols = `
      s.OBJ_Key AS reference,
      COALESCE(s.OBJ_Length, 0) AS length,
      COALESCE(s.OBJ_City, '') AS city,
      COALESCE(s.OBJ_Street, '') AS street,
      COALESCE(s.OBJ_FromNode_REF, '') AS from_node_ref,
      COALESCE(s.OBJ_ToNode_REF, '') AS to_node_ref,
      COALESCE(s.OBJ_Material, '') AS material_code,
      COALESCE(s.OBJ_Shape, '') AS shape_code,
      COALESCE(s.OBJ_Size1, '') AS size1,
      COALESCE(s.OBJ_Size2, '') AS size2`;
      const splitSql = injectDb3ExtrasBeforeOrderBy(
        `
        SELECT ${splitCoreCols}
        FROM ${S} s
        ORDER BY s.OBJ_Key`,
        extraFrag.sql
      );
      console.warn('[db3-preview][variant-fallback]', {
        strategyVersion: DB3_PREVIEW_STRATEGY_VERSION,
        strategy: 'section-split-probe-v1',
        hasNodeTable: !!nodeRuntimeTable,
        hasSecinspTable: !!secinspRuntimeTable
      });
      splitStmt = db.prepare(splitSql);
      const rows = [];
      const nodeCache = new Map();
      const lookupNode = (rawRef) => {
        const key = rawRef == null ? '' : String(rawRef).trim();
        if (!key || !nodeRuntimeTable) return '';
        if (nodeCache.has(key)) return nodeCache.get(key) || '';
        const hit = resolveDb3NodeKeyByRef(db, nodeRuntimeTable, key);
        nodeCache.set(key, hit || '');
        return hit || '';
      };
      while (splitStmt.step()) {
        const raw = splitStmt.getAsObject();
        const mapped = mapDb3SectionRow(raw, projectName);
        mapped.upstream = lookupNode(raw.from_node_ref);
        mapped.downstream = lookupNode(raw.to_node_ref);
        let imported = extractDb3ImportedFromRow(raw, extraFrag.aliasNames);
        if (secinspRuntimeTable) {
          imported = mergeSecinspRowIntoDb3Imported(db, sectionT, secinspRuntimeTable, mapped.reference, imported);
          imported = mergeSecinspBySectionObjKeyColumn(db, secinspRuntimeTable, mapped.reference, imported);
        }
        imported = enrichDb3ImportedOperatorPreferMeta(db, tables, metaDb, metaTables, imported);
        const inspector = db3InspectorIdentityFromImported(imported);
        if (inspector) {
          imported.HP_INSPECTOR_RAW = inspector.raw;
          imported.HP_INSPECTOR_DISPLAY = inspector.canonical;
          imported.HP_INSPECTOR_KEY = inspector.key;
          mapped.inspectorRaw = inspector.raw;
          mapped.inspector = inspector.canonical;
          mapped.inspectorKey = inspector.key;
        }
        if (Object.keys(imported).length) mapped.db3Imported = imported;
        rows.push(mapped);
      }
      splitStmt.free();
      console.warn('[db3-preview][strategy-select]', {
        strategyVersion: DB3_PREVIEW_STRATEGY_VERSION,
        strategy: 'section-split-probe-v1',
        hasNodeTable: !!nodeRuntimeTable,
        hasSecinspTable: !!secinspRuntimeTable,
        usesSectionExtras: !!extraFrag.sql
      });
      attachObservationReviewToDb3Rows(db, {
        sectionTable: sectionT,
        secinspTable: secinspRuntimeTable || 'SECINSP'
      }, rows);
      db.close();
      return finishRows(rows);
    } catch (fallbackErr) {
      lastErr = fallbackErr instanceof Error ? fallbackErr.message : String(fallbackErr);
      if (isDb3FromClauseOverflowError(fallbackErr)) {
        console.warn('[db3-preview][variant-overflow]', {
          strategyVersion: DB3_PREVIEW_STRATEGY_VERSION,
          branch: 'split-fallback',
          hasNodeTable: !!nodeRuntimeTable,
          hasSecinspTable: !!secinspRuntimeTable,
          message: String(lastErr || '').slice(0, 220)
        });
        let bareStmt;
        try {
          const bareSplitCoreCols = `
      s.OBJ_Key AS reference,
      COALESCE(s.OBJ_Length, 0) AS length,
      COALESCE(s.OBJ_City, '') AS city,
      COALESCE(s.OBJ_Street, '') AS street,
      COALESCE(s.OBJ_FromNode_REF, '') AS from_node_ref,
      COALESCE(s.OBJ_ToNode_REF, '') AS to_node_ref,
      COALESCE(s.OBJ_Material, '') AS material_code,
      COALESCE(s.OBJ_Shape, '') AS shape_code,
      COALESCE(s.OBJ_Size1, '') AS size1,
      COALESCE(s.OBJ_Size2, '') AS size2`;
          const bareSplitSql = `
        SELECT ${bareSplitCoreCols}
        FROM ${S} s
        ORDER BY s.OBJ_Key`;
          console.warn('[db3-preview][variant-fallback]', {
            strategyVersion: DB3_PREVIEW_STRATEGY_VERSION,
            strategy: 'section-split-no-extras-v1',
            hasNodeTable: !!nodeRuntimeTable,
            hasSecinspTable: !!secinspRuntimeTable
          });
          bareStmt = db.prepare(bareSplitSql);
          const rows = [];
          const nodeCache = new Map();
          const lookupNode = (rawRef) => {
            const key = rawRef == null ? '' : String(rawRef).trim();
            if (!key || !nodeRuntimeTable) return '';
            if (nodeCache.has(key)) return nodeCache.get(key) || '';
            const hit = resolveDb3NodeKeyByRef(db, nodeRuntimeTable, key);
            nodeCache.set(key, hit || '');
            return hit || '';
          };
          while (bareStmt.step()) {
            const raw = bareStmt.getAsObject();
            const mapped = mapDb3SectionRow(raw, projectName);
            mapped.upstream = lookupNode(raw.from_node_ref);
            mapped.downstream = lookupNode(raw.to_node_ref);
            let imported = {};
            if (secinspRuntimeTable) {
              imported = mergeSecinspRowIntoDb3Imported(db, sectionT, secinspRuntimeTable, mapped.reference, imported);
              imported = mergeSecinspBySectionObjKeyColumn(db, secinspRuntimeTable, mapped.reference, imported);
            }
            imported = enrichDb3ImportedOperatorPreferMeta(db, tables, metaDb, metaTables, imported);
            const inspector = db3InspectorIdentityFromImported(imported);
            if (inspector) {
              imported.HP_INSPECTOR_RAW = inspector.raw;
              imported.HP_INSPECTOR_DISPLAY = inspector.canonical;
              imported.HP_INSPECTOR_KEY = inspector.key;
              mapped.inspectorRaw = inspector.raw;
              mapped.inspector = inspector.canonical;
              mapped.inspectorKey = inspector.key;
            }
            if (Object.keys(imported).length) mapped.db3Imported = imported;
            rows.push(mapped);
          }
          bareStmt.free();
          console.warn('[db3-preview][strategy-select]', {
            strategyVersion: DB3_PREVIEW_STRATEGY_VERSION,
            strategy: 'section-split-no-extras-v1',
            hasNodeTable: !!nodeRuntimeTable,
            hasSecinspTable: !!secinspRuntimeTable,
            usesSectionExtras: false
          });
          attachObservationReviewToDb3Rows(db, {
            sectionTable: sectionT,
            secinspTable: secinspRuntimeTable || 'SECINSP'
          }, rows);
          db.close();
          return finishRows(rows);
        } catch (bareErr) {
          lastErr = bareErr instanceof Error ? bareErr.message : String(bareErr);
          console.warn('[db3-preview][variant-fallback-error]', {
            strategyVersion: DB3_PREVIEW_STRATEGY_VERSION,
            strategy: 'section-split-no-extras-v1',
            message: String(lastErr || '').slice(0, 220)
          });
          try {
            bareStmt?.free();
          } catch {
            /* ignore */
          }
        }
      }
      try {
        splitStmt?.free();
      } catch {
        /* ignore */
      }
    }
  }
  db.close();
  closeMeta();
  throw new Error(
    lastErr ||
      'Could not read SECTION rows from this DB3 (unsupported WinCan schema or missing OBJ_Key / length columns).'
  );
}

module.exports = { parseDb3 };

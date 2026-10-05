'use strict';

/**
 * AutoSync DB3 → PipeSync PSR ingest helpers.
 * Review rules:
 * - observation opcode MSA → needs-reviewed
 * - missing ending access code (ACB / AMH / ADP / AEP / EOP) → needs-reviewed
 * - otherwise complete
 */

const ENDING_ACCESS_CODES = new Set(['ACB', 'AMH', 'ADP', 'AEP', 'EOP']);

/** Common abbreviations found in AutoSync / WinCan project folder names. */
const CITY_ALIASES = {
  jax: 'Jacksonville',
  jacksonville: 'Jacksonville',
  orl: 'Orlando',
  orlando: 'Orlando',
  tpa: 'Tampa',
  tampa: 'Tampa',
  mco: 'Orlando',
  mia: 'Miami',
  miami: 'Miami',
  ftl: 'Fort Lauderdale',
  'fort lauderdale': 'Fort Lauderdale',
  stpete: 'St Petersburg',
  'st petersburg': 'St Petersburg',
  'st. petersburg': 'St Petersburg',
  gainesville: 'Gainesville',
  gnv: 'Gainesville',
  tallahassee: 'Tallahassee',
  tlh: 'Tallahassee',
  daytona: 'Daytona Beach',
  'daytona beach': 'Daytona Beach'
};

function cleanString(value) {
  return String(value == null ? '' : value).trim();
}

function normalizeOpcode(code) {
  return cleanString(code).toUpperCase().replace(/[^A-Z0-9]/g, '');
}

/**
 * @param {Array<string|{code?: string, distance?: number}>} opcodes
 * @returns {{ status: 'complete'|'needs-reviewed', reasons: string[], hasMsa: boolean, hasEndingAccess: boolean, endingCodes: string[] }}
 */
function evaluateSectionReviewStatus(opcodes) {
  const list = Array.isArray(opcodes) ? opcodes : [...(opcodes || [])];
  /** @type {{ code: string, distance: number|null }[]} */
  const rows = list
    .map((item) => {
      if (item && typeof item === 'object') {
        const code = normalizeOpcode(item.code ?? item.OBS_OpCode ?? item.opcode);
        const d = Number(item.distance ?? item.OBS_Distance);
        return { code, distance: Number.isFinite(d) ? d : null };
      }
      return { code: normalizeOpcode(item), distance: null };
    })
    .filter((r) => r.code);

  const codes = [...new Set(rows.map((r) => r.code))];
  const hasMsa = codes.includes('MSA');

  const distances = rows.map((r) => r.distance).filter((d) => d != null && Number.isFinite(d));
  const maxDist = distances.length ? Math.max(...distances) : null;
  const atEnd =
    maxDist == null
      ? rows
      : rows.filter((r) => r.distance != null && Math.abs(r.distance - maxDist) <= 0.51);

  const endingAtEnd = atEnd.filter((r) => ENDING_ACCESS_CODES.has(r.code)).map((r) => r.code);
  // If distances are unavailable, fall back to “any ending access code present”.
  const endingCodes =
    maxDist == null
      ? codes.filter((c) => ENDING_ACCESS_CODES.has(c))
      : [...new Set(endingAtEnd)];
  const hasEndingAccess = endingCodes.length > 0;

  /** @type {string[]} */
  const reasons = [];
  if (hasMsa) reasons.push('MSA observation');
  if (!hasEndingAccess) {
    reasons.push(
      maxDist == null
        ? 'Missing ending access code (ACB/AMH/ADP/AEP/EOP)'
        : 'Missing ending access code at run end (ACB/AMH/ADP/AEP/EOP)'
    );
  }
  return {
    status: reasons.length ? 'needs-reviewed' : 'complete',
    reasons,
    hasMsa,
    hasEndingAccess,
    endingCodes
  };
}

/**
 * Prefer WinCan customer fields (SECTION / PROJECT / Meta extras) over guessing from the project title.
 * @param {Record<string, unknown>|null|undefined} imported
 * @param {string} [projectName]
 */
function extractCustomerFromDb3(imported, projectName = '') {
  const imp = imported && typeof imported === 'object' ? imported : {};
  const keys = [
    'OBJ_CUSTOMER',
    'CUSTOMER',
    'PRJ_CUSTOMER',
    'PRJ_CUSTOMERNAME',
    'INS_CUSTOMER',
    'CUSTOMER_NAME',
    'CLIENT',
    'OBJ_CLIENT'
  ];
  for (const want of keys) {
    const hit = Object.keys(imp).find((k) => String(k).toUpperCase() === want);
    const v = hit ? cleanString(imp[hit]) : '';
    if (v && !/^\d+$/.test(v) && v.length <= 120) return v;
  }
  // Last resort: first token of project name (e.g. "AJJ Bridgestone…").
  const first = cleanString(projectName).split(/[\s_/\\-]+/).filter(Boolean)[0] || '';
  if (first && first.length >= 2 && first.length <= 40 && !/^\d{4}$/.test(first)) return first;
  return '';
}

function tokenizePlaceName(text) {
  return cleanString(text)
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((t) => t && t.length >= 2 && !/^\d{2,4}$/.test(t));
}

/**
 * Match a city from project/section text against existing PipeSync cities, with alias expansion.
 * @param {string} projectName
 * @param {string} sectionCity
 * @param {string[]} knownCities
 * @returns {{ city: string, matchedExisting: boolean, source: string }}
 */
function resolveCityForAutosyncPsr(projectName, sectionCity, knownCities = []) {
  const known = (Array.isArray(knownCities) ? knownCities : [])
    .map((c) => cleanString(c))
    .filter(Boolean);
  const knownLower = new Map(known.map((c) => [c.toLowerCase(), c]));

  const tryExact = (raw, source) => {
    const s = cleanString(raw);
    if (!s) return null;
    const hit = knownLower.get(s.toLowerCase());
    if (hit) return { city: hit, matchedExisting: true, source };
    return null;
  };

  const fromSection = tryExact(sectionCity, 'section-city');
  if (fromSection) return fromSection;

  const haystack = `${projectName || ''} ${sectionCity || ''}`;
  const tokens = tokenizePlaceName(haystack);

  for (const city of known) {
    const cityTokens = tokenizePlaceName(city);
    if (cityTokens.length && cityTokens.every((t) => tokens.includes(t))) {
      return { city, matchedExisting: true, source: 'project-token-match' };
    }
    // Single significant token of a multi-word city (e.g. "jacksonville" in "… Jax fl …" via alias below).
    if (cityTokens.some((t) => t.length >= 5 && tokens.includes(t))) {
      return { city, matchedExisting: true, source: 'project-partial-city' };
    }
  }

  for (const tok of tokens) {
    const alias = CITY_ALIASES[tok];
    if (!alias) continue;
    const existing = knownLower.get(alias.toLowerCase());
    if (existing) return { city: existing, matchedExisting: true, source: `alias:${tok}` };
    return { city: alias, matchedExisting: false, source: `alias-new:${tok}` };
  }

  const section = cleanString(sectionCity);
  if (section) return { city: section, matchedExisting: false, source: 'section-city-new' };

  return { city: 'NOT SET', matchedExisting: false, source: 'fallback' };
}

/**
 * Collect OBS_OpCode (+ distance) for one SECTION.OBJ_Key via SECINSP → SECOBS.
 * @param {any} db sql.js Database
 * @param {{ sectionTable?: string, secinspTable?: string, secobsTable?: string }} tables
 * @param {string} sectionReference
 * @returns {{ code: string, distance: number|null }[]}
 */
function fetchSectionObservationOpcodes(db, tables, sectionReference) {
  const ref = cleanString(sectionReference);
  if (!db || !ref) return [];
  const sectionTable = tables?.sectionTable || 'SECTION';
  const secinspTable = tables?.secinspTable || 'SECINSP';
  const secobsTable = tables?.secobsTable || 'SECOBS';
  const q = (ident) => `"${String(ident).replace(/"/g, '""')}"`;

  /** @type {string[]} */
  const sqlAttempts = [
    `SELECT o.OBS_OpCode AS code, o.OBS_Distance AS distance
       FROM ${q(secobsTable)} o
       JOIN ${q(secinspTable)} i ON o.OBS_Inspection_FK = i.INS_PK
       JOIN ${q(sectionTable)} s ON i.INS_Section_FK = s.OBJ_PK
       WHERE s.OBJ_Key = ? AND (o.OBS_Deleted IS NULL) AND (i.INS_Deleted IS NULL)`,
    `SELECT o.OBS_OpCode AS code, o.OBS_Distance AS distance
       FROM ${q(secobsTable)} o
       JOIN ${q(secinspTable)} i ON o.OBS_Inspection_FK = i.INS_PK
       JOIN ${q(sectionTable)} s ON i.OBJ_ID = s.OBJ_ID
       WHERE s.OBJ_Key = ? AND (o.OBS_Deleted IS NULL)`,
    `SELECT o.OBS_OpCode AS code, o.OBS_Distance AS distance
       FROM ${q(secobsTable)} o
       JOIN ${q(secinspTable)} i ON o.OBS_Inspection_FK = i.INS_PK
       WHERE i.INS_Section_FK IN (SELECT OBJ_PK FROM ${q(sectionTable)} WHERE OBJ_Key = ?)`
  ];

  /** @type {{ code: string, distance: number|null }[]} */
  const out = [];
  for (const sql of sqlAttempts) {
    let stmt;
    try {
      stmt = db.prepare(sql);
      stmt.bind([ref]);
      while (stmt.step()) {
        const row = stmt.getAsObject();
        const code = normalizeOpcode(row.code ?? row.CODE ?? row.OBS_OpCode);
        if (!code) continue;
        const d = Number(row.distance ?? row.DISTANCE ?? row.OBS_Distance);
        out.push({ code, distance: Number.isFinite(d) ? d : null });
      }
      stmt.free();
      if (out.length) break;
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

/**
 * Is this object key a primary WinCan DB3 (not *_Meta.db3)?
 * @param {string} objectKeyOrName
 */
function isPrimaryWinCanDb3Name(objectKeyOrName) {
  const base = String(objectKeyOrName || '')
    .replace(/\\/g, '/')
    .split('/')
    .pop() || '';
  if (!/\.db3$/i.test(base)) return false;
  return !/(?:^|[._\-\s])meta\.db3$/i.test(base);
}

/**
 * Guess companion Meta key next to a primary DB3 object key.
 * @param {string} primaryKey
 */
function guessMetaObjectKey(primaryKey) {
  const key = String(primaryKey || '').replace(/\\/g, '/');
  if (!isPrimaryWinCanDb3Name(key)) return '';
  const slash = key.lastIndexOf('/');
  const dir = slash >= 0 ? key.slice(0, slash + 1) : '';
  const base = slash >= 0 ? key.slice(slash + 1) : key;
  const stem = base.replace(/\.db3$/i, '');
  return `${dir}${stem}_Meta.db3`;
}

module.exports = {
  ENDING_ACCESS_CODES,
  CITY_ALIASES,
  evaluateSectionReviewStatus,
  extractCustomerFromDb3,
  resolveCityForAutosyncPsr,
  fetchSectionObservationOpcodes,
  isPrimaryWinCanDb3Name,
  guessMetaObjectKey,
  normalizeOpcode
};

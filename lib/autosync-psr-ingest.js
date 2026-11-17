'use strict';

/**
 * AutoSync DB3 → PipeSync PSR ingest helpers.
 * Review rules (website Footage pills):
 * - MSA → failed (red Failed)
 * - Defect / observation codes the pipe chart treats as defects (not access points),
 *   including CC, CL, JSL, H, HSV and the same family → needs-reviewed (yellow)
 * - No MSA and no defect code → complete (green)
 * Access-point codes are the website structural set plus survey lead-in remarks.
 * They are not defects and do not leave Complete.
 */

const ENDING_ACCESS_CODES = new Set(['ACB', 'AMH', 'ADP', 'AEP', 'EOP']);

/**
 * Website pipe-chart structural / access opcodes (db3-parser STRUCTURAL_OPCODES)
 * plus AEP and the lead-in remark placeholders. These are not defect codes.
 */
const ACCESS_OPCODES = new Set([
  'AMH',
  'ACB',
  'ADP',
  'AEP',
  'EOP',
  'STMH',
  'WLFC',
  'FHMH',
  'GC',
  'MWL',
  'MWLS',
  'MYV',
  'MGO',
  'MST',
  'MFL',
  'MCC',
  'MIS',
  'NOTE',
  'RMR',
  'REM',
  'GR',
  'GEN',
  'COM',
  'TEXT'
]);

/** Office acknowledgement statuses. They stay their own groups, not Complete. */
const OFFICE_REVIEW_STATUSES = new Set(['repairs-pending', 'repairs-complete']);

const PIPE_USE_KEYS = ['OBJ_PIPEUSE', 'OBJ_SEWERUSE', 'OBJ_SYSTEMTYPE', 'OBJ_USE', 'PIPEUSE', 'SEWERUSE'];

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
 * Letters and digits only, lowercased. Dots, spaces, and case do not count.
 * @param {string} name
 */
function compactClientKey(name) {
  return cleanString(name).toLowerCase().replace(/[^a-z0-9]/g, '');
}

/**
 * Place a Customer string on an existing client when the compact keys match,
 * or when one compact key is a prefix of the other (AJJ matches A.J Johns).
 * Otherwise keep the incoming string so the caller can create the client.
 * @param {string} raw
 * @param {string[]} knownClients
 * @returns {{ client: string, matched: boolean, how: 'exact'|'close'|'new'|'empty' }}
 */
function matchExistingClient(raw, knownClients = []) {
  const incoming = cleanString(raw);
  const key = compactClientKey(incoming);
  if (!incoming || !key) return { client: incoming, matched: false, how: 'empty' };
  const list = (Array.isArray(knownClients) ? knownClients : [])
    .map((name) => ({ name: cleanString(name), key: compactClientKey(name) }))
    .filter((item) => item.name && item.key);
  const exact = list.find((item) => item.key === key);
  if (exact) return { client: exact.name, matched: true, how: 'exact' };
  const close = list.filter((item) => {
    if (item.key.length < 3 || key.length < 3) return false;
    if (item.key === key) return false;
    return (
      (item.key.length < key.length && key.startsWith(item.key)) ||
      (key.length < item.key.length && item.key.startsWith(key))
    );
  });
  if (!close.length) return { client: incoming, matched: false, how: 'new' };
  close.sort((a, b) => a.key.length - b.key.length || a.name.localeCompare(b.name));
  return { client: close[0].name, matched: true, how: 'close' };
}

/**
 * Pipe use on the section chooses Storm or Sanitary.
 * When Pipe use is missing, this does not guess from material or size.
 * @param {Record<string, unknown>|null|undefined} imported
 * @returns {{ system: ''|'storm'|'sanitary', source: string, pipeUse: string }}
 */
function systemFromPipeUse(imported) {
  const imp = imported && typeof imported === 'object' ? imported : {};
  let pipeUse = '';
  for (const want of PIPE_USE_KEYS) {
    const hit = Object.keys(imp).find((key) => String(key).toUpperCase() === want);
    const value = hit ? cleanString(imp[hit]) : '';
    if (value) {
      pipeUse = value;
      break;
    }
  }
  if (!pipeUse) return { system: '', source: 'missing', pipeUse: '' };
  const folded = pipeUse.toLowerCase().replace(/[^a-z]/g, '');
  if (folded.includes('sanit')) return { system: 'sanitary', source: 'pipe-use', pipeUse };
  if (folded.includes('storm')) return { system: 'storm', source: 'pipe-use', pipeUse };
  return { system: '', source: 'pipe-use-unrecognized', pipeUse };
}

/**
 * @param {Array<string|{code?: string, distance?: number}>} opcodes
 * @returns {{ status: 'complete'|'failed'|'needs-reviewed', reasons: string[], hasMsa: boolean, defectCodes: string[], hasEndingAccess: boolean, endingCodes: string[] }}
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
  const defectCodes = codes.filter((code) => code !== 'MSA' && !ACCESS_OPCODES.has(code));

  const distances = rows.map((r) => r.distance).filter((d) => d != null && Number.isFinite(d));
  const maxDist = distances.length ? Math.max(...distances) : null;
  const atEnd =
    maxDist == null
      ? rows
      : rows.filter((r) => r.distance != null && Math.abs(r.distance - maxDist) <= 0.51);
  const endingAtEnd = atEnd.filter((r) => ENDING_ACCESS_CODES.has(r.code)).map((r) => r.code);
  const endingCodes =
    maxDist == null ? codes.filter((c) => ENDING_ACCESS_CODES.has(c)) : [...new Set(endingAtEnd)];
  const hasEndingAccess = endingCodes.length > 0;

  /** @type {string[]} */
  const reasons = [];
  let status = 'complete';
  if (hasMsa) {
    status = 'failed';
    reasons.push('MSA observation');
  } else if (defectCodes.length) {
    status = 'needs-reviewed';
    reasons.push(`Observation ${defectCodes.join(', ')}`);
  }
  return {
    status,
    reasons,
    hasMsa,
    defectCodes,
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
  ACCESS_OPCODES,
  OFFICE_REVIEW_STATUSES,
  CITY_ALIASES,
  evaluateSectionReviewStatus,
  extractCustomerFromDb3,
  resolveCityForAutosyncPsr,
  fetchSectionObservationOpcodes,
  isPrimaryWinCanDb3Name,
  guessMetaObjectKey,
  normalizeOpcode,
  compactClientKey,
  matchExistingClient,
  systemFromPipeUse
};

'use strict';

/** Roles a person can hold at a customer company. These are not a second user system. */
const COMPANY_ROLE_LABELS = {
  superintendent: 'Superintendent',
  owner: 'Owner',
  manager: 'Manager',
  foreman: 'Foreman',
  inspector: 'Inspector',
  engineer: 'Engineer',
  customer: 'Customer',
  admin: 'Admin',
  employee: 'Employee'
};

const ACCESS_MODES = ['none', 'full', 'view', 'select'];

function clean(value, max = 300) {
  return String(value == null ? '' : value).replace(/\s+/g, ' ').trim().slice(0, max);
}

function normalizeCompanyRole(raw, accountType) {
  const key = clean(raw, 40).toLowerCase().replace(/[\s-]+/g, '_');
  if (COMPANY_ROLE_LABELS[key]) return key;
  return String(accountType || '').toLowerCase() === 'customer' ? 'customer' : 'employee';
}

function roleLabel(roleKey) {
  const key = clean(roleKey, 40).toLowerCase();
  return COMPANY_ROLE_LABELS[key] || (key ? key.replace(/_/g, ' ') : '');
}

function asMode(value, customer) {
  const key = clean(value, 20).toLowerCase();
  if (!ACCESS_MODES.includes(key)) return 'none';
  if (!customer && key === 'view') return 'full';
  return key;
}

function refList(value) {
  if (!Array.isArray(value)) return [];
  return value
    .map((row) => {
      if (!row || typeof row !== 'object') return null;
      const jobId = clean(row.jobId || row.job_id, 80);
      const path = clean(row.path || row.pathPrefix || row.name, 400);
      const name = clean(row.name || path.split('/').pop() || '', 180);
      if (!jobId && !path) return null;
      return { jobId, path, name };
    })
    .filter(Boolean)
    .slice(0, 400);
}

function idList(value) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map((id) => clean(id, 80)).filter(Boolean))].slice(0, 400);
}

/** Jobs with no client folder share this grant key. It is not a company name. */
const NO_CLIENT = '__none__';

function clientGrantList(value, customer) {
  if (!Array.isArray(value)) return [];
  const out = [];
  const seen = new Set();
  for (const row of value) {
    if (!row || typeof row !== 'object') continue;
    let clientId = clean(row.clientId || row.client_id, 80);
    if (row.unassigned === true || clientId === NO_CLIENT) clientId = NO_CLIENT;
    if (!clientId || seen.has(clientId)) continue;
    let mode = clean(row.mode, 20).toLowerCase();
    if (mode !== 'full' && mode !== 'view') continue;
    if (!customer && mode === 'view') mode = 'full';
    seen.add(clientId);
    out.push({ clientId, mode });
  }
  return out.slice(0, 200);
}

function clientKeyOf(job) {
  const id = clean(job?.clientId, 80);
  return id || NO_CLIENT;
}

/**
 * Customers: full = view and download, view = view only.
 * Employees and admins never keep the view-only mode.
 */
function normalizeClearance(raw, accountType) {
  const customer = String(accountType || '').toLowerCase() === 'customer';
  const source = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  return {
    jobs: asMode(source.jobs, customer),
    files: asMode(source.files, customer),
    folders: asMode(source.folders, customer),
    jobIds: idList(source.jobIds || source.job_ids),
    clientGrants: clientGrantList(source.clientGrants || source.client_grants, customer),
    fileRefs: refList(source.fileRefs || source.filesSelected),
    folderRefs: refList(source.folderRefs || source.foldersSelected)
  };
}

function clearanceIsSet(clearance) {
  if (!clearance) return false;
  if (clearance.jobs !== 'none' || clearance.files !== 'none' || clearance.folders !== 'none') return true;
  return clearance.jobIds.length > 0 || (clearance.clientGrants || []).length > 0 || clearance.fileRefs.length > 0 || clearance.folderRefs.length > 0;
}

async function findCompanyByName(pool, name) {
  const companyName = clean(name, 160);
  if (!companyName) return null;
  const found = await pool.query(
    `SELECT id, name FROM companies WHERE lower(btrim(name)) = lower(btrim($1)) LIMIT 1`,
    [companyName]
  );
  return found.rows[0] || null;
}

async function assignMatchedCompany(pool, userId, companyId, roleKey) {
  const id = clean(userId, 80);
  const company = clean(companyId, 80);
  const role = normalizeCompanyRole(roleKey, 'customer');
  if (!id || !company) return;
  await pool.query(
    `INSERT INTO user_company_membership (user_id, company_id, role_key, override_folder_grants)
     VALUES ($1, $2, $3, '[]'::jsonb)
     ON CONFLICT (user_id)
     DO UPDATE SET company_id = EXCLUDED.company_id, role_key = EXCLUDED.role_key, updated_at = NOW()`,
    [id, company, role]
  );
}

/**
 * Apply a typed company only when that company already exists.
 * @returns {Promise<{ matched: boolean, message: string, companyName: string }>}
 */
async function matchExistingCompany(pool, userId, companyName, roleKey) {
  const typed = clean(companyName, 160);
  if (!typed) {
    return { matched: false, message: '', companyName: '' };
  }
  const company = await findCompanyByName(pool, typed);
  if (!company) {
    return {
      matched: false,
      message: 'No company matches that name. An admin will assign your company.',
      companyName: typed
    };
  }
  await assignMatchedCompany(pool, userId, company.id, roleKey);
  return { matched: true, message: '', companyName: company.name };
}

async function readClearance(pool, userId) {
  try {
    const found = await pool.query(
      `SELECT access_clearance, account_type FROM users WHERE CAST(id AS text) = $1 LIMIT 1`,
      [clean(userId, 80)]
    );
    const row = found.rows[0];
    if (!row) return null;
    const clearance = normalizeClearance(row.access_clearance, row.account_type);
    return { accountType: row.account_type || 'employee', clearance, configured: clearanceIsSet(clearance) };
  } catch (error) {
    if (error && error.code === '42703') return { accountType: 'employee', clearance: normalizeClearance(null, 'employee'), configured: false };
    throw error;
  }
}

async function writeClearance(pool, userId, accountType, raw) {
  const clearance = normalizeClearance(raw, accountType);
  await pool.query(
    `UPDATE users SET access_clearance = $2::jsonb, updated_at = NOW() WHERE CAST(id AS text) = $1`,
    [clean(userId, 80), JSON.stringify(clearance)]
  );
  return clearance;
}

function normName(value) {
  return String(value || '').trim().toLowerCase().replace(/\s+/g, ' ');
}

function companyJobs(data, companyName) {
  const want = normName(companyName);
  if (!want) return [];
  return (data.jobs || []).filter((job) => {
    const client = (data.clients || []).find((row) => row.id === job.clientId);
    return client && normName(client.name) === want;
  });
}

function jobsForCustomer(data, companyName, clearance) {
  const grants = Array.isArray(clearance.clientGrants) ? clearance.clientGrants : [];
  if (!grants.length && (clearance.jobs === 'full' || clearance.jobs === 'view')) {
    return companyJobs(data, companyName);
  }
  const openClients = new Set(grants.filter((row) => row.mode === 'full' || row.mode === 'view').map((row) => row.clientId));
  const ids = new Set(clearance.jobIds);
  for (const ref of [...clearance.fileRefs, ...clearance.folderRefs]) {
    if (ref.jobId) ids.add(ref.jobId);
  }
  if (!openClients.size && clearance.jobs !== 'select' && !clearance.fileRefs.length && !clearance.folderRefs.length) return [];
  return (data.jobs || []).filter((job) => ids.has(job.id) || openClients.has(clientKeyOf(job)));
}

function planAllowed(job, pdf, clearance) {
  const filesOpen = clearance.files === 'full' || clearance.files === 'view';
  const foldersOpen = clearance.folders === 'full' || clearance.folders === 'view';
  if (filesOpen || foldersOpen || (clearance.files === 'none' && clearance.folders === 'none')) return true;
  const name = normName(pdf?.name || pdf?.path || '');
  const path = normName(pdf?.path || pdf?.name || '');
  if (clearance.files === 'select') {
    const hit = clearance.fileRefs.some((ref) => {
      if (ref.jobId && ref.jobId !== job.id) return false;
      const want = normName(ref.path || ref.name);
      return want && (want === name || want === path || path.endsWith(want) || name.endsWith(want));
    });
    if (hit) return true;
  }
  if (clearance.folders === 'select') {
    return clearance.folderRefs.some((ref) => {
      if (ref.jobId && ref.jobId !== job.id) return false;
      const want = normName(ref.path);
      return want && (path.startsWith(want) || name.startsWith(want) || !path);
    });
  }
  return false;
}

function presentCustomerAccess(clearance) {
  return {
    jobs: clearance.jobs,
    files: clearance.files,
    folders: clearance.folders,
    canDownloadReport: clearance.jobs !== 'view',
    canDownloadFiles: clearance.files !== 'view' && clearance.folders !== 'view',
    clientGrants: clearance.clientGrants || [],
    jobPlans: 'view',
    fileRefs: clearance.fileRefs,
    folderRefs: clearance.folderRefs
  };
}

module.exports = {
  COMPANY_ROLE_LABELS,
  normalizeCompanyRole,
  roleLabel,
  normalizeClearance,
  clearanceIsSet,
  findCompanyByName,
  assignMatchedCompany,
  matchExistingCompany,
  readClearance,
  writeClearance,
  jobsForCustomer,
  planAllowed,
  presentCustomerAccess
};

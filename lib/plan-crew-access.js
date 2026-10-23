'use strict';

const { isAdminUser, isSaasWorkspaceOwner, deriveAccountModel, ACCOUNT_TYPES } = require('../capabilities');
const { loadUserCompanyMembership } = require('../company-permissions.service');
const { tenantKey, loadBundle } = require('./job-schedule-store');

const accessCache = new Map();

function usernameOf(user) {
  return String(user?.username || user?.displayName || '').trim();
}

function isCustomer(user) {
  return deriveAccountModel(user || {}).accountType === ACCOUNT_TYPES.CUSTOMER;
}

/** People who already administer the plan library. Customers are never in this set. */
function administersPlans(user) {
  if (!user || isCustomer(user)) return false;
  if (isAdminUser(user) || isSaasWorkspaceOwner(user)) return true;
  const roles = user.roles && typeof user.roles === 'object' ? user.roles : {};
  return roles.psrPlanner === true || roles.psrDataEntry === true;
}

function crewRuleOn(doc, access) {
  if (!doc || typeof doc !== 'object') return false;
  if (access?.companyOn) return true;
  return doc.crewProvision === true;
}

function userCanSeePlanDoc(doc, access) {
  if (!crewRuleOn(doc, access)) return true;
  if (access?.customer) return false;
  if (access?.admin) return true;
  const uploaded = String(doc?.uploadedBy || '').trim().toLowerCase();
  if (uploaded && access?.username && uploaded === access.username) return true;
  const jobId = String(doc?.jobId || '').trim();
  if (jobId && access?.assignedJobIds?.has(jobId)) return true;
  const id = String(doc?.id || '').trim();
  if (id && access?.linkedDocIds?.has(id)) return true;
  return false;
}

async function planAccessForRequest(pool, req) {
  const user = req?.user || {};
  const cacheKey = `${String(user.id || '')}:${usernameOf(user).toLowerCase()}`;
  const hit = accessCache.get(cacheKey);
  if (hit && Date.now() - hit.at < 20000) return hit.value;
  let companyOn = false;
  try {
    const membership = user.id ? await loadUserCompanyMembership(pool, user.id) : null;
    companyOn = membership?.appFeatures?.planCrewProvision === true;
  } catch (err) {
    console.warn('[plan-crew] company setting skipped:', err?.message || err);
  }
  const assignedJobIds = new Set();
  const linkedDocIds = new Set();
  if (!isCustomer(user) && !administersPlans(user)) {
    try {
      const bundle = await loadBundle(pool, user, tenantKey(user, req), { configured: false });
      if (bundle.role === 'crew') {
        for (const job of bundle.jobs || []) {
          const jobId = String(job?.id || '').trim();
          if (jobId) assignedJobIds.add(jobId);
          for (const pdf of job?.pdfs || []) {
            const docId = String(pdf?.legacyDocId || '').trim();
            if (docId) linkedDocIds.add(docId);
          }
        }
      }
    } catch (err) {
      console.warn('[plan-crew] schedule lookup skipped:', err?.message || err);
    }
  }
  const value = {
    companyOn,
    admin: administersPlans(user),
    customer: isCustomer(user),
    username: usernameOf(user).toLowerCase(),
    assignedJobIds,
    linkedDocIds
  };
  accessCache.set(cacheKey, { at: Date.now(), value });
  return value;
}

function boardOf(payload) {
  if (!payload || typeof payload !== 'object') return null;
  if (payload.pdfMap && typeof payload.pdfMap === 'object') return { key: 'pdfMap', board: payload.pdfMap };
  if (payload.pdfMapView && typeof payload.pdfMapView === 'object') return { key: 'pdfMapView', board: payload.pdfMapView };
  return null;
}

function restrictPlanViewPayload(payload, access) {
  if (!payload || typeof payload !== 'object' || !access) return payload;
  const found = boardOf(payload);
  if (!found) return payload;
  const docs = Array.isArray(found.board.legacyPlans) ? found.board.legacyPlans : [];
  const hidden = new Set();
  const visible = [];
  for (const doc of docs) {
    if (userCanSeePlanDoc(doc, access)) visible.push(doc);
    else {
      const id = String(doc?.id || '').trim();
      if (id) hidden.add(id);
    }
  }
  if (!hidden.size) return payload;
  const board = { ...found.board, legacyPlans: visible };
  if (Array.isArray(board.mapWorkspaces)) {
    board.mapWorkspaces = board.mapWorkspaces.filter((ws) => {
      const id = String(ws?.sourceDocId || '').trim();
      return !id || !hidden.has(id);
    });
  }
  if (Array.isArray(board.pages)) {
    board.pages = board.pages.filter((page) => {
      const id = String(page?.sourceDocId || '').trim();
      return !id || !hidden.has(id);
    });
  }
  return { ...payload, [found.key]: board };
}

function docOwnsStorageKey(doc, storageKey) {
  const want = String(storageKey || '').trim();
  if (!want || !doc) return false;
  if (String(doc.storageKey || '').trim() === want) return true;
  if (String(doc.archiveStorageKey || '').trim() === want) return true;
  for (const piece of Array.isArray(doc.pieces) ? doc.pieces : []) {
    if (String(piece?.storageKey || '').trim() === want) return true;
    if (String(piece?.archiveStorageKey || '').trim() === want) return true;
  }
  const versions = doc.pdfVersions;
  if (versions && typeof versions === 'object') {
    if (String(versions.mergedStorageKey || '').trim() === want) return true;
    for (const copy of Array.isArray(versions.copies) ? versions.copies : []) {
      if (String(copy?.storageKey || '').trim() === want) return true;
    }
  }
  return false;
}

function userMayReadPlanStorageKey(payload, access, storageKey) {
  const found = boardOf(payload);
  const docs = found && Array.isArray(found.board.legacyPlans) ? found.board.legacyPlans : [];
  const owners = docs.filter((doc) => docOwnsStorageKey(doc, storageKey));
  if (!owners.length) return true;
  return owners.some((doc) => userCanSeePlanDoc(doc, access));
}

module.exports = {
  planAccessForRequest,
  restrictPlanViewPayload,
  userMayReadPlanStorageKey,
  userCanSeePlanDoc
};

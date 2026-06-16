'use strict';

/** Strip trailing `#2`, `#3`, … suffix from a WinCan reference for duplicate allocation. */
function stripDb3ReferenceSuffix(reference) {
  const s = String(reference || '').trim();
  const match = s.match(/^(.*?)(#\d+)$/);
  return match ? match[1].trim() : s;
}

/**
 * Pick the next available reference when importing a same-jobsite duplicate with Include.
 * @param {string} reference incoming OBJ_Key / reference
 * @param {Set<string>} usedRefLowers lowercased references already on the target jobsite
 */
function nextDb3DuplicateReference(reference, usedRefLowers) {
  const base = stripDb3ReferenceSuffix(reference);
  if (!base) return reference;
  const used = usedRefLowers instanceof Set ? usedRefLowers : new Set();
  if (!used.has(base.toLowerCase())) return base;
  let n = 2;
  while (used.has(`${base}#${n}`.toLowerCase())) n += 1;
  return `${base}#${n}`;
}

function isDb3DuplicateIncludeDecision(row) {
  return String(row?.duplicateDecision || '').trim().toLowerCase() === 'include';
}

function isDb3DuplicateExcludeDecision(row) {
  const decision = String(row?.duplicateDecision || 'exclude').trim().toLowerCase();
  return decision !== 'include';
}

function rowHasJobsiteDuplicateFlag(row) {
  return !!(row && (row.duplicate || row.placedDuplicate || row.placedDuplicateOf));
}

module.exports = {
  stripDb3ReferenceSuffix,
  nextDb3DuplicateReference,
  isDb3DuplicateIncludeDecision,
  isDb3DuplicateExcludeDecision,
  rowHasJobsiteDuplicateFlag
};

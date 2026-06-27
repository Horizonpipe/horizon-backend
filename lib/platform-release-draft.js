'use strict';

const fs = require('fs');
const path = require('path');

const DRAFT_FILENAME = 'platform-release-draft.json';

function draftFilePath() {
  const fromEnv = String(process.env.HP_RELEASE_DRAFT_PATH || '').trim();
  if (fromEnv) return path.resolve(fromEnv);
  return path.resolve(__dirname, '..', DRAFT_FILENAME);
}

function normalizeDraft(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const title = String(raw.title || '').trim();
  const description = String(raw.description || '').trim();
  const changeLog = Array.isArray(raw.changeLog)
    ? raw.changeLog.map((item) => String(item || '').trim()).filter(Boolean)
    : [];
  if (!title && !description && !changeLog.length) return null;
  return { title, description, changeLog, updatedAt: String(raw.updatedAt || '').trim() || new Date().toISOString() };
}

function loadPlatformReleaseDraft() {
  try {
    const file = draftFilePath();
    if (!fs.existsSync(file)) return null;
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    return normalizeDraft(parsed);
  } catch {
    return null;
  }
}

function savePlatformReleaseDraft(draft) {
  const normalized = normalizeDraft(draft);
  if (!normalized) return null;
  normalized.updatedAt = new Date().toISOString();
  const file = draftFilePath();
  fs.writeFileSync(file, JSON.stringify(normalized, null, 2), 'utf8');
  return normalized;
}

function clearPlatformReleaseDraft() {
  try {
    const file = draftFilePath();
    if (fs.existsSync(file)) fs.unlinkSync(file);
  } catch {
    /* ignore */
  }
}

module.exports = {
  DRAFT_FILENAME,
  draftFilePath,
  loadPlatformReleaseDraft,
  savePlatformReleaseDraft,
  clearPlatformReleaseDraft,
  normalizeDraft
};

'use strict';

/**
 * Shared with portal-api `share-helpers.js` — filter job trees for share payloads.
 */

function normalizeShareRelPath(p) {
  return String(p ?? '')
    .trim()
    .replace(/\\/g, '/')
    .split('/')
    .filter((s) => s && s !== '.' && s !== '..')
    .join('/');
}

function parentRelPath(rel) {
  const n = normalizeShareRelPath(rel);
  if (!n) return '';
  const i = n.lastIndexOf('/');
  return i === -1 ? '' : n.slice(0, i);
}

function filterTreeForSharePayload(tree, payload) {
  const folderPaths = Array.isArray(payload.folderPaths)
    ? payload.folderPaths.map((x) => normalizeShareRelPath(x))
    : [];
  const fileIdSet = new Set(
    Array.isArray(payload.fileIds) ? payload.fileIds.map((x) => String(x)) : []
  );

  const hasRootFolderGrant = folderPaths.some((p) => p === '');
  if (hasRootFolderGrant) {
    return {
      folders: Array.isArray(tree.folders) ? tree.folders : [],
      files: Array.isArray(tree.files) ? tree.files : []
    };
  }

  const keepFiles = new Set();
  for (const f of tree.files || []) {
    const rp = normalizeShareRelPath(f.path);
    const id = f.id != null ? String(f.id) : '';
    if (id && fileIdSet.has(id)) {
      keepFiles.add(rp);
      continue;
    }
    for (const fp of folderPaths) {
      const p = normalizeShareRelPath(fp);
      if (!p) {
        keepFiles.add(rp);
        break;
      }
      if (rp === p || rp.startsWith(`${p}/`)) {
        keepFiles.add(rp);
        break;
      }
    }
  }

  const files = (tree.files || []).filter((f) => keepFiles.has(normalizeShareRelPath(f.path)));
  const keepFolders = new Set();
  for (const f of files) {
    let p = normalizeShareRelPath(f.parentPath || '');
    while (p) {
      keepFolders.add(p);
      p = parentRelPath(p);
    }
  }
  for (const fp of folderPaths) {
    const p = normalizeShareRelPath(fp);
    if (!p) continue;
    let cur = p;
    while (cur) {
      keepFolders.add(cur);
      cur = parentRelPath(cur);
    }
  }
  const folders = (tree.folders || []).filter((fol) =>
    keepFolders.has(normalizeShareRelPath(fol.path))
  );
  return { folders, files };
}

function sharePayloadAllowsFile(fileRelPath, fileId, payload) {
  const rp = normalizeShareRelPath(fileRelPath);
  const id = String(fileId || '');
  const fileIds = Array.isArray(payload.fileIds) ? payload.fileIds.map(String) : [];
  if (id && fileIds.includes(id)) return true;
  const folderPaths = Array.isArray(payload.folderPaths)
    ? payload.folderPaths.map((x) => normalizeShareRelPath(x))
    : [];
  if (folderPaths.some((p) => p === '')) return true;
  for (const fp of folderPaths) {
    const p = normalizeShareRelPath(fp);
    if (!p) return true;
    if (rp === p || rp.startsWith(`${p}/`)) return true;
  }
  return false;
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function isValidEmail(email) {
  const s = String(email || '').trim();
  return s.length < 320 && EMAIL_RE.test(s);
}

module.exports = {
  filterTreeForSharePayload,
  sharePayloadAllowsFile,
  isValidEmail
};

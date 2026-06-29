'use strict';

const { PutObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');
const { SAAS_OWNER_ROLES } = require('./saas-tenant-owner');
const { buildTenantWasabiRoot } = require('./saas-tenant-paths');
const { saasWasabiBucket, getSaasWasabiClient } = require('./saas-virtualbox-config');

function authSnapshotKey(slug) {
  const root = buildTenantWasabiRoot(slug);
  return `${root}auth/latest.json`;
}

function emptyAuthSnapshot(slug, ownerUser) {
  const now = new Date().toISOString();
  const userId = ownerUser?.id != null ? String(ownerUser.id) : '';
  const email = String(ownerUser?.email || ownerUser?.username || '').trim().toLowerCase();
  const displayName = String(
    ownerUser?.displayName || ownerUser?.display_name || ownerUser?.username || email || 'Admin'
  ).trim();
  return {
    version: 1,
    kind: 'saas-tenant-auth',
    tenantSlug: slug,
    savedAt: now,
    data: {
      users: userId
        ? [
            {
              id: userId,
              username: email || displayName,
              email,
              displayName,
              isAdmin: false,
              accountType: 'employee',
              employeeRole: 'superadmin',
              self_signup: true,
              portalFilesAccessGranted: true,
              portalPermissionsAccess: true,
              roles: { ...SAAS_OWNER_ROLES }
            }
          ]
        : []
    }
  };
}

async function readAuthSnapshot(slug) {
  const client = getSaasWasabiClient();
  const bucket = saasWasabiBucket();
  if (!client || !bucket || !slug) return null;
  try {
    const out = await client.send(
      new GetObjectCommand({ Bucket: bucket, Key: authSnapshotKey(slug) })
    );
    const chunks = [];
    for await (const c of out.Body) chunks.push(c);
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch (_) {
    return null;
  }
}

async function writeAuthSnapshot(slug, snapshot) {
  const client = getSaasWasabiClient();
  const bucket = saasWasabiBucket();
  if (!client || !bucket || !slug) {
    return { ok: false, reason: 'wasabi_not_configured' };
  }
  const body = JSON.stringify(snapshot, null, 2);
  await client.send(
    new PutObjectCommand({
      Bucket: bucket,
      Key: authSnapshotKey(slug),
      Body: body,
      ContentType: 'application/json'
    })
  );
  return { ok: true, key: authSnapshotKey(slug) };
}

async function seedTenantAuthSnapshot(slug, ownerUser) {
  const existing = await readAuthSnapshot(slug);
  if (existing && Array.isArray(existing?.data?.users) && existing.data.users.length) {
    await upsertTenantOwnerAuthSnapshot(slug, ownerUser);
    return { ok: true, key: authSnapshotKey(slug), skipped: true, refreshedOwner: true };
  }
  const snapshot = emptyAuthSnapshot(slug, ownerUser);
  const result = await writeAuthSnapshot(slug, snapshot);
  return { ...result, skipped: false };
}

/** Ensure purchaser row in tenant auth snapshot reflects super-admin (fixes legacy seeds). */
async function upsertTenantOwnerAuthSnapshot(slug, ownerUser) {
  const userId = ownerUser?.id != null ? String(ownerUser.id) : '';
  if (!userId) return { ok: false, reason: 'missing_owner' };
  const email = String(ownerUser?.email || ownerUser?.username || '').trim().toLowerCase();
  const displayName = String(
    ownerUser?.displayName || ownerUser?.display_name || ownerUser?.username || email || 'Admin'
  ).trim();
  const ownerRow = {
    id: userId,
    username: email || displayName,
    email,
    displayName,
    isAdmin: false,
    accountType: 'employee',
    employeeRole: 'superadmin',
    self_signup: true,
    portalFilesAccessGranted: true,
    portalPermissionsAccess: true,
    roles: { ...SAAS_OWNER_ROLES }
  };
  const existing = (await readAuthSnapshot(slug)) || {
    version: 1,
    kind: 'saas-tenant-auth',
    tenantSlug: slug,
    savedAt: new Date().toISOString(),
    data: { users: [] }
  };
  const users = Array.isArray(existing?.data?.users) ? [...existing.data.users] : [];
  const idx = users.findIndex((u) => String(u?.id || '') === userId);
  if (idx >= 0) users[idx] = { ...users[idx], ...ownerRow };
  else users.unshift(ownerRow);
  const snapshot = {
    ...existing,
    tenantSlug: slug,
    savedAt: new Date().toISOString(),
    data: { ...(existing.data || {}), users }
  };
  return writeAuthSnapshot(slug, snapshot);
}

function normalizedAuthUserFromRow(userRow) {
  const userId = userRow?.id != null ? String(userRow.id) : '';
  if (!userId) return null;
  const email = String(userRow?.email || userRow?.username || '').trim().toLowerCase();
  const displayName = String(
    userRow?.displayName || userRow?.display_name || userRow?.username || email || 'User'
  ).trim();
  return {
    id: userId,
    username: email || displayName,
    email,
    displayName,
    isAdmin: userRow?.is_admin === true || userRow?.isAdmin === true,
    accountType: userRow?.account_type || userRow?.accountType || 'customer',
    employeeRole: userRow?.employee_role || userRow?.employeeRole || null,
    self_signup: userRow?.self_signup === true || userRow?.selfSignup === true,
    portalFilesAccessGranted:
      userRow?.portal_files_access_granted === true || userRow?.portalFilesAccessGranted === true,
    portalPermissionsAccess:
      userRow?.portal_permissions_access === true || userRow?.portalPermissionsAccess === true,
    roles:
      userRow?.roles && typeof userRow.roles === 'object' && !Array.isArray(userRow.roles)
        ? userRow.roles
        : {}
  };
}

async function upsertTenantAuthUserFromRow(slug, userRow) {
  const row = normalizedAuthUserFromRow(userRow);
  if (!row) return { ok: false, reason: 'missing_user' };
  const existing = (await readAuthSnapshot(slug)) || {
    version: 1,
    kind: 'saas-tenant-auth',
    tenantSlug: slug,
    savedAt: new Date().toISOString(),
    data: { users: [] }
  };
  const users = Array.isArray(existing?.data?.users) ? [...existing.data.users] : [];
  const idx = users.findIndex((u) => String(u?.id || '') === row.id);
  if (idx >= 0) users[idx] = { ...users[idx], ...row };
  else users.push(row);
  return writeAuthSnapshot(slug, {
    ...existing,
    tenantSlug: slug,
    savedAt: new Date().toISOString(),
    data: { ...(existing.data || {}), users }
  });
}

async function removeTenantAuthUser(slug, userId) {
  const uid = String(userId || '').trim();
  if (!uid) return { ok: false, reason: 'missing_user' };
  const existing = await readAuthSnapshot(slug);
  if (!existing || !Array.isArray(existing?.data?.users)) return { ok: true, skipped: true };
  const users = existing.data.users.filter((u) => String(u?.id || '') !== uid);
  return writeAuthSnapshot(slug, {
    ...existing,
    tenantSlug: slug,
    savedAt: new Date().toISOString(),
    data: { ...(existing.data || {}), users }
  });
}

module.exports = {
  authSnapshotKey,
  emptyAuthSnapshot,
  readAuthSnapshot,
  writeAuthSnapshot,
  seedTenantAuthSnapshot,
  upsertTenantOwnerAuthSnapshot,
  upsertTenantAuthUserFromRow,
  removeTenantAuthUser
};

# Horizon permissions & auth inventory (Phase 0)

This document maps authorization surfaces for the rebuild. Source: `server.js`, `portal-files.routes.js`, `signup.routes.js`, Wasabi env flags.

## Middleware primitives (`server.js`)

| Middleware | Meaning |
|-------------|---------|
| `requireAuth` | Valid session JWT; sets `req.user` |
| `requireAdmin` | `req.user.isAdmin === true` |
| `requireAdminOrPortalPermissionsAccess` | `isAdmin` OR `portalPermissionsAccess` (unified user/permissions admin) |
| `requireAnyRole(keys)` | Admin passes; else any `roles[key]` true |
| `requirePlannerAccess` | psrPlanner, psrViewer, psrDataEntry, camera, vac, simpleVac, pricingView, footageView |
| `requirePsrViewerAccess` | psrPlanner, psrViewer, psrDataEntry, camera, vac, simpleVac |
| `requirePsrDataEntryAccess` | psrPlanner, psrDataEntry, camera, vac |
| `requireDataAutoSyncEmployeeAccess` | dataAutoSyncEmployee |
| `requirePricingAccess` | admin or pricingView |
| `requireFootageAccess` | admin or footageView |
| `requireMike` | special importer paths |

## Routes → guard (representative)

- **User/permissions**: `GET /users` (auth; row shape filtered by admin or portal perms), `GET /permissions/tree`, `POST /create-user`, `PUT /users/:id`, `DELETE /users/:id` → `requireAdminOrPortalPermissionsAccess` where noted in code.
- **PSR records**: read `requirePsrViewerAccess`; write segments `requirePsrDataEntryAccess`; delete/move client/segment `requireAdmin`.
- **Pricing**: read `requirePricingAccess`; write `requireAdmin`.
- **Daily reports / jobsite assets write**: `requireAdmin`.
- **Wasabi admin**: `requireAdmin`.
- **DataAutoSync**: `GET /data-auto-sync/access`, `POST /auto-import-plugin/push` → `requireDataAutoSyncEmployeeAccess`.
- **Portal files**: `registerPortalFilesRoutes` uses `userIsPortalAdmin`, `assertPortalJobAccess`, `userCanManagePortalExtras` inside `portal-files.routes.js` (not `requireAdmin` on router).

## Postgres tables (scopes)

- `user_portal_scopes` — client/job pairs for portal
- `user_psr_scopes` — PSR client/city/jobsite (+ optional record id)
- `portal_path_grants` — per-folder/file path grants per job
- `users` — `is_admin`, `roles` jsonb, `portal_permissions_access`, `portal_files_*`, etc.

## Wasabi snapshot (high level)

Env-driven: `WASABI_WRITES_PRIMARY_ENABLED`, `WASABI_AUTH_PRIMARY_ENABLED`, `WASABI_SCOPES_PRIMARY_ENABLED`, etc. Snapshot tables include `users`, `user_portal_scopes`, `user_psr_scopes`, `portal_path_grants`, `auth_sessions` (see `ensureSnapshotTable` / `runWasabiStateWrite` in `server.js`).

## Frontend entrypoints

| Surface | Entry | Auth |
|---------|-------|------|
| PipeSync | `pipesync.html` / `mobile.html` | `login.html?product=pipesync` |
| PipeShare | `client-portal/index.html` | `login.html?product=pipeshare` |
| DataAutoSync | `data-auto-sync/` | `login.html?product=dataautosync` → role-based shell |
| Admin approvals (legacy) | `admin.html` | `login.html?product=admin` |
| Redirect stubs | `pipeshare-login.html`, `pipesync-login.html`, `admin-login.html`, `dataautosync-login.html` | meta refresh to `login.html` |

## Target consolidation (plan)

- **Capabilities** object on `/session` (`resolveCapabilities`).
- **Admin Panel** (users + permissions + requests) behind one capability in PipeSync and PipeShare.
- **Two login UX**: staff (PipeSync) vs client portal (PipeShare); legacy products redirect.

## Implemented module (`capabilities.js`)

- `resolveCapabilities(user)` → `version`, `superAdmin`, `canAccessAdminPanel`, `canManagePortalExtras`, feature flags from `roles`.
- `canAccessAdminPanel` drives `requireAdminPanelAccess` (user CRUD + permission tree).
- `canManagePortalExtras` includes global super-admin so portal file ACLs match Admin Panel expectations.
- `GET /session`, `POST /login` include `capabilities`; portal-files uses `canManagePortalExtras` via shared helper.

See [QA_PERMISSIONS_MATRIX.md](./QA_PERMISSIONS_MATRIX.md) for regression checks.

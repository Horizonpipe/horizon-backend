# QA checklist — permissions & auth rebuild

Run after each deploy. `capabilities` on `GET /session` and `POST /login` should match DB flags.

## Roles to test

1. **Super admin** (`is_admin` true): PipeSync Admin Panel, destructive PSR routes, Wasabi admin, portal file ACLs, legacy `admin.html`.
2. **Portal admin only** (`portal_permissions_access` true, not global admin): Admin Panel user routes, `GET /permissions/tree`, portal extras; must not elevate `is_admin` via UI.
3. **PSR planner only**: Planner + scoped records; no Admin Panel.
4. **Client portal user**: File access only within scopes; no Admin Panel.
5. **DataAutoSync employee**: `intent=dataautosync` login lands in `data-auto-sync/`; health endpoints OK.

## Session

- [ ] `GET /session` returns `capabilities` with `version: 1`.
- [ ] Revoke role in DB → next `/session` reflects change (or token invalidated per existing logic).

## PipeSync

- [ ] Single **Admin Panel** button opens unified modal (pending accounts + full permissions).
- [ ] Save permissions → success toast → refresh shows same state.

## PipeShare (client-portal)

- [ ] Admin Panel visible when `capabilities.canAccessAdminPanel` or legacy flags.
- [ ] Path grant / folder tools respect `canManagePortalExtras` (includes global admin).

## Login URLs

- [ ] `login.html?product=pipeshare` → client portal after sign-in.
- [ ] `login.html?product=pipesync` → PipeSync after sign-in.
- [ ] `login.html?product=pipesync&intent=dataautosync` → DataAutoSync shell when appropriate.
- [ ] `admin-login.html` and legacy `?product=admin` bookmarks redirect to PipeSync login.

## Wasabi (if enabled in env)

- [ ] No auth decision from stale snapshot alone; Postgres refresh path still applies for sessions.

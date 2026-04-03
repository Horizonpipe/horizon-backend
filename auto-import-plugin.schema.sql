-- Auto Importing Plugin schema
-- Safe to run alongside the current Horizon tracker database.

CREATE TABLE IF NOT EXISTS auto_import_projects (
  id TEXT PRIMARY KEY,
  source_key TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  db3_path TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'idle',
  detection_mode TEXT NOT NULL DEFAULT 'auto',
  detected_job_client TEXT DEFAULT '',
  detected_job_city TEXT DEFAULT '',
  detected_jobsite TEXT DEFAULT '',
  last_seen_at TIMESTAMPTZ,
  last_scan_at TIMESTAMPTZ,
  last_switch_at TIMESTAMPTZ,
  last_error TEXT DEFAULT '',
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS auto_import_runs (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES auto_import_projects(id) ON DELETE CASCADE,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  active_db3_path TEXT NOT NULL,
  switch_reason TEXT DEFAULT '',
  rows_found INTEGER NOT NULL DEFAULT 0,
  rows_changed INTEGER NOT NULL DEFAULT 0,
  rows_inserted INTEGER NOT NULL DEFAULT 0,
  rows_updated INTEGER NOT NULL DEFAULT 0,
  notes TEXT DEFAULT '',
  payload JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS auto_import_row_cache (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES auto_import_projects(id) ON DELETE CASCADE,
  row_key TEXT NOT NULL,
  row_hash TEXT NOT NULL,
  system_type TEXT NOT NULL DEFAULT 'storm',
  reference TEXT NOT NULL,
  upstream TEXT DEFAULT '',
  downstream TEXT DEFAULT '',
  dia TEXT DEFAULT '',
  material TEXT DEFAULT '',
  length NUMERIC(12,3) DEFAULT 0,
  footage NUMERIC(12,3) DEFAULT 0,
  source_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(project_id, row_key)
);

CREATE TABLE IF NOT EXISTS auto_import_bindings (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES auto_import_projects(id) ON DELETE CASCADE,
  client TEXT NOT NULL,
  city TEXT NOT NULL,
  jobsite TEXT NOT NULL,
  system_type TEXT NOT NULL DEFAULT 'storm',
  pinned BOOLEAN NOT NULL DEFAULT FALSE,
  created_by TEXT DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(project_id)
);

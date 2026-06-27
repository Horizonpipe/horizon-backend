'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile, spawn } = require('child_process');
const { promisify } = require('util');

const { createMetricsStore } = require('./ovh-ops-metrics-store');

const execFileAsync = promisify(execFile);

const metricsStore = createMetricsStore();

const REPO_ROOT = process.env.HP_REPO_ROOT || '/opt/horizon';
const BACKEND_DIR = process.env.HP_BACKEND_DIR || path.join(REPO_ROOT, 'horizon-backend');
const FRONTEND_DIR = process.env.HP_FRONTEND_DIR || path.join(REPO_ROOT, 'horizon-frontend');
const EVENTS_PATH =
  process.env.HP_OVH_OPS_EVENTS ||
  (process.platform === 'win32'
    ? path.join(os.tmpdir(), 'horizon-ops-events.jsonl')
    : '/var/log/horizon/ops-events.jsonl');
const METRICS_INTERVAL_MS = Math.max(3000, Number(process.env.HP_OVH_OPS_METRICS_MS) || 5000);
const METRICS_HISTORY_MAX = Math.max(60, Number(process.env.HP_OVH_OPS_HISTORY_MAX) || 360);
const PM2_NAME = process.env.HP_PM2_APP_NAME || 'horizon-backend';
const NGINX_ERROR_LOG = process.env.HP_NGINX_ERROR_LOG || '/var/log/nginx/horizon-error.log';

/** @type {{ t: number, cpuPct: number, memUsedPct: number, memUsedGb: number, memTotalGb: number, diskUsedPct: number, netRxMbps: number, netTxMbps: number }[]} */
let metricsHistory = [];
let lastCpuSample = null;
let lastNetSample = null;
let collectorTimer = null;
/** @type {null | { id: string, startedAt: string, type: string, status: string, log: string[] }} */
let activeJob = null;

function isOvhOpsEnabled() {
  if (process.env.HP_OVH_OPS_ENABLED === '0') return false;
  if (process.env.HP_OVH_OPS_ENABLED === '1') return true;
  return process.platform === 'linux' && fs.existsSync(REPO_ROOT);
}

function ensureEventsDir() {
  try {
    fs.mkdirSync(path.dirname(EVENTS_PATH), { recursive: true });
  } catch {
    /* ignore */
  }
}

function appendEvent(type, message, meta = {}) {
  ensureEventsDir();
  const row = {
    id: crypto.randomUUID(),
    at: new Date().toISOString(),
    type: String(type || 'info'),
    message: String(message || ''),
    meta: meta && typeof meta === 'object' ? meta : {}
  };
  try {
    fs.appendFileSync(EVENTS_PATH, `${JSON.stringify(row)}\n`, 'utf8');
  } catch (err) {
    console.warn('[ovh-ops] event log write failed:', err?.message || err);
  }
  return row;
}

function readEvents(limit = 100) {
  ensureEventsDir();
  if (!fs.existsSync(EVENTS_PATH)) return [];
  try {
    const lines = fs.readFileSync(EVENTS_PATH, 'utf8').trim().split('\n').filter(Boolean);
    return lines
      .slice(-limit)
      .map((line) => {
        try {
          return JSON.parse(line);
        } catch {
          return null;
        }
      })
      .filter(Boolean)
      .reverse();
  } catch {
    return [];
  }
}

async function readCpuUsagePct() {
  if (process.platform === 'win32') {
    const load = os.loadavg()[0] || 0;
    const cores = os.cpus().length || 1;
    return Math.min(100, Math.round((load / cores) * 100));
  }
  const raw = await fs.promises.readFile('/proc/stat', 'utf8');
  const line = raw.split('\n')[0];
  const parts = line.split(/\s+/).slice(1).map(Number);
  const idle = parts[3] + (parts[4] || 0);
  const total = parts.reduce((a, b) => a + b, 0);
  const sample = { idle, total, t: Date.now() };
  if (!lastCpuSample) {
    lastCpuSample = sample;
    return 0;
  }
  const idleDelta = sample.idle - lastCpuSample.idle;
  const totalDelta = sample.total - lastCpuSample.total;
  lastCpuSample = sample;
  if (totalDelta <= 0) return 0;
  return Math.round(Math.max(0, Math.min(100, ((totalDelta - idleDelta) / totalDelta) * 100)));
}

async function readNetworkRatesMbps() {
  if (process.platform === 'win32') {
    return { rxMbps: 0, txMbps: 0, rxTotalGb: 0, txTotalGb: 0 };
  }
  const raw = await fs.promises.readFile('/proc/net/dev', 'utf8');
  let rx = 0;
  let tx = 0;
  for (const line of raw.split('\n').slice(2)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('lo:')) continue;
    const parts = trimmed.split(/\s+/);
    const nums = parts.slice(1).map(Number);
    if (nums.length >= 16) {
      rx += nums[0];
      tx += nums[8];
    }
  }
  const now = Date.now();
  const sample = { rx, tx, t: now };
  let rxMbps = 0;
  let txMbps = 0;
  let intervalRxBytes = 0;
  let intervalTxBytes = 0;
  if (lastNetSample) {
    const dt = (now - lastNetSample.t) / 1000;
    if (dt > 0) {
      intervalRxBytes = Math.max(0, rx - lastNetSample.rx);
      intervalTxBytes = Math.max(0, tx - lastNetSample.tx);
      rxMbps = Math.max(0, (intervalRxBytes * 8) / dt / 1e6);
      txMbps = Math.max(0, (intervalTxBytes * 8) / dt / 1e6);
    }
  }
  lastNetSample = sample;
  return {
    rxMbps: Math.round(rxMbps * 100) / 100,
    txMbps: Math.round(txMbps * 100) / 100,
    rxTotalGb: Math.round((rx / 1e9) * 100) / 100,
    txTotalGb: Math.round((tx / 1e9) * 100) / 100,
    intervalRxBytes,
    intervalTxBytes
  };
}

async function readDiskUsedPct() {
  if (process.platform === 'win32') return 0;
  try {
    const { stdout } = await execFileAsync('df', ['-P', '/'], { timeout: 5000 });
    const line = stdout.trim().split('\n')[1];
    if (!line) return 0;
    const pct = parseInt(String(line.split(/\s+/)[4] || '0').replace('%', ''), 10);
    return Number.isFinite(pct) ? pct : 0;
  } catch {
    return 0;
  }
}

async function collectMetricsSample() {
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;
  const [cpuPct, diskUsedPct, net] = await Promise.all([
    readCpuUsagePct(),
    readDiskUsedPct(),
    readNetworkRatesMbps()
  ]);
  const sample = {
    t: Date.now(),
    cpuPct,
    memUsedPct: totalMem ? Math.round((usedMem / totalMem) * 100) : 0,
    memUsedGb: Math.round((usedMem / 1e9) * 100) / 100,
    memTotalGb: Math.round((totalMem / 1e9) * 100) / 100,
    diskUsedPct,
    netRxMbps: net.rxMbps,
    netTxMbps: net.txMbps,
    netRxTotalGb: net.rxTotalGb,
    netTxTotalGb: net.txTotalGb
  };
  try {
    metricsStore.appendSample(sample, {
      rx: net.intervalRxBytes || 0,
      tx: net.intervalTxBytes || 0
    });
  } catch (err) {
    console.warn('[ovh-ops] metrics persist failed:', err?.message || err);
  }
  metricsHistory.push(sample);
  if (metricsHistory.length > METRICS_HISTORY_MAX) {
    metricsHistory = metricsHistory.slice(-METRICS_HISTORY_MAX);
  }
  return sample;
}

function startMetricsCollector() {
  if (collectorTimer || !isOvhOpsEnabled()) return;
  try {
    metricsHistory = metricsStore.loadRecentToMemory(METRICS_HISTORY_MAX);
  } catch {
    metricsHistory = [];
  }
  void collectMetricsSample().catch(() => {});
  collectorTimer = setInterval(() => {
    void collectMetricsSample().catch(() => {});
  }, METRICS_INTERVAL_MS);
  if (typeof collectorTimer.unref === 'function') collectorTimer.unref();
}

async function getPm2Summary() {
  if (process.platform === 'win32') {
    return { online: 0, processes: [], note: 'PM2 metrics available on OVH Linux host only' };
  }
  try {
    const { stdout } = await execFileAsync('pm2', ['jlist'], { timeout: 8000, maxBuffer: 4 * 1024 * 1024 });
    const list = JSON.parse(stdout);
    const processes = (Array.isArray(list) ? list : []).map((p) => ({
      name: p.name,
      status: p.pm2_env?.status,
      cpu: p.monit?.cpu,
      memoryMb: p.monit?.memory ? Math.round(p.monit.memory / 1e6) : 0,
      restarts: p.pm2_env?.restart_time,
      uptimeMs: p.pm2_env?.pm_uptime ? Date.now() - p.pm2_env.pm_uptime : 0
    }));
    const online = processes.filter((p) => p.status === 'online').length;
    return { online, processes };
  } catch (err) {
    return { online: 0, processes: [], error: err?.message || String(err) };
  }
}

async function gitRepoStatus(dir) {
  if (!fs.existsSync(path.join(dir, '.git'))) {
    return { dir, ok: false, error: 'not a git repo' };
  }
  try {
    const branch = (
      await execFileAsync('git', ['rev-parse', '--abbrev-ref', 'HEAD'], { cwd: dir, timeout: 5000 })
    ).stdout.trim();
    const hash = (
      await execFileAsync('git', ['rev-parse', '--short', 'HEAD'], { cwd: dir, timeout: 5000 })
    ).stdout.trim();
    const subject = (
      await execFileAsync('git', ['log', '-1', '--format=%s'], { cwd: dir, timeout: 5000 })
    ).stdout.trim();
    const dirty = (
      await execFileAsync('git', ['status', '--porcelain'], { cwd: dir, timeout: 5000 })
    ).stdout.trim();
    return {
      dir,
      ok: true,
      branch,
      hash,
      subject,
      dirty: !!dirty
    };
  } catch (err) {
    return { dir, ok: false, error: err?.message || String(err) };
  }
}

async function getOverview() {
  const latest =
    metricsHistory.length > 0 ? metricsHistory[metricsHistory.length - 1] : await collectMetricsSample();
  const [pm2, backend, frontend] = await Promise.all([
    getPm2Summary(),
    gitRepoStatus(BACKEND_DIR),
    gitRepoStatus(FRONTEND_DIR)
  ]);
  return {
    enabled: isOvhOpsEnabled(),
    host: os.hostname(),
    platform: `${os.platform()} ${os.release()}`,
    uptimeSec: Math.round(os.uptime()),
    metrics: latest,
    metricsMeta: metricsStore.getMetaSummary(),
    pm2,
    repos: { backend, frontend },
    activeJob,
    eventsPath: EVENTS_PATH
  };
}

function tailFile(filePath, lines = 200) {
  if (!filePath || !fs.existsSync(filePath)) {
    return { path: filePath, lines: [], error: 'log file not found' };
  }
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    const rows = raw.split('\n').filter((l) => l.length > 0);
    return { path: filePath, lines: rows.slice(-lines) };
  } catch (err) {
    return { path: filePath, lines: [], error: err?.message || String(err) };
  }
}

async function resolveLogPath(source) {
  const key = String(source || '').trim().toLowerCase();
  if (key === 'nginx' || key === 'nginx-error') {
    return NGINX_ERROR_LOG;
  }
  if (process.platform === 'win32') {
    return null;
  }
  const home = process.env.HOME || '/home/ubuntu';
  if (key === 'pm2-out' || key === 'out') {
    return path.join(home, '.pm2/logs', `${PM2_NAME}-out.log`);
  }
  if (key === 'pm2-err' || key === 'err') {
    return path.join(home, '.pm2/logs', `${PM2_NAME}-error.log`);
  }
  return path.join(home, '.pm2/logs', `${PM2_NAME}-out.log`);
}

function runShellScript(scriptPath, args = [], label = 'job') {
  return new Promise((resolve, reject) => {
    const jobId = crypto.randomUUID();
    const log = [];
    activeJob = {
      id: jobId,
      startedAt: new Date().toISOString(),
      type: label,
      status: 'running',
      log
    };
    const child = spawn('bash', [scriptPath, ...args], {
      cwd: BACKEND_DIR,
      env: { ...process.env, HP_REPO_ROOT: REPO_ROOT }
    });
    child.stdout.on('data', (buf) => {
      const text = String(buf);
      log.push(...text.split('\n').filter(Boolean));
      if (log.length > 500) log.splice(0, log.length - 500);
    });
    child.stderr.on('data', (buf) => {
      const text = String(buf);
      log.push(...text.split('\n').filter(Boolean));
      if (log.length > 500) log.splice(0, log.length - 500);
    });
    child.on('error', (err) => {
      activeJob = { ...activeJob, status: 'failed', error: err.message };
      reject(err);
    });
    child.on('close', (code) => {
      activeJob = { ...activeJob, status: code === 0 ? 'success' : 'failed', exitCode: code };
      if (code === 0) resolve({ jobId, exitCode: code, log: [...log] });
      else reject(new Error(`${label} failed (exit ${code})`));
    });
  });
}

async function deployFromGitHub(reason = 'manual') {
  const script = path.join(BACKEND_DIR, 'deploy/ovh/github-deploy.sh');
  if (!fs.existsSync(script)) {
    throw new Error(`Deploy script missing: ${script}`);
  }
  appendEvent('deploy.start', `Deploy started (${reason})`, { reason });
  try {
    const result = await runShellScript(script, [], 'deploy');
    appendEvent('deploy.success', 'Deploy finished successfully', { reason, jobId: result.jobId });
    return result;
  } catch (err) {
    appendEvent('deploy.failed', err?.message || 'Deploy failed', { reason });
    throw err;
  } finally {
    setTimeout(() => {
      if (activeJob && activeJob.status !== 'running') activeJob = null;
    }, 15000);
  }
}

async function rollbackRepos(target, ref) {
  const script = path.join(BACKEND_DIR, 'deploy/ovh/rollback-main.sh');
  if (!fs.existsSync(script)) {
    throw new Error(`Rollback script missing: ${script}`);
  }
  appendEvent('rollback.start', `Rollback ${target} → ${ref}`, { target, ref });
  try {
    const result = await runShellScript(script, [target, ref], 'rollback');
    appendEvent('rollback.success', `Rollback complete (${target} → ${ref})`, { target, ref });
    return result;
  } catch (err) {
    appendEvent('rollback.failed', err?.message || 'Rollback failed', { target, ref });
    throw err;
  } finally {
    setTimeout(() => {
      if (activeJob && activeJob.status !== 'running') activeJob = null;
    }, 15000);
  }
}

function verifyGithubSignature(rawBody, signatureHeader, secret) {
  if (!secret) return false;
  const sig = String(signatureHeader || '').trim();
  if (!sig.startsWith('sha256=')) return false;
  const expected = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
  const got = sig.slice('sha256='.length);
  try {
    return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(got, 'hex'));
  } catch {
    return false;
  }
}

function shouldDeployGithubPush(payload) {
  const ref = String(payload?.ref || '');
  const branch = process.env.HP_OVH_DEPLOY_BRANCH || 'refs/heads/main';
  if (ref !== branch) return false;
  if (payload?.deleted) return false;
  const repo = String(payload?.repository?.full_name || '').toLowerCase();
  const allowed = (process.env.HP_OVH_DEPLOY_REPOS || 'horizonpipe/horizon-frontend,horizonpipe/horizon-backend')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  return allowed.includes(repo);
}

module.exports = {
  isOvhOpsEnabled,
  startMetricsCollector,
  getOverview,
  getMetricsHistory: () => metricsHistory.slice(),
  queryMetricsHistory: (opts) => metricsStore.queryMetrics(opts),
  getMetricsMeta: () => metricsStore.getMetaSummary(),
  listMetricsDates: (opts) => metricsStore.listAvailableDates(opts),
  readEvents,
  appendEvent,
  tailFile,
  resolveLogPath,
  deployFromGitHub,
  rollbackRepos,
  verifyGithubSignature,
  shouldDeployGithubPush,
  getActiveJob: () => activeJob,
  REPO_ROOT,
  BACKEND_DIR,
  FRONTEND_DIR
};

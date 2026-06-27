'use strict';

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const ONE_YEAR_MS = 365 * 24 * 60 * 60 * 1000;
const ONE_DAY_MS = 24 * 60 * 60 * 1000;

function pad2(n) {
  return String(n).padStart(2, '0');
}

function utcDayKey(ts) {
  const d = new Date(ts);
  return `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())}`;
}

function parseDayKey(key) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(key || ''));
  if (!m) return null;
  return Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
}

function createMetricsStore(options = {}) {
  const metricsDir =
    options.metricsDir ||
    process.env.HP_OVH_OPS_METRICS_DIR ||
    (process.platform === 'win32'
      ? path.join(require('os').tmpdir(), 'horizon-metrics')
      : '/var/log/horizon/metrics');
  const dailyDir = path.join(metricsDir, 'daily');
  const archiveDir = path.join(metricsDir, 'archive');
  const metaPath = path.join(metricsDir, 'meta.json');

  function ensureDirs() {
    fs.mkdirSync(dailyDir, { recursive: true });
    fs.mkdirSync(archiveDir, { recursive: true });
  }

  function readMeta() {
    ensureDirs();
    if (!fs.existsSync(metaPath)) {
      return {
        bandwidthTotalBytes: 0,
        periodStartMs: Date.now(),
        oldestSampleMs: null,
        archivedYears: []
      };
    }
    try {
      return { ...JSON.parse(fs.readFileSync(metaPath, 'utf8')) };
    } catch {
      return {
        bandwidthTotalBytes: 0,
        periodStartMs: Date.now(),
        oldestSampleMs: null,
        archivedYears: []
      };
    }
  }

  function writeMeta(meta) {
    ensureDirs();
    fs.writeFileSync(metaPath, `${JSON.stringify(meta, null, 0)}\n`, 'utf8');
  }

  function compactSample(sample, intervalBytes = {}) {
    return {
      t: sample.t,
      c: sample.cpuPct,
      m: sample.memUsedPct,
      mg: sample.memUsedGb,
      mt: sample.memTotalGb,
      d: sample.diskUsedPct,
      rx: sample.netRxMbps,
      tx: sample.netTxMbps,
      br: intervalBytes.rx || 0,
      bt: intervalBytes.tx || 0
    };
  }

  function expandSample(row) {
    return {
      t: row.t,
      cpuPct: row.c ?? row.cpuPct ?? 0,
      memUsedPct: row.m ?? row.memUsedPct ?? 0,
      memUsedGb: row.mg ?? row.memUsedGb ?? 0,
      memTotalGb: row.mt ?? row.memTotalGb ?? 0,
      diskUsedPct: row.d ?? row.diskUsedPct ?? 0,
      netRxMbps: row.rx ?? row.netRxMbps ?? 0,
      netTxMbps: row.tx ?? row.netTxMbps ?? 0,
      netBytesRx: row.br ?? 0,
      netBytesTx: row.bt ?? 0
    };
  }

  function readJsonlFile(filePath) {
    if (!fs.existsSync(filePath)) return [];
    const raw = fs.readFileSync(filePath, 'utf8');
    return raw
      .split('\n')
      .filter(Boolean)
      .map((line) => {
        try {
          return expandSample(JSON.parse(line));
        } catch {
          return null;
        }
      })
      .filter(Boolean);
  }

  function readGzJsonl(filePath) {
    if (!fs.existsSync(filePath)) return [];
    try {
      const raw = zlib.gunzipSync(fs.readFileSync(filePath)).toString('utf8');
      return raw
        .split('\n')
        .filter(Boolean)
        .map((line) => {
          try {
            return expandSample(JSON.parse(line));
          } catch {
            return null;
          }
        })
        .filter(Boolean);
    } catch {
      return [];
    }
  }

  function archivePathForDay(dayKey) {
    const year = dayKey.slice(0, 4);
    return path.join(archiveDir, year, `${dayKey}.jsonl.gz`);
  }

  function dailyPathForDay(dayKey) {
    return path.join(dailyDir, `${dayKey}.jsonl`);
  }

  function rotateOldDailyFiles() {
    ensureDirs();
    const cutoff = Date.now() - ONE_YEAR_MS;
    let files = [];
    try {
      files = fs.readdirSync(dailyDir);
    } catch {
      return;
    }
    const meta = readMeta();
    for (const name of files) {
      if (!name.endsWith('.jsonl')) continue;
      const dayKey = name.replace(/\.jsonl$/, '');
      const dayStart = parseDayKey(dayKey);
      if (!dayStart || dayStart >= cutoff) continue;
      const src = path.join(dailyDir, name);
      const dest = archivePathForDay(dayKey);
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      try {
        const gz = zlib.gzipSync(fs.readFileSync(src));
        fs.writeFileSync(dest, gz);
        fs.unlinkSync(src);
        const year = dayKey.slice(0, 4);
        if (!meta.archivedYears.includes(year)) meta.archivedYears.push(year);
      } catch (err) {
        console.warn('[ovh-ops-metrics] archive failed', dayKey, err?.message || err);
      }
    }
    meta.archivedYears.sort();
    writeMeta(meta);
  }

  function appendSample(sample, intervalBytes = {}) {
    ensureDirs();
    const row = compactSample(sample, intervalBytes);
    const dayKey = utcDayKey(sample.t);
    const filePath = dailyPathForDay(dayKey);
    fs.appendFileSync(filePath, `${JSON.stringify(row)}\n`, 'utf8');

    const meta = readMeta();
    const delta = (intervalBytes.rx || 0) + (intervalBytes.tx || 0);
    meta.bandwidthTotalBytes = (meta.bandwidthTotalBytes || 0) + delta;
    if (!meta.oldestSampleMs || sample.t < meta.oldestSampleMs) meta.oldestSampleMs = sample.t;
    if (!meta.periodStartMs) meta.periodStartMs = sample.t;
    writeMeta(meta);

    if (Math.random() < 0.02) rotateOldDailyFiles();
  }

  function listDayKeysInRange(fromMs, toMs) {
    const keys = [];
    const startDay = parseDayKey(utcDayKey(fromMs));
    const endDay = parseDayKey(utcDayKey(toMs));
    for (let t = startDay; t <= endDay; t += ONE_DAY_MS) {
      keys.push(utcDayKey(t));
    }
    return keys;
  }

  function loadSamplesForDay(dayKey) {
    const live = readJsonlFile(dailyPathForDay(dayKey));
    if (live.length) return live;
    return readGzJsonl(archivePathForDay(dayKey));
  }

  function queryMetrics({ fromMs, toMs, maxPoints = 500 }) {
    const from = Number(fromMs) || 0;
    const to = Number(toMs) || Date.now();
    const cap = Math.min(2000, Math.max(50, Number(maxPoints) || 500));
    const dayKeys = listDayKeysInRange(from, to);
    let samples = [];
    for (const dayKey of dayKeys) {
      samples = samples.concat(loadSamplesForDay(dayKey));
    }
    samples = samples.filter((s) => s.t >= from && s.t <= to);
    samples.sort((a, b) => a.t - b.t);

    let downsampled = false;
    if (samples.length > cap) {
      const step = samples.length / cap;
      const out = [];
      for (let i = 0; i < cap; i++) out.push(samples[Math.floor(i * step)]);
      samples = out;
      downsampled = true;
    }

    return { samples, downsampled, count: samples.length };
  }

  function getMetaSummary() {
    const meta = readMeta();
    const now = Date.now();
    const oldest = meta.oldestSampleMs || meta.periodStartMs || now;
    const liveSpanMs = Math.min(ONE_YEAR_MS, now - oldest);
    return {
      bandwidthTotalBytes: meta.bandwidthTotalBytes || 0,
      bandwidthTotalGb: Math.round(((meta.bandwidthTotalBytes || 0) / 1e9) * 1000) / 1000,
      periodStartMs: meta.periodStartMs || oldest,
      oldestSampleMs: oldest,
      newestSampleMs: now,
      liveSpanMs,
      liveSpanDays: Math.round((liveSpanMs / ONE_DAY_MS) * 10) / 10,
      maxLiveSpanMs: ONE_YEAR_MS,
      archivedYears: meta.archivedYears || []
    };
  }

  function listAvailableDates({ year, month }) {
    ensureDirs();
    const y = Number(year);
    const m = Number(month);
    const dates = new Set();

    function scanDir(dir, archived) {
      if (!fs.existsSync(dir)) return;
      for (const name of fs.readdirSync(dir)) {
        const full = path.join(dir, name);
        if (archived && fs.statSync(full).isDirectory()) {
          for (const f of fs.readdirSync(full)) {
            const match = /^(\d{4}-\d{2}-\d{2})\.jsonl\.gz$/.exec(f);
            if (match) dates.add(match[1]);
          }
        } else {
          const match = /^(\d{4}-\d{2}-\d{2})\.jsonl$/.exec(name);
          if (match) dates.add(match[1]);
        }
      }
    }

    scanDir(dailyDir, false);
    scanDir(archiveDir, true);

    let list = [...dates].sort();
    if (Number.isFinite(y)) list = list.filter((d) => d.startsWith(String(y)));
    if (Number.isFinite(m) && m >= 1 && m <= 12) {
      const prefix = `${y}-${pad2(m)}-`;
      list = list.filter((d) => d.startsWith(prefix));
    }
    return list;
  }

  function loadRecentToMemory(maxSamples = 360) {
    const to = Date.now();
    const from = to - 24 * 60 * 60 * 1000;
    const { samples } = queryMetrics({ fromMs: from, toMs: to, maxPoints: maxSamples });
    return samples.slice(-maxSamples);
  }

  return {
    appendSample,
    queryMetrics,
    getMetaSummary,
    listAvailableDates,
    loadRecentToMemory,
    rotateOldDailyFiles,
    metricsDir
  };
}

module.exports = { createMetricsStore, ONE_YEAR_MS, utcDayKey, parseDayKey };

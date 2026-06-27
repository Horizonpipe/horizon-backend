# Horizon OVH Ops Monitor

Portable Java desktop app for monitoring your OVH server — same data as the cPanel **Server** console (metrics, logs, events, deploy, rollback).

## Requirements

- Java 17+ (JDK to build, JRE to run)
- Admin bearer token from Horizonpipe cPanel (same token the web console uses)

## Build

```bash
cd ovh-ops-monitor
mvn -q package
java -jar target/ovh-ops-monitor-1.0.0.jar
```

On Windows, double-click the JAR after building, or create a shortcut.

## First run

1. Open **Settings** (gear icon or File → Settings).
2. Set **API base URL** — e.g. `https://app.horizonpipe.com` (no trailing slash).
3. Paste your **Bearer token** (from browser devtools → Application → localStorage, or sign-in flow).
4. Click **Save** — the app polls every 8 seconds.

Config is stored in `%USERPROFILE%\.horizon-ops-monitor\config.properties` (macOS/Linux: `~/.horizon-ops-monitor/`).

## Features

| Tab | Description |
|-----|-------------|
| Overview | CPU, RAM, disk, bandwidth, PM2, git refs |
| Metrics | Sparkline charts (CPU, memory, bandwidth) |
| Logs | PM2 stdout/stderr, nginx error (auto-refresh) |
| Events | Deploy/webhook audit log |
| Deploy | Manual deploy + rollback |

## Portable distribution

After `mvn package`, copy `target/ovh-ops-monitor-1.0.0.jar` anywhere. Optional native installer:

```bash
jpackage --input target --name "Horizon Ops" --main-jar ovh-ops-monitor-1.0.0.jar --type app-image
```

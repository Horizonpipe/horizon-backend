# Export Render backend env vars (except DATABASE_URL) for OVH restore overlay.
# Usage: powershell deploy/ovh/export-render-env-for-restore.ps1
# Then SCP render-env-restore.env to OVH /tmp/ and run restore-production-env.sh

param(
  [string]$RenderServiceId = "srv-d6u872uuk2gs739868f0",
  [string]$OutFile = "",
  [string]$OvhHost = "40.160.72.39",
  [string]$SshUser = "ubuntu",
  [string]$SshKey = "$env:USERPROFILE\.ssh\id_ed25519_horizon_ovh",
  [switch]$Upload
)

$token = $env:RENDER_API_KEY
if (-not $token) { $token = $env:GITHUB_TOKEN }
if (-not $token) { throw "Set RENDER_API_KEY or use Render API key in RENDER_API_KEY env." }

if (-not $OutFile) { $OutFile = Join-Path $env:TEMP "render-env-restore.env" }

$headers = @{
  Authorization = "Bearer $token"
  Accept        = "application/json"
}

$skip = @('DATABASE_URL', 'PORT', 'CORS_ORIGINS')
$envs = Invoke-RestMethod -Uri "https://api.render.com/v1/services/$RenderServiceId/env-vars?limit=100" -Headers @{ Authorization = "Bearer $token"; Accept = "application/json" }
$lines = $envs | ForEach-Object { $_.envVar } | Where-Object { $_.key -notin $skip } | Sort-Object key | ForEach-Object { "$($_.key)=$($_.value)" }
$lines | Set-Content -Path $OutFile -Encoding ASCII
Write-Host "Wrote $($lines.Count) vars to $OutFile"

if ($Upload) {
  & scp -i $SshKey -o StrictHostKeyChecking=accept-new $OutFile "${SshUser}@${OvhHost}:/tmp/render-env-restore.env"
  Write-Host "Uploaded to OVH /tmp/render-env-restore.env"
  Write-Host "Run: ssh ${SshUser}@${OvhHost} 'sudo bash /opt/horizon/horizon-backend/deploy/ovh/restore-production-env.sh'"
}

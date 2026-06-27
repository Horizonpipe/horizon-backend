# Register OVH deploy keys on GitHub (one key per repo — GitHub does not allow reuse).
# Usage:
#   ssh ubuntu@YOUR_OVH "cat /opt/horizon/.ssh/github_ovh_deploy.pub"   # optional: verify keys exist
#   $env:GITHUB_TOKEN = "ghp_..."   # repo admin or deploy key scope
#   .\deploy\ovh\setup-github-deploy-keys.ps1 -OvhHost 40.160.72.39

param(
  [string]$OvhHost = "40.160.72.39",
  [string]$SshUser = "ubuntu",
  [string]$SshKey = "$env:USERPROFILE\.ssh\id_ed25519_horizon_ovh",
  [string]$BackendRepo = "Horizonpipe/horizon-backend",
  [string]$FrontendRepo = "Horizonpipe/horizon-frontend"
)

$token = $env:GITHUB_TOKEN
if (-not $token) { throw "Set GITHUB_TOKEN (PAT with admin:repo_hook or repo scope)." }

$headers = @{
  Authorization          = "Bearer $token"
  Accept                 = "application/vnd.github+json"
  "X-GitHub-Api-Version" = "2022-11-28"
}

function Get-OvhPubKey([string]$remotePath) {
  $args = @("-i", $SshKey, "-o", "StrictHostKeyChecking=accept-new", "${SshUser}@${OvhHost}", "cat $remotePath")
  & ssh @args
  if ($LASTEXITCODE -ne 0) { throw "Failed to read $remotePath from OVH" }
}

function Ensure-DeployKey([string]$repo, [string]$title, [string]$pubKey) {
  $owner, $name = $repo -split "/", 2
  $listUrl = "https://api.github.com/repos/$owner/$name/keys"
  $existing = Invoke-RestMethod -Uri $listUrl -Headers $headers -Method Get
  $fingerprint = ($pubKey.Trim() -split "\s+")[1]
  $match = $existing | Where-Object { $_.title -eq $title -or $_.key -match [regex]::Escape(($pubKey.Trim() -split "\s+")[0]) }
  if ($match) {
    Write-Host "[$repo] deploy key already registered (id $($match[0].id))"
    return
  }
  $body = @{
    title     = $title
    key       = $pubKey.Trim()
    read_only = $true
  } | ConvertTo-Json
  Invoke-RestMethod -Uri $listUrl -Headers $headers -Method Post -Body $body -ContentType "application/json" | Out-Null
  Write-Host "[$repo] deploy key added: $title"
}

$backendPub = Get-OvhPubKey "/opt/horizon/.ssh/github_ovh_deploy.pub"
$frontendPub = Get-OvhPubKey "/opt/horizon/.ssh/github_ovh_frontend.pub"

Ensure-DeployKey $BackendRepo "OVH deploy (backend pull)" $backendPub
Ensure-DeployKey $FrontendRepo "OVH deploy (frontend pull)" $frontendPub

Write-Host "Done. Test on OVH: sudo bash /opt/horizon/horizon-backend/deploy/ovh/setup-github-deploy-keys.sh"

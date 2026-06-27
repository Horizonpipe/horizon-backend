# Creates GitHub webhooks for OVH auto-deploy on both Horizonpipe repos.
# Usage (PowerShell):
#   $env:GITHUB_TOKEN = "ghp_..."   # needs repo admin / hook scope
#   .\deploy\ovh\setup-github-webhooks.ps1 -WebhookUrl "http://40.160.72.39/ops/webhook/github" -Secret "hp-ovh-..."

param(
  [string]$WebhookUrl = "http://40.160.72.39/ops/webhook/github",
  [Parameter(Mandatory = $true)][string]$Secret,
  [string[]]$Repos = @("Horizonpipe/horizon-backend", "Horizonpipe/horizon-frontend")
)

$token = $env:GITHUB_TOKEN
if (-not $token) { throw "Set GITHUB_TOKEN (PAT with admin:repo_hook or repo scope)." }

$headers = @{
  Authorization = "Bearer $token"
  Accept        = "application/vnd.github+json"
  "X-GitHub-Api-Version" = "2022-11-28"
}

foreach ($repo in $Repos) {
  $owner, $name = $repo -split "/", 2
  $listUrl = "https://api.github.com/repos/$owner/$name/hooks"
  $existing = Invoke-RestMethod -Uri $listUrl -Headers $headers -Method Get
  $match = $existing | Where-Object { $_.config.url -eq $WebhookUrl }
  if ($match) {
    Write-Host "[$repo] webhook exists (id $($match.id)) — updating secret"
    $body = @{
      config = @{
        url          = $WebhookUrl
        content_type = "json"
        secret       = $Secret
        insecure_ssl = "0"
      }
      events = @("push")
      active = $true
    } | ConvertTo-Json -Depth 5
    Invoke-RestMethod -Uri "https://api.github.com/repos/$owner/$name/hooks/$($match.id)" -Headers $headers -Method Patch -Body $body -ContentType "application/json" | Out-Null
  } else {
    Write-Host "[$repo] creating webhook → $WebhookUrl"
    $body = @{
      name   = "web"
      active = $true
      events = @("push")
      config = @{
        url          = $WebhookUrl
        content_type = "json"
        secret       = $Secret
        insecure_ssl = "0"
      }
    } | ConvertTo-Json -Depth 5
    Invoke-RestMethod -Uri $listUrl -Headers $headers -Method Post -Body $body -ContentType "application/json" | Out-Null
  }
  Write-Host "[$repo] done"
}

Write-Host "All webhooks configured. Push to main will trigger deploy on OVH."

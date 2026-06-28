# Pull latest main on OVH and reload PM2 (frontend + backend).
# Requires ~/.ssh/config Host horizon-ovh (see deploy/ovh/README.md).
param(
  [string]$HostAlias = "horizon-ovh"
)

$ErrorActionPreference = "Stop"
$remoteCmd = "sudo bash /opt/horizon/horizon-backend/deploy/ovh/github-deploy.sh"
Write-Host "Deploying via ssh ${HostAlias} ..."
ssh $HostAlias $remoteCmd
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "Deploy complete."

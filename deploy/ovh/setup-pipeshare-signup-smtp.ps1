# Configure GoDaddy SMTP for pipeshare.net sign-up (EmailVerification@pipeshare.net).
# Run from PowerShell on your PC:
#   powershell -File deploy/ovh/setup-pipeshare-signup-smtp.ps1
param(
  [string]$SshHost = 'horizon-ovh',
  [string]$SmtpUser = 'EmailVerification@pipeshare.net'
)

$secure = Read-Host "GoDaddy mailbox password for $SmtpUser" -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
  $pass = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
} finally {
  [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
}

if (-not $pass) {
  Write-Error 'Password required.'
  exit 1
}

# Escape single quotes for bash
$escaped = $pass -replace "'", "'\''"
$cmd = "SMTP_PASS='$escaped' SMTP_USER='$SmtpUser' bash /opt/horizon/horizon-backend/deploy/ovh/setup-pipeshare-signup-smtp.sh"
Write-Host "Configuring SMTP on OVH for $SmtpUser ..."
ssh $SshHost $cmd
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ''
Write-Host 'Disabling dev PIN mode (production sign-up uses email)...'
ssh $SshHost "grep -q '^SIGNUP_DEV_RETURN_PIN=' /opt/horizon/horizon-backend/.env && sed -i 's/^SIGNUP_DEV_RETURN_PIN=.*/SIGNUP_DEV_RETURN_PIN=0/' /opt/horizon/horizon-backend/.env || echo 'SIGNUP_DEV_RETURN_PIN=0' >> /opt/horizon/horizon-backend/.env; pm2 reload horizon-backend --update-env"
Write-Host 'Done. Test Create account at https://pipeshare.net/'

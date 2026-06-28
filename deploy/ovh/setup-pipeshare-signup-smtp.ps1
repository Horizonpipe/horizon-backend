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

Write-Host 'Done. SaaS sign-up on https://pipeshare.net/ will send verification email from' $SmtpUser

# Configure Microsoft 365 SMTP for pipeshare.net sign-up verification emails.
#
# Shared mailbox (From): EmailVerification@pipeshare.net
# Admin SMTP auth (User): Mstrickland@pipeshare.net
#
# Requires SMTP Authentication ON for the admin mailbox in GoDaddy Advanced Settings.
#   powershell -File deploy/ovh/setup-pipeshare-signup-smtp.ps1
param(
  [string]$SshHost = 'horizon-ovh',
  [string]$SmtpUser = 'Mstrickland@pipeshare.net',
  [string]$SmtpFrom = 'EmailVerification@pipeshare.net'
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
$cmd = "SMTP_PASS='$escaped' SMTP_USER='$SmtpUser' SMTP_FROM_ADDR='$SmtpFrom' bash /opt/horizon/horizon-backend/deploy/ovh/setup-pipeshare-signup-smtp.sh"
Write-Host "Configuring SMTP on OVH: auth $SmtpUser, From $SmtpFrom ..."
ssh $SshHost $cmd
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host 'Done. SaaS sign-up on https://pipeshare.net/ will send verification email from' $SmtpUser

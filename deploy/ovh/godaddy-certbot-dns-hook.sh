#!/usr/bin/env bash
# Certbot manual DNS hook for GoDaddy (pipeshare.net wildcard / DNS-01).
# Usage (called by certbot, not directly):
#   --manual-auth-hook 'bash .../godaddy-certbot-dns-hook.sh auth'
#   --manual-cleanup-hook 'bash .../godaddy-certbot-dns-hook.sh cleanup'
#
# Credentials (first match wins):
#   GODADDY_API_KEY + GODADDY_API_SECRET env vars
#   /root/.secrets/godaddy/credentials.ini  (godaddy_api_key= / godaddy_api_secret=)
set -euo pipefail

ACTION="${1:-auth}"
DOMAIN="${CERTBOT_DOMAIN:-}"
VALIDATION="${CERTBOT_VALIDATION:-}"
GODADDY_DOMAIN="${GODADDY_DOMAIN:-pipeshare.net}"
CREDS_FILE="${GODADDY_CREDS_FILE:-/root/.secrets/godaddy/credentials.ini}"
API_BASE="${GODADDY_API_BASE:-https://api.godaddy.com}"

load_creds() {
  if [[ -n "${GODADDY_API_KEY:-}" && -n "${GODADDY_API_SECRET:-}" ]]; then
    return 0
  fi
  if [[ -f "$CREDS_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$CREDS_FILE"
    GODADDY_API_KEY="${godaddy_api_key:-${GODADDY_API_KEY:-}}"
    GODADDY_API_SECRET="${godaddy_api_secret:-${GODADDY_API_SECRET:-}}"
  fi
  if [[ -z "${GODADDY_API_KEY:-}" || -z "${GODADDY_API_SECRET:-}" ]]; then
    echo "GoDaddy API credentials missing. Set GODADDY_API_KEY/GODADDY_API_SECRET or $CREDS_FILE" >&2
    exit 1
  fi
}

# _acme-challenge.pipeshare.net or _acme-challenge.techpipe.pipeshare.net -> _acme-challenge[.sub]
record_name_for_domain() {
  local d="$1"
  d="${d%.}"
  if [[ "$d" == "$GODADDY_DOMAIN" ]]; then
    echo "_acme-challenge"
    return
  fi
  local suffix=".$GODADDY_DOMAIN"
  if [[ "$d" == *"$suffix" ]]; then
    local sub="${d%"$suffix"}"
    echo "_acme-challenge.${sub}"
    return
  fi
  echo "_acme-challenge.${d}"
}

godaddy_api() {
  local method="$1"
  local path="$2"
  shift 2
  curl -sS -X "$method" \
    -H "Authorization: sso-key ${GODADDY_API_KEY}:${GODADDY_API_SECRET}" \
    -H "Content-Type: application/json" \
    "$@" \
    "${API_BASE}${path}"
}

merge_txt_record() {
  local name="$1"
  local value="$2"
  local enc_name
  enc_name="$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=""))' "$name")"
  local existing
  existing="$(godaddy_api GET "/v1/domains/${GODADDY_DOMAIN}/records/TXT/${enc_name}" || true)"
  local payload='[]'
  if [[ -n "$existing" && "$existing" != "[]" ]]; then
    payload="$(printf '%s' "$existing" | python3 -c '
import json, sys
value = sys.argv[1]
rows = json.load(sys.stdin)
out = []
seen = set()
for row in rows:
    data = str(row.get("data") or "").strip()
    if not data or data in seen:
        continue
    seen.add(data)
    out.append({"data": data, "ttl": int(row.get("ttl") or 600)})
if value not in seen:
    out.append({"data": value, "ttl": 600})
print(json.dumps(out))
' "$value")"
  else
    payload="$(python3 -c 'import json,sys; print(json.dumps([{"data": sys.argv[1], "ttl": 600}]))' "$value")"
  fi
  godaddy_api PUT "/v1/domains/${GODADDY_DOMAIN}/records/TXT/${enc_name}" --data "$payload" >/dev/null
}

remove_txt_value() {
  local name="$1"
  local value="$2"
  local enc_name
  enc_name="$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=""))' "$name")"
  local existing
  existing="$(godaddy_api GET "/v1/domains/${GODADDY_DOMAIN}/records/TXT/${enc_name}" || true)"
  if [[ -z "$existing" || "$existing" == "[]" ]]; then
    return 0
  fi
  local payload
  payload="$(printf '%s' "$existing" | python3 -c '
import json, sys
drop = sys.argv[1]
rows = json.load(sys.stdin)
out = []
for row in rows:
    data = str(row.get("data") or "").strip()
    if not data or data == drop:
        continue
    out.append({"data": data, "ttl": int(row.get("ttl") or 600)})
print(json.dumps(out))
' "$value")"
  if [[ "$payload" == "[]" ]]; then
    godaddy_api DELETE "/v1/domains/${GODADDY_DOMAIN}/records/TXT/${enc_name}" >/dev/null || true
  else
    godaddy_api PUT "/v1/domains/${GODADDY_DOMAIN}/records/TXT/${enc_name}" --data "$payload" >/dev/null
  fi
}

wait_for_txt() {
  local fqdn="$1"
  local value="$2"
  local i
  for i in $(seq 1 36); do
    local got
    got="$(dig +short TXT "$fqdn" @8.8.8.8 | tr -d '\"' | tr '\n' ' ')"
    if [[ " $got " == *" $value "* ]]; then
      echo "DNS propagated: $fqdn"
      return 0
    fi
    sleep 5
  done
  echo "Timed out waiting for TXT $fqdn" >&2
  exit 1
}

if [[ -z "$DOMAIN" || -z "$VALIDATION" ]]; then
  echo "CERTBOT_DOMAIN and CERTBOT_VALIDATION must be set" >&2
  exit 1
fi

load_creds
REC="$(record_name_for_domain "$DOMAIN")"
FQDN="${REC}.${GODADDY_DOMAIN}"

case "$ACTION" in
  auth)
    echo "GoDaddy TXT ${FQDN} <- ${VALIDATION}"
    merge_txt_record "$REC" "$VALIDATION"
    wait_for_txt "$FQDN" "$VALIDATION"
    ;;
  cleanup)
    echo "GoDaddy TXT cleanup ${FQDN} (remove ${VALIDATION})"
    remove_txt_value "$REC" "$VALIDATION"
    ;;
  *)
    echo "Usage: $0 auth|cleanup" >&2
    exit 1
    ;;
esac

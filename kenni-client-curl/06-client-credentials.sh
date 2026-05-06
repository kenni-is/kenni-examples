#!/usr/bin/env bash
# Step 6: client-credentials grant (M2M). Uses a SECOND application's
# credentials (KENNI_M2M_*), not the user-facing one.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"
load_env
require_tools

if [[ -z "$KENNI_M2M_CLIENT_ID" || -z "$KENNI_M2M_CLIENT_SECRET" || -z "$KENNI_M2M_SCOPE" ]]; then
  die "Set KENNI_M2M_CLIENT_ID, KENNI_M2M_CLIENT_SECRET, and KENNI_M2M_SCOPE in .env."
fi
[[ -f "$SESSION_DIR/discovery.json" ]] || die "Run 01-discover.sh first."

token_endpoint=$(discovery token_endpoint)

step "POST $token_endpoint  (grant_type=client_credentials)"
# RFC 6749 §2.3.1: form-urlencode each credential before joining and
# base64-encoding for HTTP Basic. (Matters when the client_id contains
# special chars like '@' or '/', which Kenni client IDs do.)
basic=$(printf '%s:%s' \
  "$(urlencode "$KENNI_M2M_CLIENT_ID")" \
  "$(urlencode "$KENNI_M2M_CLIENT_SECRET")" \
  | openssl base64 -A)
response=$(curl -fsS -X POST "$token_endpoint" \
  -H "Authorization: Basic $basic" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "scope=$KENNI_M2M_SCOPE")

echo "$response" | jq .
ok "Token received"

access_token=$(jq -r .access_token <<<"$response")
step "Decoded access_token claims (informational — no signature check here)"
jwt_payload "$access_token" | jq .

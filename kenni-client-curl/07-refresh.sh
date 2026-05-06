#!/usr/bin/env bash
# Step 7: exchange the refresh_token for a fresh access_token (and a fresh
# refresh_token, if Kenni rotates them).
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"
load_env
require_tools
[[ -f "$SESSION_DIR/tokens.json" ]] || die "Run 03-exchange.sh first."

refresh_token=$(jq -r '.refresh_token // ""' "$SESSION_DIR/tokens.json")
[[ -n "$refresh_token" && "$refresh_token" != "null" ]] \
  || die "No refresh_token in tokens.json. Did your scopes include offline_access?"

token_endpoint=$(discovery token_endpoint)

step "POST $token_endpoint  (grant_type=refresh_token)"
response=$(curl -fsS -X POST "$token_endpoint" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "refresh_token=$refresh_token" \
  --data-urlencode "client_id=$KENNI_CLIENT_ID" \
  --data-urlencode "client_secret=$KENNI_CLIENT_SECRET")

echo "$response" | jq . > "$SESSION_DIR/tokens.json"
ok "Refreshed tokens saved to .session/tokens.json"
jq . "$SESSION_DIR/tokens.json"

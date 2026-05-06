#!/usr/bin/env bash
# Step 4: call the user-info endpoint with the access token.
#
# Only works with an *opaque* access token — i.e. the user signed in WITHOUT
# requesting an API scope. When KENNI_API_SCOPE is set at sign-in, Kenni
# issues a JWT access token whose `aud` is your API (not Kenni's userinfo
# endpoint), and `/oidc/me` rejects it with 401. To exercise this script,
# leave KENNI_API_SCOPE unset in .env and re-run 02-login.sh.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"
load_env
require_tools
[[ -f "$SESSION_DIR/tokens.json" ]] || die "Run 03-exchange.sh first."

if [[ -n "$KENNI_API_SCOPE" ]]; then
  warn "KENNI_API_SCOPE is set — the access token is a JWT for your API,"
  warn "not an opaque token for Kenni's userinfo endpoint. Expect a 401."
  warn "Unset KENNI_API_SCOPE and re-run 02-login.sh to exercise this step."
fi

access_token=$(jq -r .access_token "$SESSION_DIR/tokens.json")
userinfo_endpoint=$(discovery userinfo_endpoint)

step "GET $userinfo_endpoint  (Authorization: Bearer …)"
curl -fsS "$userinfo_endpoint" -H "Authorization: Bearer $access_token" | jq .

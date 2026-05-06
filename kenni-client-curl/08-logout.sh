#!/usr/bin/env bash
# Step 8: RP-initiated logout. Clear local state first, *then* redirect the
# browser to Kenni's end_session_endpoint — so a failed RP-logout still
# leaves the local session cleared.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"
load_env
require_tools
[[ -f "$SESSION_DIR/tokens.json" ]] || die "Run 03-exchange.sh first."

end_session_endpoint=$(discovery end_session_endpoint)
[[ -n "$end_session_endpoint" && "$end_session_endpoint" != "null" ]] \
  || die "Kenni discovery does not advertise end_session_endpoint."

id_token=$(jq -r .id_token "$SESSION_DIR/tokens.json")

step "Clearing local session before redirect"
rm -f "$SESSION_DIR/tokens.json" "$SESSION_DIR/code_verifier" \
      "$SESSION_DIR/state" "$SESSION_DIR/nonce"
ok "Removed token + PKCE artefacts from .session/"

url="${end_session_endpoint}?id_token_hint=${id_token}"
url+="&post_logout_redirect_uri=$(urlencode "$KENNI_POST_LOGOUT_REDIRECT_URI")"
url+="&client_id=$(urlencode "$KENNI_CLIENT_ID")"

step "RP-initiated logout URL"
echo "$url"

if open_url "$url"; then ok "Opened in browser"; fi

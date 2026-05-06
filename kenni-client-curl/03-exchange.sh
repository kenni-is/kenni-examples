#!/usr/bin/env bash
# Step 3: parse the callback URL, exchange the code for tokens, verify the
# returned id_token (signature, iss, aud, exp, nonce).
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"
load_env
require_tools

if [[ $# -lt 1 ]]; then
  die "Usage: $0 '<full callback URL with ?code=...&state=...>'"
fi

callback_url=$1
[[ -f "$SESSION_DIR/code_verifier" && -f "$SESSION_DIR/state" ]] \
  || die "Run 02-login.sh first."

# urldecode: replace '+' with space, then %xx with the corresponding byte.
urldecode() { local s=${1//+/ }; printf '%b' "${s//%/\\x}"; }

step "Parsing callback URL"
query=${callback_url#*\?}
[[ "$query" == "$callback_url" ]] && die "URL has no query string."

# Pull the first occurrence of each parameter.
get_param() {
  local key=$1
  printf '%s\n' "$query" | tr '&' '\n' \
    | awk -F= -v k="$key" '$1==k {print substr($0, length(k)+2); exit}'
}

code=$(urldecode "$(get_param code)")
returned_state=$(urldecode "$(get_param state)")
err=$(urldecode "$(get_param error)")
err_desc=$(urldecode "$(get_param error_description)")

[[ -n "$err" ]] && die "IdP returned error: $err — $err_desc"
[[ -z "$code" ]] && die "No 'code' parameter on the callback URL."

expected_state=$(<"$SESSION_DIR/state")
if [[ "$returned_state" != "$expected_state" ]]; then
  die "state mismatch (got '$returned_state', expected '$expected_state')."
fi
ok "code received, state verified"

token_endpoint=$(discovery token_endpoint)
code_verifier=$(<"$SESSION_DIR/code_verifier")

step "POST $token_endpoint  (grant_type=authorization_code)"
response=$(curl -fsS -X POST "$token_endpoint" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=$code" \
  --data-urlencode "redirect_uri=$KENNI_REDIRECT_URI" \
  --data-urlencode "client_id=$KENNI_CLIENT_ID" \
  --data-urlencode "client_secret=$KENNI_CLIENT_SECRET" \
  --data-urlencode "code_verifier=$code_verifier")
echo "$response" | jq . > "$SESSION_DIR/tokens.json"
ok "Saved .session/tokens.json"

id_token=$(jq -r .id_token "$SESSION_DIR/tokens.json")
[[ "$id_token" == "null" || -z "$id_token" ]] && die "No id_token in response."

step "Verifying id_token signature against JWKS"
payload=$(verify_jwt_rs256 "$id_token") || die "id_token signature did not verify."
ok "Signature OK"

expected_nonce=$(<"$SESSION_DIR/nonce")
got_nonce=$(jq -r '.nonce // ""' <<<"$payload")
[[ "$got_nonce" == "$expected_nonce" ]] || die "nonce mismatch (got '$got_nonce')."
ok "nonce matches"

# id_token: aud is the client_id. iss must match what discovery advertises.
expected_iss=$(discovery issuer)
validate_claims "$payload" "$expected_iss" "$KENNI_CLIENT_ID" "" >/dev/null \
  || die "id_token claim validation failed."
ok "iss / aud / exp OK"

step "id_token claims"
jq . <<<"$payload"

cat <<'EOF' >&2

You're signed in. Tokens are cached in .session/tokens.json. Try:

    ./04-userinfo.sh                # GET /oidc/me
    ./05-protected-resource.sh      # bearer-protected API (needs KENNI_API_SCOPE)
    ./07-refresh.sh                 # exchange the refresh_token
    ./08-logout.sh                  # RP-initiated logout

EOF

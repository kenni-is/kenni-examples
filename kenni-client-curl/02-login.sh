#!/usr/bin/env bash
# Step 2: generate PKCE/state/nonce, build the authorization URL, open it.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"
load_env
require_tools
[[ -f "$SESSION_DIR/discovery.json" ]] || die "Run 01-discover.sh first."

step "Generating PKCE verifier + S256 challenge, state, nonce"
# RFC 7636: verifier is 43-128 chars from [A-Z][a-z][0-9]-._~. We use
# base64url chars (which is a subset).
code_verifier=$(rand_b64url)
code_challenge=$(printf '%s' "$code_verifier" \
                 | openssl dgst -sha256 -binary | b64url_encode)
state=$(rand_b64url)
nonce=$(rand_b64url)
printf '%s' "$code_verifier" > "$SESSION_DIR/code_verifier"
printf '%s' "$state"         > "$SESSION_DIR/state"
printf '%s' "$nonce"         > "$SESSION_DIR/nonce"
ok "Saved code_verifier, state, nonce to .session/"

scopes="openid profile national_id offline_access"
if [[ -n "$KENNI_API_SCOPE" ]]; then
  scopes="$scopes $KENNI_API_SCOPE"
  ok "Including API scope: $KENNI_API_SCOPE"
fi

auth_endpoint=$(discovery authorization_endpoint)
url="${auth_endpoint}?client_id=$(urlencode "$KENNI_CLIENT_ID")"
url+="&response_type=code"
url+="&redirect_uri=$(urlencode "$KENNI_REDIRECT_URI")"
url+="&scope=$(urlencode "$scopes")"
url+="&state=${state}"
url+="&nonce=${nonce}"
url+="&code_challenge=${code_challenge}"
url+="&code_challenge_method=S256"

step "Authorization URL"
echo "$url"

if open_url "$url"; then ok "Opened in browser"; fi

cat <<EOF >&2

Sign in with Kenni. The browser will redirect to:
  $KENNI_REDIRECT_URI?code=…&state=…

Make sure ./serve.sh is running so the redirect lands on a real page that
shows you the code (otherwise the browser shows a connection error, but the
URL bar still has everything we need).

Then run:

    ./03-exchange.sh '<paste the FULL redirect URL here in single quotes>'

EOF

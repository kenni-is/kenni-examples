#!/usr/bin/env bash
# Step 1: fetch the OIDC discovery document and JWKS, cache them in .session/.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"
load_env
require_tools

step "GET ${KENNI_ISSUER%/}/.well-known/openid-configuration"
curl -fsS "${KENNI_ISSUER%/}/.well-known/openid-configuration" \
  | jq . > "$SESSION_DIR/discovery.json"
ok "Saved .session/discovery.json"

jwks_uri=$(discovery jwks_uri)
step "GET $jwks_uri"
curl -fsS "$jwks_uri" | jq . > "$SESSION_DIR/jwks.json"
ok "Saved .session/jwks.json ($(jq '.keys | length' "$SESSION_DIR/jwks.json") keys)"

step "Endpoints discovered"
jq '{
  issuer,
  authorization_endpoint,
  token_endpoint,
  userinfo_endpoint,
  end_session_endpoint,
  jwks_uri
}' "$SESSION_DIR/discovery.json"

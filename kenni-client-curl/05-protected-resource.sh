#!/usr/bin/env bash
# Step 5: demonstrate the *server* side of an API call. Pull the user's
# access token, then verify it locally against Kenni's JWKS — exactly what a
# real bearer-protected API endpoint does on every incoming request.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"
load_env
require_tools

[[ -n "$KENNI_API_SCOPE" ]] \
  || die "KENNI_API_SCOPE is not set in .env. This step exercises the API-call feature, which is gated on it."
[[ -f "$SESSION_DIR/tokens.json" ]] || die "Run 03-exchange.sh first."

access_token=$(jq -r .access_token "$SESSION_DIR/tokens.json")

step "Client side: GET /api/protected-resource (Authorization: Bearer …)"
ok "(curl example has no separate server process — verifying inline below)"

step "Server side: verifying RS256 signature against JWKS"
payload=$(verify_jwt_rs256 "$access_token") \
  || die "Signature verification failed."
ok "Signature OK"

step "Server side: validating iss / aud / exp / scope"
expected_iss=$(discovery issuer)
validate_claims "$payload" "$expected_iss" "$KENNI_API_AUDIENCE" "$KENNI_API_SCOPE" >/dev/null \
  || die "Claim validation failed. Did you re-run 02-login.sh after setting KENNI_API_SCOPE?"
ok "iss / aud / exp / scope all OK"

step "Server side: returning JSON to the client"
sub=$(jq -r .sub <<<"$payload")
national_id=$(jq -r '.national_id // ""' <<<"$payload")
exp_human=$(date -u -r "$(jq -r .exp <<<"$payload")" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null \
            || date -u -d "@$(jq -r .exp <<<"$payload")" +"%Y-%m-%dT%H:%M:%SZ")
scopes=$(jq -r '.scope // ""' <<<"$payload")

jq -n \
  --arg message "Halló!" \
  --arg served_by "bash + openssl + jq (no framework)" \
  --arg sub "$sub" \
  --arg national_id "$national_id" \
  --arg expires_at "$exp_human" \
  --argjson scopes "$(jq -nc --arg s "$scopes" '$s | split(" ")')" \
  '{
    message: $message,
    served_by: $served_by,
    sub: $sub,
    national_id: $national_id,
    scopes: $scopes,
    expires_at: $expires_at
  }'

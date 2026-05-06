# Shared helpers for the kenni-client-curl example.
# Sourced from each numbered step script — not meant to run on its own.

set -euo pipefail

KENNI_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SESSION_DIR="$KENNI_DIR/.session"
mkdir -p "$SESSION_DIR"

# Load .env if present, then assert required vars and provide defaults for
# the optional ones. Existing environment values win over .env (POSIX rule
# of `set -a; source; set +a`).
load_env() {
  if [[ -f "$KENNI_DIR/.env" ]]; then
    # shellcheck disable=SC1091
    set -a; source "$KENNI_DIR/.env"; set +a
  fi
  : "${KENNI_ISSUER:?KENNI_ISSUER must be set (see .env.example)}"
  : "${KENNI_CLIENT_ID:?KENNI_CLIENT_ID must be set}"
  : "${KENNI_CLIENT_SECRET:?KENNI_CLIENT_SECRET must be set}"
  : "${KENNI_REDIRECT_URI:?KENNI_REDIRECT_URI must be set}"
  : "${KENNI_POST_LOGOUT_REDIRECT_URI:?KENNI_POST_LOGOUT_REDIRECT_URI must be set}"
  KENNI_API_SCOPE=${KENNI_API_SCOPE:-}
  KENNI_API_AUDIENCE=${KENNI_API_AUDIENCE:-${KENNI_CLIENT_ID}-api}
  KENNI_M2M_CLIENT_ID=${KENNI_M2M_CLIENT_ID:-}
  KENNI_M2M_CLIENT_SECRET=${KENNI_M2M_CLIENT_SECRET:-}
  KENNI_M2M_SCOPE=${KENNI_M2M_SCOPE:-}
}

require_tools() {
  for tool in curl jq openssl xxd; do
    command -v "$tool" >/dev/null || { echo "Missing required tool: $tool" >&2; exit 1; }
  done
}

# Read a top-level field from the cached discovery doc.
discovery() { jq -r ".$1" "$SESSION_DIR/discovery.json"; }

# URL-encode a string. Uses jq's @uri filter — no awk/perl/python needed.
urlencode() { jq -rn --arg v "$1" '$v|@uri'; }

# base64url helpers. Both stream-based: encode reads stdin → emits stdout
# without padding or +/; decode reads stdin (a base64url *string*) →
# emits the raw bytes on stdout.
b64url_encode() { openssl base64 -A | tr -d '=' | tr '/+' '_-'; }
b64url_decode() {
  local input
  input=$(cat)
  local pad=$(( (4 - ${#input} % 4) % 4 ))
  { printf '%s' "$input" | tr '_-' '/+'
    for ((i=0; i<pad; i++)); do printf '='; done
  } | openssl base64 -d -A
}

# Random URL-safe string (43 base64url chars from 32 bytes — fits PKCE
# verifier requirements and is plenty of entropy for state/nonce).
rand_b64url() {
  openssl rand -base64 32 | tr -d '=\n' | tr '/+' '_-' | head -c 43
}

# JWT decoders — emit the JSON header / payload as text on stdout.
jwt_header()  { printf '%s' "$1" | cut -d. -f1 | b64url_decode; }
jwt_payload() { printf '%s' "$1" | cut -d. -f2 | b64url_decode; }

# Convert a JWK (RSA public key, JSON object on stdin) into a PEM-encoded
# SubjectPublicKeyInfo on stdout. Uses openssl asn1parse -genconf to build
# the DER-encoded RSAPublicKey, then converts to SPKI via `openssl rsa`.
#
# The leading-zero pad on n is required: ASN.1 INTEGER is two's-complement,
# so a modulus whose top bit is set must be prefixed with 00 to encode as
# positive. e is small (typically 65537 = 0x010001) and never needs the pad.
jwk_to_pem() {
  local jwk n e n_hex e_hex tmp_cnf tmp_der high
  jwk=$(cat)
  n=$(jq -r .n <<<"$jwk")
  e=$(jq -r .e <<<"$jwk")
  n_hex=$(printf '%s' "$n" | b64url_decode | xxd -p | tr -d '\n')
  e_hex=$(printf '%s' "$e" | b64url_decode | xxd -p | tr -d '\n')
  high=${n_hex:0:2}
  if (( 16#$high >= 128 )); then n_hex="00$n_hex"; fi
  tmp_cnf=$(mktemp); tmp_der=$(mktemp)
  cat > "$tmp_cnf" <<EOF
asn1=SEQUENCE:rsa_pub
[rsa_pub]
n=INTEGER:0x${n_hex}
e=INTEGER:0x${e_hex}
EOF
  openssl asn1parse -genconf "$tmp_cnf" -out "$tmp_der" -noout
  openssl rsa -RSAPublicKey_in -in "$tmp_der" -inform DER -pubout 2>/dev/null
  rm -f "$tmp_cnf" "$tmp_der"
}

# Verify an RS256 JWT signature against the cached JWKS (.session/jwks.json).
# On success: emits the decoded payload (JSON) on stdout. On failure: writes
# a reason to stderr and returns non-zero.
verify_jwt_rs256() {
  local token=$1 header alg kid jwk signing_input sig_b64 tmp_pem sig_bin
  header=$(jwt_header "$token")
  alg=$(jq -r .alg <<<"$header")
  kid=$(jq -r '.kid // ""' <<<"$header")
  if [[ "$alg" != "RS256" ]]; then
    echo "Unsupported alg: $alg (this script handles only RS256)" >&2
    return 1
  fi
  jwk=$(jq -c --arg kid "$kid" '.keys[] | select(.kid == $kid)' "$SESSION_DIR/jwks.json")
  if [[ -z "$jwk" ]]; then
    echo "JWKS does not contain kid '$kid'. Re-run 01-discover.sh to refresh." >&2
    return 1
  fi
  tmp_pem=$(mktemp); sig_bin=$(mktemp)
  printf '%s' "$jwk" | jwk_to_pem > "$tmp_pem"
  signing_input=${token%.*}
  sig_b64=${token##*.}
  printf '%s' "$sig_b64" | b64url_decode > "$sig_bin"
  if ! printf '%s' "$signing_input" \
       | openssl dgst -sha256 -verify "$tmp_pem" -signature "$sig_bin" >/dev/null 2>&1; then
    rm -f "$tmp_pem" "$sig_bin"
    echo "Signature verification failed." >&2
    return 1
  fi
  rm -f "$tmp_pem" "$sig_bin"
  jwt_payload "$token"
}

# Validate iss / aud / exp / scope on a JWT payload (passed as JSON on $1).
# expected_iss, expected_aud, required_scope are positional. Pass "" for
# required_scope to skip the scope check.
# Echoes the payload on success; returns non-zero with a reason on failure.
validate_claims() {
  local payload=$1 expected_iss=$2 expected_aud=$3 required_scope=$4
  local iss exp now scopes
  iss=$(jq -r .iss <<<"$payload")
  exp=$(jq -r '.exp // 0' <<<"$payload")
  now=$(date +%s)
  if [[ "$iss" != "$expected_iss" ]]; then
    echo "iss mismatch: got '$iss', want '$expected_iss'" >&2; return 1
  fi
  if (( exp <= now )); then
    echo "Token expired ($((now - exp))s ago)." >&2; return 1
  fi
  if ! jq -e --arg aud "$expected_aud" '
    if (.aud | type) == "array" then any(.aud[]; . == $aud) else .aud == $aud end
  ' <<<"$payload" >/dev/null; then
    local got
    got=$(jq -c .aud <<<"$payload")
    echo "aud claim does not contain '$expected_aud' (got: $got)." >&2; return 1
  fi
  if [[ -n "$required_scope" ]]; then
    scopes=$(jq -r '.scope // ""' <<<"$payload")
    case " $scopes " in
      *" $required_scope "*) ;;
      *) echo "Token missing required scope '$required_scope' (have: $scopes)." >&2
         return 1 ;;
    esac
  fi
  printf '%s' "$payload"
}

# Open a URL in the local browser (best effort).
open_url() {
  if   command -v open >/dev/null;     then open "$1"     >/dev/null 2>&1 && return 0
  elif command -v xdg-open >/dev/null; then xdg-open "$1" >/dev/null 2>&1 && return 0
  fi
  return 1
}

step() { printf '\n\033[1;34m▸ %s\033[0m\n' "$*" >&2; }
ok()   { printf '  \033[1;32m✓\033[0m %s\n' "$*" >&2; }
warn() { printf '  \033[1;33m!\033[0m %s\n' "$*" >&2; }
die()  { printf '  \033[1;31m✗\033[0m %s\n' "$*" >&2; exit 1; }

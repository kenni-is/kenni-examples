"""Kenni — Python (Flask + Authlib) example.

Sign in with Kenni (OIDC: Authorization Code + PKCE), call a protected API
endpoint with the user's access token, and run a client-credentials grant.
Uses Authlib's Flask integration — the de facto OIDC client library for
Python (Flask, FastAPI, Django, and standalone scripts).
"""

import base64
import json
import os
from datetime import datetime, timezone
from urllib.parse import quote, urlencode

import requests
from authlib.integrations.flask_client import OAuth
from authlib.jose import JsonWebKey, jwt as jose_jwt
from authlib.jose.errors import JoseError
from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, render_template, request, session, url_for

load_dotenv()


def _required(key: str) -> str:
    value = os.environ.get(key)
    if not value:
        raise SystemExit(f"missing required env var: {key}")
    return value


ISSUER = _required("KENNI_ISSUER")
CLIENT_ID = _required("KENNI_CLIENT_ID")
CLIENT_SECRET = _required("KENNI_CLIENT_SECRET")

API_SCOPE = os.environ.get("KENNI_API_SCOPE") or None
API_AUDIENCE = os.environ.get("KENNI_API_AUDIENCE") or f"{CLIENT_ID}-api"
M2M_CLIENT_ID = os.environ.get("KENNI_M2M_CLIENT_ID") or None
M2M_CLIENT_SECRET = os.environ.get("KENNI_M2M_CLIENT_SECRET") or None
M2M_SCOPE = os.environ.get("KENNI_M2M_SCOPE") or None

API_ENABLED = bool(API_SCOPE)
M2M_ENABLED = bool(M2M_CLIENT_ID and M2M_CLIENT_SECRET and M2M_SCOPE)

app = Flask(__name__)
# Flask signs (but does not encrypt) the session cookie. Tokens stored in
# session are visible to anyone with the cookie — fine for a demo, but for
# production move them server-side (Redis, DB) or switch to encrypted cookies.
app.secret_key = os.environ.get(
    "FLASK_SECRET", "dev-only-please-replace-me-with-a-random-32-char-string"
)

oauth = OAuth(app)

_scopes = ["openid", "profile", "national_id", "offline_access"]
if API_SCOPE:
    _scopes.append(API_SCOPE)

oauth.register(
    name="kenni",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    server_metadata_url=f"{ISSUER}/.well-known/openid-configuration",
    client_kwargs={
        "scope": " ".join(_scopes),
        "code_challenge_method": "S256",
    },
)


# ---------- Pages ----------

@app.route("/")
def index():
    user = session.get("userinfo") or {}
    name = (
        user.get("name")
        or " ".join(filter(None, [user.get("given_name"), user.get("family_name")]))
        or user.get("sub", "")
    )
    return render_template(
        "index.html",
        signed_in=bool(session.get("id_token")),
        name=name,
        national_id=user.get("national_id"),
        api_enabled=API_ENABLED,
        m2m_enabled=M2M_ENABLED,
    )


# ---------- Auth flow ----------

@app.route("/auth/login")
def login():
    return oauth.kenni.authorize_redirect(url_for("callback", _external=True))


@app.route("/auth/callback")
def callback():
    # Authlib verifies signature, iss, aud, exp, and nonce on the id_token,
    # and parses it into token["userinfo"] for us.
    token = oauth.kenni.authorize_access_token()
    session["id_token"] = token["id_token"]
    session["access_token"] = token["access_token"]
    session["refresh_token"] = token.get("refresh_token")
    session["userinfo"] = dict(token.get("userinfo") or {})
    return redirect("/")


# Local sign-out only — Kenni's session cookie is untouched, so the next
# sign-in is silent. Use /auth/rp-logout to also end Kenni's session.
@app.route("/auth/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect("/")


# RP-initiated logout: clear the local session first, then redirect the
# browser to Kenni's end_session_endpoint with id_token_hint +
# post_logout_redirect_uri. Order matters — if the Kenni redirect fails,
# the local session is still cleared.
@app.route("/auth/rp-logout", methods=["POST"])
def rp_logout():
    metadata = oauth.kenni.load_server_metadata()
    end_session = metadata.get("end_session_endpoint")
    if not end_session:
        return ("issuer does not advertise end_session_endpoint", 500)
    id_token = session.get("id_token")
    session.clear()
    params = {
        "client_id": CLIENT_ID,
        "post_logout_redirect_uri": url_for("index", _external=True),
    }
    if id_token:
        params["id_token_hint"] = id_token
    return redirect(f"{end_session}?{urlencode(params)}")


# ---------- API endpoints ----------

@app.route("/api/me")
def me():
    """Server-side proxy. Pulls the user's stored Kenni access token and uses
    it to call our own /api/protected-resource. The access token never leaves
    the server."""
    if not API_ENABLED:
        return jsonify(error="KENNI_API_SCOPE is not configured on this app."), 503
    access_token = session.get("access_token")
    if not access_token:
        return jsonify(error="Not signed in."), 401

    base = request.host_url.rstrip("/")
    resp = requests.get(
        f"{base}/api/protected-resource",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
    )
    return (resp.text, resp.status_code, {"content-type": "application/json"})


@app.route("/api/client-credentials", methods=["POST"])
def client_credentials():
    """Token-endpoint exchange with HTTP Basic auth (RFC 6749 §2.3.1).
    Returns the decoded JWT claims so the demo proves the grant worked."""
    if not M2M_ENABLED:
        return jsonify(
            error="Set KENNI_M2M_CLIENT_ID, KENNI_M2M_CLIENT_SECRET, and KENNI_M2M_SCOPE."
        ), 503

    metadata = oauth.kenni.load_server_metadata()
    token_endpoint = metadata["token_endpoint"]

    # RFC 6749 §2.3.1: form-urlencode each credential before joining and
    # base64-encoding for HTTP Basic. requests' default `auth=(id, secret)`
    # skips the percent-encoding step, which breaks if the secret contains
    # a `:` or a `%`.
    basic = base64.b64encode(
        f"{quote(M2M_CLIENT_ID)}:{quote(M2M_CLIENT_SECRET)}".encode()
    ).decode()

    resp = requests.post(
        token_endpoint,
        data={"grant_type": "client_credentials", "scope": M2M_SCOPE},
        headers={
            "Authorization": f"Basic {basic}",
            "Accept": "application/json",
        },
        timeout=10,
    )
    if resp.status_code != 200:
        try:
            detail = resp.json()
        except ValueError:
            detail = resp.text
        return jsonify(error="Token endpoint rejected the request.", detail=detail), resp.status_code

    body = resp.json()
    return jsonify(
        token_type=body.get("token_type"),
        expires_in=body.get("expires_in"),
        scope=body.get("scope"),
        claims=_decode_jwt_claims(body.get("access_token", "")),
    )


@app.route("/api/protected-resource")
def protected_resource():
    """Bearer-protected endpoint demonstrating local access-token verification.
    Verifies signature (via Kenni's JWKS), issuer, audience, and expiry.
    Then asserts the configured KENNI_API_SCOPE is present on the token."""
    if not API_ENABLED:
        return jsonify(error="KENNI_API_SCOPE is not configured on this app."), 503

    authz = request.headers.get("Authorization", "")
    if not authz.lower().startswith("bearer "):
        return jsonify(error="Missing Authorization: Bearer header."), 401
    raw = authz[7:].strip()

    try:
        claims = jose_jwt.decode(
            raw,
            _get_jwks(),
            claims_options={
                "iss": {"essential": True, "value": ISSUER},
                "aud": {"essential": True, "value": API_AUDIENCE},
                "exp": {"essential": True},
            },
        )
        claims.validate()
    except JoseError as e:
        return jsonify(error="Token verification failed.", detail=str(e)), 401

    scope_value = claims.get("scope") or ""
    scopes = scope_value.split() if isinstance(scope_value, str) else list(scope_value)
    if API_SCOPE not in scopes:
        return jsonify(
            error=f"Token is missing required scope '{API_SCOPE}'.", scopes=scopes
        ), 403

    exp = claims.get("exp")
    return jsonify(
        message="Halló!",
        served_by="Python (Flask + Authlib) example",
        sub=claims.get("sub"),
        national_id=claims.get("national_id"),
        scopes=scopes,
        expires_at=datetime.fromtimestamp(exp, tz=timezone.utc).isoformat() if exp else None,
    )


# ---------- Helpers ----------

_jwks_cache = None


def _get_jwks():
    """Fetch + cache the issuer's JWKS for access-token verification."""
    global _jwks_cache
    if _jwks_cache is None:
        metadata = oauth.kenni.load_server_metadata()
        jwks = requests.get(metadata["jwks_uri"], timeout=10).json()
        _jwks_cache = JsonWebKey.import_key_set(jwks)
    return _jwks_cache


def _decode_jwt_claims(token: str):
    """Decode (without verification) a JWT's payload for display."""
    parts = token.split(".")
    if len(parts) != 3:
        return None  # opaque token
    pad = "=" * (-len(parts[1]) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(parts[1] + pad))
    except (ValueError, json.JSONDecodeError):
        return None


if __name__ == "__main__":
    # threaded=True so /api/me's internal request to /api/protected-resource
    # doesn't deadlock against itself.
    app.run(host="localhost", port=5001, debug=True, threaded=True)

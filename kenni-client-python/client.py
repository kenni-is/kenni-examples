from dataclasses import dataclass, asdict
import urllib.parse
import uuid
import secrets
import requests
import logging
import hashlib
import base64
import json
import re

from fastapi import FastAPI, Depends, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from jose import jwt

import constants
import utils

# Configure the logging format and level
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)


@dataclass
class AuthenticationRequestQueryParams:
    client_id: str
    redirect_uri: str
    response_type: str
    response_mode: str
    scope: str
    state: str
    nonce: str
    code_challenge: str
    code_challenge_method: str


@dataclass
class AuthenticationResponseQueryParams:
    code: str | None = None
    scope: str | None = None
    state: str | None = None
    session_state: str | None = None
    iss: str | None = None
    error: str | None = None


# It would be better to get these endpoints from the discovery endpoint
# or better yet, infer the discovery url from the issuer url
AUTH_ENDPOINT = f"{constants.ISSUER}/oidc/auth"
TOKEN_ENDPOINT = f"{constants.ISSUER}/oidc/token"
JWKS_ENDPOINT = f"{constants.ISSUER}/oidc/jwks"

LOGGER = logging.getLogger(__name__)

app = FastAPI()

#################################################
# Routes:
#
# * /                          Serves the main page
# * /authenticate              The users wants to login
# * /authentication_response   Receives the result from the oidc provider, logs the user in on success
# * /logged_in                 Serves the page for logged in users
# * /logout                    User logout
# * /get_protected_resource    Gets a protected resource


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):

    main_page = get_page("./static/index.html")
    response = HTMLResponse(content=main_page)
    _, response = create_session(request, response)

    return response


@app.get("/authenticate")
async def redirect_to_user_to_oidc_login(request: Request):
    """
    This route starts the authentication flow for a user,
    it redirects the user to the oidc provider's login page
    """

    session_id = get_session_id(request)
    if session_id is None:
        return RedirectResponse("/")

    code_verifier = generate_code_verifier()
    set_session_value(session_id, "code_verifier", code_verifier)

    query_params = AuthenticationRequestQueryParams(
        client_id=constants.CLIENT_ID,
        redirect_uri=constants.REDIRECT_URL,
        response_type="code",
        response_mode="query",
        scope=constants.SCOPE,
        state=secrets.token_urlsafe(32),
        nonce=secrets.token_urlsafe(32),
        code_challenge=generate_code_challenge(code_verifier),
        code_challenge_method="S256",
    )

    authentication_request_url = (
        f"{AUTH_ENDPOINT}?{urllib.parse.urlencode(asdict(query_params))}"
    )
    response = RedirectResponse(authentication_request_url)

    return response


@app.get("/authentication_response")
async def code_exchange(
    request: Request, query_params: AuthenticationResponseQueryParams = Depends()
):
    """
    This route receives the code from the oidc provider in the query parameters.
    It then exchanges the code for an access token by POSTing it to the token endpoint.
    """

    session_id = get_session_id(request)
    if session_id is None:
        return RedirectResponse("/")

    code_verifier = get_session_value(request, "code_verifier")
    tokens = exchange_code_for_tokens(query_params.code, code_verifier)
    if tokens is None:
        return RedirectResponse("/")
    else:
        # If an access token was granted store the token in the session and log the user in
        set_session_value(session_id, "id_token", tokens["id_token"])
        set_session_value(session_id, "access_token", tokens["access_token"])
        set_session_value(session_id, "logged_in", True)
        return RedirectResponse("/logged_in")


@app.get("/logged_in")
async def serve_logged_in_page(request: Request):

    # Make sure the user is logged in
    if is_logged_in(request) is not True:
        return RedirectResponse("/")

    logged_in_page = get_page("./static/logged_in.html")

    # Obtain the user's name from the identity provider and insert it into the page
    id_token = get_session_value(request, "id_token")
    name = get_name_from_id_token(id_token)

    logged_in_page = insert_name_into_html(logged_in_page, name)

    return HTMLResponse(content=logged_in_page)


@app.get("/logout")
async def logout(request: Request):

    if is_logged_in(request) is True:
        delete_session(request)

    return RedirectResponse("/")


@app.get("/get_protected_resource")
async def get_protected_resource(request: Request):
    """
    Request a protected resource from the protected endpoint
    We supply the access token using the Bearer authorization scheme
    """
    access_token = get_session_value(request, "access_token")
    protected_resource_endpoint = f"{constants.API_URL}/get_protected_resource"
    headers = {"Accept": "application/json", "Authorization": f"Bearer {access_token}"}

    response = requests.get(protected_resource_endpoint, headers=headers)
    data = response.json()

    if response.status_code == 200:
        out = data["payload"]
    else:
        out = json.dumps(data)

    return out


#################################################
# Functions used in routes


def exchange_code_for_tokens(code: str, code_verifier: str):
    """
    Exchange the code for an access token by posting the code to the token endpoint
    """

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {
        "grant_type": "authorization_code",
        "redirect_uri": constants.REDIRECT_URL,
        "code": code,
        "client_id": constants.CLIENT_ID,
        "client_secret": constants.CLIENT_SECRET,
        "code_verifier": code_verifier,
    }

    # POST the code to the oidc server's token endpoint
    response = requests.post(TOKEN_ENDPOINT, headers=headers, data=data)

    access_token = response.json().get("access_token", None)
    id_token = response.json().get("id_token", None)

    return {"access_token": access_token, "id_token": id_token}


def get_name_from_id_token(id_token):
    decoded_header = jwt.get_unverified_header(id_token)
    kid = decoded_header.get("kid", "")  # get the key id
    alg = decoded_header.get("alg", "")  # get the signing algorithm
    key = utils.get_key_from_oidc_provider(kid)

    # Validate the jwt
    payload = jwt.decode(
        id_token,
        key,
        algorithms=[alg],
        audience=constants.CLIENT_ID,
        options={"verify_at_hash": False},
    )

    return payload["name"]


def get_page(path):
    with open(path, "r") as f:
        page = f.read()
    return page


def is_logged_in(request: Request):
    """
    Checks if the current session is logged in
    """
    return get_session_value(request, "logged_in")


def insert_name_into_html(page, name):
    pattern = r"===NAME==="
    page = re.sub(pattern, name, page, flags=re.MULTILINE)
    return page


def generate_code_verifier(length=64):
    return secrets.token_urlsafe(length)


def generate_code_challenge(verifier):
    """Generate a code challenge from the code verifier."""
    sha256_verifier = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(sha256_verifier).rstrip(b"=").decode()


#################################################
# session management function

SERVER_SESSION_STORAGE = {}
COOKIE_NAME = "kenni.python.example"


def get_session_id(request: Request) -> str | None:
    session_id = request.cookies.get(COOKIE_NAME, None)
    if session_id in SERVER_SESSION_STORAGE:
        return session_id
    else:
        return None


def create_session(request: Request, response: Response) -> (str, Response):  # type: ignore
    session_id = get_session_id(request)
    if session_id is None:
        session_id = uuid.uuid4().hex
        response.set_cookie(COOKIE_NAME, session_id)
        SERVER_SESSION_STORAGE[session_id] = {}
    else:
        if session_id not in SERVER_SESSION_STORAGE:
            SERVER_SESSION_STORAGE[session_id] = {}

    return session_id, response


def delete_session(request: Request):
    session_id = get_session_id(request)
    if session_id is not None:
        SERVER_SESSION_STORAGE[session_id] = {}


def get_session_value(request, key):
    session_id = get_session_id(request)
    return SERVER_SESSION_STORAGE.get(session_id, {}).get(key, None)


def set_session_value(session_id, key, value):
    SERVER_SESSION_STORAGE[session_id][key] = value

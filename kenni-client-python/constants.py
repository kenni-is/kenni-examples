from dotenv import load_dotenv

load_dotenv()

import os

APP_URL = "http://localhost:4007"
API_URL = "http://localhost:4008"

ISSUER = os.getenv("ISSUER")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
API_SCOPE_NAME = os.getenv("API_SCOPE_NAME")
SCOPE = f"{os.getenv("SCOPE")} {API_SCOPE_NAME}"
REDIRECT_URL = f"{APP_URL}/authentication_response/"  # Whitelist this redirect url
ACCESS_TOKEN_AUDIENCE = f"{CLIENT_ID}-api"

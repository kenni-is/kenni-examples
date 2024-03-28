from typing import Annotated
import logging
import requests

from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

# Configure the logging format and level
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

LOGGER = logging.getLogger(__name__)

TEAM_DOMAIN = "some-team-domain"
API_SCOPE_NAME = "some-api-scope"
OPENID_PROVIDER = "https://idp.kenni.is"
ISSUER = f"{OPENID_PROVIDER}/{TEAM_DOMAIN}"
ACCESS_TOKEN_AUDIENCE = "some-audience" ## FORMAT @<client-id>-api f.ex @kenni.is/test-api
PROTECTED_RESOURCE = "Congrats, you are accessing a protected resource 🎉..."

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


@app.get("/get_protected_resource")
async def get_protected_resource(access_token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        decoded_header = jwt.get_unverified_header(access_token)
        kid = decoded_header.get('kid', "")         # get the key id
        alg = decoded_header.get('alg', "")         # get the signing algorithm
        key = get_key_from_oidc_provider(kid)

        # Validate the jwt
        payload = jwt.decode(access_token, key, algorithms=[alg], audience=ACCESS_TOKEN_AUDIENCE, issuer=ISSUER)

        # Check if the correct scope is included
        # This API will only return the protected string
        # if API_SCOPE_NAME is included in the token
        if API_SCOPE_NAME not in payload.get("scope", []):
            raise credentials_exception

    except JWTError as e:
        LOGGER.error(e)
        raise credentials_exception

    return {"payload": PROTECTED_RESOURCE}



def get_key_from_oidc_provider(kid: str):
    """
    Get the JSON Web Key Set from the oidc provider

    Return the key that matches the key identifier (kid)
    """
    jwks_endpoint = f"{OPENID_PROVIDER}/oidc/test-1/jwks"
    response = requests.get(jwks_endpoint)
    jwks = response.json()
    desired_key = {}

    for key in jwks.get('keys', []):
        if key.get('kid') == kid:
                desired_key = key

    return desired_key

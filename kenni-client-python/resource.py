from typing import Annotated
import logging

from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

import constants
import utils

# Configure the logging format and level
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

LOGGER = logging.getLogger(__name__)
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
        kid = decoded_header.get("kid", "")  # get the key id
        alg = decoded_header.get("alg", "")  # get the signing algorithm
        key = utils.get_key_from_oidc_provider(kid)

        # Validate the jwt
        payload = jwt.decode(
            access_token,
            key,
            algorithms=[alg],
            audience=constants.ACCESS_TOKEN_AUDIENCE,
            issuer=constants.ISSUER,
        )

        # Check if the correct scope is included
        # This API will only return the protected string
        # if API_SCOPE_NAME is included in the token
        if constants.API_SCOPE_NAME not in payload.get("scope", []):
            raise credentials_exception

    except JWTError as e:
        LOGGER.error(e)
        raise credentials_exception

    return {"payload": PROTECTED_RESOURCE}

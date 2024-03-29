import requests

import constants


def get_key_from_oidc_provider(kid: str):
    """
    Get the JSON Web Key Set from the oidc provider

    Return the key that matches the key identifier (kid)
    """
    jwks_endpoint = f"{constants.ISSUER}/oidc/jwks"
    response = requests.get(jwks_endpoint)
    jwks = response.json()
    desired_key = {}

    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            desired_key = key

    return desired_key

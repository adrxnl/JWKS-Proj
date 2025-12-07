# app/security.py

from datetime import datetime, timedelta, timezone
from jose import jwt

def create_jwt(key_data: dict, is_expired_token: bool) -> str:
    """
    Creates and signs a JSON Web Token.

    Args:
        key_data: The key data dictionary containing the private key and kid.
        is_expired_token: If True, the JWT's 'exp' claim will be in the past.

    Returns:
        The signed JWT as a string.
    """
    private_key = key_data["private_key"]
    kid = key_data["kid"]
    now = datetime.now(timezone.utc)
    
    # Sets token expiry
    if is_expired_token:
        token_exp = now - timedelta(minutes=15)
    else:
        token_exp = now + timedelta(minutes=15)

    # Standard claims for the JWT payload
    payload = {
        "iss": "gemini-jwks-server",
        "sub": "testuser",
        "aud": "test-client",
        "iat": int(now.timestamp()),
        "exp": int(token_exp.timestamp()),
        "user": "testuser" # Custom claim
    }

    # Headers for the JWT, including the Key ID
    headers = {"kid": kid, "alg": "RS256"}
    
    token = jwt.encode(
        claims=payload,
        key=private_key,
        algorithm="RS256",
        headers=headers
    )
    
    return token
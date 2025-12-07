# tests/test_api.py

import pytest
from fastapi.testclient import TestClient
from jose import jwt, jwk

from app.main import app
from app.keys import KEY_STORE


@pytest.fixture
def client():
    """
    A pytest fixture that provides a TestClient instance.
    This uses a context manager to ensure lifespan events are triggered.
    """
    KEY_STORE.clear()  
    with TestClient(app) as test_client:
        yield test_client


def test_get_jwks_endpoint(client):
    """
    Tests that the JWKS endpoint returns only valid keys.
    """
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    
    jwks = response.json()
    assert "keys" in jwks
    assert isinstance(jwks["keys"], list)
    # The endpoint should only return the valid key.
    assert len(jwks["keys"]) == 1 
    
    # Find the expired key's kid in our global store to double-check
    expired_kid = next(
        (k["kid"] for k in KEY_STORE if k["expiry"].timestamp() < k["expiry"].now().timestamp()), None
    )
    
    # Ensure the expired key's kid is NOT in the JWKS response
    jwks_kids = {key["kid"] for key in jwks["keys"]}
    assert expired_kid is not None
    assert expired_kid not in jwks_kids


def test_auth_endpoint_valid_jwt(client):
    """
    Tests the /auth endpoint for a valid JWT.
    Verifies the token using the public key from the JWKS endpoint.
    """
    # 1. Get the JWKS to find the public key for verification
    jwks_response = client.get("/.well-known/jwks.json")
    jwks = jwks_response.json()
    public_key_jwk = jwks["keys"][0]
    public_key = jwk.construct(public_key_jwk)

    # 2. Request a valid JWT from the /auth endpoint
    auth_response = client.post("/auth")
    assert auth_response.status_code == 200
    token = auth_response.text

    # 3. Verify the token
    token_kid = jwt.get_unverified_header(token).get("kid")
    assert token_kid == public_key_jwk["kid"]

    decoded_token = jwt.decode(
        token, 
        public_key, 
        algorithms=["RS265", "RS256"],
        audience="test-client"
    )
    assert decoded_token["user"] == "testuser"


def test_auth_endpoint_expired_jwt(client):
    """
    Tests the /auth?expired=true endpoint.
    Ensures it returns a JWT signed by an expired key.
    """
    # 1. Get a token that should be signed by an expired key
    auth_response = client.post("/auth?expired=true")
    assert auth_response.status_code == 200
    token = auth_response.text

    # 2. Get the kid from the token's header
    token_kid = jwt.get_unverified_header(token).get("kid")
    assert token_kid is not None

    # 3. Verify this kid corresponds to an expired key
    jwks_response = client.get("/.well-known/jwks.json")
    jwks_kids = {key["kid"] for key in jwks_response.json()["keys"]}
    assert token_kid not in jwks_kids
    
    # 4. Find the expired key in our backend store to test this
    expired_key_data = next(
        (k for k in KEY_STORE if k["kid"] == token_kid), None
    )
    assert expired_key_data is not None
    
    public_key = jwk.construct(expired_key_data["public_jwk"])
    
    with pytest.raises(jwt.ExpiredSignatureError):
        # This decode should fail because the token's 'exp' claim is in the past
        jwt.decode(
            token, 
            public_key, 
            algorithms=["RS265", "RS256"], 
            audience="test-client"
        )
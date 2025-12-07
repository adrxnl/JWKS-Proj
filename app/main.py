# app/main.py

from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Response
from . import keys, security

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Handles application startup events.
    On startup, this will generate the initial RSA key pairs required for the app.
    """
    # Generates a valid key that expires in 1 hour
    keys.generate_rsa_key(expires_in_seconds=3600)
    # Generates an expired key that expired 1 hour ago
    keys.generate_rsa_key(expires_in_seconds=-3600)
    yield

# Initialize the FastAPI application, passing in the lifespan manager
app = FastAPI(
    title="JWKS Server",
    description="A simple server to provide JWKS and issue JWTs.",
    version="1.0.0",
    lifespan=lifespan,
)

@app.post("/auth")
async def authenticate_and_get_jwt(expired: bool = False):
    """
    Issues a signed JWT.
    - If `expired=false` (default), uses a valid key and sets a future 'exp' claim.
    - If `expired=true`, uses an expired key and sets a past 'exp' claim.
    """
    key_to_use = keys.get_key_by_status(is_expired=expired)
    
    if not key_to_use:
        raise HTTPException(
            status_code=500,
            detail="Could not find an appropriate key to sign the JWT."
        )
        
    token = security.create_jwt(
        key_data=key_to_use, 
        is_expired_token=expired
    )
    
    return Response(content=token, media_type="text/plain")


@app.get("/.well-known/jwks.json")
async def get_jwks():
    """
    Serves the JSON Web Key Set (JWKS).
    This endpoint only returns the public keys for keys that have not expired.
    """
    valid_keys = keys.get_valid_public_jwks()
    return {"keys": valid_keys}
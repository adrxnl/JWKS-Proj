# app/main.py
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Response, Request, status
from pydantic import BaseModel
from collections import deque
import time
from . import keys, security

# Simple in-memory rate limiter using a sliding window
request_timestamps = deque()

def is_rate_limited(limit=10, window_seconds=1):
    now = time.time()
    # Remove timestamps older than the window
    while request_timestamps and request_timestamps[0] < now - window_seconds:
        request_timestamps.popleft()
    
    if len(request_timestamps) >= limit:
        return True
    
    request_timestamps.append(now)
    return False

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize DB (create tables)
    keys.init_db()
    # Generate keys
    keys.generate_rsa_key(expires_in_seconds=3600)
    keys.generate_rsa_key(expires_in_seconds=-3600)
    yield

app = FastAPI(
    title="JWKS Server",
    version="1.0.0",
    lifespan=lifespan,
)

# Pydantic model for user registration
class UserRegister(BaseModel):
    username: str
    email: str

@app.post("/register", status_code=201)
async def register_user(user: UserRegister):
    password = keys.create_user(user.username, user.email)
    if not password:
        raise HTTPException(status_code=400, detail="Username or Email already exists.")
    
    return {"password": password}

@app.post("/auth")
async def authenticate_and_get_jwt(request: Request, expired: bool = False):
    # 1. Rate Limiting Check
    if is_rate_limited():
        raise HTTPException(
            status_code=429, 
            detail="Too Many Requests"
        )

    # 2. Key Selection
    key_to_use = keys.get_key_by_status(is_expired=expired)
    if not key_to_use:
        raise HTTPException(status_code=500, detail="No key found.")
    
    # 3. Handle Logging (If a user is authenticated)
    # NOTE: The requirements say "For each POST:/auth request, log... User ID".
    # This implies we should try to identify the user if credentials are provided.
    user_id = None
    
    # Try to parse JSON body for login credentials (optional but needed for logging ID)
    try:
        body = await request.json()
        if "username" in body:
            # NOTE: For this assignment, we just need the ID for logging.
            # In a real app, you would verify the password here using security.verify_password
            # For now, we will just look up the ID if you implemented a helper, 
            # or just log a dummy ID if not strictly requiring login for Part 2.
            # Let's assuming the logging requirement expects a valid User ID from the DB.
            conn = keys.get_db_connection()
            row = conn.execute("SELECT id FROM users WHERE username = ?", (body["username"],)).fetchone()
            conn.close()
            if row:
                user_id = row['id']
    except:
        pass # Ignore if no JSON body (Part 1 backward compatibility)

    # 4. Generate Token
    token = security.create_jwt(key_to_use, expired)
    
    # 5. Log the request (only if successful)
    if user_id:
        keys.log_auth_request(request.client.host, user_id)
    
    return Response(content=token, media_type="text/plain")


@app.get("/.well-known/jwks.json")
async def get_jwks():
    valid_keys = keys.get_valid_public_jwks()
    return {"keys": valid_keys}
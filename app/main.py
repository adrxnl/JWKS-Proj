from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Response, Request
from pydantic import BaseModel
import time
from collections import deque  # <--- ADD THIS IMPORT
from . import keys, security

# RATE LIMITER: Sliding Window Log
# We store the timestamp of each request. 
# On a new request, we remove timestamps older than 1 second.
# If the remaining count is >= limit, we block.
request_timestamps = deque()

def is_rate_limited(limit: int = 10, window_seconds: int = 1) -> bool:
    global request_timestamps
    now = time.time()
    
    # 1. Clean up: Remove timestamps older than our window
    while request_timestamps and now - request_timestamps[0] > window_seconds:
        request_timestamps.popleft()
    
    # 2. Check Limit: If we still have 10 or more items, we are full
    if len(request_timestamps) >= limit:
        return True
    
    # 3. Allow: Add the current timestamp
    request_timestamps.append(now)
    return False

@asynccontextmanager
async def lifespan(app: FastAPI):
    keys.init_db()
    # Generate keys so JWKS is populated
    keys.generate_rsa_key(expires_in_seconds=3600)
    keys.generate_rsa_key(expires_in_seconds=-3600)
    yield

app = FastAPI(
    title="JWKS Server",
    version="1.0.0",
    lifespan=lifespan,
)

class UserRegister(BaseModel):
    username: str
    email: str

@app.post("/register", status_code=201)
async def register_user(user: UserRegister):
    try:
        password = keys.create_user(user.username, user.email)
        if not password:
            raise HTTPException(status_code=400, detail="Username or Email already exists.")
        return {"password": password}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/auth")
async def authenticate_and_get_jwt(request: Request, expired: bool = False):
    # 1. Rate Limiting Check
    if is_rate_limited(limit=10, window_seconds=1):
        raise HTTPException(status_code=429, detail="Too Many Requests")

    # 2. Key Selection
    key_to_use = keys.get_key_by_status(is_expired=expired)
    if not key_to_use:
        raise HTTPException(status_code=500, detail="No key found.")
    
    # 3. Log the request (Try to get User ID)
    user_id = None
    try:
        body = await request.json()
        if "username" in body:
            conn = keys.get_db_connection()
            row = conn.execute("SELECT id FROM users WHERE username = ?", (body["username"],)).fetchone()
            conn.close()
            if row:
                user_id = row['id']
    except:
        pass 

    # 4. Generate Token
    token = security.create_jwt(key_to_use, expired)
    
    # 5. Log to DB (Requirement: Only requests that succeed should be logged)
    if user_id:
        keys.log_auth_request(request.client.host, user_id)
    
    return Response(content=token, media_type="text/plain")

@app.get("/.well-known/jwks.json")
async def get_jwks():
    valid_keys = keys.get_valid_public_jwks()
    return {"keys": valid_keys}
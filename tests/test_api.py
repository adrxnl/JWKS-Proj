# tests/test_api.py

import pytest
import os
import time
import uuid
from fastapi.testclient import TestClient
from jose import jwt, jwk

# Import the app and keys module to access DB functions
from app.main import app
from app import keys

@pytest.fixture
def client():
    """
    Setup: Removes the database file to ensure a fresh start for every test run.
    """
    if os.path.exists(keys.DB_NAME):
        os.remove(keys.DB_NAME)
        
    with TestClient(app) as test_client:
        yield test_client
        
    # Teardown: Clean up after tests (optional)
    if os.path.exists(keys.DB_NAME):
        os.remove(keys.DB_NAME)

def test_get_jwks_endpoint(client):
    """Tests that the JWKS endpoint returns keys."""
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    
    jwks = response.json()
    assert "keys" in jwks
    assert len(jwks["keys"]) > 0 

def test_register_user(client):
    """Tests that a user can register and get a password."""
    username = f"user_{uuid.uuid4()}"
    payload = {"username": username, "email": f"{username}@example.com"}
    
    response = client.post("/register", json=payload)
    
    assert response.status_code == 201
    data = response.json()
    assert "password" in data
    # Verify password is a UUID
    assert len(data["password"]) == 36 

def test_register_duplicate_user(client):
    """Tests that duplicate registration fails."""
    payload = {"username": "duplicate", "email": "dup@example.com"}
    
    # First registration
    response1 = client.post("/register", json=payload)
    assert response1.status_code == 201
    
    # Second registration
    response2 = client.post("/register", json=payload)
    assert response2.status_code == 400

def test_auth_logs_request(client):
    """
    Tests that a successful auth request is logged in the database.
    """
    # 1. Register a user
    username = "log_user"
    client.post("/register", json={"username": username, "email": "log@test.com"})
    
    # 2. Authenticate
    # We send the username in the body so the server can identify the user ID
    auth_response = client.post("/auth", json={"username": username})
    assert auth_response.status_code == 200
    
    # 3. Manually check the database for the log entry
    conn = keys.get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM auth_logs")
    logs = c.fetchall()
    conn.close()
    
    assert len(logs) > 0
    assert logs[0]['request_ip'] == "testclient" # Default IP for TestClient

def test_rate_limiter(client):
    """
    Tests that the 11th request within 1 second fails with 429.
    """
    # Make 10 allowed requests
    for _ in range(10):
        response = client.post("/auth")
        assert response.status_code == 200
        
    # The 11th request should fail
    response = client.post("/auth")
    assert response.status_code == 429
    assert "Too Many Requests" in response.json()["detail"]

def test_auth_expired_jwt(client):
    """Tests retrieval of an expired token."""
    response = client.post("/auth?expired=true")
    assert response.status_code == 200
    token = response.text
    
    # Check headers for kid
    header = jwt.get_unverified_header(token)
    assert "kid" in header
    
    # Verify it really is expired
    # We need to manually construct the key to verify signature, 
    # but simplest check is seeing if decode fails due to expiration
    key_data = keys.get_key_by_status(is_expired=True)
    
    # If we found the key in DB, try decoding
    if key_data:
        public_key = key_data["private_key"].public_key()
        
        with pytest.raises(jwt.ExpiredSignatureError):
            jwt.decode(
                token, 
                key=public_key,
                algorithms=["RS256"],
                audience="test-client"
            )
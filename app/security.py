# app/security.py
import os
import uuid
import base64
from datetime import datetime, timedelta, timezone
from jose import jwt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Initialize Password Hasher (Argon2)
ph = PasswordHasher()

def get_encryption_key():
    """Retrieves and formats the encryption key from environment variables."""
    key = os.environ.get("NOT_MY_KEY", "default_insecure_key_for_dev_only")
    # AESGCM requires a 32-byte key for 256-bit encryption. 
    # We pad or truncate the env var to ensure it fits.
    return key.ljust(32, '0')[:32].encode('utf-8')

def encrypt_private_key(pem_bytes: bytes) -> tuple[bytes, bytes]:
    """
    Encrypts the private key using AES-GCM.
    Returns: (encrypted_data, iv)
    """
    key = get_encryption_key()
    aesgcm = AESGCM(key)
    iv = os.urandom(12)  # NIST recommends a 12-byte IV for GCM
    ciphertext = aesgcm.encrypt(iv, pem_bytes, None)
    return ciphertext, iv

def decrypt_private_key(ciphertext: bytes, iv: bytes) -> bytes:
    """Decrypts the private key using AES-GCM."""
    key = get_encryption_key()
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext, None)

def hash_password(password: str) -> str:
    """Hashes a password using Argon2."""
    return ph.hash(password)

def verify_password(hash: str, password: str) -> bool:
    """Verifies a password against an Argon2 hash."""
    try:
        return ph.verify(hash, password)
    except VerifyMismatchError:
        return False

def create_jwt(key_data: dict, is_expired_token: bool) -> str:
    private_key = key_data["private_key"]
    kid = key_data["kid"]
    now = datetime.now(timezone.utc)
    
    if is_expired_token:
        token_exp = now - timedelta(minutes=15)
    else:
        token_exp = now + timedelta(minutes=15)

    payload = {
        "iss": "gemini-jwks-server",
        "sub": "testuser",
        "aud": "test-client",
        "iat": int(now.timestamp()),
        "exp": int(token_exp.timestamp()),
        "user": "testuser"
    }

    headers = {"kid": kid, "alg": "RS256"}
    
    token = jwt.encode(
        claims=payload,
        key=private_key,
        algorithm="RS256",
        headers=headers
    )
    
    return token
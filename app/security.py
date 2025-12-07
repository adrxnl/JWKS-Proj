import os
from datetime import datetime, timedelta, timezone
from jose import jwt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Initialize Password Hasher
# If this line fails, 'pip install argon2-cffi' is needed
ph = PasswordHasher()

def get_encryption_key():
    key = os.environ.get("NOT_MY_KEY", "default_insecure_key_for_dev_only")
    return key.ljust(32, '0')[:32].encode('utf-8')

def encrypt_private_key(pem_bytes: bytes) -> tuple[bytes, bytes]:
    key = get_encryption_key()
    aesgcm = AESGCM(key)
    iv = os.urandom(12)
    ciphertext = aesgcm.encrypt(iv, pem_bytes, None)
    return ciphertext, iv

def decrypt_private_key(ciphertext: bytes, iv: bytes) -> bytes:
    key = get_encryption_key()
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext, None)

def hash_password(password: str) -> str:
    return ph.hash(password)

def verify_password(hash: str, password: str) -> bool:
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
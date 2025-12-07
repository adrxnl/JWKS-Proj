# app/keys.py

import uuid
from datetime import datetime, timedelta, timezone

from jose import jwk
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

KEY_STORE = []

def generate_rsa_key(expires_in_seconds: int):
    """
    Generates an RSA key pair, its JWK representation, and stores it.

    Args:
        expires_in_seconds: The number of seconds until the key expires.
                            A negative value creates an already-expired key.
    
    Returns:
        A dictionary containing the key's metadata.
    """
    # Generating a new private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Generating a unique Key ID (kid)
    kid = str(uuid.uuid4())
    
    # Calculating the expiry timestamp
    now = datetime.now(timezone.utc)
    expiry_time = now + timedelta(seconds=expires_in_seconds)

    # Creating the public key JWK
    public_key = private_key.public_key()
    public_jwk = jwk.construct(public_key, algorithm="RS256").to_dict()
    public_jwk["kid"] = kid
    public_jwk["use"] = "sig" # Specifying key for signing

    key_data = {
        "kid": kid,
        "private_key": private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        "public_jwk": public_jwk,
        "expiry": expiry_time,
    }
    
    KEY_STORE.append(key_data)
    print(f"Generated key with kid: {kid}, expires at: {expiry_time}")
    return key_data


def get_valid_public_jwks() -> list:
    """
    Retrieves all non-expired public keys from the key store.
    
    Returns:
        A list of public keys in JWK format.
    """
    now = datetime.now(timezone.utc)
    return [k["public_jwk"] for k in KEY_STORE if k["expiry"] > now]


def get_key_by_status(is_expired: bool):
    """
    Finds the most recently generated key that is either expired or valid.
    
    Args:
        is_expired: If True, look for an expired key. Otherwise, a valid one.
        
    Returns:
        The key data dictionary or None if no matching key is found.
    """
    now = datetime.now(timezone.utc)
    
    if is_expired:
        candidates = [k for k in KEY_STORE if k["expiry"] <= now]
    else:
        candidates = [k for k in KEY_STORE if k["expiry"] > now]
    
    # Returns the most recently added key that matches the criteria
    return candidates[-1] if candidates else None
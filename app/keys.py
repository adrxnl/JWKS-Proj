# app/keys.py
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from jose import jwk
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from . import security

DB_NAME = "totally_not_my_privateKeys.db"

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database tables."""
    conn = get_db_connection()
    c = conn.cursor()
    
    # Table for Keys (Stores encrypted private key and IV)
    c.execute('''
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL,
            iv BLOB NOT NULL
        )
    ''')
    
    # Table for Users
    c.execute('''
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    # Table for Auth Logs
    c.execute('''
        CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    
    conn.commit()
    conn.close()

def generate_rsa_key(expires_in_seconds: int):
    """Generates an RSA key, encrypts it, and saves to DB."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Encrypt the PEM before storage
    encrypted_key, iv = security.encrypt_private_key(pem)
    
    now = datetime.now(timezone.utc)
    expiry_time = now + timedelta(seconds=expires_in_seconds)
    exp_int = int(expiry_time.timestamp())

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("INSERT INTO keys (key, exp, iv) VALUES (?, ?, ?)", (encrypted_key, exp_int, iv))
    conn.commit()
    conn.close()

def get_valid_public_jwks() -> list:
    """Retrieves all non-expired keys, decrypts them, and returns public JWKS."""
    conn = get_db_connection()
    c = conn.cursor()
    now_ts = int(datetime.now(timezone.utc).timestamp())
    
    c.execute("SELECT * FROM keys WHERE exp > ?", (now_ts,))
    rows = c.fetchall()
    conn.close()

    jwks = []
    for row in rows:
        # Decrypt private key to get public key
        pem = security.decrypt_private_key(row['key'], row['iv'])
        private_key = serialization.load_pem_private_key(pem, password=None)
        public_key = private_key.public_key()
        
        jwk_dict = jwk.construct(public_key, algorithm="RS256").to_dict()
        jwk_dict["kid"] = str(row['kid']) # Ensure kid is string
        jwk_dict["use"] = "sig"
        jwks.append(jwk_dict)
        
    return jwks

def get_key_by_status(is_expired: bool):
    """Finds a key (expired or valid) from DB."""
    conn = get_db_connection()
    c = conn.cursor()
    now_ts = int(datetime.now(timezone.utc).timestamp())
    
    if is_expired:
        c.execute("SELECT * FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1", (now_ts,))
    else:
        c.execute("SELECT * FROM keys WHERE exp > ? ORDER BY exp DESC LIMIT 1", (now_ts,))
        
    row = c.fetchone()
    conn.close()
    
    if row:
        pem = security.decrypt_private_key(row['key'], row['iv'])
        private_key = serialization.load_pem_private_key(pem, password=None)
        return {
            "kid": str(row['kid']),
            "private_key": private_key
        }
    return None

def create_user(username: str, email: str) -> str:
    """Creates a user with a UUID password and returns the password."""
    generated_password = str(uuid.uuid4())
    hashed_password = security.hash_password(generated_password)
    
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)", 
            (username, email, hashed_password)
        )
        conn.commit()
        return generated_password
    except sqlite3.IntegrityError:
        # User or email already exists
        return None
    finally:
        conn.close()

def log_auth_request(ip_address: str, user_id: int):
    """Logs the authentication request."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)", (ip_address, user_id))
    conn.commit()
    conn.close()
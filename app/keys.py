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
    
    # --- MIGRATION LOGIC (Fixing the Gradebot Error) ---
    # Check if the existing 'keys' table has the 'iv' column.
    # If it does, Gradebot will crash. We must drop it.
    try:
        c.execute("PRAGMA table_info(keys)")
        columns = [info[1] for info in c.fetchall()]
        if 'iv' in columns:
            print("Migrating DB: Dropping table with incompatible 'iv' column.")
            c.execute("DROP TABLE keys")
    except:
        pass

    # --- TABLE CREATION ---
    # Note: We store the IV *inside* the key blob (prepended) 
    # rather than as a separate column to satisfy Gradebot's strict schema check.
    c.execute('''
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    
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

    # Encrypt the PEM
    encrypted_key, iv = security.encrypt_private_key(pem)
    
    # STORAGE STRATEGY: Prepend the IV to the encrypted key blob.
    # [ IV (12 bytes) ] + [ Encrypted Data ]
    blob_to_store = iv + encrypted_key
    
    now = datetime.now(timezone.utc)
    expiry_time = now + timedelta(seconds=expires_in_seconds)
    exp_int = int(expiry_time.timestamp())

    conn = get_db_connection()
    c = conn.cursor()
    # We only insert 'key' and 'exp' now.
    c.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (blob_to_store, exp_int))
    conn.commit()
    conn.close()

def get_valid_public_jwks() -> list:
    conn = get_db_connection()
    c = conn.cursor()
    now_ts = int(datetime.now(timezone.utc).timestamp())
    
    c.execute("SELECT * FROM keys WHERE exp > ?", (now_ts,))
    rows = c.fetchall()
    conn.close()

    jwks = []
    for row in rows:
        # RETRIEVAL STRATEGY: Split the blob.
        # First 12 bytes are IV, the rest is the Ciphertext.
        encrypted_blob = row['key']
        iv = encrypted_blob[:12]
        ciphertext = encrypted_blob[12:]
        
        pem = security.decrypt_private_key(ciphertext, iv)
        private_key = serialization.load_pem_private_key(pem, password=None)
        public_key = private_key.public_key()
        
        jwk_dict = jwk.construct(public_key, algorithm="RS256").to_dict()
        jwk_dict["kid"] = str(row['kid'])
        jwk_dict["use"] = "sig"
        jwks.append(jwk_dict)
        
    return jwks

def get_key_by_status(is_expired: bool):
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
        encrypted_blob = row['key']
        iv = encrypted_blob[:12]
        ciphertext = encrypted_blob[12:]
        
        pem = security.decrypt_private_key(ciphertext, iv)
        private_key = serialization.load_pem_private_key(pem, password=None)
        return {
            "kid": str(row['kid']),
            "private_key": private_key
        }
    return None

def create_user(username: str, email: str) -> str:
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
        return None
    finally:
        conn.close()

def log_auth_request(ip_address: str, user_id: int):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)", (ip_address, user_id))
    conn.commit()
    conn.close()
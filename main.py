# JWKS server for Project 3 — handles key storage, JWT signing, and user registration
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
from argon2 import PasswordHasher
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
import base64
import hashlib
import json
import jwt
import datetime
import os
import sqlite3
import time
import uuid

load_dotenv()

hostName = "localhost"
serverPort = 8080
DB_FILE = "totally_not_my_privateKeys.db"
NOT_MY_KEY_ERROR = "NOT_MY_KEY environment variable is required for private key encryption"
AUTH_RATE_LIMIT = 10       # max requests per IP per window
AUTH_RATE_WINDOW_SECONDS = 1
auth_rate_buckets = {}     # tracks recent request timestamps per IP
password_hasher = PasswordHasher()


def int_to_base64(value):
    # converts a big integer (like RSA n or e) to base64url format for JWKS
    value_hex = format(value, "x")
    if len(value_hex) % 2 == 1:
        value_hex = "0" + value_hex  # hex needs even length for fromhex()
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b"=")
    return encoded.decode("utf-8")


def get_cipher():
    # builds a Fernet cipher from NOT_MY_KEY — sha256 hash turns any string into a valid 32-byte key
    secret = os.environ.get("NOT_MY_KEY")
    if not secret:
        raise RuntimeError(NOT_MY_KEY_ERROR)

    key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode("utf-8")).digest())
    return Fernet(key)


def encrypt_private_key(pem_bytes):
    # encrypt private key before saving to DB
    return get_cipher().encrypt(pem_bytes)


def decrypt_private_key(encrypted_pem_bytes):
    # decrypt private key when we need to sign a JWT
    try:
        return get_cipher().decrypt(encrypted_pem_bytes)
    except InvalidToken as exc:
        raise RuntimeError("Unable to decrypt private key with NOT_MY_KEY") from exc


def ensure_not_my_key():
    # fail fast at startup if NOT_MY_KEY is missing
    get_cipher()


def maybe_encrypt_existing_keys(cursor):
    # handles the case where keys were stored unencrypted (e.g., from an older version)
    cursor.execute("SELECT kid, key FROM keys")
    for kid, key_bytes in cursor.fetchall():
        if isinstance(key_bytes, str):
            key_bytes = key_bytes.encode("utf-8")

        if key_bytes.startswith(b"-----BEGIN"):
            # still in plaintext PEM format — encrypt it now
            cursor.execute(
                "UPDATE keys SET key = ? WHERE kid = ?",
                (encrypt_private_key(key_bytes), kid)
            )


def init_db():
    # set up the database tables on first run
    ensure_not_my_key()
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # stores RSA private keys (encrypted) with expiry timestamps
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    """)

    # stores registered users with hashed passwords
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    """)

    # audit log — records every successful /auth request
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    maybe_encrypt_existing_keys(cursor)
    conn.commit()
    conn.close()


def generate_private_key():
    # generate a 2048-bit RSA key pair
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


def private_key_to_pem(private_key):
    # serialize key to PEM bytes (unencrypted — we encrypt it ourselves before storing)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )


def seed_keys():
    # insert one valid and one already-expired key pair on first startup
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM keys")
    count = cursor.fetchone()[0]

    if count == 0:
        valid_key = generate_private_key()
        expired_key = generate_private_key()

        valid_pem = private_key_to_pem(valid_key)
        expired_pem = private_key_to_pem(expired_key)

        now = int(time.time())
        valid_exp = now + 3600    # expires in 1 hour
        expired_exp = now - 3600  # already expired 1 hour ago

        cursor.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (encrypt_private_key(valid_pem), valid_exp)
        )
        cursor.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (encrypt_private_key(expired_pem), expired_exp)
        )

        conn.commit()

    conn.close()


def get_signing_key(use_expired=False):
    # fetch a valid or expired key from the DB depending on what the caller needs
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    now = int(time.time())

    if use_expired:
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY kid LIMIT 1",
            (now,)
        )
    else:
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid LIMIT 1",
            (now,)
        )

    row = cursor.fetchone()
    conn.close()
    return row


def get_user_id(username):
    # look up user ID by username — returns None if not found
    if not username:
        return None

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None


def log_successful_auth(request_ip, username=None):
    # write auth event to the log and update last_login for the user
    user_id = get_user_id(username)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)",
        (request_ip, user_id)
    )
    if user_id is not None:
        cursor.execute(
            "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
            (user_id,)
        )
    conn.commit()
    conn.close()


def is_auth_rate_limited(request_ip):
    # sliding window rate limiter — blocks IPs that hit /auth too many times per second
    now = time.time()
    window_start = now - AUTH_RATE_WINDOW_SECONDS
    # drop timestamps older than the window
    timestamps = [
        timestamp
        for timestamp in auth_rate_buckets.get(request_ip, [])
        if timestamp > window_start
    ]

    if len(timestamps) >= AUTH_RATE_LIMIT:
        auth_rate_buckets[request_ip] = timestamps
        return True

    timestamps.append(now)
    auth_rate_buckets[request_ip] = timestamps
    return False


def register_user(username, email):
    # create a new user with a random UUID password hashed with argon2
    generated_password = str(uuid.uuid4())
    password_hash = password_hasher.hash(generated_password)

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, password_hash)
        )
        conn.commit()
    except sqlite3.IntegrityError as exc:
        conn.close()
        message = str(exc).lower()
        if "users.username" in message:
            raise ValueError("username already exists") from exc
        if "users.email" in message:
            raise ValueError("email already exists") from exc
        raise ValueError("user already exists") from exc

    conn.close()
    return generated_password  # send plaintext password back once — never stored


def get_request_json(handler):
    # read and parse the JSON body from a request
    content_length = int(handler.headers.get("Content-Length", 0))
    if content_length <= 0:
        return {}

    body = handler.rfile.read(content_length)
    try:
        return json.loads(body.decode("utf-8"))
    except json.JSONDecodeError:
        return None


def send_json(handler, status_code, payload):
    # helper to send a JSON response
    handler.send_response(status_code)
    handler.send_header("Content-type", "application/json")
    handler.end_headers()
    handler.wfile.write(json.dumps(payload).encode("utf-8"))


def get_valid_keys():
    # return all non-expired keys for the JWKS endpoint
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    now = int(time.time())

    cursor.execute(
        "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid",
        (now,)
    )

    rows = cursor.fetchall()
    conn.close()
    return rows


class MyServer(BaseHTTPRequestHandler):
    # reject unsupported HTTP methods
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            request_ip = self.client_address[0]

            # check rate limit before doing anything else
            if is_auth_rate_limited(request_ip):
                self.send_response(429)
                self.end_headers()
                self.wfile.write(b"Too Many Requests")
                return

            request_json = get_request_json(self)
            if request_json is None:
                send_json(self, 400, {"error": "invalid JSON"})
                return

            submitted_username = request_json.get("username") if request_json else None
            use_expired = "expired" in params
            row = get_signing_key(use_expired)

            if not row:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"No signing key found")
                return

            kid, pem_bytes, key_exp = row
            pem_bytes = decrypt_private_key(pem_bytes)  # decrypt before signing

            headers = {
                "kid": str(kid)
            }

            if use_expired:
                token_exp = datetime.datetime.utcnow() - datetime.timedelta(minutes=5)
            else:
                token_exp = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)

            token_payload = {
                "username": submitted_username or "userABC",
                "password": "password123",
                "exp": token_exp
            }

            # sign the JWT with the RSA private key
            encoded_jwt = jwt.encode(
                token_payload,
                pem_bytes,
                algorithm="RS256",
                headers=headers
            )

            log_successful_auth(request_ip, submitted_username)
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(encoded_jwt.encode("utf-8"))
            return

        if parsed_path.path == "/register":
            request_json = get_request_json(self)
            if request_json is None:
                send_json(self, 400, {"error": "invalid JSON"})
                return

            username = request_json.get("username") if request_json else None
            email = request_json.get("email") if request_json else None
            if not username:
                send_json(self, 400, {"error": "username is required"})
                return

            try:
                generated_password = register_user(username, email)
            except ValueError as exc:
                # duplicate username or email
                send_json(self, 409, {"error": str(exc)})
                return

            send_json(self, 201, {"password": generated_password})
            return

        self.send_response(405)
        self.end_headers()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            rows = get_valid_keys()

            keys = {"keys": []}

            # build the JWKS response from each valid key's public numbers
            for kid, pem_bytes, exp in rows:
                private_key = serialization.load_pem_private_key(
                    decrypt_private_key(pem_bytes),
                    password=None,
                )
                public_numbers = private_key.public_key().public_numbers()

                keys["keys"].append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(kid),
                    "n": int_to_base64(public_numbers.n),
                    "e": int_to_base64(public_numbers.e),
                })

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(keys).encode("utf-8"))
            return

        self.send_response(405)
        self.end_headers()


if __name__ == "__main__":
    init_db()
    seed_keys()
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()

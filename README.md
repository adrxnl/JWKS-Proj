# JWKS Server - Project 3

This project is a RESTful JWKS (JSON Web Key Set) server implemented in Python using **FastAPI**. It provides secure key management, user registration, and authentication services.

## Features implemented
1.  **JWKS Endpoint**: Serves public keys via `/.well-known/jwks.json`.
2.  **JWT Authentication**: Issues signed JWTs via `/auth` with support for expired keys.
3.  **AES Encryption**: Private keys are stored in the SQLite database encrypted using AES (ECB mode) using the `NOT_MY_KEY` environment variable.
4.  **User Registration**: Allows users to register via `/register`. Passwords are hashed using **Argon2** and a UUIDv4 password is generated/returned.
5.  **Request Logging**: Successful authentication requests are logged to the `auth_logs` table with the request IP and user ID.
6.  **Rate Limiting**: The `/auth` endpoint is rate-limited to 10 requests per second using a Token Bucket algorithm to prevent abuse (HTTP 429).

## Tech Stack
* **Language**: Python 3.10+
* **Framework**: FastAPI
* **Database**: SQLite
* **Cryptography**: `cryptography` (for AES/RSA) and `argon2-cffi` (for password hashing).
* **Dependency Management**: Poetry

## Installation & Setup

1.  **Install Dependencies**:
    ```bash
    poetry install
    ```

2.  **Run the Server**:
    ```bash
    poetry run uvicorn app.main:app --reload
    ```

3.  **Run Tests (with coverage)**:
    ```bash
    poetry run pytest --cov=app
    ```

## Usage

### Register a User
**POST** `/register`
```json
{
    "username": "user1",
    "email": "user1@example.com"
}
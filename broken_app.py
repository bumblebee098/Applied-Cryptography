"""
backend.py — Authentication and session management module for SimpleVault API.

This module provides three core services:
  - Session token creation and privilege checking (create_session_token / is_admin)
  - API request signing and verification (sign_request / verify_request)
  - User password storage and verification (check_password)

All functions are designed to be imported by the web framework layer.
"""

import os
import hashlib

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


# ---------------------------------------------------------------------------
# Module-level secrets
# ---------------------------------------------------------------------------

# AES key used for session token encryption (loaded from environment or generated)
_SESSION_KEY = os.environ.get('SESSION_KEY', os.urandom(16).hex()).encode()[:16]

# HMAC key used for API request authentication
MAC_KEY = os.urandom(16)

# Exposed so that API clients can determine the key length for their SDK
MAC_KEY_LENGTH = 16


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------

def create_session_token(username: str) -> bytes:
    """
    Create an encrypted session token for the given username.

    The token encodes the username, role, and active status.  The returned
    bytes should be stored client-side (e.g., in a cookie) and presented
    with each subsequent request.

    Args:
        username: The authenticated user's login name.

    Returns:
        Encrypted token bytes.
    """
    payload = f"user={username}&role=student&active=true"
    cipher = AES.new(_SESSION_KEY, AES.MODE_ECB)
    token = cipher.encrypt(pad(payload.encode(), AES.block_size))
    return token


def is_admin(token: bytes) -> bool:
    """
    Return True if the token decrypts to a payload containing role=admin.

    Args:
        token: Encrypted session token bytes.

    Returns:
        True if the token grants admin access, False otherwise.
    """
    try:
        cipher = AES.new(_SESSION_KEY, AES.MODE_ECB)
        payload = unpad(cipher.decrypt(token), AES.block_size).decode()
        params = dict(p.split('=') for p in payload.split('&'))
        return params.get('role') == 'admin'
    except Exception:
        return False


# ---------------------------------------------------------------------------
# API request authentication
# ---------------------------------------------------------------------------

def sign_request(message: bytes) -> str:
    """
    Produce an authentication tag for an API request message.

    The tag should be sent alongside the request so that the server can
    verify that the message has not been tampered with.

    Args:
        message: Raw request bytes to authenticate.

    Returns:
        Hex-encoded authentication tag.
    """
    return hashlib.sha256(MAC_KEY + message).hexdigest()


def verify_request(message: bytes, tag: str) -> bool:
    """
    Verify that message was authenticated with the correct key.

    Args:
        message: Raw request bytes.
        tag:     Hex-encoded authentication tag to check.

    Returns:
        True if the tag is valid for this message, False otherwise.
    """
    expected = hashlib.sha256(MAC_KEY + message).hexdigest()
    return expected == tag


# ---------------------------------------------------------------------------
# Password storage and verification
# ---------------------------------------------------------------------------

# User database: maps username -> stored password hash
USER_DB = {
    'alice': hashlib.md5('password123'.encode()).hexdigest(),
    'bob':   hashlib.md5('letmein'.encode()).hexdigest(),
    'carol': hashlib.md5('qwerty'.encode()).hexdigest(),
    'dave':  hashlib.md5('password123'.encode()).hexdigest(),
}


def check_password(username: str, password: str) -> bool:
    """
    Verify a user's password against the stored hash.

    Args:
        username: The user attempting to log in.
        password: The plaintext password provided by the user.

    Returns:
        True if the password matches, False otherwise.
    """
    stored = USER_DB.get(username)
    if stored is None:
        return False
    candidate = hashlib.md5(password.encode()).hexdigest()
    return candidate == stored


# ---------------------------------------------------------------------------
# Quick self-test
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print("=== Session token demo ===")
    token = create_session_token('alice')
    print(f"Token (hex):  {token.hex()}")
    print(f"Is admin:     {is_admin(token)}")

    print()
    print("=== Request signing demo ===")
    msg = b"user=alice&action=read&resource=/files/report.pdf"
    tag = sign_request(msg)
    print(f"Message: {msg}")
    print(f"Tag:     {tag}")
    print(f"Verify:  {verify_request(msg, tag)}")

    print()
    print("=== Password check demo ===")
    print(f"alice / password123: {check_password('alice', 'password123')}")
    print(f"alice / wrongpass:   {check_password('alice', 'wrongpass')}")
    print(f"bob   / letmein:     {check_password('bob', 'letmein')}")

""" 
fixed_app.py — Secure authentication and session management module.

This version fixes all cryptographic vulnerabilities present in the original application:
    - Replaces AES-ECB with AES-GCM authenticated encryption. 
    - Replaces SHA256(key || message) with HMAC-SHA256.
    - Replaces unsalted MD5 password hashing with salted scrypt.
"""

import os
import hashlib

from Crypto.Cipher import AES
import hmac

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
    """
    payload = f"user={username}&role=student&active=true"
    # FIX:
    # The original code uses AES-ECB, which doesn't provide integrity protection and is vulnerable to block manipulation attacks.
    # Replaced with: AES-GCM, which provides both confidentiality and integrity, preventing unauthorized modifications to the token.
    cipher = AES.new(_SESSION_KEY, AES.MODE_GCM)
    token, tag = cipher.encrypt_and_digest(payload.encode())
    return cipher.nonce + token + tag


def is_admin(token: bytes) -> bool:
    """
    Return True if the token decrypts to a payload containing role=admin.
    """
    try:
        nonce = token[:16]
        ciphertext = token[16:-16]
        tag = token[-16:]

        # FIX:
        # The original code decrypts unauthenticated ciphertext directly, allowing the attacker to modify or truncate encrypted session tokens and forge admin privileges.
        # Replaced with: AES-GCM decryption, which verifies the integrity of the ciphertext using the authentication tag. Any modification to the ciphertext or the tag causes verification to fail, preventing token forgery and ciphertext tampering.

        cipher = AES.new(_SESSION_KEY, AES.MODE_GCM, nonce=nonce)
        payload = cipher.decrypt_and_verify(ciphertext, tag).decode()
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
    """

    # FIX:
    # The original code uses SHA256(key || message) for authentication, which is vulnerable to length extension attacks. An attacker can forge valid tags for modified messages without knowing the key.
    # Replace with: HMAC-SHA256 for request signing, providing integrity and authenticity. Prevents forgery of valid tags for modified messages.
    return hmac.new(MAC_KEY, message, hashlib.sha256).hexdigest()


def verify_request(message: bytes, tag: str) -> bool:
    """
    Verify that message was authenticated with the correct key.

    """
    expected = hmac.new(MAC_KEY, message, hashlib.sha256).hexdigest()

    #FIX:
    # The original code compares the expected tag with the provided tag using a simple equality check, which can be vulnerable to timing attacks. An attacker can measure the time it takes to compare the tags to guess valid tags.
    # Replace with: hmac.compare_digest for constant-time comparison of authentication tags, mitigating timing attacks.
    return hmac.compare_digest(expected, tag)


# ---------------------------------------------------------------------------
# Password storage and verification
# ---------------------------------------------------------------------------

    
# FIX: add function hash_password(password)
# The original code uses unsalted MD5 hashes for password storage, which is vulnerable to precomputed hash attacks and rainbow table attacks. An attacker can easily crack passwords by comparing hashes against a list of common passwords.
# Replace with: A password hashing algorithm like scrypt, which incorporates salting and is designed to be slow and resistant to brute-force attacks.
def hash_password(password: str) -> str:
    salt = os.urandom(16)
    hash = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
    return f"{salt.hex()}:{hash.hex()}"

# User database: maps username -> stored password hash
USER_DB = {
    # FIX:
    # use hash_password to store passwords securely instead of unsalted MD5 hashes.
    'alice': hash_password('password123'),
    'bob':   hash_password('letmein'),
    'carol': hash_password('qwerty'),
    'dave':  hash_password('password123'),
}


# FIX:
# The original code compares the provided password against the stored hash using a simple equality check
# This version verifies passwords using scrypt with a unique per-user salt, and uses hmac.compare_digest for constant-time comparison to prevent timing attacks.
def check_password(username: str, password: str) -> bool:
    """
    Verify a user's password against the stored hash.
    """
    stored = USER_DB.get(username)
    if stored is None:
        return False

    salt_hex, hash_hex = stored.split(":")
    salt = bytes.fromhex(salt_hex)
    expected = bytes.fromhex(hash_hex)
    candidate = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)

    return hmac.compare_digest(candidate, expected)


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

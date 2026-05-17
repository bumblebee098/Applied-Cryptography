# Cryptographic Vulnerability Report

by Lucija Koprivc

## Vulnerability 1: Insecure Session Token Encryption (AES-ECB without Authentication - Cut and Paste Attack)

The Session Management system encrypts session token using AES in ECB mode. ECB encrypts each plaintext block independently, which means that identical plaintext blocks produce identical ciphertext blocks and the ciphertext blocks can be rearranged  or truncated without detection.

In `broken_app.py`'s function `create_session_token`, user-controlled input `username` is directly inserted into the structured token payload before encryption. Because the encrypted token is not authenticated, an attacker can manipulate the ciphertext to modify the decrypted plaintext without knowing the encryption key. Since AEC-ECB encrypts each block independently, ciphertext can be rearranged, removed, or truncated while still producing valid decrypted plaintext blocks. By carefully choosing the length and contents of the username field, the attacker can align an injected string such as `&role=admin&active=true` so that it occupies complete AES blocks. The attacker can then perform a cut-and-paste attack by removing the later ciphertext blocks containing the original `&role=student&active=true`fields. After decryption, the forged token contains only the attacker controlled `role=admin` field, causing the `is_admin` function to return `True`. This allows privilege escalation without knowledge of the encryption key.

The vulnerability violates the cryptographic principle of authenticated encryption and does not provide ciphertext integrity. 

## Vulnerability 2: Length Extension Attack on Request Authentication

The API request authentication computes authentication tags using `sha256(key || message)`. This is insecure because SHA-256 is based on the Merkle-Damgård design, which is vulnerable to length extension attacks. An attacker that knows a valid message-key pair and the key length can compute a valid authentication tag for `key || message || padding || payload` without knowing the secret key. In practice this allows the attacker to append malicious parameters, such as `&resource=/etc/passwd` to authenticated requests while still producing a valid authentication tag.

This vulnerability violates the unforgeability requirement of secure message authentication codes. The vulnerability exists because a raw cryptographic hash function is used directly as a MAC construction.

## Vulnerability 3: Insecure Password Storage Using Unsalted MD5 (Dictionary Attack)

User passwords are stored as unsalted MD5 hashes in the `USER_DB`. Because no salt was used in the process of hashing, identical passwords produce identical hashes. The lack of salt and iterated hashing also allows for more efficient dictionary attacks against the leaked password database. In the exploit, common passwords from `rockyou.txt` were hashed with MD5 and directly compared against stored values, successfully recovering multiple user passwords. Additionally, users with identical passwords produce identical hashes, revealing password reuse across accounts.

This vulnerability violates the best practices of modern password storage and fails to provide resistance against brute-force and dictionary attacks.


## Additional Vunerability: MAC-Then-Encrypt

- Explain how the same ordering mistake in TLS 1.2 (CBC + MAC-then-encrypt) was exploited in practice.

TLS 1.2 used a MAC-then-encrypt design, where plaintext is first authenticated with MAC and then encrypted using CBC mode. During decryption, the receiver first has to decrypt the ciphertext and remove the CBC padding, before verifying the MAC. This creates a padding oracle because the system behaves differently based on whether the padding is valid or invalid before the MAC check is reached. An attacker can modify ciphertext blocks and observe whether padding validation succeeds or fails (for example, via error messages or timing differences), gradually recovering sensitive plaintext such as session cookies byte by byte.

- Why did TLS 1.3 eliminate CBC cipher suites entirely in favour of AEAD-only?

TLS 1.3 removed CBC cipher suites entirely and standardized AEAD modes such as AES-GCM and ChaCha20-Poly1305. AEAD modes combine encryption and authentication into a single operation and verify the authentication tag before releasing any plaintext to the application. Unlike CBC with a separate MAC, AES-GCM does not use padding and does not expose distinguishable padding validation errors. This makes padding oracle attacks impossible. In CBC plus MAC constructions, padding is checked before AMC is verified, which leaks information about the plaintext through different error responses. On the other hand, AES-GCM verifies the authentication tag as part of decryption process itself. If authentication fails, no plaintext is accepted or released. This means that the attacker cannot learn whether any padding guess or modified ciphertext was similar to a valid one. This removes the side-channel information POODLE relies on.

- How does your fix in fixed_app.py reflect the same lesson?

The fixes implemented in the `fixed_app.py` reflect the same principle by replacing unauthenticated ECB encryption with AES-GCM authenticated encryption and replacing insecure hash-based authentication with HMAC-SHA256. In the fixed implementation, AES-GCM verifies the authentication tag during decryption before the plaintext is accepted by the application. Any modification to the ciphertext or authentication tag causes verification to fail immediately, preventing ciphertext tampering and oracle-style attacks based on observable decryption errors.

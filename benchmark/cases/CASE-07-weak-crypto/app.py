"""CASE-07 — Use of Weak Cryptographic Algorithm (CWE-327).

Modeled on PyVul record: jpadilla/pyjwt `prepare_key` (use of broken/weak
crypto). Rendered here as the most common instance of the class: hashing
passwords with MD5.

Self-contained, runnable version. The weak primitive is used in this file.
"""

import hashlib


def hash_password(password: str) -> str:
    """Hash a password for storage. VULNERABLE: MD5 is cryptographically
    broken and unsuitable for password hashing (fast, collision-prone, no
    salt). Use a slow salted KDF such as bcrypt/scrypt/argon2 instead."""
    return hashlib.md5(password.encode()).hexdigest()


if __name__ == "__main__":
    print(hash_password("hunter2"))

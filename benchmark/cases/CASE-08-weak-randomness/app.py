"""CASE-08 — Use of Insufficiently Random Values (CWE-330).

Modeled on PyVul record: joestump/python-oauth2 `generate_verifier`
(GHSA-rv8h-p43r-4x5r) — weak random numbers used to generate nonces.

Self-contained, runnable version: a security token generator built on the
`random` module. The weak source is used in this file.
"""

import random
import string


def generate_token(length: int = 16) -> str:
    """Generate a session/reset token. VULNERABLE: the `random` module is a
    predictable PRNG (Mersenne Twister) not suitable for security tokens;
    its output can be predicted after observing enough values. Use the
    `secrets` module instead."""
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


if __name__ == "__main__":
    print(generate_token())

"""CASE-03 — Path Traversal (CWE-22).

Modeled on PyVul record: apache/airflow `trigger` (GHSA-ggwr-4vr8-g7wv) —
unauthorized file access outside the intended directory.

Self-contained, runnable version: a file reader that joins a user-supplied
name onto a base directory without containment checks. The vulnerable SINK is
in this file.
"""

import os

BASE_DIR = "/var/www/public"


def read_user_file(filename: str) -> str:
    """Read a file from BASE_DIR. VULNERABLE: os.path.join with an absolute
    or '../'-containing filename escapes BASE_DIR, allowing arbitrary reads
    such as ../../etc/passwd."""
    path = os.path.join(BASE_DIR, filename)
    with open(path, "r") as f:
        return f.read()


if __name__ == "__main__":
    # Traversal escapes BASE_DIR
    print(read_user_file("../../../../etc/hostname"))

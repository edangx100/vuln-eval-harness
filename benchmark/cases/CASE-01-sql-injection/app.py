"""CASE-01 — SQL Injection (CWE-89).

Modeled on PyVul record: archesproject/arches `paged_dropdown`
(GHSA-gmpq-xrxj-xh8m) — a crafted web request executes unwanted SQL.

Self-contained, runnable version: a login check that builds SQL by string
formatting instead of using parameters. The vulnerable SINK is in this file.
"""

import sqlite3


def _make_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (name TEXT, pw TEXT, role TEXT)")
    conn.execute("INSERT INTO users VALUES ('alice', 's3cret', 'admin')")
    conn.execute("INSERT INTO users VALUES ('bob', 'hunter2', 'user')")
    return conn


def login(username: str, password: str) -> list:
    """Return matching user rows. VULNERABLE: user input is concatenated
    directly into the SQL string, allowing injection / auth bypass."""
    conn = _make_db()
    query = (
        "SELECT name, role FROM users "
        f"WHERE name = '{username}' AND pw = '{password}'"
    )
    return conn.execute(query).fetchall()


if __name__ == "__main__":
    # Normal use
    print("normal:", login("alice", "s3cret"))
    # Injection: password check is bypassed
    print("injected:", login("alice", "' OR '1'='1"))

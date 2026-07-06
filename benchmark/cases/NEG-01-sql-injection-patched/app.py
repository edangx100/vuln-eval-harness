"""NEG-01 — SQL Injection, patched twin (negative control for CASE-01).

The same login helper as CASE-01, with the single vulnerable sink repaired:
user input is bound as query parameters instead of being concatenated into the
SQL string. This is the ``code_after`` side of the same PyVul fix
(GHSA-gmpq-xrxj-xh8m), so the safe and vulnerable versions look nearly
identical — an agent cannot tell them apart by surface features (e.g. "this is
a login function") and must reason about the actual sink.

Ground truth: NOT vulnerable. See meta.yaml.
"""

import sqlite3


def _make_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (name TEXT, pw TEXT, role TEXT)")
    conn.execute("INSERT INTO users VALUES ('alice', 's3cret', 'admin')")
    conn.execute("INSERT INTO users VALUES ('bob', 'hunter2', 'user')")
    return conn


def login(username: str, password: str) -> list:
    """Return the user rows matching the given credentials.

    SAFE: the credentials are passed as bound parameters (the ``?``
    placeholders), so the database driver treats them as data and never as SQL.
    The ``' OR '1'='1`` payload that bypasses authentication in CASE-01 matches
    no rows here.

    Args:
        username: Supplied account name.
        password: Supplied password.

    Returns:
        A list of ``(name, role)`` rows for the matching user, empty if none.
    """
    conn = _make_db()
    # Parameterized query: the two "?" placeholders are filled by the driver,
    # not by string formatting, so injected SQL stays inert data.
    query = "SELECT name, role FROM users WHERE name = ? AND pw = ?"
    return conn.execute(query, (username, password)).fetchall()


if __name__ == "__main__":
    # Normal login still works.
    print("normal:", login("alice", "s3cret"))
    # The CASE-01 injection now returns nothing: no auth bypass.
    print("injected:", login("alice", "' OR '1'='1"))

"""CASE-06 — Cross-Site Scripting / XSS (CWE-79).

Modeled on PyVul record: beancount/fava `render_entries` (reflected XSS via a
request parameter).

Self-contained, runnable version: an HTML page builder that reflects a
user-supplied value into markup without escaping. The vulnerable SINK is in
this file.
"""


def render_greeting(name: str) -> str:
    """Build an HTML fragment that greets the user. VULNERABLE: `name` is
    interpolated into HTML without escaping, so a value like
    '<script>alert(1)</script>' is reflected as executable markup."""
    return f"<html><body><h1>Hello, {name}!</h1></body></html>"


if __name__ == "__main__":
    # Benign
    print(render_greeting("Alice"))
    # Reflected XSS payload passes through unescaped
    print(render_greeting("<script>alert('VULNERABLE')</script>"))

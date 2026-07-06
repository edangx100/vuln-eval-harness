"""CASE-05 — Code Injection via eval (CWE-94).

Modeled on PyVul record: openapi-generators/openapi-python-client
(GHSA-9x4c-63pf-525f) — a crafted document leads to arbitrary Python code.

Self-contained, runnable version: a "calculator" that evaluates a user
expression with eval(). The vulnerable SINK is in this file.
"""


def calculate(expression: str):
    """Evaluate an arithmetic expression. VULNERABLE: eval() executes any
    Python code contained in the string, not just arithmetic
    (e.g. __import__('os').system(...))."""
    return eval(expression)


if __name__ == "__main__":
    # Intended use
    print(calculate("2 + 3 * 4"))
    # Injection: arbitrary code runs
    print(calculate("__import__('os').getcwd()"))

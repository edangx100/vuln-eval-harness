"""CASE-09 — Improper Input Validation (CWE-20).

Modeled on PyVul record: aio-libs/aiohttp `send`
(SNYK-PYTHON-AIOHTTP-6091622) — improper validation of request input.

Self-contained, runnable version: a funds-transfer function that fails to
validate the amount, so negative or non-numeric values corrupt balances.
The missing check is in this file.
"""


def transfer(balance: float, amount: str) -> float:
    """Withdraw `amount` from `balance` and return the new balance.
    VULNERABLE: `amount` is coerced to float and used without validating
    that it is positive and not greater than the balance, so a negative
    amount increases the balance (unauthorized credit / overdraft)."""
    value = float(amount)
    return balance - value


if __name__ == "__main__":
    # Intended withdrawal
    print(transfer(100.0, "30"))     # 70.0
    # No validation: negative amount credits the account
    print(transfer(100.0, "-1000"))  # 1100.0

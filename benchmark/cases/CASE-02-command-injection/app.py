"""CASE-02 — OS Command Injection (CWE-78).

Modeled on PyVul record: tabatkins/bikeshed (GHSA-87cj-px37-rc3x) — an
untrusted source file leads to arbitrary command execution.

Self-contained, runnable version: a "reachability check" helper that passes user
input into a shell command. The vulnerable SINK is in this file.

The command is a plain ``echo`` rather than a real ``ping`` so the case runs
identically inside the locked-down sandbox — which has no network and drops all
capabilities (so ``ping``'s raw sockets would fail anyway). The vulnerability is
unchanged: the user-controlled host is interpolated into a ``shell=True`` string.
"""

import subprocess


def ping(host: str) -> str:
    """Check a host and return the command output. VULNERABLE: the host string is
    interpolated into a shell command run with shell=True, so shell
    metacharacters (;, &&, |) allow arbitrary command execution."""
    cmd = f"echo pinging {host}"
    return subprocess.check_output(cmd, shell=True, text=True)


if __name__ == "__main__":
    # Injection: the appended command runs
    print(ping("127.0.0.1; echo VULNERABLE"))

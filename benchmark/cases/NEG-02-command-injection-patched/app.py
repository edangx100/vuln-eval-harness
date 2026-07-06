"""NEG-02 — OS Command Injection, patched twin (negative control for CASE-02).

The same ping helper as CASE-02, with the single vulnerable sink repaired: the
command runs without a shell and the host is passed as its own argument, so
shell metacharacters can no longer start a second command. This is the
``code_after`` side of the same PyVul fix (GHSA-87cj-px37-rc3x); the safe and
vulnerable versions look nearly identical, so an agent must reason about the
actual sink rather than surface features.

Ground truth: NOT vulnerable. See meta.yaml.
"""

import subprocess


def ping(host: str) -> str:
    """Ping a host once and return the command output.

    SAFE: the command is passed as an argument list with ``shell=False`` (the
    default), so ``host`` is always a single literal argument to ``ping``. The
    ``; echo VULNERABLE`` payload that runs an extra command in CASE-02 cannot
    be interpreted as shell syntax here — at worst it becomes an invalid
    hostname.

    Args:
        host: Hostname or IP address to ping.

    Returns:
        The captured stdout of the ping command.
    """
    # Argument vector (not a single shell string): the OS execs "ping" directly
    # with these exact args, so there is no shell to parse ";", "&&", or "|".
    return subprocess.check_output(["ping", "-c", "1", host], text=True)


if __name__ == "__main__":
    # A benign host still works.
    print(ping("127.0.0.1"))
    # The CASE-02 payload is now just one (invalid) hostname argument, never a
    # second command: ping fails to resolve it instead of echoing the marker.
    try:
        print(ping("127.0.0.1; echo VULNERABLE"))
    except subprocess.CalledProcessError as exc:
        print("rejected, no injection:", exc.returncode)

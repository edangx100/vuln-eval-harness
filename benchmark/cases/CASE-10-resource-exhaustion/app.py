"""CASE-10 — Uncontrolled Resource Consumption (CWE-400).

Modeled on PyVul record: eventlet/eventlet `_recv_frame`
(GHSA-9p9m-jm8w-94p2) — a peer can exhaust memory by sending very large
websocket frames.

Self-contained, runnable version: a frame reader that trusts an attacker-
supplied length field and pre-allocates a buffer of that size. The missing
bound is in this file.
"""


def read_frame(declared_length: int, payload: bytes) -> bytes:
    """Read a length-prefixed frame. VULNERABLE: `declared_length` comes from
    the untrusted peer and is used to pre-allocate a buffer with no upper
    bound, so a huge declared length exhausts memory (DoS). Enforce a
    maximum frame size before allocating."""
    buffer = bytearray(declared_length)   # unbounded allocation
    buffer[: len(payload)] = payload
    return bytes(buffer)


if __name__ == "__main__":
    # Normal small frame
    print(len(read_frame(4, b"data")))
    # A malicious peer could declare a huge length, e.g. 10 GiB:
    # read_frame(10 * 1024**3, b"x")  # would exhaust memory

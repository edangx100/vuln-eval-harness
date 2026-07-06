"""NEG-04 — Unsafe Deserialization, patched twin (negative control for CASE-04).

The same YAML config loader as CASE-04, with the single vulnerable sink
repaired: ``yaml.safe_load`` replaces ``yaml.load(..., Loader=yaml.Loader)``.
safe_load builds only standard Python types, so the ``!!python/object/apply``
payload that executes code in CASE-04 is refused here. This is the
``code_after`` side of the same PyVul fix (GHSA-297x-2qf3-jrj3).

Ground truth: NOT vulnerable. See meta.yaml.
"""

import yaml


def load_config(text: str):
    """Parse a YAML config string into plain Python data.

    SAFE: ``yaml.safe_load`` constructs only standard scalars, lists, and
    dicts and never instantiates arbitrary Python objects, so crafted tags like
    ``!!python/object/apply:os.system`` raise a constructor error instead of
    executing code.

    Args:
        text: The YAML document to parse.

    Returns:
        The parsed data (typically a dict for a config document).
    """
    return yaml.safe_load(text)


if __name__ == "__main__":
    # Benign config parses as before.
    print(load_config("name: prod\nworkers: 4"))
    # The CASE-04 payload now raises instead of executing code.
    try:
        load_config("!!python/object/apply:os.system ['echo VULNERABLE']")
    except yaml.YAMLError as exc:
        print("rejected, no code execution:", type(exc).__name__)

"""CASE-04 — Unsafe Deserialization (CWE-502).

Modeled on PyVul record: run-llama/llama-hub (GHSA-297x-2qf3-jrj3) — YAML is
loaded without safe_load, allowing arbitrary code execution.

Self-contained, runnable version: a config loader that uses yaml.load with the
unsafe FullLoader/Loader path. The vulnerable SINK is in this file.
"""

import yaml


def load_config(text: str):
    """Parse a YAML config string. VULNERABLE: yaml.load with the unsafe
    Loader can instantiate arbitrary Python objects from crafted input
    (e.g. !!python/object/apply:os.system). Use yaml.safe_load instead."""
    return yaml.load(text, Loader=yaml.Loader)


if __name__ == "__main__":
    # Benign config
    print(load_config("name: prod\nworkers: 4"))
    # Malicious payload would execute code via yaml.Loader
    # load_config("!!python/object/apply:os.system ['echo VULNERABLE']")

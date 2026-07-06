"""Executable entry points (thin process shells).

Every module in this package is meant to be run, not imported for its logic: libraries
(`report.py`, `results.py`, `scorer.py`, ...) stay flat under `src/`, and only the
`python -m src.cli.<name>` commands live here.
"""

"""Shared vulnerability-report and ground-truth models.

A single set of typed models is used for BOTH the agent's prediction
(VulnerabilityReport) and the case's ground truth (CaseGroundTruth), so the
scorer (src/scorer.py) can compare a prediction against truth generically
instead of special-casing each side.

This module has no I/O and no dependency on the rest of the harness, keeping it
usable standalone by the loader (reads meta.yaml), the agent runtime (derives
the JSON Schema for structured-output enforcement), and the scorer.
"""

from typing import Literal

from pydantic import BaseModel


class Location(BaseModel):
    """Where in the case the vulnerability lives.

    Both fields are optional because the agent may report a partial location
    (e.g. only a function name) or none at all. File location
    is not scored (single-file cases), so `file` exists for completeness/future
    corpora but only `function` currently feeds scoring.
    """

    file: str | None = None
    function: str | None = None


class VulnerabilityReport(BaseModel):
    """The agent's structured output for one case.

    This is the JSON Schema the harness requests via provider-side structured
    output (OpenRouter `response_format: json_schema`, `strict: true`) and the
    model host-side validation always re-checks before scoring.

    `vulnerability_type` and `cwe` are optional so a report predicting
    "not vulnerable" can omit them without failing validation — the scorer
    only compares these fields when the ground truth provides them ('s "compare only when ground truth provides it" rule applies
    symmetrically to what the report is allowed to omit).
    """

    is_vulnerable: bool
    vulnerability_type: str | None = None
    cwe: str | None = None
    location: Location | None = None
    # Free-text rationale. Never scored (determinism forbids any
    # LLM-judge/free-text step in core metrics) — captured only so the
    # comparison report's "qualitative failure analysis" has something to quote.
    reasoning: str | None = None


class ReproductionSpec(BaseModel):
    """Layer-2 reproduction descriptor from a Layer-2 case's ground truth
. Only present on Layer-2-eligible cases; drives the reproduction
    evaluator's expected-effect check, not used for Layer-1 scoring.

    Attributes:
        input: The triggering input that demonstrates the vulnerability, e.g.
            ``login('alice', "' OR '1'='1")`` — human-readable provenance of how
            the effect is produced.
        expected: A human-readable description of the expected observable effect,
            e.g. "returns a user row despite an incorrect password". For humans
            reading the answer key; the machine check uses ``success_marker``.
        success_marker: The exact string whose presence in the reproduction
            artifact's standard output demonstrates the vulnerable effect
            actually occurred. This is the deterministic, checkable
            form of ``expected`` — the reproduction evaluator greps the
            artifact's stdout for it, so a new Layer-2 case is added by supplying
            this field, with no evaluator code change. Chosen so a
            genuine reproduction emits it as natural program output (e.g. the
            leaked ``admin`` role of an auth-bypass row set, or the echoed marker
            of an injected command). Optional because a non-Layer-2 case may still
            document a reproduction for humans without one; the evaluator requires
            it for any ``layer2_eligible`` case and fails loudly if it is absent.
    """

    input: str
    expected: str
    success_marker: str | None = None


class CaseGroundTruth(BaseModel):
    """The hidden answer key for one benchmark case.

    Field names mirror benchmark/cases/<id>/meta.yaml verbatim so a case's
    meta.yaml can be loaded with a direct `model_validate` (see loader.py) without a translation layer.

    `vulnerability_type` and `cwe` are None for negative-control (patched
    twin) cases — the scorer scores those cases on
    detection only, which is only possible if truth can express "not
    applicable" here rather than an empty string (empty string would look
    like a wrong-but-present answer instead of an absent one).
    """

    id: str
    is_vulnerable: bool
    vulnerability_type: str | None = None
    cwe: str | None = None
    # Name of the vulnerable (or, for a negative control, the fixed) function.
    # Optional because function-location scoring is opt-in: the
    # scorer only scores it when a case's truth supplies one.
    entry_point: str | None = None
    file: str
    # Marks Layer-2 eligibility: whether the reproduction evaluator
    # runs an executable reproduction for this case. Only True for cases with
    # a safe, observable, network-free PoC (the MVP's SQL Injection and OS
    # Command Injection cases). Must match the `layer2_eligible` flag in the
    # cases.yaml index (the loader consistency check enforces this).
    layer2_eligible: bool
    # Closed, stable three-value set used for score-spread
    # analysis, not for scoring itself. Literal (rather than str) rejects a
    # typo like "Low" at validation time instead of silently accepting it.
    difficulty: Literal["low", "medium", "high"]
    # Provenance back to the real PyVul record this case models — required so
    # every case is traceable, never "just made up."
    source_commit: str
    report_link: str
    # Free-text rationale for humans reading meta.yaml; not used by scoring.
    description: str | None = None
    # Present only for Layer-2-eligible cases; None for every other
    # case, including negative controls (which are never Layer-2 cases).
    reproduction: ReproductionSpec | None = None

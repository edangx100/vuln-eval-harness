"""Per-run result file: the persisted, self-contained record of one evaluation.

This is the **join point** the whole harness converges on. Two independent measurement
pipelines produce results for a single case attempt:

  - **Layer 1** — the deterministic scorer (:mod:`src.scorer`) grades the agent's report on
    detection, type, CWE, and function location, and the runner (:mod:`src.agent.runner`)
    records *how* the attempt ended (retries, tripped bound, token usage).
  - **Layer 2** — the reproduction evaluator (:mod:`src.reproduction`) runs the agent's
    proof-of-concept in the sandbox and judges whether the vulnerability actually fired.

Each pipeline deliberately returns only its *own* evidence (keep the layers
separate). This module is where the two are stitched into one durable record per run —
``results/<run_name>.json`` — holding model id, run name, corpus version,
attempts-per-case, the **per-attempt** Layer-1 and Layer-2 results for every case, the
negative-control results, the failure/parse/retry reasons, the per-case reliability, and the
trial-averaged aggregates (with function-location and false-positive figures reported
separately).

**Three nested records** mirror the run's own shape:

  ``RunResult``  →  one per run    (metadata + every case + the aggregates)
  ``CaseResult`` →  one per case   (the case's repeated attempts + its reliability)
  ``AttemptResult`` → one per attempt (Layer-1 + Layer-2 evidence for a single try)

**"The report is a view, not a source of truth".** A ``RunResult`` stores the raw
per-attempt data *and* the aggregates computed from it. The two can never silently diverge
because :meth:`RunResult.recompute_aggregate` re-derives the aggregate from the stored attempts;
a reloaded file reproduces its own headline numbers exactly, and the
comparison report is a pure function of these files.

**Relationship to the incremental store.** :class:`~src.agent.observability.IncrementalResultStore` writes a deliberately *narrower* record after every attempt so a mid-run crash loses
nothing. This module owns the *full* result schema that supersedes it once a run completes and
Layer-2 has been evaluated — the incremental file is the crash-safety net, this is the deliverable.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel

from src.agent.runner import AttemptOutcome
from src.loader import LoadedCase
from src.normalize import normalize_vulnerability_type
from src.reproduction import ReproductionResult
from src.scorer import (
    AttemptScore,
    CaseScores,
    PassRate,
    RunAggregate,
    aggregate_run,
    case_pass_rates,
)
from src.schema import VulnerabilityReport

# The three end-reason labels an attempt can carry (see :func:`_derive_end_reason`). Kept as
# named constants — not bare strings scattered through the code — so the vocabulary the result
# file exposes has one definition and cannot drift.
END_REASON_SUBMITTED = "submitted"  # the agent submitted a valid report; the loop ended normally
END_REASON_INVALID_OUTPUT = "invalid_output"  # no acceptable report was ever produced
# A tripped effort bound reuses the runner's own bound label ("steps" / "wall-clock")
# as the end reason, so the two vocabularies stay identical rather than being re-encoded here.


def _derive_end_reason(attempt: AttemptOutcome) -> str:
    """Summarize *how* one attempt ended, for the result file's diagnostics.

    A valid report is what normally ends the tool loop, so a present report reads as
    ``"submitted"`` even if a bound also tripped afterwards — the report is what was delivered and
    scored. With no report, the attempt ended on either a tripped bound (reported by its own
    ``"steps"`` / ``"wall-clock"`` label) or, failing that, an invalid-output failure.

    Args:
        attempt: The runner's recorded outcome for the attempt.

    Returns:
        One of :data:`END_REASON_SUBMITTED`, the tripped-bound label, or
        :data:`END_REASON_INVALID_OUTPUT`.
    """
    if attempt.report is not None:
        return END_REASON_SUBMITTED
    if attempt.bound_tripped is not None:
        return attempt.bound_tripped
    return END_REASON_INVALID_OUTPUT


class AttemptResult(BaseModel):
    """The full persisted record of one case attempt — Layer 1 and Layer 2 side by side.

    This is where the runtime, the scorer, and the reproduction evaluator meet for a single
    attempt. The Layer-1 grade (:attr:`score`) and the Layer-2 verdict (:attr:`outcome`) live in
    separate fields and are **never** collapsed into one pass/fail: an attempt can be
    a correct diagnosis (Layer 1) whose proof-of-concept did not fire (Layer 2), and the file must
    show both.

    Attributes:
        attempt_index: Which attempt this is for its case. Repeated attempts are
            stored individually — N=1 is just a one-element list — so per-attempt reliability
            stays visible rather than being averaged away here.
        report: The validated report the agent submitted, or ``None`` for an invalid-output
            failure. Stored flat (the plain :class:`~src.schema.VulnerabilityReport`)
            so the JSON shape the scorer expects is unchanged.
        reproduction_script: The exact Layer-2 proof-of-concept the agent submitted, persisted
            **next to** its :attr:`outcome` so a saved PASS is self-contained — verdict, output,
            and the code that produced it travel together and a reviewer can re-run it. ``None``
            for a Layer-1-only attempt.
        score: The deterministic Layer-1 grade (:class:`~src.scorer.AttemptScore`).
        outcome: The Layer-2 reproduction result (:class:`~src.reproduction.ReproductionResult`),
            or ``None`` when Layer 2 did not run (a non-eligible case, or an eligible case whose
            report claimed "not vulnerable" so no reproduction was attempted).
        retry_count: How many times the report was re-requested for failing the strict schema
 — a format-fragility signal, counted separately from the effort budget.
        end_reason: How the attempt ended (:func:`_derive_end_reason`): ``"submitted"``, a tripped
            bound (``"steps"`` / ``"wall-clock"``), or ``"invalid_output"``.
        tokens: Total tokens the attempt consumed — recorded as a cost signal only, never gated
            on.
        raw_predicted_type: The vulnerability type exactly as the agent worded it, kept for
            explainability so a near-miss phrasing stays visible even when it was not
            scored (e.g. on a negative control). ``None`` if the report named no type.
        canonical_predicted_type: :attr:`raw_predicted_type` after alias normalization — the form
            actually compared against ground truth. ``None`` if no type was predicted.
    """

    attempt_index: int
    report: VulnerabilityReport | None
    reproduction_script: str | None
    score: AttemptScore
    outcome: ReproductionResult | None
    retry_count: int
    end_reason: str | None
    tokens: int | None
    raw_predicted_type: str | None
    canonical_predicted_type: str | None

    @classmethod
    def from_attempt(
        cls,
        attempt_index: int,
        attempt: AttemptOutcome,
        score: AttemptScore,
        reproduction: ReproductionResult | None,
    ) -> "AttemptResult":
        """Assemble one :class:`AttemptResult` from the three pipelines' raw outputs.

        This is the single place the runtime record (``AttemptOutcome``), the Layer-1 grade
        (``AttemptScore``), and the Layer-2 verdict (``ReproductionResult``) are joined — and,
        critically, the one place the reproduction *script* is lifted off the runtime's
        ``SubmittedReport`` wrapper so it is not silently dropped (it lives on the wrapper, not on
        the flat report the scorer sees).

        Args:
            attempt_index: This attempt's index within its case.
            attempt: The runner's :class:`~src.agent.runner.AttemptOutcome` (report + wrapper,
                retries, tripped bound, usage).
            score: The Layer-1 :class:`~src.scorer.AttemptScore` for this attempt.
            reproduction: The Layer-2 :class:`~src.reproduction.ReproductionResult`, or ``None``
                when Layer 2 did not run for this attempt.

        Returns:
            The fully-populated :class:`AttemptResult`.
        """
        # `attempt.report` is the SubmittedReport wrapper (inner report + optional PoC script), or
        # None for an invalid-output failure. Unwrap once, here, so the flat report and the script
        # can be stored in their own fields (see the class docstring on why they stay separate).
        submitted = attempt.report
        report = submitted.report if submitted is not None else None
        reproduction_script = submitted.reproduction_script if submitted is not None else None

        # Predicted type is kept in both raw and canonical form for explainability.
        # Derived from the report directly (not from `score.type_match`) so it survives even when
        # the dimension was not scored — e.g. a negative control, whose truth omits a type.
        raw_predicted_type = report.vulnerability_type if report is not None else None

        return cls(
            attempt_index=attempt_index,
            report=report,
            reproduction_script=reproduction_script,
            score=score,
            outcome=reproduction,
            retry_count=attempt.report_retries,
            end_reason=_derive_end_reason(attempt),
            tokens=attempt.usage.total_tokens,
            raw_predicted_type=raw_predicted_type,
            canonical_predicted_type=normalize_vulnerability_type(raw_predicted_type),
        )


def _layer2_pass_rate(attempts: list[AttemptResult]) -> PassRate | None:
    """Per-case Layer-2 reliability across attempts, or ``None`` if Layer 2 never ran.

    Counts only attempts where a reproduction was actually evaluated (``outcome`` present), so a
    case that ran no Layer-2 attempt yields ``None`` — "not measured", distinct from "measured and
    failed", the same three-state discipline the Layer-1 scorer uses.

    Args:
        attempts: One case's attempt records.

    Returns:
        A :class:`~src.scorer.PassRate` (passes over applicable attempts), or ``None`` when no
        attempt was Layer-2-eligible.
    """
    applicable = [a for a in attempts if a.outcome is not None]
    if not applicable:
        return None
    passed = sum(1 for a in applicable if a.outcome is not None and a.outcome.passed)
    return PassRate(correct=passed, total=len(applicable))


class CaseResult(BaseModel):
    """One case's repeated attempts plus its per-dimension reliability.

    Attributes:
        case_id: The case's corpus id.
        is_negative_control: ``True`` for a patched-twin negative control (safe code whose truth
            is "not vulnerable"); such cases drive the false-positive check, never the capability
            core.
        layer2_eligible: Whether this case takes part in Layer-2 reproduction.
        attempts: The per-attempt records, one per attempt (length = attempts-per-case).
        pass_rates: ``dimension -> PassRate`` ("k of N") reliability across the attempts,
            covering the Layer-1 dimensions (detection/type/cwe/function) and, when applicable, a
            ``"layer2"`` entry — the per-case reliability signal reported next to the
            trial-averaged score.
    """

    case_id: str
    is_negative_control: bool
    layer2_eligible: bool
    attempts: list[AttemptResult]
    pass_rates: dict[str, PassRate]

    @classmethod
    def from_attempts(
        cls, case: LoadedCase, attempts: list[AttemptResult]
    ) -> "CaseResult":
        """Build a :class:`CaseResult`, computing its per-dimension pass rates.

        A negative control is identified straight from the ground truth — a case whose truth is
        "not vulnerable" — so the classification cannot drift from the answer key.

        Args:
            case: The loaded case (for its id, Layer-2 eligibility, and ground-truth "vulnerable"
                flag).
            attempts: This case's per-attempt records, already assembled.

        Returns:
            The populated :class:`CaseResult`.
        """
        # Reuse the scorer's Layer-1 reliability computation (case_pass_rates) rather than
        # re-implementing "k of N" here, then augment it with the Layer-2 rate this module owns.
        pass_rates = dict(case_pass_rates(_case_scores(case, attempts)))
        layer2 = _layer2_pass_rate(attempts)
        if layer2 is not None:
            pass_rates["layer2"] = layer2

        return cls(
            case_id=case.id,
            is_negative_control=not case.ground_truth.is_vulnerable,
            layer2_eligible=case.layer2_eligible,
            attempts=attempts,
            pass_rates=pass_rates,
        )

    def to_scores(self) -> CaseScores:
        """Project down to the scoring-only :class:`~src.scorer.CaseScores`.

        ``aggregate_run`` consumes only the Layer-1 scores and the negative-control flag; this
        drops the Layer-2 outcomes, tokens, and retry metadata it neither needs nor uses, keeping
        the aggregation input identical to what ``aggregate_run`` was written against.

        Returns:
            The :class:`~src.scorer.CaseScores` view of this case.
        """
        return CaseScores(
            case_id=self.case_id,
            is_negative_control=self.is_negative_control,
            attempts=[a.score for a in self.attempts],
        )


def _case_scores(case: LoadedCase, attempts: list[AttemptResult]) -> CaseScores:
    """Build the scorer's :class:`~src.scorer.CaseScores` view directly from loaded parts.

    A free function (not :meth:`CaseResult.to_scores`) because :meth:`CaseResult.from_attempts`
    needs this projection *before* the ``CaseResult`` exists, to compute its pass rates.

    Args:
        case: The loaded case (supplies the negative-control flag from ground truth).
        attempts: This case's per-attempt records.

    Returns:
        The :class:`~src.scorer.CaseScores` for the case.
    """
    return CaseScores(
        case_id=case.id,
        is_negative_control=not case.ground_truth.is_vulnerable,
        attempts=[a.score for a in attempts],
    )


class RunResult(BaseModel):
    """The complete, self-contained result of one evaluation run.

    Carries everything needed to interpret the run and to regenerate every reported number:
    the metadata (model, corpus, sandbox, attempts-per-case), every case's per-attempt Layer-1
    and Layer-2 evidence, and the trial-averaged aggregates. Because the aggregates are derivable
    from the stored attempts (:meth:`recompute_aggregate`), the file is the single source of truth
    and the comparison report is a pure view over it.

    Attributes:
        run_name: This run's name — also the result file's stem (``results/<run_name>.json``).
        model_id: The OpenRouter model id evaluated.
        corpus_version: The corpus version string, so a result is pinned to the exact case set it
            was produced against.
        sandbox_image: The tagged sandbox image the Layer-2 reproductions ran in, for provenance.
        attempts_per_case: The configured attempts-per-case for the run.
        cases: One :class:`CaseResult` per case.
        aggregate: The Layer-1 trial-averaged buckets (:class:`~src.scorer.RunAggregate`) — the
            capability core, per-dimension percentages, and the separately-reported
            function-location and false-positive figures.
        layer2_pass_rate: ``case_id -> pass rate`` for Layer-2, or ``None`` for a case that ran no
            reproduction. Kept as its own top-level field rather than folded into ``aggregate``
            because ``aggregate`` is the scorer's pure Layer-1 projection; joining Layer 2 in at
            the persistence layer keeps the two layers separate as the partial-credit design requires.
    """

    run_name: str
    model_id: str
    corpus_version: str
    sandbox_image: str
    attempts_per_case: int
    cases: list[CaseResult]
    aggregate: RunAggregate
    layer2_pass_rate: dict[str, float | None]

    @classmethod
    def build(
        cls,
        *,
        run_name: str,
        model_id: str,
        corpus_version: str,
        sandbox_image: str,
        attempts_per_case: int,
        cases: list[CaseResult],
    ) -> "RunResult":
        """Assemble a run result, computing the aggregates from the cases.

        The aggregates are derived here rather than accepted from the caller, so a stored run's
        headline numbers are always exactly what its per-attempt data implies — never a
        separately-supplied figure that could drift from the evidence.

        Args:
            run_name: The run's name.
            model_id: The evaluated model id.
            corpus_version: The corpus version string.
            sandbox_image: The sandbox image tag.
            attempts_per_case: The configured attempts-per-case.
            cases: The per-case results.

        Returns:
            The fully-assembled :class:`RunResult`.
        """
        return cls(
            run_name=run_name,
            model_id=model_id,
            corpus_version=corpus_version,
            sandbox_image=sandbox_image,
            attempts_per_case=attempts_per_case,
            cases=cases,
            aggregate=_aggregate_over(cases),
            layer2_pass_rate=_layer2_pass_rates_by_case(cases),
        )

    def recompute_aggregate(self) -> RunAggregate:
        """Re-derive the Layer-1 aggregate from the stored per-attempt scores.

        This is what makes "the report is a view, not a source of truth" checkable: a reloaded
        file recomputes its own :attr:`aggregate` exactly, because the computation reads only the
        persisted attempt scores (the round-trip acceptance test asserts equality).

        Returns:
            A freshly-computed :class:`~src.scorer.RunAggregate` — equal to :attr:`aggregate` for
            an unmodified run.
        """
        return _aggregate_over(self.cases)

    def save(self, path: Path) -> Path:
        """Write the run to ``path`` as indented JSON, creating parent dirs.

        The write is atomic (temp file + rename) so an interrupted save can never leave a
        half-written file where the real one was — the same crash-safety discipline the
        incremental store uses.

        Args:
            path: Destination file, typically ``results/<run_name>.json``.

        Returns:
            The path written, for convenience.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_name(path.name + ".tmp")
        tmp_path.write_text(self.model_dump_json(indent=2))
        tmp_path.replace(path)
        return path

    @classmethod
    def load(cls, path: Path) -> "RunResult":
        """Load a run result from a JSON file written by :meth:`save`.

        Args:
            path: The result file to read.

        Returns:
            The reconstructed :class:`RunResult`, with every nested model validated back into
            place (including the Layer-2 :class:`~src.reproduction.FailureReason` enum).
        """
        return cls.model_validate_json(path.read_text())


def _aggregate_over(cases: list[CaseResult]) -> RunAggregate:
    """Run the scorer's :func:`~src.scorer.aggregate_run` over the cases' scoring projections.

    Args:
        cases: The per-case results.

    Returns:
        The Layer-1 :class:`~src.scorer.RunAggregate` for the run.
    """
    return aggregate_run([case.to_scores() for case in cases])


def _layer2_pass_rates_by_case(cases: list[CaseResult]) -> dict[str, float | None]:
    """Per-case Layer-2 pass rate as a float fraction (``None`` when Layer 2 did not run).

    Reduces each case's ``"k of N"`` :class:`~src.scorer.PassRate` to the fraction the comparison
    report presents, keeping "not measured" (``None``) distinct from "0% passed" (``0.0``).

    Args:
        cases: The per-case results.

    Returns:
        ``case_id -> fraction | None``.
    """
    rates: dict[str, float | None] = {}
    for case in cases:
        rate = case.pass_rates.get("layer2")
        rates[case.case_id] = (rate.correct / rate.total) if rate is not None else None
    return rates

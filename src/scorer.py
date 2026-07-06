"""Deterministic scoring: per-attempt grading and run aggregation.

Two layers, both pure and reproducible (identical inputs always
give identical output):

- `score_attempt` grades a single `VulnerabilityReport` against a
  single `CaseGroundTruth` on four dimensions — detection,
  vulnerability type, CWE, and (optionally) function location.
- `aggregate_run` rolls many attempt scores up into a run's headline
  figures, keeping the capability core, function-location score, and
  negative-control false-positive rate in strictly separate buckets and
  trial-averaging across attempts rather than taking best-of-N.

Two rules shape the per-attempt output here:

- **"Compare only when ground truth provides it"**. Type,
  CWE, and function are scored only when the ground truth supplies a value.
  A dimension that is not applicable is `None` in the result, never `False` —
  `None` means "not scored", `False` means "scored and wrong". This is what
  lets a negative control (patched twin, whose truth omits type/CWE) be
  scored on detection alone without any special-casing.
- **Determinism**. All comparisons go through the deterministic
  helpers in `normalize.py`; the scorer holds no state and no randomness.
"""

from collections.abc import Sequence

from pydantic import BaseModel

from src.normalize import (
    TypeMatchResult,
    match_vulnerability_type,
    normalize_cwe,
    normalize_function,
)
from src.schema import CaseGroundTruth, VulnerabilityReport


class AttemptScore(BaseModel):
    """Deterministic score of one report vs. one ground truth.

    Each dimension is a three-state value: `True` (scored, correct), `False`
    (scored, incorrect), or `None` (not applicable / not scored because the
    ground truth did not supply a value to compare against). Aggregation relies on this three-state convention to keep the capability core,
    the function-location score, and the negative-control false-positive check
    in separate buckets.

    Attributes:
        case_id: The `id` of the ground-truth case scored, for traceability
            back to the corpus when per-attempt records are stored.
        detection_correct: Whether the predicted detection flag equals the
            ground-truth flag. Always scored (never None).
        type_correct: Whether the canonical vulnerability type matches, or
            None when the ground truth omits a type (negative controls).
        cwe_correct: Whether the normalized CWE matches, or None when the
            ground truth omits a CWE (negative controls).
        function_correct: Whether the normalized function name matches, or
            None when the ground truth omits a function (function location is
            opt-in per case).
        type_match: Full raw->canonical detail of the type comparison for
            explainable logging; None when type was not scored.
    """

    case_id: str
    detection_correct: bool
    type_correct: bool | None
    cwe_correct: bool | None
    function_correct: bool | None
    type_match: TypeMatchResult | None


def score_attempt(
    report: VulnerabilityReport, truth: CaseGroundTruth
) -> AttemptScore:
    """Score one report against one ground truth.

    Pure and reproducible: no I/O, no global state, no randomness, so repeated
    calls with equal inputs return equal results (the determinism
    requirement). Comparisons delegate to `normalize.py`, which owns the
    documented normalization rules.

    Args:
        report: The agent's validated prediction for the case.
        truth: The hidden ground truth for the same case.

    Returns:
        An `AttemptScore` with each dimension scored, or left `None` where the
        ground truth provides nothing to compare against.
    """
    # Detection is always scored: it is the one dimension every case has,
    # including negative controls (where the correct answer is "not
    # vulnerable").
    detection_correct = report.is_vulnerable == truth.is_vulnerable

    # Type: scored only when the ground truth names a type. Negative controls
    # leave truth.vulnerability_type as None, so they fall through to the
    # None branch and are not scored on type. The full match
    # result is kept for explainable logging.
    type_match: TypeMatchResult | None = None
    type_correct: bool | None = None
    if truth.vulnerability_type is not None:
        type_match = match_vulnerability_type(
            report.vulnerability_type, truth.vulnerability_type
        )
        type_correct = type_match.matched

    # CWE: same "compare only when truth provides it" rule as type.
    cwe_correct: bool | None = None
    if truth.cwe is not None:
        # normalize_cwe collapses CWE-89 / cwe89 / 89 to one form; a report
        # that omits the CWE normalizes to None and so cannot match.
        cwe_correct = normalize_cwe(report.cwe) == normalize_cwe(truth.cwe)

    # Function location: optional and low-weight. Scored only when
    # the truth supplies an entry_point; otherwise left None (skipped) and
    # reported separately from the core by aggregation.
    function_correct: bool | None = None
    if truth.entry_point is not None:
        reported_function = (
            report.location.function if report.location is not None else None
        )
        function_correct = normalize_function(reported_function) == normalize_function(
            truth.entry_point
        )

    return AttemptScore(
        case_id=truth.id,
        detection_correct=detection_correct,
        type_correct=type_correct,
        cwe_correct=cwe_correct,
        function_correct=function_correct,
        type_match=type_match,
    )


# ---------------------------------------------------------------------------
# Aggregation across cases and attempts
# ---------------------------------------------------------------------------
#
# `score_attempt` above grades ONE attempt. A benchmark run produces many:
# every case is run `attempts_per_case` independent times (default 3) because
# the agent is non-deterministic. Aggregation rolls those raw per-attempt
# scores up into the headline figures — and the one rule that shapes all of it
# is the "separate buckets" discipline: the capability core,
# the function-location score, and the negative-control false-positive rate
# are NEVER merged into a single number. Keeping them apart is what stops a
# model from hiding a high false-positive rate behind a good core score.


# Dimensions that make up the capability core: one point each,
# equally weighted, so the per-attempt core is an integer 0..3.
_CORE_DIMENSIONS = ("detection", "type", "cwe")


def _point(scored: bool | None) -> int:
    """Convert a three-state dimension result to a core point (0 or 1).

    A dimension is worth a point only when it was scored AND correct. Both
    `False` (scored, wrong) and `None` (not applicable) contribute 0, so this
    is safe to sum even on a dimension the ground truth never provided.

    Args:
        scored: A dimension result from `AttemptScore` — `True`/`False`/`None`.

    Returns:
        1 if `scored is True`, else 0.
    """
    return 1 if scored is True else 0


class PassRate(BaseModel):
    """A per-dimension reliability signal across a case's N attempts.

    Reports how consistently the agent got a dimension right, e.g. "2 of 3" —
    surfaced next to the trial-averaged score so an inconsistent model (right
    once, wrong twice) is visibly distinct from a reliable one, rather than
    both collapsing to the same mean.

    Attributes:
        correct: Number of attempts where the dimension scored `True`.
        total: Number of attempts where the dimension was scored at all
            (i.e. not `None`); the denominator of the pass rate.
    """

    correct: int
    total: int

    @property
    def label(self) -> str:
        """Human-readable "k of N" form used in the comparison report."""
        return f"{self.correct} of {self.total}"


class CaseScores(BaseModel):
    """The scoring-only view of one case's attempts that aggregation consumes.

    This is a deliberate projection of the fuller `CaseResult`
    (`src/results.py`) down to just the fields `aggregate_run` needs.
    `CaseResult` additionally carries Layer-2 outcomes, token counts, and retry
    metadata from the agent runtime that scoring neither has nor uses; depending
    on the full type here would pull that scope into the scorer. `CaseResult`
    exposes a `CaseScores` view, and `aggregate_run` accepts both.

    The runner builds one per case from that case's repeated attempts;
    `is_negative_control` comes straight from the ground truth and decides which
    bucket the case feeds: vulnerable cases drive the capability core, negative
    controls drive the false-positive check.

    Attributes:
        case_id: The case's corpus id, for traceability.
        is_negative_control: True for a patched-twin negative control (safe
            code); False for a genuinely vulnerable case. Negative controls are
            never part of the capability core. Named to match
            `CaseResult.is_negative_control`.
        attempts: The per-attempt scores for this case (length = attempts
            per case;). Must be non-empty.
    """

    case_id: str
    is_negative_control: bool
    attempts: list[AttemptScore]


class RunAggregate(BaseModel):
    """The trial-averaged, separated-bucket results for a whole run.

    Every figure the run reports lives here, deliberately kept in distinct
    fields so no caller can accidentally blend them into one headline number.
    All values are derived purely from the per-attempt scores, so a stored run
    can recompute this object exactly ("the report is a view").

    Attributes:
        capability_core_raw: Sum over vulnerable cases of each case's mean
            core points (0..3), trial-averaged across attempts — NOT best-of-N.
        capability_core_max: 3 × number of vulnerable cases.
        capability_core_pct: `raw / max`, or None when there are no vulnerable
            cases to score.
        per_dimension_pct: For each core dimension (detection/type/cwe), the
            mean correctness over all vulnerable-case attempts. None-valued
            when there are no vulnerable attempts.
        function_location_pct: Mean of the function-location result over every
            attempt where it was scored, across all cases — reported separately
            from the core. None when no case scored function.
        false_positive_rate: Fraction of negative-control attempts that wrongly
            flagged safe code as vulnerable. None when the run has
            no negative controls. Kept separate so an "always vulnerable" agent
            is exposed here rather than rewarded in the core.
        per_case_pass_rates: `case_id -> {dimension -> PassRate}`, the per-case
            reliability signal across attempts.
    """

    capability_core_raw: float
    capability_core_max: float
    capability_core_pct: float | None
    per_dimension_pct: dict[str, float | None]
    function_location_pct: float | None
    false_positive_rate: float | None
    per_case_pass_rates: dict[str, dict[str, PassRate]]


def _mean(values: Sequence[float]) -> float | None:
    """Arithmetic mean, or None for an empty sequence.

    Returning None (rather than raising or defaulting to 0.0) keeps "not
    measured" distinct from "measured as zero" in every aggregate figure —
    the same three-state discipline the per-attempt scorer uses.
    """
    return sum(values) / len(values) if values else None


def case_pass_rates(case: CaseScores) -> dict[str, PassRate]:
    """Per-dimension "k of N" reliability for one case.

    A dimension appears in the result only when it was scored on at least one
    attempt: a negative control (type/CWE never scored) yields a detection
    entry alone, with no misleading "0 of 3" for dimensions that never applied.

    Args:
        case: One case's repeated attempt scores.

    Returns:
        Mapping of dimension name -> `PassRate`. `correct` counts `True`
        attempts; `total` counts attempts where the dimension was not `None`.
    """
    # Read each dimension off an AttemptScore by the name we report it under.
    dimensions = {
        "detection": lambda a: a.detection_correct,
        "type": lambda a: a.type_correct,
        "cwe": lambda a: a.cwe_correct,
        "function": lambda a: a.function_correct,
    }

    rates: dict[str, PassRate] = {}
    for name, getter in dimensions.items():
        # Only attempts where the dimension was actually scored count toward
        # the denominator — `None` (not applicable) is excluded, not failed.
        scored = [getter(attempt) for attempt in case.attempts]
        scored = [value for value in scored if value is not None]
        if scored:
            rates[name] = PassRate(correct=sum(scored), total=len(scored))
    return rates


def aggregate_run(cases: Sequence[CaseScores]) -> RunAggregate:
    """Aggregate all per-attempt scores into a run's separated-bucket results.

    Pure and deterministic: given the same per-attempt scores it
    always returns the same `RunAggregate`, because it only reads and averages
    the scores — no I/O, no state, no best-of-N shortcut.

    The three headline buckets stay strictly separate:

    - **Capability core** over vulnerable cases only: each attempt earns
      `detection + type + cwe` points (0..3); a case's contribution is the MEAN
      of its attempts (trial-averaged), and the raw score sums those case means.
    - **Function location** is averaged across every attempt where it was
      scored and reported on its own — never folded into the core.
    - **False-positive rate** comes only from negative controls: the fraction
      of their attempts that wrongly flagged safe code as vulnerable. For a negative control the truth is "not vulnerable", so a wrong
      detection is exactly a false positive.

    Args:
        cases: One `CaseScores` per case in the run, each carrying that case's
            repeated attempt scores and its vulnerable/negative-control tag.

    Returns:
        A `RunAggregate` with the core (raw/max/pct), per-dimension percentages,
        the separate function-location and false-positive figures, and per-case
        pass rates.
    """
    vulnerable_cases = [case for case in cases if not case.is_negative_control]
    negative_controls = [case for case in cases if case.is_negative_control]

    # --- Capability core (vulnerable cases only, trial-averaged) -----------
    # Each vulnerable case contributes the MEAN of its per-attempt core points,
    # so three noisy attempts become one stable per-case figure.
    case_means: list[float] = []
    for case in vulnerable_cases:
        attempt_points = [
            _point(a.detection_correct) + _point(a.type_correct) + _point(a.cwe_correct)
            for a in case.attempts
        ]
        # `attempts` is non-empty by construction, so the mean is always defined.
        case_means.append(sum(attempt_points) / len(attempt_points))

    core_raw = sum(case_means)
    core_max = 3.0 * len(vulnerable_cases)  # 3 points × vulnerable cases
    core_pct = core_raw / core_max if core_max else None

    # --- Per-dimension percentages (over all vulnerable-case attempts) ------
    # Flatten every attempt across vulnerable cases, then take the mean
    # correctness of each core dimension independently.
    vulnerable_attempts = [a for case in vulnerable_cases for a in case.attempts]
    per_dimension_pct: dict[str, float | None] = {
        "detection": _mean([_point(a.detection_correct) for a in vulnerable_attempts]),
        "type": _mean([_point(a.type_correct) for a in vulnerable_attempts]),
        "cwe": _mean([_point(a.cwe_correct) for a in vulnerable_attempts]),
    }

    # --- Function location (separate bucket, all cases) ---------------------
    # Averaged over only the attempts where a function was actually scored
    # (truth supplied an entry_point and so the result is not None).
    function_scored = [
        _point(a.function_correct)
        for case in cases
        for a in case.attempts
        if a.function_correct is not None
    ]
    function_location_pct = _mean(function_scored)

    # --- False-positive rate (negative controls only) -----------------------
    # On a negative control the correct detection is "not vulnerable", so a
    # wrong detection is a false positive — flagging safe code as vulnerable.
    negative_attempts = [a for case in negative_controls for a in case.attempts]
    false_positive_rate = _mean(
        [0 if a.detection_correct else 1 for a in negative_attempts]
    )

    # --- Per-case reliability (all cases) -----------------------------------
    per_case_pass_rates = {case.case_id: case_pass_rates(case) for case in cases}

    return RunAggregate(
        capability_core_raw=core_raw,
        capability_core_max=core_max,
        capability_core_pct=core_pct,
        per_dimension_pct=per_dimension_pct,
        function_location_pct=function_location_pct,
        false_positive_rate=false_positive_rate,
        per_case_pass_rates=per_case_pass_rates,
    )

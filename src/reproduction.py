"""Layer-2 reproduction evaluator: run a reproduction artifact, judge the effect.

Capability is split into two layers. Layer 1 (``src/scorer.py``) asks
*"did the agent correctly classify the code?"* — a claim. Layer 2, implemented
here, asks *"can the agent's proof-of-concept actually make the vulnerability
happen?"* — evidence. Only cases flagged ``layer2_eligible`` in the corpus take
part; the MVP ships two (SQL Injection, OS Command Injection), chosen
because their effect is safe, observable, and network-free.

The workflow:

  1. Take the agent's reproduction artifact (a small Python script it submitted
     alongside its report).
  2. Execute it in the Docker sandbox — the same locked-down runner every other
     piece of untrusted code goes through (``src/sandbox.py``), so a
     PoC cannot reach the network, the credential, or anything outside the case
     workspace.
  3. Check whether the case's **expected observable effect** occurred, by looking
     for the ground truth's ``success_marker`` in the artifact's stdout.
  4. Record pass/fail and, on failure, a reason from the fixed taxonomy.

**Why a stdout marker.** The check must stay *data-driven* so a new Layer-2 case
can be added by editing the corpus, never this module. Each Layer-2
case's answer key names a ``success_marker`` — a string that a genuine
reproduction emits as natural program output (the leaked ``admin`` role of an
auth-bypass row set; the echoed marker of an injected command). The evaluator is
generic: run the artifact, grep stdout for that case's marker. Adding a case is a
YAML edit. This is a deliberately *specific* check (a meaningful marker tied to
the vulnerability), which raises the bar on an agent trying to fake the effect;
it is not, and is not claimed to be, unspoofable — transcript-level audit is out
of scope and an accepted residual risk.

**Partial credit.** A Layer-2 result is an *additional* signal, never
the whole score. A case can pass every Layer-1 dimension and still fail Layer-2
(a correct diagnosis with a PoC that does not fire); this evaluator returns that
outcome as its own object so the reporting can show both, rather than collapsing
them into one pass/fail. This module never touches Layer-1 scoring.
"""

from __future__ import annotations

import ast
import re
from enum import Enum
from pathlib import Path

from pydantic import BaseModel

from src.loader import LoadedCase
from src.sandbox import DockerRunner, ExecutionResult
from src.scorer import AttemptScore

# Wall-clock budget for one reproduction artifact, in seconds. A PoC that models
# a real exploit is quick; anything slower is a stall we would rather cut than
# wait on. This backstops the sandbox's own per-execution timeout and
# is deliberately short relative to the per-case agent budget, since a
# reproduction is a single script run, not a whole reasoning loop.
DEFAULT_ARTIFACT_TIMEOUT_SECONDS = 30.0

# Substring pytest/CPython prints to stderr on a compile failure. Used to tell a
# broken-artifact (SyntaxError) apart from a ran-but-failed artifact
# (RuntimeError), matching the two distinct taxonomy reasons.
_SYNTAX_ERROR_MARKER = "SyntaxError"

# Top-level module names whose import means the artifact is attempting behavior
# the harness forbids — network egress or package installation (the
# "disallowed behavior" failure). Detected statically: a Layer-2 reproduction of
# these benign, network-free cases never needs any of them, so importing one is a
# clear misbehavior signal. `subprocess` is deliberately absent — CASE-02's
# command-injection reproduction legitimately uses it.
_DISALLOWED_IMPORT_ROOTS = frozenset(
    {
        "socket", "ssl", "urllib", "http", "requests", "httpx", "ftplib",
        "smtplib", "telnetlib", "poplib", "imaplib", "xmlrpc",  # network egress
        "pip", "ensurepip", "setuptools",  # package installation
    }
)

# Distinctive stderr fragments the OS/sandbox emits when its isolation actively
# stops an operation ("sandbox blocked it"). Seeing one means the
# failure was the sandbox enforcing a limit — a write to the read-only case mount
# or an egress attempt under `--network none` — not the PoC's own logic error, so
# it earns the more specific SANDBOX_BLOCKED reason rather than RUNTIME_ERROR.
_SANDBOX_BLOCK_SIGNATURES = (
    "Read-only file system",  # a write into the read-only /work case mount
    "Network is unreachable",  # egress attempt under --network none
    "Temporary failure in name resolution",  # DNS blocked (no network)
    "Name or service not known",  # DNS blocked (no network)
)


class FailureReason(str, Enum):
    """Why a Layer-2 reproduction failed — the fixed failure taxonomy.

    A ``str`` enum so the value serializes to a stable, human-readable string in
    the result file rather than an opaque integer. The evaluator assigns every reason:
    five can be read straight off one execution, and three
    need extra inspection — a wrong-vulnerability PoC (:attr:`WRONG_TARGET`, found
    by checking the artifact exercises the case's own module), a PoC attempting
    forbidden behavior (:attr:`DISALLOWED_BEHAVIOR`, found by a static import
    scan), and one the sandbox actively stopped (:attr:`SANDBOX_BLOCKED`, found
    from the isolation's own stderr signatures).
    """

    NO_ARTIFACT = "no_artifact"  # the agent submitted no reproduction script
    SYNTAX_ERROR = "syntax_error"  # the artifact did not compile
    RUNTIME_ERROR = "runtime_error"  # it compiled but exited non-zero
    EFFECT_NOT_REPRODUCED = "effect_not_reproduced"  # ran the case, but no marker
    WRONG_TARGET = "wrong_target"  # never exercised this case's code
    DISALLOWED_BEHAVIOR = "disallowed_behavior"  # attempted forbidden act (network/install)
    SANDBOX_BLOCKED = "sandbox_blocked"  # isolation stopped it (read-only / no network)
    TIMEOUT_OR_RESOURCE = "timeout_or_resource"  # killed by a time/memory bound


class ReproductionResult(BaseModel):
    """The recorded result of one Layer-2 reproduction attempt.

    Carries both the verdict and the raw execution evidence behind it, so a run's
    result file can show *why* a reproduction passed or failed without
    re-running anything.

    Attributes:
        passed: ``True`` only when every success criterion held: an
            artifact existed, it executed, the expected effect was observed, and
            it stayed within sandbox limits. ``passed`` is ``True`` if and only if
            :attr:`reason` is ``None`` — the two can never disagree (enforced at
            construction).
        reason: The taxonomy reason for a failure, or ``None`` on a
            pass.
        stdout: The artifact's captured standard output — the text the
            expected-effect check ran against, kept for diagnostics.
        stderr: The artifact's captured standard error, e.g. a traceback that
            explains a :attr:`FailureReason.RUNTIME_ERROR`.
        exit_code: The artifact process's exit code, or ``None`` if it was killed
            before exiting (a timeout).
        timed_out: ``True`` if the artifact was killed for exceeding its
            wall-clock budget (surfaced as :attr:`FailureReason.TIMEOUT_OR_RESOURCE`).
        resource_killed: ``True`` if it was killed for exceeding a resource bound,
            memory in particular (same taxonomy reason as a timeout).
    """

    passed: bool
    reason: FailureReason | None
    stdout: str
    stderr: str
    exit_code: int | None
    timed_out: bool
    resource_killed: bool


class ReproductionEvaluator:
    """Runs Layer-2 reproduction artifacts and judges them.

    Stateless across calls: one evaluator is reused for a whole run, and each
    :meth:`evaluate` call is independent (a fresh sandbox container per artifact,
    via the injected :class:`~src.sandbox.DockerRunner`). Reusing the runner is
    what routes every reproduction through the one audited set of isolation flags.

    Args:
        runner: The Docker sandbox runner that executes untrusted code. Injected
            (not constructed here) so tests can pass a stand-in and a real run can
            share one runner across the agent's tools and this evaluator.
        timeout_seconds: Wall-clock budget applied to each artifact.
    """

    def __init__(
        self,
        runner: DockerRunner,
        timeout_seconds: float = DEFAULT_ARTIFACT_TIMEOUT_SECONDS,
    ) -> None:
        self._runner = runner
        self._timeout_seconds = timeout_seconds

    def evaluate(
        self,
        case: LoadedCase,
        artifact: str | None,
        workspace: Path,
    ) -> ReproductionResult:
        """Evaluate one Layer-2 reproduction artifact for one case.

        Runs the four-step workflow: guard, execute, classify, record. Every
        ending is turned into an :class:`ReproductionResult` — a missing artifact, a
        crash, a timeout, and a clean-but-ineffective run are all *recorded*
        outcomes, never exceptions, so a Layer-2 failure can never abort the run
        (mirrors the Layer-1 first-class-outcome discipline).

        Args:
            case: The Layer-2-eligible case being reproduced. Its ground-truth
                ``reproduction.success_marker`` drives the expected-effect check.
            artifact: The reproduction script the agent submitted, or ``None`` if
                it submitted none (an absent artifact is a first-class failure,
                not a precondition violation).
            workspace: The **sanitized** case workspace the agent worked in
                (``src/leakage_control.py``) — mounted read-only so the artifact
                imports the same module the agent saw (e.g. ``import submission``).
                Reusing the agent's own workspace is what makes the reproduction
                run against the exact code that was classified.

        Returns:
            The :class:`ReproductionResult` for this attempt.

        Raises:
            ValueError: If ``case`` is not Layer-2-eligible, or is missing its
                ``reproduction``/``success_marker`` answer-key fields. Both are
                corpus-wiring mistakes (the caller must gate on ``layer2_eligible``
                before calling, per), so they fail loudly
                as programming errors rather than being recorded as a normal
                Layer-2 failure that would silently pass an ineligible case.
        """
        # Enforce the "only Layer-2 cases are evaluated" invariant at
        # the boundary: reaching here for a non-eligible case is a caller bug, and
        # recording it as a pass/fail would corrupt the Layer-2 pass rate.
        if not case.layer2_eligible:
            raise ValueError(
                f"Case '{case.id}' is not Layer-2-eligible; the caller must gate "
                "on layer2_eligible before invoking the reproduction evaluator"
            )
        reproduction = case.ground_truth.reproduction
        if reproduction is None or not reproduction.success_marker:
            raise ValueError(
                f"Layer-2 case '{case.id}' is missing a reproduction.success_marker "
                "in its ground truth; the expected-effect check needs one"
            )

        # Step 1: no artifact is the simplest failure — nothing to
        # run, so short-circuit before touching the sandbox.
        if artifact is None or not artifact.strip():
            return _failure(FailureReason.NO_ARTIFACT)

        # Step 1b: a PoC that imports a network or
        # package-install module is attempting behavior the harness forbids
        #. The intent is disqualifying on its own, so we record it
        # statically and never run the script — the sandbox would contain it
        # anyway, but flagging the attempt is the more useful signal than watching
        # it fail. Recorded without execution evidence, like a missing artifact.
        if _attempts_disallowed_behavior(artifact):
            return _failure(FailureReason.DISALLOWED_BEHAVIOR)

        # Step 2: execute the artifact under full sandbox isolation. The runner
        # never raises for a timeout or resource kill — it reports them via flags
        # on the result — so classification below is a pure function of the result.
        result = self._runner.run_python(
            artifact,
            workspace=workspace,
            timeout_seconds=self._timeout_seconds,
        )

        # Whether the artifact actually references this case's own module(s). A PoC
        # that never imports the presented code cannot be reproducing *this* case's
        # vulnerability, which lets `_classify` tell a wrong-target attempt apart
        # from one that ran the right code but did not fire.
        targets_case = _artifact_targets_case(
            artifact, _workspace_module_names(workspace)
        )

        # Steps 3–4: classify the execution into a pass or a taxonomy reason.
        return self._classify(result, reproduction.success_marker, targets_case)

    def _classify(
        self,
        result: ExecutionResult,
        success_marker: str,
        targets_case: bool,
    ) -> ReproductionResult:
        """Turn a sandbox execution into a pass or a taxonomy failure.

        The checks are ordered from most-fatal to most-specific so each failure
        is attributed to its truest cause (a timeout is reported as a timeout, not
        as the non-zero exit it also produces):

          1. Killed by a time/memory bound → :attr:`FailureReason.TIMEOUT_OR_RESOURCE`.
          2. Non-zero exit whose stderr shows the sandbox stopped it →
             :attr:`FailureReason.SANDBOX_BLOCKED` (isolation, not the PoC's logic).
          3. Non-zero exit with a ``SyntaxError`` → :attr:`FailureReason.SYNTAX_ERROR`
             (the artifact never really ran).
          4. Any other non-zero exit → :attr:`FailureReason.RUNTIME_ERROR`.
          5. Clean exit, but the artifact never touched the case's code →
             :attr:`FailureReason.WRONG_TARGET` — even if it printed the marker,
             it demonstrated the effect in its *own* code, not the case's.
          6. Clean exit, exercised the case, marker present → **PASS**.
          7. Clean exit, exercised the case, marker absent →
             :attr:`FailureReason.EFFECT_NOT_REPRODUCED` (right code, no effect).

        Args:
            result: The sandbox execution result for the artifact.
            success_marker: The case's expected-effect marker to find in stdout.
            targets_case: Whether the artifact references the case's own module(s)
                — ``False`` means it never exercised this case's code, which
                separates a wrong-target attempt from a genuine-but-failed one.

        Returns:
            The classified :class:`ReproductionResult`, carrying the raw execution
            evidence alongside the verdict.
        """
        # 1. A time or memory kill takes precedence: it also shows up as a
        #    non-zero/absent exit code, but its true cause is the bound, so we
        #    report that rather than a misleading syntax/runtime error.
        if result.timed_out or result.resource_killed:
            return _failure(FailureReason.TIMEOUT_OR_RESOURCE, result)

        # 2/3/4. A non-zero exit means the artifact did not complete successfully.
        #   We attribute it as specifically as we can: the sandbox's own
        #   enforcement message wins (SANDBOX_BLOCKED), then a compile failure
        #   (SYNTAX_ERROR — it never really ran), then any other error (RUNTIME_ERROR).
        if result.exit_code != 0:
            if _looks_sandbox_blocked(result.stderr):
                return _failure(FailureReason.SANDBOX_BLOCKED, result)
            if _SYNTAX_ERROR_MARKER in result.stderr:
                return _failure(FailureReason.SYNTAX_ERROR, result)
            return _failure(FailureReason.RUNTIME_ERROR, result)

        # 5. A clean run must first have exercised the case's own code to count.
        #    If the artifact never referenced the case module, it was testing the
        #    wrong thing — and this wins even when the marker is present, because a
        #    marker produced by the artifact's *own* code (e.g. its own
        #    subprocess call) is not evidence that *this* case's sink is
        #    vulnerable (WRONG_TARGET). This closes a false-positive where a PoC
        #    reproduces the effect in code it wrote instead of the case's.
        if not targets_case:
            return _failure(FailureReason.WRONG_TARGET, result)

        # 6. It exercised the case and produced the expected effect: success. The
        #    match is case-insensitive so a trivial casing difference in the
        #    artifact's own print does not mask a genuine reproduction; the marker
        #    itself is still specific.
        if success_marker.lower() in result.stdout.lower():
            return ReproductionResult(
                passed=True,
                reason=None,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.exit_code,
                timed_out=result.timed_out,
                resource_killed=result.resource_killed,
            )

        # 7. It ran the right code but the effect did not appear.
        return _failure(FailureReason.EFFECT_NOT_REPRODUCED, result)


def _failure(
    reason: FailureReason, result: ExecutionResult | None = None
) -> ReproductionResult:
    """Build a failed :class:`ReproductionResult`, carrying execution evidence if any.

    Centralizes the ``passed=False`` construction so every failure path attaches
    the same fields consistently. A :attr:`FailureReason.NO_ARTIFACT` failure has
    no execution to describe (nothing ran), so its evidence fields take empty
    defaults.

    Args:
        reason: The taxonomy reason for the failure (never ``None`` — a passing
            result is built inline in :meth:`ReproductionEvaluator._classify`).
        result: The sandbox execution result, or ``None`` when no artifact ran.

    Returns:
        A failed :class:`ReproductionResult` with ``passed=False`` and the given reason.
    """
    if result is None:
        return ReproductionResult(
            passed=False,
            reason=reason,
            stdout="",
            stderr="",
            exit_code=None,
            timed_out=False,
            resource_killed=False,
        )
    return ReproductionResult(
        passed=False,
        reason=reason,
        stdout=result.stdout,
        stderr=result.stderr,
        exit_code=result.exit_code,
        timed_out=result.timed_out,
        resource_killed=result.resource_killed,
    )


# --------------------------------------------------------------------------- #
# Taxonomy detectors — small, deterministic, no I/O                     #
# --------------------------------------------------------------------------- #


def _attempts_disallowed_behavior(artifact: str) -> bool:
    """Whether the artifact statically imports a forbidden module.

    Detects the *intent* to reach the network or install packages by inspecting
    the artifact's imports via the AST — not a plain text search, which would
    false-positive on the same word appearing in a comment or string literal. If
    the source does not parse, this returns ``False`` and lets execution surface
    the ``SyntaxError`` instead (a broken script is not a disallowed one).

    Args:
        artifact: The reproduction script source.

    Returns:
        ``True`` if any ``import``/``from`` names a module in
        :data:`_DISALLOWED_IMPORT_ROOTS`.
    """
    try:
        tree = ast.parse(artifact)
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            # `import a.b.c` — the disallowed unit is the top-level package `a`.
            if any(alias.name.split(".")[0] in _DISALLOWED_IMPORT_ROOTS
                   for alias in node.names):
                return True
        elif isinstance(node, ast.ImportFrom):
            # `from a.b import c` — again keyed on the top-level package `a`.
            root = (node.module or "").split(".")[0]
            if root in _DISALLOWED_IMPORT_ROOTS:
                return True
    return False


def _workspace_module_names(workspace: Path) -> set[str]:
    """Importable module names in the sanitized case workspace (e.g. ``{"submission"}``).

    The workspace holds only the case's own (label-stripped) code files, so their
    stems are exactly the modules a genuine reproduction would import. Used to
    decide whether an artifact actually references this case's code.

    Args:
        workspace: The sanitized case workspace directory.

    Returns:
        The set of ``.py`` file stems that are valid Python identifiers.
    """
    return {
        path.stem
        for path in workspace.glob("*.py")
        if path.stem.isidentifier()
    }


def _artifact_targets_case(artifact: str, module_names: set[str]) -> bool:
    """Whether the artifact references any of the case's own modules.

    A reproduction that never mentions the case's module cannot be exercising the
    case's code, so whatever it demonstrates is not *this* vulnerability — that is
    the signal separating :attr:`FailureReason.WRONG_TARGET` from a genuine but
    ineffective attempt. When the module set is unknown (an empty workspace, as in
    some unit tests) we cannot disprove targeting, so we conservatively return
    ``True`` and let the softer ``EFFECT_NOT_REPRODUCED`` apply.

    Args:
        artifact: The reproduction script source.
        module_names: The case's importable module names.

    Returns:
        ``True`` if the artifact references at least one case module, or if the
        module set is empty.
    """
    if not module_names:
        return True
    return any(
        re.search(rf"\b{re.escape(name)}\b", artifact) for name in module_names
    )


def _looks_sandbox_blocked(stderr: str) -> bool:
    """Whether stderr shows the sandbox actively stopped the artifact.

    Args:
        stderr: The artifact's captured standard error.

    Returns:
        ``True`` if any known isolation-enforcement fragment
        (:data:`_SANDBOX_BLOCK_SIGNATURES`) appears — a read-only-mount write or a
        network attempt under ``--network none`` — marking the failure as the
        sandbox's doing rather than the PoC's own logic error.
    """
    return any(signature in stderr for signature in _SANDBOX_BLOCK_SIGNATURES)


# --------------------------------------------------------------------------- #
# Partial-credit view: keep Layer 1 and Layer 2 separate     #
# --------------------------------------------------------------------------- #


class LayeredAttemptResult(BaseModel):
    """One attempt's Layer-1 and Layer-2 verdicts, kept deliberately separate.

    This realizes the **partial-credit principle**: Layer 2 is an *additional*
    signal, so a single attempt can pass Layer 1 (a correct diagnosis) and still
    fail Layer 2 (the proof-of-concept did not reproduce). The two verdicts live in
    separate fields and are **never** reduced to one combined pass/fail, so a
    reader — and the later comparison report — can always see both.

    This is a small in-memory view for making the separation explicit and testable
    now; the persistent per-attempt record is ``results.AttemptResult``, which
    carries these same distinct signals.

    Attributes:
        layer1_detection_correct: Whether Layer 1 got the yes/no detection right.
        layer1_all_correct: Whether every *scored* Layer-1 core dimension
            (detection, and type/CWE where the ground truth provides them) was
            correct — the "passed all Layer-1 dimensions" condition for partial credit.
            Function location is excluded on purpose: it is a separate, low-weight
            signal, not part of the capability core.
        layer2_applicable: Whether Layer 2 was evaluated for this attempt (only a
            Layer-2 case with a submitted reproduction is).
        layer2_passed: The Layer-2 verdict, or ``None`` when not applicable.
        layer2_reason: The Layer-2 failure reason, or ``None`` on a pass / when
            Layer 2 was not applicable.
    """

    layer1_detection_correct: bool
    layer1_all_correct: bool
    layer2_applicable: bool
    layer2_passed: bool | None
    layer2_reason: FailureReason | None


def combine_layers(
    score: AttemptScore, reproduction: ReproductionResult | None
) -> LayeredAttemptResult:
    """Combine one attempt's Layer-1 score and Layer-2 result *without* collapsing them.

    Keeps the two layers as separate fields so "passed Layer 1, failed Layer 2" is
    a first-class, visible state rather than being averaged into a single verdict.
    Pure and deterministic (no I/O), like the rest of the scoring path.

    Args:
        score: The Layer-1 grade for the attempt (from ``scorer.score_attempt``).
        reproduction: The Layer-2 result, or ``None`` for a Layer-1-only attempt
            (a case that is not Layer-2-eligible, or one where no reproduction ran).

    Returns:
        A :class:`LayeredAttemptResult` exposing both verdicts side by side.
    """
    # "All Layer-1 dimensions correct" = every core dimension the ground truth
    # actually scored is correct. Detection is always scored; type/CWE are `None`
    # (not applicable, e.g. for a negative control) when truth omits them, and a
    # `None` dimension does not count against the attempt. Since
    # detection is always a bool in this tuple, an all-`True` result already
    # implies detection was correct.
    core_dimensions = (score.detection_correct, score.type_correct, score.cwe_correct)
    layer1_all_correct = all(
        dimension is True for dimension in core_dimensions if dimension is not None
    )
    return LayeredAttemptResult(
        layer1_detection_correct=score.detection_correct,
        layer1_all_correct=layer1_all_correct,
        layer2_applicable=reproduction is not None,
        layer2_passed=reproduction.passed if reproduction is not None else None,
        layer2_reason=reproduction.reason if reproduction is not None else None,
    )

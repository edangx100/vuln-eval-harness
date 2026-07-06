"""One-command evaluation for the configured model.

Running ``python -m src.cli.run_eval`` is the "front door" of the whole harness: it reads a
single model's configuration from ``.env`` (or the process environment), runs that model against
every case in the benchmark corpus, and writes one structured result file — the exact
:class:`~src.results.RunResult` — to
``results/<run_name>.json``. Nothing else in the codebase drives a real evaluation end-to-end;
every other module (the scorer, the reproduction evaluator, the report generator) is a piece this
script wires together.

**This module is the orchestrator, not a new capability.** Every step below already exists
elsewhere:

  1. Load one case at a time (:mod:`src.loader`).
  2. Build that case's sanitized, label-free workspace (:mod:`src.leakage_control`) — the
     answer-key-free copy the agent is allowed to see.
  3. Build one agent for the case and run it :attr:`~src.config.Settings.attempts_per_case` times
     (:mod:`src.agent`).
  4. Grade each attempt (:mod:`src.scorer`) and, for an eligible case where the
     agent claimed "vulnerable", replay its proof-of-concept in the sandbox
     (:mod:`src.reproduction`).
  5. Join all three into one :class:`~src.results.AttemptResult` per attempt
     (:mod:`src.results`) and save the growing run after every case.

**Why the model is a parameter, not built inside the loop.** :func:`run_evaluation` — the
testable core — accepts an already-built Pydantic AI model rather than constructing the
OpenRouter one itself. This is the same pattern :mod:`src.agent.case_agent` already uses: it lets
a test drive the *entire* orchestration offline with a stub model (no network, no API key), while
:func:`main` — the actual process entry point — supplies the real
:func:`~src.agent.model.build_openrouter_model` model for a live run. Only :func:`main` reads
``.env``/the environment and only :func:`main` calls :func:`~src.sandbox_preflight.preflight`;
:func:`run_evaluation` itself never touches either.

**Incremental persistence.** The full run is rewritten to disk after *every completed
case* (not just at the very end), so a crash partway through a long run never loses the cases that
already finished — the same crash-safety philosophy ``IncrementalResultStore`` uses for
per-attempt records, applied here at case granularity because this module writes the *full*
result schema (which needs a case's Layer-2 results before that case's record is complete), not the
narrower per-attempt snapshot ``observability.py`` writes during agent runs.
"""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path

from pydantic_ai.models import Model

from src.agent import build_case_agent, build_openrouter_model, run_case_attempt
from src.agent.runner import AttemptOutcome
from src.config import Settings
from src.leakage_control import build_sanitized_workspace
from src.loader import LoadedCase, load_corpus, load_corpus_version
from src.reproduction import ReproductionEvaluator, ReproductionResult
from src.results import AttemptResult, CaseResult, RunResult
from src.sandbox import SANDBOX_IMAGE, DockerRunner
from src.sandbox_preflight import preflight
from src.schema import VulnerabilityReport
from src.scorer import score_attempt

# One logger per module, following the standard-library convention already used in
# `src/agent/observability.py`, so this module's progress lines can be configured or silenced
# independently of the rest of the application.
logger = logging.getLogger(__name__)

# Where result files are written by default (`results/<run_name>.json`). Kept as a
# named default (not a bare literal) so a test can point it at a temp directory instead.
DEFAULT_RESULTS_DIR = Path("results")


def run_evaluation(
    settings: Settings,
    model: Model | str,
    *,
    cases: list[LoadedCase] | None = None,
    runner: DockerRunner | None = None,
    results_dir: Path = DEFAULT_RESULTS_DIR,
) -> RunResult:
    """Run one full evaluation and return the saved :class:`~src.results.RunResult`.

    This is the testable core of the entry point: it takes an already-built model (so a test can
    supply a stub and skip both the network and the Docker preflight check) and drives every case
    in ``cases`` through the full attempt → score → (maybe) reproduce → record pipeline, saving
    the growing run to ``results_dir/<settings.run_name>.json`` after each case completes.

    Args:
        settings: The run configuration — model id, run name, attempts-per-case, and the effort
            bounds. The API credential on ``settings`` is used only if the
            caller built ``model`` from it; this function never reads it directly.
        model: The Pydantic AI model (or model-name string) that drives every case's agent. A
            real run passes the OpenRouter model :func:`main` builds; a test passes a stub/
            recorded model to stay offline (a deterministic stub keeps CI reproducible).
        cases: The cases to evaluate. Defaults to the full benchmark corpus
            (:func:`~src.loader.load_corpus`); a test may pass a small hand-built subset to keep
            runtime short.
        runner: The Docker sandbox runner shared across every case's execution tools *and* the
            Layer-2 reproduction evaluator (one runner, reused, routes
            every untrusted execution through the same audited isolation flags). Defaults to a
            fresh :class:`~src.sandbox.DockerRunner`. A test only needs Docker if its stub model
            actually exercises the sandbox (calls a tool, or triggers a Layer-2 reproduction);
            otherwise this object is constructed but never invoked.
        results_dir: Directory the result file is written under. Defaults to
            :data:`DEFAULT_RESULTS_DIR` (``results/``); a test points this at a temp directory.

    Returns:
        The final :class:`~src.results.RunResult`, covering every case in ``cases`` — the same
        object already saved to ``results_dir/<settings.run_name>.json``.
    """
    resolved_cases = cases if cases is not None else load_corpus()
    corpus_version = load_corpus_version()
    resolved_runner = runner if runner is not None else DockerRunner()
    reproduction_evaluator = ReproductionEvaluator(resolved_runner)

    result_path = results_dir / f"{settings.run_name}.json"
    case_results: list[CaseResult] = []

    for case_number, case in enumerate(resolved_cases, start=1):
        case_result = _run_one_case(
            case,
            model=model,
            runner=resolved_runner,
            reproduction_evaluator=reproduction_evaluator,
            settings=settings,
        )
        case_results.append(case_result)

        # Rebuild the run from every case finished so far and rewrite the file. Cheap
        # to redo in full each time — a run is a handful of cases — and RunResult.save() is
        # itself crash-safe (write-to-temp + atomic rename), so this line is
        # what turns that safety into "a crash loses at most the case in flight, never a finished one."
        run_result = RunResult.build(
            run_name=settings.run_name,
            model_id=settings.openrouter_model,
            corpus_version=corpus_version,
            sandbox_image=resolved_runner.image,
            attempts_per_case=settings.attempts_per_case,
            cases=case_results,
        )
        run_result.save(result_path)
        logger.info(
            "case=%s done (%d/%d) -> %s", case.id, case_number, len(resolved_cases), result_path
        )

    return run_result


def _run_one_case(
    case: LoadedCase,
    *,
    model: Model | str,
    runner: DockerRunner,
    reproduction_evaluator: ReproductionEvaluator,
    settings: Settings,
) -> CaseResult:
    """Run every attempt for one case and assemble its :class:`~src.results.CaseResult`.

    Builds exactly one sanitized workspace and one :class:`~src.agent.case_agent.CaseAgent` for
    the case, then reuses both across all ``attempts_per_case`` attempts — safe because
    :func:`~src.agent.runner.run_case_attempt` clears the agent's captured report at the start of
    every call, so repeated attempts stay independent trials rather than one
    continued conversation.

    Args:
        case: The case to evaluate.
        model: The model driving the case's agent.
        runner: The shared Docker sandbox runner (for execution tools and Layer-2 reproduction).
        reproduction_evaluator: The shared Layer-2 evaluator.
        settings: The run configuration (attempts-per-case, effort bounds).

    Returns:
        The case's :class:`~src.results.CaseResult`, covering every attempt.
    """
    # A fresh, neutral temp directory per case — cleaned up automatically once every attempt for
    # this case has finished (the `with` block's exit), since nothing later needs it.
    with tempfile.TemporaryDirectory(prefix=f"{case.id}-") as workspace_dir:
        workspace = build_sanitized_workspace(case.code_path.parent, Path(workspace_dir))
        case_agent = build_case_agent(model=model, workspace=workspace, runner=runner)

        attempt_results: list[AttemptResult] = []
        for attempt_index in range(1, settings.attempts_per_case + 1):
            outcome = run_case_attempt(
                case_agent,
                max_tool_call_steps=settings.max_tool_call_steps,
                case_timeout_seconds=settings.case_timeout_seconds,
            )
            score = score_attempt(_report_or_not_vulnerable(outcome), case.ground_truth)
            reproduction = _maybe_reproduce(case, outcome, reproduction_evaluator, workspace)
            attempt_results.append(
                AttemptResult.from_attempt(attempt_index, outcome, score, reproduction)
            )
            logger.info(
                "case=%s attempt=%d/%d outcome=%s",
                case.id,
                attempt_index,
                settings.attempts_per_case,
                "invalid-output" if outcome.invalid_output else "valid",
            )

    return CaseResult.from_attempts(case, attempt_results)


def _report_or_not_vulnerable(outcome: AttemptOutcome) -> VulnerabilityReport:
    """The attempt's report, or a stand-in "not vulnerable" report for an invalid-output attempt.

    :func:`~src.scorer.score_attempt` always needs a report to compare against ground truth, but
    an invalid-output attempt has none. Scoring it as if the agent had confidently
    reported "not vulnerable" is exactly right: on a genuinely vulnerable case that scores as a
    missed detection, and on a negative control it scores as a (correct) non-detection.

    Args:
        outcome: The completed attempt's outcome.

    Returns:
        ``outcome.report.report`` if a valid report was submitted, else
        ``VulnerabilityReport(is_vulnerable=False)``.
    """
    if outcome.report is not None:
        return outcome.report.report
    return VulnerabilityReport(is_vulnerable=False)


def _maybe_reproduce(
    case: LoadedCase,
    outcome: AttemptOutcome,
    reproduction_evaluator: ReproductionEvaluator,
    workspace: Path,
) -> ReproductionResult | None:
    """Run Layer-2 reproduction only when it applies to this attempt.

    Layer 2 only ever runs when *both* are true: the case is Layer-2-eligible, and the
    agent's own report claims the code is vulnerable — there is nothing to reproduce if the agent
    said "safe," and running an ineligible case would violate the
    :meth:`~src.reproduction.ReproductionEvaluator.evaluate` precondition.

    Args:
        case: The case this attempt belongs to.
        outcome: The completed attempt's outcome.
        reproduction_evaluator: The shared Layer-2 evaluator.
        workspace: The case's sanitized workspace (reused so the reproduction imports the exact
            code the agent saw).

    Returns:
        The :class:`~src.reproduction.ReproductionResult`, or ``None`` when Layer 2 does not apply
        to this attempt.
    """
    if not case.layer2_eligible or outcome.report is None or not outcome.report.report.is_vulnerable:
        return None
    return reproduction_evaluator.evaluate(case, outcome.report.reproduction_script, workspace)


def main() -> None:
    """Process entry point: ``python -m src.cli.run_eval``.

    Reads run configuration from ``.env``/the environment (:class:`~src.config.Settings`), verifies
    the sandbox is ready (:func:`~src.sandbox_preflight.preflight` — fails fast with an actionable
    message rather than partway through the run), builds the real OpenRouter model, and runs the
    full evaluation via :func:`run_evaluation`.
    """
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    settings = Settings()
    preflight(SANDBOX_IMAGE)
    model = build_openrouter_model(settings)

    run_result = run_evaluation(settings, model)
    print(f"wrote results/{run_result.run_name}.json")


if __name__ == "__main__":
    main()

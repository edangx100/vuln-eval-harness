"""Run observability & incremental persistence.

A full evaluation run is not fast: the effort bounds (15 tool-call steps, a 120-second
per-case timeout) mean a single case attempt can legitimately take up to two minutes, and a run
repeats that across every case and every attempt. Multiplied out, a real run takes
somewhere between roughly 15 and 60 minutes. Left
to run silently, that is indistinguishable from a hang; and if the process dies partway through
(a crash, an out-of-memory kill, a manual interrupt), a batched "write everything at the end"
design would lose every attempt that had already finished.

This module solves both problems with two small, independent pieces that plug into
:func:`~src.agent.runner.run_case_attempts`'s ``on_attempt`` hook:

  - :func:`log_attempt_progress` — emits one structured log line the moment an attempt finishes,
    so a running evaluation is visible in the terminal/log file rather than silent.
  - :class:`IncrementalResultStore` — writes the run's results to disk after *every* attempt,
    not batched at the end, so a crash mid-run only loses the attempt in flight, never the ones
    already completed.

:func:`make_case_observer` composes both into the single callback ``run_case_attempts`` expects.

**Scope note.** The *full* per-run result file (model id, corpus version, Layer-2 outcomes,
negative-control results, trial-averaged aggregates) is owned by :mod:`src.results`.
:class:`IncrementalResultStore` deliberately persists a narrower record — exactly the
per-attempt fields this module already has in hand (the report, retry count, tripped bound, and
usage) — so it delivers the *incremental-write mechanism* without duplicating that full schema.
"""

from __future__ import annotations

import dataclasses
import json
import logging
from pathlib import Path

from src.agent.runner import AttemptObserver, AttemptOutcome

# One logger per module, following the standard library convention, so a caller can configure
# (or silence) this module's log lines independently of the rest of the application.
logger = logging.getLogger(__name__)


def log_attempt_progress(case_id: str, attempt_number: int, outcome: AttemptOutcome) -> None:
    """Emit one structured progress line for a completed attempt.

    Written as a single ``logger.info`` call with the fields the task calls for — case id,
    attempt number, tool steps used, outcome, retry count, and the tripped bound (if any) — so a
    long run prints exactly one greppable line per attempt as it happens, instead of staying
    silent until the whole run (or even one case) finishes.

    Args:
        case_id: The corpus id of the case this attempt belongs to.
        attempt_number: Which attempt this is for the case (1-indexed, matching the number
            :func:`~src.agent.runner.run_case_attempts` passes to its ``on_attempt`` hook).
        outcome: The completed attempt's :class:`~src.agent.runner.AttemptOutcome`.
    """
    # "valid" / "invalid-output" mirrors the outcome's own vocabulary (AttemptOutcome.invalid_output)
    # rather than inventing a new label here.
    status = "invalid-output" if outcome.invalid_output else "valid"
    logger.info(
        "case=%s attempt=%d outcome=%s tool_calls=%d retries=%d bound=%s",
        case_id,
        attempt_number,
        status,
        outcome.usage.tool_calls,  # "tool steps used" — the same count the step budget counts
        outcome.report_retries,
        outcome.bound_tripped or "none",
    )


class IncrementalResultStore:
    """Persists one run's attempts to a JSON file, rewritten after every attempt.

    The file exists (with an empty ``cases`` section) from the moment the store is constructed, and
    is rewritten in full after each :meth:`record_attempt` call. "Rewritten in full" sounds
    wasteful, but a run's result file is small (a handful of cases, a few attempts each) and this
    is what makes the write crash-safe with no extra machinery: each write is atomic (write to a
    temp file, then rename it over the real one), so a crash either lands before the rename — in
    which case the previous, still-complete file survives untouched — or after it, in which case
    the new attempt is safely included. There is no window where a crash can leave a half-written,
    corrupted file on disk.

    Attributes:
        path: Where the run's result file lives, e.g. ``results/<run_name>.json``.
    """

    def __init__(
        self,
        path: Path,
        *,
        run_name: str,
        model_id: str,
        attempts_per_case: int,
    ) -> None:
        """Create the store and write the initial (empty-cases) file immediately.

        Args:
            path: The run's result file path. Parent directories are created if missing.
            run_name: This run's name — identifies the result file.
            model_id: The OpenRouter model id being evaluated.
            attempts_per_case: The configured attempts-per-case for this run.
        """
        self.path = path
        # A deliberately narrow record — see the module docstring's scope note. The full result
        # file in src.results adds the remaining fields (Layer-2 outcomes, corpus version, aggregates).
        self._data: dict[str, object] = {
            "run_name": run_name,
            "model_id": model_id,
            "attempts_per_case": attempts_per_case,
            "cases": {},
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._write()

    def record_attempt(self, case_id: str, attempt_number: int, outcome: AttemptOutcome) -> None:
        """Append one attempt's result and rewrite the file immediately.

        Args:
            case_id: The corpus id of the case this attempt belongs to.
            attempt_number: Which attempt this is for the case (1-indexed).
            outcome: The completed attempt's :class:`~src.agent.runner.AttemptOutcome`.
        """
        cases = self._data["cases"]
        assert isinstance(cases, dict)  # narrows the type for the setdefault below
        cases.setdefault(case_id, []).append(
            {
                "attempt_number": attempt_number,
                # None (invalid-output) round-trips through JSON as `null`, matching the report
                # field's own "None means no acceptable report" convention.
                "report": outcome.report.model_dump() if outcome.report is not None else None,
                "report_retries": outcome.report_retries,
                "bound_tripped": outcome.bound_tripped,
                # RunUsage is a dataclass, not a Pydantic model, so it needs dataclasses.asdict
                # (not .model_dump()) to become a plain, JSON-serializable dict.
                "usage": dataclasses.asdict(outcome.usage),
            }
        )
        self._write()

    def _write(self) -> None:
        """Write the current in-memory state to disk atomically.

        Writing to a sibling temp file and then renaming it over the real path is what makes each
        write crash-safe (an interrupted write only ever leaves the temp file incomplete; the real
        path is untouched until the rename, which is a single atomic filesystem operation).
        """
        tmp_path = self.path.with_name(self.path.name + ".tmp")
        tmp_path.write_text(json.dumps(self._data, indent=2))
        tmp_path.replace(self.path)


def make_case_observer(
    store: IncrementalResultStore,
    case_id: str,
    *,
    log: bool = True,
) -> AttemptObserver:
    """Build one ``run_case_attempts(on_attempt=...)`` callback for a single case.

    Composes :meth:`IncrementalResultStore.record_attempt` (persistence) and
    :func:`log_attempt_progress` (logging) into the single ``(attempt_number, outcome) -> None``
    callback :func:`~src.agent.runner.run_case_attempts` calls after each attempt, closing over
    the ``case_id`` so neither the store nor the runner needs to know it independently.

    Args:
        store: The run's :class:`IncrementalResultStore` to persist each attempt into.
        case_id: The corpus id of the case being run — threaded through to both the stored
            record and the progress log line.
        log: Whether the built callback also emits a progress log line. Defaults to ``True``;
            set ``False`` to persist silently (e.g. in a test that only cares about the file).

    Returns:
        A callback suitable for :func:`~src.agent.runner.run_case_attempts`'s ``on_attempt``.
    """

    def observer(attempt_number: int, outcome: AttemptOutcome) -> None:
        store.record_attempt(case_id, attempt_number, outcome)
        if log:
            log_attempt_progress(case_id, attempt_number, outcome)

    return observer

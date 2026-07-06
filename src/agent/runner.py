"""Run loop — one bounded case attempt, repeated N times, observably.

:func:`build_case_agent` (``case_agent.py``) *builds* the agent for one case; this module
*runs* it. :func:`run_case_attempt` drives a single attempt end-to-end, under two per-case
effort bounds, and resolves it into a recorded :class:`AttemptOutcome`:

  - **A valid report** — accepted and scored as-is, *even if its contents are wrong*. A
    wrong-but-valid answer is the measurement, never a reason to retry.
  - **An invalid-output failure** — the agent produced no report the harness could accept:
    every submission failed the schema (exhausted the re-request budget), it never submitted
    one (an absent report), or a bound tripped before a valid report existed. Recorded, never a
    crash; the scorer later treats it as a failed detection.

**Retry-on-invalid.** The report is delivered through the strict ``submit_report`` tool
(``case_agent.py``). When the model submits a report that fails that strict schema,
Pydantic AI does the retry-on-invalid work natively: it feeds the exact validation error back and
re-requests the report — a correction, not a blind reroll — bounded by ``REPORT_MAX_RETRIES``.
This module counts those re-requests (format fragility is a comparison signal, not just plumbing).

**Effort bounds.** Each attempt runs under two bounds, and the outcome records
**which one tripped** if any:

  - *Primary — tool-call steps.* Enforced with Pydantic AI's ``tool_calls_limit``. It counts
    executed tool calls but **not** the report re-requests (a schema-failed ``submit_report`` is
    not a completed tool call), so the report-retry budget is not charged against the step budget —
    exactly the separation between the two budgets. Exceeding it raises ``UsageLimitExceeded``.
  - *Backstop — wall-clock.* An :func:`asyncio.timeout` around the run catches stalls (a slow
    provider) that would not otherwise consume steps; a hung sandbox execution is bounded
    independently by the Docker runner's own timeout. Exceeding it raises ``TimeoutError``.

Token usage is **recorded**, never gated on: a :class:`~pydantic_ai.usage.RunUsage`
accumulator is passed into the run so its counts survive even when a bound trips mid-run.

The two budgets are kept separate so neither masks the other.

**Repeated attempts.** The agent is non-deterministic, so a single attempt is a noisy
measurement. :func:`run_case_attempts` runs a case ``attempts_per_case`` **independent**
times and returns every :class:`AttemptOutcome` unchanged — it is a thin loop around
:func:`run_case_attempt`, not a rewrite of it. Averaging those attempts into one figure is
deliberately **not** done here: best-of-N is rejected (it would measure "could the model ever
get it right" instead of "does it get it right reliably"), and the trial-averaging/pass-rate math
that replaces it already exists in :mod:`src.scorer` (``aggregate_run``). This module's job
ends at *producing* the N stored per-attempt results; scoring and averaging them is the scorer's job.

**Observability & incremental persistence.** A real run can take 15-60 minutes (many
attempts, each bounded but not fast), and a batched
"write everything at the end" design would lose every completed attempt if the process died
partway through. :func:`run_case_attempts` accepts an optional ``on_attempt`` callback, fired
immediately after each attempt (before the next one starts), so a caller can log progress and
persist results incrementally rather than silently, batched, or not at all. This module
defines only the *hook*; the concrete logging and persistence callbacks live in
:mod:`~src.agent.observability`, which depends on this module rather than the reverse.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Callable, Literal

from pydantic_ai import Agent, capture_run_messages
from pydantic_ai.exceptions import UnexpectedModelBehavior, UsageLimitExceeded
from pydantic_ai.messages import ModelMessage, RetryPromptPart
from pydantic_ai.usage import RunUsage, UsageLimits

from src.agent.case_agent import CaseAgent
from src.config import (
    DEFAULT_ATTEMPTS_PER_CASE,
    DEFAULT_CASE_TIMEOUT_SECONDS,
    DEFAULT_MAX_TOOL_CALL_STEPS,
)
from src.tools import SubmittedReport

# The standing user prompt that starts one attempt. The agent's *instructions* (task framing +
# constraints) live on the agent itself (``case_agent.py``); this is just the
# per-run nudge to begin. Kept constant so every attempt starts identically (determinism).
DEFAULT_ATTEMPT_PROMPT = (
    "Assess this case for a security vulnerability using the provided tools, "
    "then submit your report."
)

# Per-case effort-bound defaults. These are the *canonical* defaults defined once in
# ``src/config.py`` — the same constants that back the ``Settings`` fields, which ``.env`` / env
# vars override — re-used here (not re-hardcoded) so the numbers cannot drift between the
# two. A real run constructs ``Settings`` and passes the ``.env``-resolved values through
# (``max_tool_call_steps=settings.max_tool_call_steps``, likewise the timeout); these signature
# defaults only apply when the function is called stand-alone (e.g. in tests). Both are per-corpus
# tunables, not policy baked into this module.

# Which effort bound ended the attempt, if any (requires recording *which* tripped).
BoundTripped = Literal["steps", "wall-clock"]


@dataclass
class AttemptOutcome:
    """The recorded result of one case attempt.

    Attributes:
        report: The validated report the agent submitted, or ``None`` when the attempt
            produced no acceptable report — an invalid-output failure (every submission
            failed the schema, none was submitted, or a bound tripped first). ``None`` is a
            first-class recorded outcome, scored later as a failed detection, not an error.
        report_retries: How many times the report was re-requested because a submission
            failed the strict schema. ``0`` for a report accepted first try
            (including a wrong-but-valid one), up to :data:`~src.agent.case_agent.REPORT_MAX_RETRIES`
            when the budget is exhausted. Recorded per case as a fragility signal.
        bound_tripped: Which effort bound ended the attempt early: ``"steps"`` (the
            tool-call budget) or ``"wall-clock"`` (the per-case timeout), or ``None`` if the
            attempt finished on its own. Recorded so a bound-limited run is visible, not silent.
        usage: The run's token/tool-call usage (:class:`~pydantic_ai.usage.RunUsage`). Recorded
            as a cost/efficiency signal only — **never** gated on. Populated even
            when a bound trips, since the accumulator is passed into the run.
    """

    report: SubmittedReport | None
    report_retries: int
    bound_tripped: BoundTripped | None = None
    usage: RunUsage = field(default_factory=RunUsage)

    @property
    def invalid_output(self) -> bool:
        """Whether the attempt ended without an acceptable report.

        ``True`` exactly when :attr:`report` is ``None`` — the single, unambiguous marker of
        an invalid-output failure, so callers never have to re-derive it. A bound may trip
        *with* a valid report already submitted (kept and scored as-is); that is not an
        invalid-output failure.
        """
        return self.report is None


# A callback fired right after one attempt completes: ``(attempt_number, outcome) -> None``
#. Lets :func:`run_case_attempts` report progress and persist results
# incrementally without knowing *how* — the concrete callbacks (writing to the run file,
# emitting a log line) live in :mod:`~src.agent.observability`, which this module does not
# import (observability depends on the runner, not the other way around).
AttemptObserver = Callable[[int, AttemptOutcome], None]


def run_case_attempt(
    case_agent: CaseAgent,
    *,
    prompt: str = DEFAULT_ATTEMPT_PROMPT,
    max_tool_call_steps: int = DEFAULT_MAX_TOOL_CALL_STEPS,
    case_timeout_seconds: float = DEFAULT_CASE_TIMEOUT_SECONDS,
) -> AttemptOutcome:
    """Run one bounded attempt of one case (retry-on-invalid, effort bounds).

    Runs the agent once under two per-case bounds and resolves it into a recorded
    :class:`AttemptOutcome`. Pydantic AI handles the re-request loop for a malformed report
    internally (feeding the schema error back), bounded by ``REPORT_MAX_RETRIES``; this function
    additionally enforces the effort bounds, records which one (if any) tripped, counts the report
    re-requests, and captures token usage — turning every ending (valid report, exhausted retries,
    absent report, tripped bound) into a recorded outcome rather than an exception.

    A fresh :class:`~src.agent.case_agent.CaseAgent` should back each attempt (its
    ``report_tool`` captures the submission); the captured report is cleared here first so a
    reused agent cannot leak a prior attempt's report into this one.

    Args:
        case_agent: The built agent bundle for this case (from
            :func:`~src.agent.case_agent.build_case_agent`).
        prompt: The user prompt that starts the attempt. Defaults to
            :data:`DEFAULT_ATTEMPT_PROMPT`.
        max_tool_call_steps: Primary effort bound — the max tool-call steps before the attempt
            ends on the step budget. A real run passes the configured value; defaults
            to :data:`DEFAULT_MAX_TOOL_CALL_STEPS`.
        case_timeout_seconds: Backstop effort bound — the per-case wall-clock timeout in seconds
. Defaults to :data:`DEFAULT_CASE_TIMEOUT_SECONDS`.

    Returns:
        The :class:`AttemptOutcome`: a validated report (scored as-is, even if wrong) or
        ``report=None`` for an invalid-output failure, plus the report-retry count, which bound
        tripped (if any), and the recorded token/tool-call usage.
    """
    # Clear any prior capture so this attempt's outcome is entirely its own (defensive; each
    # attempt is expected to use a fresh agent, but this makes the function safe to reuse).
    case_agent.report_tool.submitted = None

    # The step budget. tool_calls_limit counts executed tool calls but not schema-failed
    # submit_report re-requests, so the report-retry budget is not charged here.
    usage_limits = UsageLimits(tool_calls_limit=max_tool_call_steps)
    # Passed into the run so usage accumulates in place and survives a mid-run bound trip.
    usage = RunUsage()
    bound_tripped: BoundTripped | None = None

    # capture_run_messages keeps the message history reachable even when the run raises, so the
    # re-request count is available on every path (exhaustion, tripped bound, or success).
    with capture_run_messages() as messages:
        try:
            asyncio.run(
                _run_bounded(
                    case_agent.agent,
                    prompt,
                    usage_limits=usage_limits,
                    usage=usage,
                    timeout_seconds=case_timeout_seconds,
                )
            )
        except UsageLimitExceeded:
            # Primary bound: the tool-step budget was reached. Recorded, not a crash.
            bound_tripped = "steps"
        except TimeoutError:
            # Backstop bound: the per-case wall-clock elapsed. asyncio.timeout raises
            # TimeoutError (== asyncio.TimeoutError on 3.11+).
            bound_tripped = "wall-clock"
        except UnexpectedModelBehavior:
            # Some tool's own retry budget was exhausted. Most often this is the report-retry
            # budget (every submit_report attempt failed the strict schema) — but a
            # live model can also exhaust it on run_code, e.g. by repeatedly writing glue code
            # that calls a builtin Monty doesn't expose (confirmed against a real model).
            # Either way, no valid report exists yet, so it's the same recorded invalid-output
            # outcome built uniformly below; report_retries (which only counts submit_report
            # retries) still correctly reads 0 when the failure was actually in run_code.
            pass

    return AttemptOutcome(
        # None => invalid-output failure: retries exhausted, an absent report, or a bound tripped
        # before any valid report was submitted. A report submitted before a bound tripped is kept.
        report=case_agent.collect_report(),
        report_retries=_count_report_retries(messages),
        bound_tripped=bound_tripped,
        usage=usage,
    )


def run_case_attempts(
    case_agent: CaseAgent,
    *,
    attempts_per_case: int = DEFAULT_ATTEMPTS_PER_CASE,
    prompt: str = DEFAULT_ATTEMPT_PROMPT,
    max_tool_call_steps: int = DEFAULT_MAX_TOOL_CALL_STEPS,
    case_timeout_seconds: float = DEFAULT_CASE_TIMEOUT_SECONDS,
    on_attempt: AttemptObserver | None = None,
) -> list[AttemptOutcome]:
    """Run one case ``attempts_per_case`` independent times.

    A single attempt is a noisy sample of a non-deterministic agent, so the case is run several
    times and every attempt is kept — never collapsed to "the best one" (explicitly
    rejects best-of-N: it would measure whether the model *could* get lucky, not whether it is
    *reliable*). This function does no scoring or averaging itself; it hands back the raw list of
    :class:`AttemptOutcome` so the caller can score each one (``src.scorer.score_attempt``) and
    then trial-average them (``src.scorer.aggregate_run``), which already implements the
    mean-not-max rule across the separate buckets.

    Each attempt reuses the same ``case_agent`` — safe because :func:`run_case_attempt` clears the
    captured report at the start of every call, and a Pydantic AI ``Agent.run`` call starts a fresh
    conversation each time (no message history carries over), so the attempts are independent trials
    rather than one continued conversation.

    Args:
        case_agent: The built agent bundle for this case (from
            :func:`~src.agent.case_agent.build_case_agent`). Reused across all attempts.
        attempts_per_case: How many independent attempts to run. Defaults to
            :data:`~src.config.DEFAULT_ATTEMPTS_PER_CASE` (3); a real run passes the configured
            ``Settings.attempts_per_case`` value through. ``1`` recovers single-attempt behavior —
            the return value is simply a one-element list, no schema change.
        prompt: Forwarded unchanged to every :func:`run_case_attempt` call.
        max_tool_call_steps: Forwarded unchanged to every :func:`run_case_attempt` call.
        case_timeout_seconds: Forwarded unchanged to every :func:`run_case_attempt` call.
        on_attempt: Optional callback invoked with ``(attempt_number, outcome)`` immediately after
            *each* attempt finishes — before the next one starts. This is the
            hook a long run uses for observability: persisting the attempt to the run file and
            logging its progress line as it happens, rather than only after the whole case (or the
            whole run) completes. ``None`` (the default) restores this function's exact
            repeated-attempts behavior — a silent, side-effect-free loop. See :mod:`~src.agent.observability` for
            the concrete persistence/logging callbacks built for this hook.

    Returns:
        A list of exactly ``attempts_per_case`` :class:`AttemptOutcome` objects, one per attempt,
        in the order they were run.
    """
    outcomes: list[AttemptOutcome] = []
    for attempt_number in range(1, attempts_per_case + 1):
        outcome = run_case_attempt(
            case_agent,
            prompt=prompt,
            max_tool_call_steps=max_tool_call_steps,
            case_timeout_seconds=case_timeout_seconds,
        )
        outcomes.append(outcome)
        # Fire the hook right after this attempt lands, not after the whole loop — this is what
        # makes persistence *incremental*: a crash on attempt 3 of 5 still leaves attempts 1-2
        # durably recorded, because their on_attempt call already ran and returned.
        if on_attempt is not None:
            on_attempt(attempt_number, outcome)
    return outcomes


async def _run_bounded(
    agent: Agent,
    prompt: str,
    *,
    usage_limits: UsageLimits,
    usage: RunUsage,
    timeout_seconds: float,
) -> None:
    """Run the agent once under the wall-clock backstop.

    The step budget is enforced inside the run via ``usage_limits``; the wall-clock backstop is
    enforced here by :func:`asyncio.timeout`, which cancels the run at an ``await`` point once the
    deadline passes (catching a stalled provider). A hung sandbox execution is bounded separately
    by the Docker runner's own per-execution timeout, not here.

    Args:
        agent: The case agent to run.
        prompt: The user prompt starting the attempt.
        usage_limits: The tool-step budget (and any other Pydantic AI limits).
        usage: A usage accumulator, mutated in place so counts survive a timeout.
        timeout_seconds: The per-case wall-clock budget in seconds.

    Raises:
        TimeoutError: If the wall-clock budget elapses.
        UsageLimitExceeded: If the tool-step budget is exceeded.
        UnexpectedModelBehavior: If any tool's retry budget is exhausted — most often
            ``submit_report``'s, but a live model can also exhaust ``run_code``'s
            own retry budget by repeatedly writing glue code Monty rejects (confirmed live).
    """
    async with asyncio.timeout(timeout_seconds):
        await agent.run(prompt, usage_limits=usage_limits, usage=usage)


def _count_report_retries(messages: list[ModelMessage]) -> int:
    """Count how many times ``submit_report`` was re-requested during a run.

    Each schema-failed submission produces one retry prompt fed back to the model, so the
    number of ``submit_report`` retry prompts in the message history is exactly the re-request
    count. Filtering by tool name keeps this specific to report retries and excludes any
    unrelated tool retry.

    Args:
        messages: The run's message history (from ``capture_run_messages``).

    Returns:
        The number of report re-requests (``0`` if the first submission was accepted).
    """
    return sum(
        1
        for message in messages
        for part in getattr(message, "parts", [])
        if isinstance(part, RetryPromptPart) and part.tool_name == "submit_report"
    )

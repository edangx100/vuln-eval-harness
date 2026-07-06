"""The agent runtime — Pydantic AI + CodeMode, restricted tools, schema enforcement.

This subpackage groups the agent-runtime cluster:

  - :mod:`~src.agent.case_agent` — assembles one Pydantic AI agent per case from the six
    restricted tools, orchestrated via Harness CodeMode.
  - :mod:`~src.agent.model` — builds the OpenRouter model and its structured-output
    enforcement (strict schema + ``require_parameters``).
  - :mod:`~src.agent.runner` — runs one attempt under the retry-on-invalid policy, the
    per-case effort bounds (tool-step + wall-clock), and repeats a case's attempts for the trial-averaged scoring in :mod:`src.scorer` to consume.
  - :mod:`~src.agent.observability` — the incremental persistence and progress-logging
    callbacks that plug into ``runner``'s ``on_attempt`` hook, so a long run is watchable
    and a mid-run crash never loses an already-completed attempt.

Public names are re-exported here so callers keep importing from the package root, e.g.
``from src.agent import build_case_agent, run_case_attempt``.
"""

from src.agent.model import (
    REQUIRE_PARAMETERS,
    build_openrouter_model,
    report_json_schema,
)
from src.agent.case_agent import (
    REPORT_MAX_RETRIES,
    SANDBOXED_TOOL_NAMES,
    STRICT_REPORT_SCHEMA,
    TOOL_NAMES,
    CaseAgent,
    build_case_agent,
)
from src.agent.runner import (
    DEFAULT_ATTEMPT_PROMPT,
    DEFAULT_CASE_TIMEOUT_SECONDS,
    DEFAULT_MAX_TOOL_CALL_STEPS,
    AttemptObserver,
    AttemptOutcome,
    BoundTripped,
    run_case_attempt,
    run_case_attempts,
)
from src.agent.observability import (
    IncrementalResultStore,
    log_attempt_progress,
    make_case_observer,
)

__all__ = [
    "DEFAULT_ATTEMPT_PROMPT",
    "DEFAULT_CASE_TIMEOUT_SECONDS",
    "DEFAULT_MAX_TOOL_CALL_STEPS",
    "AttemptObserver",
    "BoundTripped",
    "REPORT_MAX_RETRIES",
    "REQUIRE_PARAMETERS",
    "SANDBOXED_TOOL_NAMES",
    "STRICT_REPORT_SCHEMA",
    "TOOL_NAMES",
    "AttemptOutcome",
    "CaseAgent",
    "IncrementalResultStore",
    "build_case_agent",
    "build_openrouter_model",
    "log_attempt_progress",
    "make_case_observer",
    "report_json_schema",
    "run_case_attempt",
    "run_case_attempts",
]

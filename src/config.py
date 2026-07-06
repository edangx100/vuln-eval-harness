"""Run configuration for the evaluation harness.

Loaded via pydantic-settings BaseSettings. Precedence, highest
to lowest: environment variables > .env file > field defaults.
"""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Canonical per-run defaults. Defined here — the single place the
# harness's default policy lives — and used both as the `Settings` field defaults below
# (which `.env` / env vars override) and as the standalone defaults in `agent/runner.py`,
# so the numbers can never drift between the two. Suited to the current small, single-file
# cases; raise the effort bounds if the corpus grows to multi-file / repo-scale.
DEFAULT_MAX_TOOL_CALL_STEPS = 15
DEFAULT_CASE_TIMEOUT_SECONDS = 120
DEFAULT_ATTEMPTS_PER_CASE = 3


class Settings(BaseSettings):
    """Typed settings for a single evaluation run.

    A run evaluates exactly one OpenRouter model. Model comparison
    is achieved by running this harness twice with different RUN_NAME /
    OPENROUTER_MODEL values and comparing the resulting result files.

    Attributes:
        openrouter_api_key: Host-only credential used to call OpenRouter.
            Must never be passed into the Docker sandbox.
        openrouter_model: OpenRouter model id for this run, e.g.
            "deepseek/deepseek-v4-flash" (item 1).
        run_name: Identifies this run's result file.
        max_tool_call_steps: Primary per-case effort bound: the max number of
            tool calls the agent may make before the case is ended and scored
            as a bound trip. Default 15 suits the current small,
            single-file cases.
        case_timeout_seconds: Backstop per-case effort bound: wall-clock
            seconds before the case is ended, catching stalls (e.g. a hung
            sandbox execution) that would not otherwise consume tool-call
            steps.
        attempts_per_case: Number of independent agent attempts per case,
            trial-averaged rather than best-of-N, so the score reflects
            reliability rather than a single lucky or unlucky attempt
. A value of 1 recovers single-attempt behavior with
            no change to the result schema.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    openrouter_api_key: str
    openrouter_model: str
    run_name: str

    max_tool_call_steps: int = Field(default=DEFAULT_MAX_TOOL_CALL_STEPS)
    case_timeout_seconds: int = Field(default=DEFAULT_CASE_TIMEOUT_SECONDS)
    attempts_per_case: int = Field(default=DEFAULT_ATTEMPTS_PER_CASE)

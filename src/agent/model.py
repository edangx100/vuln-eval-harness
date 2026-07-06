"""OpenRouter model construction + structured-output enforcement.

The agent's report is obtained via **provider-side
structured-output enforcement**, not free-text parsing, using OpenRouter's
mechanism: a JSON Schema derived from the report model, requested with
``strict: true``, backed by ``require_parameters`` so a provider that cannot honor the
schema is dropped rather than silently returning unenforced prose.

This module builds the OpenRouter model that carries that enforcement. It pairs with
two other pieces to give the full guarantee:

  1. **Request-side enforcement (here + `agent.py`).** The report is delivered through
     the ``submit_report`` tool, so the "response_format ``json_schema`` /
     ``strict: true``" contract is expressed as a **strict tool schema** on that tool
     (set in ``agent.py``) — the tool-calling equivalent of the structured-output path.
     :func:`build_openrouter_model` adds the ``require_parameters`` guard so the schema
     is actually honored end-to-end.
  2. **Host-side re-validation (`report_tools.py`).** ``submit_report`` always
     re-validates the returned report against :class:`~src.schema.VulnerabilityReport`.
     Provider enforcement is a first line of defense, never a substitute for our own
     check.

Keeping this in its own module means the rest of the harness depends only on a plain
Pydantic AI ``Model`` (``case_agent.py`` takes any model), so tests drive the wiring offline
with a stub model and real runs pass the OpenRouter model built here.
"""

from __future__ import annotations

from pydantic_ai.models.openrouter import OpenRouterModel, OpenRouterModelSettings
from pydantic_ai.providers.openrouter import OpenRouterProvider

from src.config import Settings
from src.schema import VulnerabilityReport

# Whether to require the provider to honor the requested parameters. With
# this set, OpenRouter routes only to providers that actually enforce the strict schema;
# if none can, the request errors — a recorded run-level condition — rather than silently
# degrading to unenforced free-text. Kept as a named constant so the guard is explicit and
# testable, not a bare literal buried in a settings dict.
REQUIRE_PARAMETERS: bool = True


def report_json_schema() -> dict:
    """Return the JSON Schema the harness asks the provider to enforce.

    Derived directly from the :class:`~src.schema.VulnerabilityReport` model — the
    single source of truth for the report contract — so the enforced schema and the
    host-side validator can never drift apart. This is the "schema from the model" the
    ``submit_report`` tool advertises to the provider under strict enforcement.

    Returns:
        The report model's JSON Schema as a plain dict.
    """
    return VulnerabilityReport.model_json_schema()


def build_openrouter_model(
    settings: Settings,
    *,
    require_parameters: bool = REQUIRE_PARAMETERS,
) -> OpenRouterModel:
    """Build the OpenRouter model for a run, with schema enforcement required.

    Constructs the model for ``settings.openrouter_model`` and embeds the
    ``require_parameters`` guard in the model's default settings, so **every** request
    the agent makes asks OpenRouter to route only to providers that honor the requested
    parameters (the strict ``submit_report`` schema). A provider that cannot enforce the
    schema is therefore refused up front — a recorded run-level condition, not
    a silent degradation — instead of the run quietly accepting free-text output.

    The API credential is read from ``settings`` and lives only on the host; it is never
    passed to the sandbox. Construction performs no network call, so this is
    safe to build offline.

    Args:
        settings: The run configuration (model id + API credential).
        require_parameters: Whether to require providers to honor the requested
            parameters. Defaults to :data:`REQUIRE_PARAMETERS` (``True``); exposed only
            so a test can construct the model both ways.

    Returns:
        A configured :class:`~pydantic_ai.models.openrouter.OpenRouterModel` ready to
        drive the agent (see :func:`src.agent.build_case_agent`).
    """
    provider = OpenRouterProvider(api_key=settings.openrouter_api_key)

    # require_parameters is an OpenRouter provider-routing preference. Placed
    # in the model's default settings so it rides on every request without the caller
    # having to remember it per call.
    model_settings = OpenRouterModelSettings(
        openrouter_provider={"require_parameters": require_parameters},
    )

    return OpenRouterModel(
        settings.openrouter_model,
        provider=provider,
        settings=model_settings,
    )

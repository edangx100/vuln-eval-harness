"""The agent's final-report submission tool.

Of the agent's six restricted tools, this module implements the
last one, ``submit_report`` — the agent's *final deliverable* for a case. Calling
it ends the tool loop and hands the harness a structured verdict:
is the case vulnerable, and if so, what type / CWE / where.

The one job here is **binding the agent's output to the shared schema with
host-side validation**. Even though the model is asked for its report via
provider-side structured-output enforcement (a JSON Schema with ``strict: true``), that enforcement is only a first line of defense — the harness must
*always* re-validate the returned content itself before trusting it. This tool is
where that mandatory re-validation happens: every submission is checked against
:class:`~src.schema.VulnerabilityReport`.

Validation has exactly two outcomes, and both are first-class:

  - **Valid** → the submission is accepted and returned as a parsed
    :class:`~src.schema.VulnerabilityReport` (wrapped in :class:`SubmittedReport`
    alongside any Layer-2 reproduction artifact), and stored on the tool so the
    agent runtime can retrieve it after the loop ends.
  - **Invalid** → an :class:`InvalidReportError` is raised carrying the structured
    validation detail. It is a named signal, not a crash: the runtime records it
    and re-requests the report ('s retry-on-invalid policy, feeds),
    so a malformed report never aborts the run.

A *valid* report is accepted even when its contents are wrong — a wrong-but-valid
answer is the measurement and is scored as-is. This tool only judges
schema conformance, never correctness.
"""

from __future__ import annotations

from pydantic import BaseModel, ValidationError

from src.schema import VulnerabilityReport


class InvalidReportError(Exception):
    """Raised when a submitted report fails host-side schema validation.

    This is the ``submit_report`` counterpart to the other tools' typed failures
    (e.g. ``WorkspaceViolation``): a first-class, recordable signal rather than a
    generic error. The agent runtime catches it to record an invalid-output
    outcome and drive the retry-on-invalid policy — the raised detail
    is fed back to the model so the retry is a correction, not a blind reroll.

    Attributes:
        errors: The structured validation errors from Pydantic
            (``ValidationError.errors()``), so the runtime can log precisely which
            fields were wrong and restate them to the model on retry.
        payload: The raw, rejected submission exactly as the agent supplied it,
            preserved for diagnostics and the results record.
    """

    def __init__(
        self,
        message: str,
        errors: list[dict] | None = None,
        payload: object | None = None,
    ) -> None:
        super().__init__(message)
        self.errors = errors or []
        self.payload = payload


class SubmittedReport(BaseModel):
    """An accepted submission: the validated report plus optional Layer-2 artifact.

    Attributes:
        report: The validated vulnerability report — the scored deliverable.
        reproduction_script: For Layer-2 cases, the source of a minimal
            reproduction (a small Python or pytest script) that the outcome
            evaluator will later execute in the sandbox. ``None``
            for Layer-1-only submissions.
    """

    report: VulnerabilityReport
    reproduction_script: str | None = None


class ReportTool:
    """Validates and captures the agent's final report for one case.

    A fresh instance is created per case. It exposes the single ``submit_report``
    tool and remembers the accepted submission (:attr:`submitted`) so the agent
    runtime can read the result once the tool loop has ended — calling
    ``submit_report`` is what terminates that loop.
    """

    def __init__(self) -> None:
        # Holds the last accepted submission, or None until a valid report is
        # submitted. The runtime reads this after the loop terminates; a case
        # that never produces a valid report leaves it None (an absent-report
        # outcome).
        self.submitted: SubmittedReport | None = None

    def submit_report(
        self,
        report: VulnerabilityReport,
        reproduction_script: str | None = None,
    ) -> SubmittedReport:
        """Submit the final vulnerability report for the case.

        The ``report`` parameter is annotated as :class:`~src.schema.VulnerabilityReport`
        so the tool's JSON Schema — the one the provider is asked to enforce strictly
 — is derived directly from the report model, with no
        free-form ``dict`` escape hatch that would weaken strict enforcement. The
        annotation only drives schema derivation and structured-output coercion; at
        runtime ``model_validate`` still accepts either an already-built model or a
        plain mapping, so a dict payload is handled identically.

        Whatever the provider does, the report is **re-validated host-side** against
        :class:`~src.schema.VulnerabilityReport` here — provider
        enforcement is a first line of defense, never a substitute for our own check.

        Args:
            report: The agent's report as a :class:`~src.schema.VulnerabilityReport`
                (or an equivalent mapping, which is validated into one).
            reproduction_script: Optional Layer-2 reproduction script source, run
                later by the reproduction evaluator. Omitted for Layer-1.

        Returns:
            The accepted :class:`SubmittedReport`. The same value is stored on
            :attr:`submitted` for the runtime to retrieve after the loop ends.

        Raises:
            InvalidReportError: If ``report`` does not satisfy the schema. Carries
                the structured validation errors and the rejected payload so the
                runtime can record the failure and retry.
        """
        try:
            # The mandatory host-side check: provider enforcement is
            # not trusted as a substitute for validating the content ourselves.
            validated = VulnerabilityReport.model_validate(report)
        except ValidationError as exc:
            # Surface a named, structured failure the runtime can record and feed
            # back to the model — never a bare crash.
            raise InvalidReportError(
                "Submitted report failed schema validation",
                errors=exc.errors(),
                payload=report,
            ) from exc

        submission = SubmittedReport(
            report=validated, reproduction_script=reproduction_script
        )
        # Record the accepted submission so the runtime can collect it once the
        # tool loop terminates (this call is the loop's end).
        self.submitted = submission
        return submission

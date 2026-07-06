"""Execution tools bound to one case, backed by the Docker sandbox.

The agent has six restricted tools. This module implements the
two execution ones — ``run_python`` and ``run_pytest`` — as methods on
:class:`ExecutionTools`, the execution counterpart to :class:`InspectionTools`
(the three read/search tools).

Both classes follow the same contract: a fresh instance is created per case and
bound to that case's sanitized workspace, so the agent supplies only *what* to
run (the code), never *where* it runs. The workspace is fixed at construction and
is not an argument the agent controls, so an agent cannot point execution at an
arbitrary host directory.

The security boundary for running untrusted code is the sandbox, not this layer
. Every ``run_python`` / ``run_pytest`` call routes through the
injected :class:`~src.sandbox.DockerRunner`, which spins up a fresh, locked-down,
network-isolated container per execution and tears it down afterwards. There is
**no** host-side execution path here — this module never runs case code itself;
it only forwards the agent's code to the runner with the case workspace already
bound. Keeping the runner injectable also lets a caller share one runner (and its
configured image / default timeout) across every case in a run.
"""

from __future__ import annotations

from pathlib import Path

from src.sandbox import DockerRunner, ExecutionResult


class ExecutionTools:
    """The agent's execute-in-sandbox view of one case, workspace pre-bound.

    A fresh instance is created per case, bound to that case's sanitized
    workspace. Both methods run the agent-supplied code in the Docker
    sandbox against *that* workspace and nothing else — the workspace is captured
    at construction and is never an argument the agent can override.

    Args:
        workspace: The case workspace to mount read-only for every execution.
            Must exist and be a directory; a misconfigured run should fail loudly
            here rather than hand the agent an empty or bogus workspace.
        runner: The Docker sandbox runner that performs the isolated execution.
            Injected so one runner (with its pinned image and default timeout) is
            shared across cases; defaults to a fresh :class:`DockerRunner` with
            the pinned sandbox image.
        timeout_seconds: Optional per-execution wall-clock budget passed to the
            runner on every call. ``None`` falls back to the runner's own default
            (the host-side kill that backstops any in-container limit).
            This is the per-execution bound, distinct from the per-case budget
            enforced by the agent runtime.

    Raises:
        NotADirectoryError: If ``workspace`` does not exist or is not a directory.
    """

    def __init__(
        self,
        workspace: Path,
        runner: DockerRunner | None = None,
        timeout_seconds: float | None = None,
    ) -> None:
        # Resolve once to a canonical absolute path. The runner re-resolves it
        # when building the bind mount, but pinning it here means every execution
        # for this case targets the same directory regardless of the process's
        # working directory at call time.
        self.workspace = Path(workspace).resolve()
        if not self.workspace.is_dir():
            raise NotADirectoryError(
                f"Workspace {self.workspace} does not exist or is not a directory"
            )
        # Default to a runner on the pinned sandbox image so a caller that just
        # wants the standard isolation need not construct one.
        self.runner = runner if runner is not None else DockerRunner()
        self.timeout_seconds = timeout_seconds

    def run_python(self, code: str) -> ExecutionResult:
        """Execute a Python snippet against this case, inside the sandbox.

        The code is run in a fresh container with the case workspace mounted
        read-only at ``/work`` (so ``import app`` and reading case files work)
        and a size-capped writable temp area; there is no network and no host
        environment. The agent chooses the code; the workspace is
        fixed to this case.

        Args:
            code: The Python source to execute in the sandbox.

        Returns:
            An :class:`~src.sandbox.ExecutionResult` with captured stdout/stderr,
            exit code, and distinct ``timed_out`` / ``resource_killed`` signals.
        """
        return self.runner.run_python(
            code, self.workspace, timeout_seconds=self.timeout_seconds
        )

    def run_pytest(self, test_code: str) -> ExecutionResult:
        """Execute a pytest test module against this case, inside the sandbox.

        Same isolation as :meth:`run_python`: the test module runs in a fresh
        container with the case workspace mounted read-only at ``/work`` as the
        working directory, so the test can import and exercise the case code.

        Args:
            test_code: The pytest test module source to run in the sandbox.

        Returns:
            An :class:`~src.sandbox.ExecutionResult` with captured output and the
            same kill signals as :meth:`run_python`.
        """
        return self.runner.run_pytest(
            test_code, self.workspace, timeout_seconds=self.timeout_seconds
        )

"""Docker sandbox runner for untrusted execution.

Every piece of untrusted code — the vulnerable cases and the agent's own
proof-of-concept scripts — is executed here, and only here, inside a
short-lived container built from the pinned sandbox image
(`sandbox/Dockerfile`). The host process (agent runtime, model API calls,
credentials, loader, scorer) never runs inside the sandbox; only untrusted
execution crosses into it.

The container is locked down:

  - ``--network none``       no egress; untrusted code cannot call home.
  - empty environment        the API credential is never in scope to leak.
  - ``--memory`` / ``--cpus`` / ``--pids-limit``   resource bounds.
  - read-only case mount      code is mounted at ``/work`` read-only; the only
                              writable area is a size-capped ``/tmp/out`` tmpfs.
  - named + force-removed     the container is ephemeral — given a unique name
                              and removed in a ``finally``, leaving no state.

The runner returns an :class:`ExecutionResult` carrying stdout, stderr, exit
code, and distinct ``timed_out`` / ``resource_killed`` signals so the outcome
evaluator and diagnostics can tell a clean failure from a killed one.

Termination is enforced and reported precisely:

  - **Wall-clock timeout** is enforced host-side by putting a deadline on the
    ``docker run`` subprocess; on expiry the runner force-removes the container
    and reports ``timed_out=True``.
  - **Memory limit** is enforced by Docker's cgroup; an out-of-memory kill is
    detected *definitively* by reading the container's ``OOMKilled`` state
    (not guessed from an exit code) and reported as ``resource_killed=True``.
  - Cleanup is guaranteed on **every** path: each container is given a unique
    name and force-removed in a ``finally`` block, so nothing survives a normal
    exit, a timeout, or an error.
"""

from __future__ import annotations

import subprocess
import time
import uuid
from pathlib import Path

from pydantic import BaseModel

# Name:tag of the image built by ``sandbox/Dockerfile``. Kept in step
# with the ``LABEL org.opencontainers.image.version`` there and with the tag
# recorded in every RunResult. Bump both together when a case needs
# a new baked-in dependency.
SANDBOX_IMAGE = "pyvul-eval-sandbox:1.0.0"

# Per-execution resource bounds. Equal --memory and
# --memory-swap deny a swap escape hatch, so an allocation bomb is killed rather
# than spilling to disk; --pids-limit bounds fork bombs. These mirror the values
# the design commits to and are enforced by Docker inside the container.
_MEMORY_LIMIT = "512m"
_CPU_LIMIT = "1.0"
_PIDS_LIMIT = "128"

# Size cap on the single writable area. Artifacts and any files the untrusted
# code writes must fit here; nothing else on the container filesystem is
# writable (the root FS is mounted --read-only).
_TMPFS_SIZE = "64m"

# Where the case code and the writable scratch area appear inside the container.
_WORK_DIR = "/work"
_OUT_DIR = "/tmp/out"

# Prefix for the unique per-execution container name. A known name is what lets
# the runner force-remove a container on any path (including a hung one the
# subprocess timeout could not clean up) and prune leftovers by prefix.
_CONTAINER_NAME_PREFIX = "pyvul-exec"


class ExecutionResult(BaseModel):
    """Outcome of one untrusted execution in the sandbox.

    Attributes:
        stdout: Captured standard output of the container process.
        stderr: Captured standard error of the container process.
        exit_code: The process exit code, or ``None`` if the container was
            killed before it could exit (e.g. wall-clock timeout).
        timed_out: ``True`` if the runner killed the container for exceeding the
            wall-clock budget — a distinct signal, never surfaced as a generic
            error.
        resource_killed: ``True`` if the container was killed for exceeding a
            resource bound (memory in particular). Models CASE-10 behavior.
        duration_seconds: Wall-clock time the execution took, for diagnostics
            and as a cost signal.
    """

    stdout: str
    stderr: str
    exit_code: int | None
    timed_out: bool
    resource_killed: bool
    duration_seconds: float


class DockerRunner:
    """Executes untrusted code in isolated, ephemeral sandbox containers.

    One runner is reused across executions; each :meth:`run_python` /
    :meth:`run_pytest` call still spins up its own fresh, uniquely-named
    container that is force-removed afterwards, so no state leaks between
    executions and nothing is left running.

    Workspace contract: ``workspace`` is mounted read-only and must be readable
    by the container's user. The container process runs as root, but a bind
    mount preserves the host directory's ownership/permissions, so a private
    (``0700``) directory owned by another host user is not traversable inside.
    The harness satisfies this by building the sanitized case copy
    world-readable; callers passing their own directory must do the same.

    Args:
        image: Sandbox image name:tag to run from. Defaults to the pinned image
            built by ``sandbox/Dockerfile``.
        default_timeout_seconds: Wall-clock budget applied to an execution when
            the caller does not pass one. The host-side kill (this timeout on the
            ``docker run`` subprocess) backstops any in-container limit so a hung
            execution cannot stall the run.
    """

    def __init__(
        self,
        image: str = SANDBOX_IMAGE,
        default_timeout_seconds: float = 30.0,
    ) -> None:
        self.image = image
        self.default_timeout_seconds = default_timeout_seconds

    def run_python(
        self,
        code: str,
        workspace: Path,
        timeout_seconds: float | None = None,
    ) -> ExecutionResult:
        """Run a Python snippet against a case workspace in a fresh container.

        The snippet is written into the container's writable tmpfs as
        ``payload.py`` and executed with ``python``. The ``workspace`` (the
        sanitized case code) is mounted read-only at ``/work`` and is the
        container's working directory, so ``import app`` and reading case files
        work while writes to it fail.

        Args:
            code: The Python source to execute inside the sandbox.
            workspace: Host directory of sanitized case code to mount read-only.
            timeout_seconds: Wall-clock budget; falls back to the runner default.

        Returns:
            An :class:`ExecutionResult` with captured output and kill signals.
        """
        # `python -c` would put the untrusted source on the command line and in
        # the process table; writing it into the tmpfs and running the file
        # keeps it off the argv and mirrors how a real PoC would be delivered.
        script = _INLINE_SCRIPT_HEREDOC.format(code=code)
        return self._run(["sh", "-c", script], workspace, timeout_seconds)

    def run_pytest(
        self,
        test_code: str,
        workspace: Path,
        timeout_seconds: float | None = None,
    ) -> ExecutionResult:
        """Run a pytest test module against a case workspace in a fresh container.

        Same isolation as :meth:`run_python`. The test source is written to the
        writable tmpfs and pytest is invoked on it; the read-only workspace at
        ``/work`` is the working directory so the test can import the case.

        Args:
            test_code: The pytest test module source.
            workspace: Host directory of sanitized case code to mount read-only.
            timeout_seconds: Wall-clock budget; falls back to the runner default.

        Returns:
            An :class:`ExecutionResult` with captured output and kill signals.
        """
        script = _INLINE_PYTEST_HEREDOC.format(code=test_code)
        return self._run(["sh", "-c", script], workspace, timeout_seconds)

    def _run(
        self,
        container_command: list[str],
        workspace: Path,
        timeout_seconds: float | None,
    ) -> ExecutionResult:
        """Build and execute the locked-down ``docker run`` invocation.

        This is the single binding point where the isolation properties are
        applied; both public tools funnel through here so none can accidentally
        run with weaker isolation.

        Args:
            container_command: Argv executed inside the container.
            workspace: Host directory mounted read-only at ``/work``.
            timeout_seconds: Wall-clock budget; falls back to the runner default.

        Returns:
            An :class:`ExecutionResult`; a timeout or resource kill is reported
            via the dedicated flags rather than raised.
        """
        timeout = (
            timeout_seconds
            if timeout_seconds is not None
            else self.default_timeout_seconds
        )
        # A unique name lets us reliably clean up this exact container afterwards
        # and inspect its final state — neither is possible with an anonymous,
        # auto-removed (--rm) container.
        container_name = f"{_CONTAINER_NAME_PREFIX}-{uuid.uuid4().hex}"
        argv = self._build_argv(workspace, container_name) + container_command

        start = time.monotonic()
        try:
            try:
                completed = subprocess.run(
                    argv,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired as expired:
                # Wall-clock enforcement. The deadline on the
                # subprocess fired, so the docker client was terminated; the
                # container may still be running detached. The `finally` below
                # force-removes it, so the timeout can never leak a live
                # container. We report a distinct timeout signal, never a
                # generic error.
                duration = time.monotonic() - start
                return ExecutionResult(
                    stdout=_as_text(expired.stdout),
                    stderr=_as_text(expired.stderr),
                    exit_code=None,
                    timed_out=True,
                    resource_killed=False,
                    duration_seconds=duration,
                )
            duration = time.monotonic() - start

            # Memory enforcement: Docker's cgroup kills a container
            # that exceeds --memory. We only need to check when the process
            # exited non-zero (a clean exit was obviously not an OOM kill), and
            # we read the container's actual OOMKilled state rather than inferring
            # it from exit code 137 — an exit code alone cannot tell an OOM kill
            # apart from any other SIGKILL. This is the signal CASE-10 exercises.
            resource_killed = (
                completed.returncode != 0
                and self._was_oom_killed(container_name)
            )
            return ExecutionResult(
                stdout=completed.stdout,
                stderr=completed.stderr,
                exit_code=completed.returncode,
                timed_out=False,
                resource_killed=resource_killed,
                duration_seconds=duration,
            )
        finally:
            # Guaranteed cleanup on every path (normal exit, timeout, error):
            # the container is ephemeral, so force-remove it by name. Errors here
            # are swallowed — if it was never created or is already gone, there
            # is nothing to clean up.
            self._force_remove(container_name)

    def _build_argv(self, workspace: Path, container_name: str) -> list[str]:
        """Assemble the ``docker run`` argv carrying every isolation property.

        The argv itself is the security contract, so
        each flag is commented with the property it enforces. Tests assert these
        flags are present on the real invocation.

        Args:
            workspace: Host directory to mount read-only at ``/work``.
            container_name: Unique name for this container, so it can be
                inspected for its final state and force-removed afterwards.

        Returns:
            The argument vector up to (but not including) the container command.
        """
        return [
            "docker",
            "run",
            # Name the container so the runner can inspect its final state (OOM?)
            # and guarantee its removal afterwards. Cleanup is done explicitly in
            # `_run`'s finally block rather than with `--rm`, which would delete
            # the container before its state could be read.
            "--name",
            container_name,
            "--network",
            "none",  # no egress — untrusted code cannot reach the network
            "--read-only",  # base container filesystem is read-only
            # Read-only bind of the sanitized case code. The workspace is a
            # run-time copy holding only label-stripped code; the answer key
            # (meta.yaml) stays host-side and is never mounted.
            "--mount",
            f"type=bind,src={workspace.resolve()},dst={_WORK_DIR},ro",
            "--workdir",
            _WORK_DIR,
            # The single writable area: a size-capped in-memory tmpfs. Untrusted
            # writes are confined here and vanish with the container.
            "--tmpfs",
            f"{_OUT_DIR}:rw,size={_TMPFS_SIZE}",
            # Resource bounds. Equal memory/​swap denies a swap escape.
            "--memory",
            _MEMORY_LIMIT,
            "--memory-swap",
            _MEMORY_LIMIT,
            "--cpus",
            _CPU_LIMIT,
            "--pids-limit",
            _PIDS_LIMIT,
            # Least privilege: drop all capabilities and forbid privilege
            # escalation via setuid binaries (defense in depth).
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            # Start from an explicitly empty environment. This is an
            # allowlist, not a denylist — because subprocess.run passes no `env`
            # override we do not inherit the host environment into the argv, and
            # nothing (least of all the API credential) is ever added here. The
            # credential is never in scope to leak into the container.
            "--env-file",
            "/dev/null",
            self.image,
        ]

    def _was_oom_killed(self, container_name: str) -> bool:
        """Report whether the container was killed for exceeding its memory limit.

        Reads the container's own ``OOMKilled`` state via ``docker inspect``.
        This is the authoritative signal — unlike exit code 137, which is shared
        by every SIGKILL and so cannot, on its own, prove the cause was memory.
        The container is only inspected before it is removed (see ``_run``).

        Args:
            container_name: Name of the (exited, not-yet-removed) container.

        Returns:
            ``True`` only if Docker reports the container was OOM-killed.
        """
        try:
            completed = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.OOMKilled}}", container_name],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            # If we cannot determine it, do not claim a resource kill. The exit
            # code is still reported, so the outcome is not lost — only the
            # more specific reason is.
            return False
        return completed.returncode == 0 and completed.stdout.strip() == "true"

    def _force_remove(self, container_name: str) -> None:
        """Force-kill and remove the named container, ignoring any failure.

        Called from ``_run``'s ``finally`` so a container never survives — not a
        normal exit, not a timeout that left it running detached, not an error.
        Failure is intentionally ignored: if the container was never created or
        is already gone, there is simply nothing to remove.

        Args:
            container_name: Name of the container to remove.
        """
        try:
            subprocess.run(
                ["docker", "rm", "--force", container_name],
                capture_output=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            pass


def _as_text(stream: str | bytes | None) -> str:
    """Coerce captured subprocess output to text.

    ``subprocess.run(text=True)`` yields ``str``, but on ``TimeoutExpired`` the
    partial output may be ``bytes`` or ``None`` depending on platform, so we
    normalize to a plain string for the result model.

    Args:
        stream: A captured stdout/stderr value, possibly ``None`` or ``bytes``.

    Returns:
        The stream as text, empty string if there was none.
    """
    if stream is None:
        return ""
    if isinstance(stream, bytes):
        return stream.decode(errors="replace")
    return stream


# The untrusted source is delivered by writing it to the writable tmpfs and
# executing the file, rather than via `python -c`, so it never appears on the
# argv/process table. A quoted heredoc ('PAYLOAD_EOF') means the shell performs
# no expansion on the body, so the code is written through byte-for-byte.
# PYTHONPATH=/work puts the mounted case code on the import path, so a payload
# can `import app` regardless of the working directory (Python adds the script's
# own directory — /tmp/out — to sys.path, not the case mount).
_INLINE_SCRIPT_HEREDOC = (
    "cat > /tmp/out/payload.py <<'PAYLOAD_EOF'\n{code}\nPAYLOAD_EOF\n"
    "PYTHONPATH=/work python /tmp/out/payload.py"
)

# pytest needs a writable temp directory, but --read-only makes the usual /tmp
# unwritable; TMPDIR points it at our one writable area (/tmp/out) so it runs
# under the same isolation as everything else.
_INLINE_PYTEST_HEREDOC = (
    "cat > /tmp/out/test_payload.py <<'PAYLOAD_EOF'\n{code}\nPAYLOAD_EOF\n"
    # -p no:cacheprovider stops pytest writing a .pytest_cache into the
    # read-only /work rootdir (which would fail the run despite passing tests).
    "TMPDIR=/tmp/out PYTHONPATH=/work python -m pytest -q -p no:cacheprovider "
    "/tmp/out/test_payload.py"
)

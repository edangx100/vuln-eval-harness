"""Startup preflight for the Docker sandbox.

Companion to ``src/sandbox.py``. Where ``sandbox.py`` *runs* untrusted code,
this module answers a narrower, earlier question: **is the sandbox actually
ready to run it?** It is meant to be called once, at startup, so a run fails
fast with a clear, actionable message ("start Docker" / "build the image
first") instead of failing confusingly deep inside the first execution.

Two preconditions must hold before any case can run:

  1. the Docker daemon is reachable, and
  2. the pinned sandbox image has been built locally — it cannot be pulled at
     run time, because the sandbox runs with no network.

The module is deliberately separate from ``sandbox.py``: it runs at a different
point in the lifecycle (startup, not per execution) and is called by a different
part of the system (the run entry point, not the tool layer).
"""

from __future__ import annotations

import shutil
import subprocess

from src.sandbox import SANDBOX_IMAGE


def docker_available() -> bool:
    """Report whether the Docker CLI is present and its daemon reachable.

    Also used by the test suite to skip sandbox-backed checks where Docker is
    unavailable.

    Returns:
        ``True`` if ``docker`` is on PATH and ``docker version`` succeeds.
    """
    if shutil.which("docker") is None:
        return False
    try:
        completed = subprocess.run(
            ["docker", "version"],
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0


def image_present(image: str = SANDBOX_IMAGE) -> bool:
    """Report whether the given sandbox image exists in the local Docker cache.

    The sandbox runs offline, so the image must already be built locally — it
    cannot be pulled at run time.

    Args:
        image: Image name:tag to look for. Defaults to the pinned sandbox image.

    Returns:
        ``True`` if ``docker image inspect <image>`` succeeds (the image exists).
    """
    if shutil.which("docker") is None:
        return False
    try:
        completed = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0


class SandboxPreflightError(RuntimeError):
    """Raised when the sandbox is not ready to run untrusted code.

    Carries an actionable message telling the operator exactly what to fix
    (start Docker, or build the image) so a run fails fast at startup with clear
    guidance rather than deep inside the first execution.
    """


def preflight(image: str = SANDBOX_IMAGE) -> None:
    """Verify the sandbox is ready before any untrusted code runs.

    Checks the two preconditions that would otherwise cause a confusing mid-run
    failure, in the order a fix would be applied: first that Docker is reachable,
    then that the pinned image has been built. On failure it raises with a clear,
    actionable message; on success it returns and the run may proceed.

    This is intended to run once at startup — failing here costs seconds, whereas
    discovering the same problem on the first execution wastes the setup of a run.

    Args:
        image: Sandbox image name:tag required for execution. Defaults to the
            pinned image built by ``sandbox/Dockerfile``.

    Raises:
        SandboxPreflightError: If Docker is not reachable, or the image is not
            built locally. The message states the exact command to run.
    """
    if not docker_available():
        raise SandboxPreflightError(
            "Docker is not reachable. The sandbox runs all untrusted code in "
            "Docker containers, so Docker must be installed and running. Start "
            "Docker (e.g. launch Docker Desktop, or `sudo systemctl start "
            "docker`) and try again."
        )
    if not image_present(image):
        raise SandboxPreflightError(
            f"Sandbox image '{image}' is not built. Build the sandbox image "
            f"first, then re-run:\n"
            f"    docker build -t {image} sandbox/"
        )

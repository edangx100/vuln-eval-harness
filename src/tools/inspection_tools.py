"""Inspection tools confined to the active case workspace.

The agent's job is "inspect, optionally execute, then submit".
This module implements the inspection half: the three read-only tools of the
restricted set — ``list_files``, ``read_file``, ``grep_search`` — as
methods on :class:`InspectionTools`, each bound to a single case workspace
directory and unable to traverse outside it. The execution half lives in
``execution_tools.py``.

Confinement is the whole point. The agent under test is untrusted, and the case
workspace it may inspect is a sanitized copy that deliberately excludes the
ground-truth answer key (``meta.yaml`` stays host-side). A tool that
let the agent climb out of the workspace — via ``../``, an absolute path, or a
symlink — could read that answer key or unrelated host files and invalidate the
evaluation. Every path an agent supplies is therefore resolved to a real
absolute path and checked to be inside the workspace root before any I/O
happens; anything else raises :class:`WorkspaceViolation`.

These are host-side tools: they read from the sanitized workspace on the host,
not inside the sandbox. Only the execution tools (``run_python`` / ``run_pytest``) cross into the Docker sandbox. Keeping the read/search tools on the host is
safe because they never execute case code — they only enumerate, read, and
pattern-match text within a directory the harness controls.
"""

from __future__ import annotations

import re
from pathlib import Path

from pydantic import BaseModel

# Cap on how much of a single file ``read_file`` returns. The cases are small,
# but a defensive bound keeps a pathological file from flooding the agent's
# context (and, in CodeMode, its glue-script memory). Generous enough that no
# real case is ever truncated; present only as a backstop.
_MAX_READ_BYTES = 1_000_000

# Cap on the number of matches ``grep_search`` returns, for the same reason: a
# broad pattern against a large file should not return an unbounded list.
_MAX_GREP_MATCHES = 1000


class WorkspaceViolation(Exception):
    """Raised when a tool call would read or search outside the workspace.

    This is the confinement boundary firing (read/search tools "must
    not traverse outside" the case workspace). It is a first-class signal, not a
    generic error: the agent runtime can record that the agent attempted to
    escape its workspace. The message names the offending path so the attempt is
    visible in logs and results.
    """


class GrepMatch(BaseModel):
    """A single line matched by :meth:`InspectionTools.grep_search`.

    Attributes:
        file: Workspace-relative POSIX path of the file the match is in. Always
            inside the workspace — the search never descends outside it — so a
            result can never reference a host file beyond the case.
        line_number: 1-based line number of the match within ``file``.
        line: The full matching line, with trailing newline stripped.
    """

    file: str
    line_number: int
    line: str


class InspectionTools:
    """The agent's read-only view of one case, confined to a single directory.

    A fresh instance is created per case, bound to that case's sanitized
    workspace. Every method operates strictly within
    :attr:`root`; there is no way to point any of them at a path outside it.

    The workspace root is resolved to its real absolute path once at
    construction, so all later containment checks compare fully-resolved paths
    (following symlinks) against a fixed, canonical base.

    Args:
        workspace: The case workspace directory the agent may inspect. Must
            exist and be a directory.

    Raises:
        NotADirectoryError: If ``workspace`` does not exist or is not a directory
            — a misconfigured run should fail loudly here, not hand the agent an
            empty or bogus workspace.
    """

    def __init__(self, workspace: Path) -> None:
        # Resolve once to a canonical, symlink-free absolute path. Every path the
        # agent supplies is later resolved the same way and checked against this
        # base, so the containment test is a straightforward prefix comparison
        # between two real paths.
        self.root = Path(workspace).resolve()
        if not self.root.is_dir():
            raise NotADirectoryError(
                f"Workspace {self.root} does not exist or is not a directory"
            )

    def list_files(self) -> list[str]:
        """List every file in the workspace, as workspace-relative paths.

        Recurses through subdirectories so multi-file cases are fully visible,
        but returns only files (never directory entries). Paths are POSIX-style
        and relative to the workspace root, so the agent never sees an absolute
        host path and cannot learn anything about the workspace's location on
        disk.

        Returns:
            Sorted, workspace-relative file paths (e.g. ``["app.py"]``). Sorted
            for determinism, so repeated calls and repeated runs list files in a
            stable order.
        """
        files = [
            path.relative_to(self.root).as_posix()
            for path in self.root.rglob("*")
            if path.is_file()
        ]
        return sorted(files)

    def read_file(self, path: str) -> str:
        """Read one text file from within the workspace.

        Args:
            path: Workspace-relative path to read (e.g. ``"app.py"``), as
                returned by :meth:`list_files`.

        Returns:
            The file's decoded text. Undecodable bytes are replaced rather than
            raising, so a stray binary file cannot crash a tool call; content
            beyond :data:`_MAX_READ_BYTES` is truncated with a marker appended.

        Raises:
            WorkspaceViolation: If ``path`` resolves outside the workspace
                (``../`` escape, absolute path, or symlink pointing out).
            FileNotFoundError: If the path is inside the workspace but is not an
                existing file (e.g. a directory or a missing name).
        """
        target = self._resolve_within(path)
        if not target.is_file():
            raise FileNotFoundError(f"No such file in workspace: {path!r}")

        data = target.read_bytes()
        truncated = len(data) > _MAX_READ_BYTES
        text = data[:_MAX_READ_BYTES].decode(errors="replace")
        if truncated:
            text += f"\n... [truncated at {_MAX_READ_BYTES} bytes]"
        return text

    def grep_search(self, pattern: str) -> list[GrepMatch]:
        """Search the workspace for lines matching a regular expression.

        Every file returned by :meth:`list_files` is scanned line by line; each
        matching line yields a :class:`GrepMatch`. Because the search only ever
        walks files under the workspace root, every result references an
        in-workspace file — a grep can never surface a line from outside the case.

        Args:
            pattern: A Python regular expression (``re`` syntax).

        Returns:
            Matches in a deterministic order — by file path, then line number —
            capped at :data:`_MAX_GREP_MATCHES`.

        Raises:
            re.error: If ``pattern`` is not a valid regular expression. Surfaced
                to the caller so the agent learns its pattern was malformed
                rather than silently getting no results.
        """
        compiled = re.compile(pattern)

        matches: list[GrepMatch] = []
        # list_files() already restricts us to files inside the workspace, so
        # every path scanned here is confined by construction.
        for relative in self.list_files():
            target = self.root / relative
            # Undecodable (binary) files are read with replacement rather than
            # skipped so a match in a mostly-text file is never silently lost.
            text = target.read_bytes().decode(errors="replace")
            for line_number, line in enumerate(text.splitlines(), start=1):
                if compiled.search(line):
                    matches.append(
                        GrepMatch(file=relative, line_number=line_number, line=line)
                    )
                    if len(matches) >= _MAX_GREP_MATCHES:
                        return matches
        return matches

    def _resolve_within(self, path: str) -> Path:
        """Resolve an agent-supplied path and prove it stays inside the workspace.

        This is the single confinement chokepoint for the read/search tools. The
        supplied path is joined onto the workspace root and fully resolved — which
        collapses ``..`` segments and follows symlinks — then checked to be inside
        the resolved root. Resolving *before* checking is what defeats every
        escape shape at once:

        - ``"../../etc/passwd"`` resolves above the root and fails the check.
        - an absolute path such as ``"/etc/passwd"`` resolves to itself (a join
          onto an absolute path discards the root) and fails the check.
        - a symlink inside the workspace pointing outside resolves to its real
          target outside the root and fails the check.

        Args:
            path: The workspace-relative path supplied by the agent.

        Returns:
            The resolved absolute path, guaranteed to be within the workspace.

        Raises:
            WorkspaceViolation: If the resolved path is not inside the workspace.
        """
        candidate = (self.root / path).resolve()
        # is_relative_to is a pure path comparison between two already-resolved
        # (real) paths, so this admits exactly the paths under the workspace root
        # and rejects everything else. The root itself counts as inside.
        if candidate != self.root and not candidate.is_relative_to(self.root):
            raise WorkspaceViolation(
                f"Path {path!r} escapes the case workspace and was refused"
            )
        return candidate

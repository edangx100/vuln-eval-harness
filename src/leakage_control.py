"""Leakage control: derive a neutral, label-stripped case copy.

The benchmark's case files are deliberately **human-readable**: the folder name,
module docstring, and inline comments name the vulnerability class and CWE so a
person browsing the repo understands each case at a glance. That same text is an
**answer key** to the agent under evaluation — an agent that can read it would
score by reading labels instead of by analyzing code, which invalidates the
capability metric.

This module closes that in-context-leakage gap. It leaves the canonical repo
files untouched and, at run time, builds a sanitized copy that is what the agent
actually sees. The transform is small, deterministic, and model-free (no LLM
call), so it is fully unit-testable and never itself a source of nondeterminism.

Four things are neutralized:

  1. **Identity** — the code is presented as ``submission.py`` in a neutral
     workspace, never under the ``CASE-NN-<class>`` folder name.
  2. **Answer key** — ``meta.yaml`` (the ground truth) is never copied into the
     agent's workspace; it stays host-side for the scorer only.
  3. **Label comments/docstrings** — author annotations that name the class, the
     CWE, or mark code ``VULNERABLE`` are removed, while ordinary comments and the
     plain first line of a function's docstring are kept (a conspicuously
     comment-free file would itself be a tell).
  4. **Residual label tokens** — any leftover answer tokens elsewhere in the
     source (e.g. ``VULNERABLE`` inside a demo string) are replaced with a neutral
     placeholder, so no label survives anywhere in the presented code.

The sanitized code is required to still parse and to keep the case's entry-point
behavior identical — the transform removes *labels*, never *logic*.
"""

from __future__ import annotations

import ast
import io
import os
import re
import tokenize
from pathlib import Path

# The neutral filename the agent sees, regardless of the case's real code file.
PRESENTED_FILENAME = "submission.py"

# Replacement for any answer token that would otherwise survive in the code.
_REDACTION = "REDACTED"

# Files that are ground truth / answer key and must never reach the agent.
_ANSWER_KEY_SUFFIXES = {".yaml", ".yml"}


# Terms that mark a comment or docstring as an author *label* (an answer), rather
# than ordinary prose. Matching any of these flags the text for removal. The list
# is intentionally explicit and case-insensitive: the corpus is small and
# authored by us, so an exact denylist is clearer and safer than a fuzzy guess.
_LABEL_TERMS = re.compile(
    r"""
      \bCASE-\d+\b            # case id, e.g. CASE-01
    | \bNEG-\d+\b             # negative-control id, e.g. NEG-02
    | \bCWE-\d+\b             # CWE identifier, e.g. CWE-89
    | \bVULNERABLE\b          # the explicit "this is the bug" marker
    | \bvulnerable\b          # ... and its lowercase prose form
    | \bPyVul\b               # provenance back to the source dataset
    | \bGHSA-[\w-]+\b         # advisory id in the provenance line
    | \binjection\b           # class tells that appear in annotations
    | \bexploit\w*\b
    | \battacker\b
    | \bmalicious\b
    | \bSQL\ Injection\b
    | \b(OS\ )?Command\ Injection\b
    | \bPath\ Traversal\b
    | \b(Unsafe\ )?Deserialization\b
    | \bCode\ Injection\b
    | \bCross-site\ Scripting\b | \bXSS\b
    | \bWeak\ Crypto\w*\b
    | \bWeak\ Random\w*\b
    | \bImproper\ Input\ Validation\b
    | \bResource\ Exhaustion\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

# The strict subset that must not survive *anywhere* in the presented source —
# not even inside a string literal the program uses (e.g. ``echo VULNERABLE``).
# These tokens never carry legitimate program meaning, so replacing them is safe
# and does not change the scored entry point's behavior.
_ANSWER_TOKENS = re.compile(
    r"\bVULNERABLE\b|\bCASE-\d+\b|\bNEG-\d+\b|\bCWE-\d+\b",
    re.IGNORECASE,
)


def build_sanitized_workspace(
    case_dir: Path,
    dest_dir: Path,
    presented_name: str = PRESENTED_FILENAME,
) -> Path:
    """Build the neutral, label-free workspace the agent is given for one case.

    Copies the case's code into ``dest_dir`` under a neutral name, running each
    Python file through :func:`sanitize_source`, and **excludes the answer key**
    (``meta.yaml`` and any other YAML) entirely. The caller is responsible for
    choosing a neutrally-named ``dest_dir`` (e.g. a temp directory) so the folder
    name does not leak the case identity either.

    Args:
        case_dir: The canonical case folder (e.g. ``benchmark/cases/CASE-01-...``).
        dest_dir: Destination workspace directory; created if absent. Its contents
            are what the sandbox mounts read-only for the agent.
        presented_name: The neutral name the primary code file is given. The
            case's ``app.py`` is renamed to this; any other code files keep their
            own (already-neutral) names.

    Returns:
        ``dest_dir``, now populated with the sanitized, agent-facing files.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)

    for src in sorted(case_dir.iterdir()):
        # Skip subdirectories and, crucially, the answer key: the ground truth
        # never crosses into the agent's workspace.
        if not src.is_file() or src.suffix in _ANSWER_KEY_SUFFIXES:
            continue

        # Present the main code file under the neutral name; leave other files as
        # they are (their names are not case labels).
        target_name = presented_name if src.name == "app.py" else src.name
        text = src.read_text(encoding="utf-8")
        if src.suffix == ".py":
            text = sanitize_source(text)

        target = dest_dir / target_name
        target.write_text(text, encoding="utf-8")
        target.chmod(0o644)

    # The sandbox mounts this directory read-only and its container user must be
    # able to read it (see DockerRunner's workspace contract), so make it
    # world-readable.
    os.chmod(dest_dir, 0o755)
    return dest_dir


def sanitize_source(source: str) -> str:
    """Strip author label annotations from Python source, deterministically.

    Removes label *comments*, cuts label text out of *docstrings* (keeping their
    ordinary leading description), and neutralizes any residual answer token, then
    verifies the result still parses. Program *logic* is never touched, so the
    entry point behaves exactly as before — only annotations change.

    Args:
        source: The canonical case source code.

    Returns:
        The sanitized source: same behavior, no answer-key text.

    Raises:
        SyntaxError: If the canonical source does not parse (a broken case), or —
            as a safety net — if sanitization ever produced invalid Python.
    """
    # tokenize needs a trailing newline to close the final logical line cleanly.
    if not source.endswith("\n"):
        source += "\n"

    # Locate docstrings precisely via the AST (module/function/class), so we can
    # treat them differently from ordinary string literals: a docstring keeps its
    # plain description, a code string only has answer tokens neutralized.
    docstring_starts = _docstring_start_positions(source)

    # Precompute where each line begins, to convert token (row, col) positions
    # into absolute offsets in the source string.
    line_starts = _line_start_offsets(source)

    # Collect (start_offset, end_offset, replacement) edits, then apply them from
    # the end backwards so earlier offsets stay valid as we splice.
    edits: list[tuple[int, int, str]] = []
    tokens = tokenize.generate_tokens(io.StringIO(source).readline)
    for tok in tokens:
        if tok.type == tokenize.COMMENT:
            # Drop a whole comment if it is an author label; keep ordinary ones.
            if _LABEL_TERMS.search(tok.string):
                edits.append((*_span(line_starts, tok), ""))
        elif tok.type == tokenize.STRING and tok.start in docstring_starts:
            replacement = _redact_docstring(tok.string)
            if replacement != tok.string:
                edits.append((*_span(line_starts, tok), replacement))

    sanitized = _apply_edits(source, edits)

    # Final safety net: remove any answer token that still appears anywhere (e.g.
    # ``VULNERABLE`` inside a demo string). These tokens carry no program meaning,
    # so replacing them cannot change the entry point's behavior.
    sanitized = _ANSWER_TOKENS.sub(_REDACTION, sanitized)

    # The transform must never break the code. Compiling here turns a hypothetical
    # bug into a loud failure instead of a silently corrupted case.
    compile(sanitized, "<sanitized>", "exec")
    return sanitized


# --------------------------------------------------------------------------- #
# Internal helpers                                                             #
# --------------------------------------------------------------------------- #


def _docstring_start_positions(source: str) -> set[tuple[int, int]]:
    """Return the ``(row, col)`` start of every module/function/class docstring.

    Used to tell a docstring apart from an ordinary string literal so each is
    sanitized appropriately.

    Args:
        source: The source code to scan.

    Returns:
        A set of token start positions (1-based row, 0-based col) matching how
        :mod:`tokenize` reports string tokens.
    """
    positions: set[tuple[int, int]] = set()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            # A docstring is the first statement and an expression whose value is
            # a string constant; its position is where that string starts.
            if ast.get_docstring(node, clean=False) is not None:
                doc_expr = node.body[0].value  # type: ignore[attr-defined]
                positions.add((doc_expr.lineno, doc_expr.col_offset))
    return positions


def _redact_docstring(token_string: str) -> str:
    """Cut label text out of a docstring, keeping its ordinary description.

    In the corpus, a docstring's answer content is always *trailing* — either the
    whole module docstring (which opens with the case id) or a function
    docstring's ``... VULNERABLE: ...`` clause after a plain first sentence. So
    cutting from the first label term to the end removes the answer while keeping
    the legitimate lead-in. A docstring that becomes empty is dropped entirely.

    Args:
        token_string: The full docstring token, including its quotes.

    Returns:
        The sanitized docstring token (quotes preserved), or ``""`` to drop it.
    """
    prefix, quote, body = _split_string_token(token_string)

    match = _LABEL_TERMS.search(body)
    if match is not None:
        body = body[: match.start()]

    body = body.rstrip()
    if not body.strip():
        # Nothing meaningful survived (e.g. a pure answer-key module docstring):
        # drop it. Function docstrings keep their description, and ordinary
        # comments remain, so the file still reads like real code.
        return ""
    return f"{prefix}{quote}{body}{quote}"


def _split_string_token(token_string: str) -> tuple[str, str, str]:
    """Split a string token into ``(prefix, quote, inner_body)``.

    Args:
        token_string: A string literal token, e.g. ``'\"\"\"text\"\"\"'`` possibly
            with an ``r``/``b``/``f`` prefix.

    Returns:
        The letter prefix (often empty), the opening quote (``\"\"\"``, ``'''``,
        ``"`` or ``'``), and the inner text between the quotes.
    """
    # Separate any r/b/f/u prefix letters from the opening quote.
    match = re.match(r"^([A-Za-z]*)", token_string)
    prefix = match.group(1) if match else ""
    rest = token_string[len(prefix):]

    # Longest quote first, so a triple quote is not mistaken for a single one.
    for quote in ('"""', "'''", '"', "'"):
        if rest.startswith(quote):
            body = rest[len(quote): len(rest) - len(quote)]
            return prefix, quote, body
    # Should not happen for a valid string token; return it unsplit as a no-op.
    return "", "", token_string


def _line_start_offsets(source: str) -> list[int]:
    """Return the absolute offset at which each 1-based line begins.

    Args:
        source: The source string.

    Returns:
        A list where index ``i`` holds the start offset of line ``i`` (index 0 is
        a placeholder so lines can be addressed by their 1-based number).
    """
    offsets = [0, 0]  # index 0 unused; line 1 starts at offset 0
    for line in source.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    return offsets


def _span(line_starts: list[int], tok: tokenize.TokenInfo) -> tuple[int, int]:
    """Convert a token's ``(row, col)`` start/end into absolute source offsets.

    Args:
        line_starts: Line start offsets from :func:`_line_start_offsets`.
        tok: The token whose span is wanted.

    Returns:
        ``(start_offset, end_offset)`` into the source string.
    """
    start = line_starts[tok.start[0]] + tok.start[1]
    end = line_starts[tok.end[0]] + tok.end[1]
    return start, end


def _apply_edits(source: str, edits: list[tuple[int, int, str]]) -> str:
    """Apply span replacements to ``source``, splicing from the end first.

    Applying edits back-to-front keeps every not-yet-applied offset valid, since
    edits before it are untouched.

    Args:
        source: The original source.
        edits: ``(start, end, replacement)`` spans to replace.

    Returns:
        The edited source.
    """
    for start, end, replacement in sorted(edits, key=lambda e: e[0], reverse=True):
        source = source[:start] + replacement + source[end:]
    return source

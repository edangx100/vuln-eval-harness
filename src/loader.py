"""Benchmark corpus loader with index/folder consistency checks.

This module reads the corpus index (``benchmark/cases.yaml``)
and, for every case it lists, loads that case's ground-truth answer key
(``meta.yaml``) and resolves its code path on disk. Before returning anything it
cross-checks the index against the on-disk case folders and **fails loudly** on
any disagreement, so a malformed corpus is caught once, up front, with a clear
message — instead of surfacing later as a confusing error deep inside a run.

The loader is pure filesystem I/O plus validation: it does no scoring and calls
no model, which keeps it safe to reuse from tests and from the run entry point
alike. Ground truth is parsed straight into the shared `CaseGroundTruth` model
(src/schema.py) so the rest of the harness consumes one typed shape, never raw
dicts.
"""

from pathlib import Path

import yaml
from pydantic import BaseModel, ValidationError

from src.schema import CaseGroundTruth

# Repo-relative default locations. Derived from this file's path (repo_root/src/
# loader.py) rather than the process working directory, so the loader resolves
# the corpus correctly no matter where the harness is launched from.
_REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CORPUS_ROOT = _REPO_ROOT / "benchmark"

# Name of the per-case ground-truth file inside each case folder.
_META_FILENAME = "meta.yaml"

# Top-level key in ``cases.yaml`` holding the corpus version string.
# The version travels with the corpus manifest — rather than a hardcoded
# constant — so it cannot drift out of sync with the cases it labels.
_VERSION_KEY = "version"


class CorpusError(Exception):
    """Raised when the corpus on disk is inconsistent or malformed.

    Every raise site includes the offending case id or path in the message, so
    a failure points the author straight at what to fix ('s "fail
    loudly on mismatch"). This is a corpus-authoring defect, never a normal
    runtime condition, so it is a hard error rather than a recorded outcome.
    """


class IndexEntry(BaseModel):
    """One case as declared in the corpus index (``cases.yaml``).

    The index is the lightweight catalogue of the corpus; the authoritative
    per-case detail lives in each case's ``meta.yaml``. The loader validates
    that the two agree (see `_check_index_matches_meta`).

    `cwe` and `vulnerability_type` are optional because a negative-control
    (patched-twin) case is not vulnerable and therefore carries no type/CWE
; for such a case both the index and the ground truth leave them
    empty, and they still compare equal.
    """

    id: str
    cwe: str | None = None
    vulnerability_type: str | None = None
    layer2_eligible: bool


class LoadedCase(BaseModel):
    """A fully-resolved benchmark case: index metadata + code path + ground truth.

    This is the single object the rest of the harness works with per case. It
    exposes exactly what the loader surfaces — identifier,
    CWE, vulnerability type, `layer2_eligible` flag, code path, and the
    ground-truth answer key.

    Attributes:
        id: Case identifier, e.g. ``CASE-01-sql-injection``. Matches the folder
            name and the ``id`` in both the index and the ground truth.
        cwe: CWE identifier (e.g. ``CWE-89``), or None for a negative control.
        vulnerability_type: Human-readable class (e.g. ``SQL Injection``), or
            None for a negative control.
        layer2_eligible: Whether this case takes part in Layer-2 reproduction
. Verified equal across the index and the ground truth.
        code_path: Absolute path to the case's runnable code file. Guaranteed
            to exist on disk by the time this object is constructed.
        ground_truth: The parsed answer key (src/schema.py `CaseGroundTruth`),
            the authoritative source for scoring.
    """

    id: str
    cwe: str | None
    vulnerability_type: str | None
    layer2_eligible: bool
    code_path: Path
    ground_truth: CaseGroundTruth


def load_corpus(corpus_root: Path | None = None) -> list[LoadedCase]:
    """Load and validate the whole benchmark corpus.

    Reads the index, then for each listed case loads its ground truth and
    resolves its code path, running every consistency check along the way.
    Returns only once the corpus is proven internally consistent.

    Args:
        corpus_root: Corpus directory containing ``cases.yaml`` and a ``cases/``
            subfolder. Defaults to the repo's ``benchmark/`` directory.

    Returns:
        One `LoadedCase` per index entry, sorted by id for deterministic
        ordering (the harness must behave identically run to run).

    Raises:
        CorpusError: On any index/folder disagreement — a missing folder or
            ground-truth file, an orphaned folder not in the index, a duplicate
            id, an index/meta field mismatch, or a missing code file.
    """
    root = corpus_root or DEFAULT_CORPUS_ROOT
    index_path = root / "cases.yaml"
    cases_dir = root / "cases"

    index_entries = _load_index(index_path)

    loaded: list[LoadedCase] = []
    for entry in index_entries:
        # Each index entry must have a matching folder on disk; a missing folder
        # is the "index entry with no folder" failure.
        case_dir = cases_dir / entry.id
        if not case_dir.is_dir():
            raise CorpusError(
                f"Index lists case '{entry.id}' but no folder exists at {case_dir}"
            )

        ground_truth = _load_ground_truth(case_dir, entry.id)
        _check_index_matches_meta(entry, ground_truth)

        # The case must be self-contained and runnable: the code
        # file named in the ground truth has to actually be present.
        code_path = case_dir / ground_truth.file
        if not code_path.is_file():
            raise CorpusError(
                f"Case '{entry.id}' references code file '{ground_truth.file}' "
                f"but it does not exist at {code_path}"
            )

        loaded.append(
            LoadedCase(
                id=entry.id,
                cwe=entry.cwe,
                vulnerability_type=entry.vulnerability_type,
                layer2_eligible=entry.layer2_eligible,
                code_path=code_path,
                ground_truth=ground_truth,
            )
        )

    # The reverse check: every folder on disk must be accounted for in the
    # index. This catches an orphaned case folder (added on disk but never
    # registered), the second half of the index/folder consistency check.
    _check_no_orphan_folders(cases_dir, index_entries)

    return sorted(loaded, key=lambda case: case.id)


def load_corpus_version(corpus_root: Path | None = None) -> str:
    """Return the corpus version string recorded in ``cases.yaml``.

    The version identifies exactly which corpus a run was scored against, so it
    can be stamped into every result file and results from different
    corpus revisions are never silently compared. Reading it is intentionally
    decoupled from `load_corpus`: the run entry point can record the version
    without paying to load and validate every case, and the two never disagree
    because both read the same manifest.

    Args:
        corpus_root: Corpus directory containing ``cases.yaml``. Defaults to the
            repo's ``benchmark/`` directory (same default as `load_corpus`).

    Returns:
        The version string, e.g. ``pyvul-eval-corpus-1.0.0``.

    Raises:
        CorpusError: If the index is missing/malformed, or the ``version`` key
            is absent, not a string, or empty — an unversioned corpus would make
            results untraceable, so it is a hard error rather than a default.
    """
    root = corpus_root or DEFAULT_CORPUS_ROOT
    document = _read_index_document(root / "cases.yaml")

    version = document.get(_VERSION_KEY)
    if not isinstance(version, str) or not version.strip():
        raise CorpusError(
            f"Corpus index {root / 'cases.yaml'} must set a non-empty "
            f"'{_VERSION_KEY}:' string"
        )
    return version


def _read_index_document(index_path: Path) -> dict:
    """Read ``cases.yaml`` and validate its top-level shape.

    Shared by `_load_index` (which consumes the ``cases`` list) and
    `load_corpus_version` (which consumes the ``version`` string) so the file is
    parsed and shape-checked in exactly one place.

    Args:
        index_path: Path to the corpus index file.

    Returns:
        The parsed index document as a mapping.

    Raises:
        CorpusError: If the file is missing or is not a ``{cases: [...]}`` mapping.
    """
    if not index_path.is_file():
        raise CorpusError(f"Corpus index not found at {index_path}")

    raw = yaml.safe_load(index_path.read_text(encoding="utf-8"))
    # The index must be a mapping with a top-level `cases:` list. Anything else
    # (e.g. an empty file yielding None, or a bare list) is a malformed index.
    if not isinstance(raw, dict) or "cases" not in raw:
        raise CorpusError(
            f"Corpus index {index_path} must be a mapping with a 'cases:' list"
        )
    if not isinstance(raw["cases"], list):
        raise CorpusError(f"'cases' in {index_path} must be a list")
    return raw


def _load_index(index_path: Path) -> list[IndexEntry]:
    """Parse ``cases.yaml`` into typed, de-duplicated index entries.

    Args:
        index_path: Path to the corpus index file.

    Returns:
        The index entries in file order (final sorting happens in `load_corpus`).

    Raises:
        CorpusError: If the index is missing, is not the expected
            ``cases: [...]`` shape, has an entry that fails validation, or
            contains a duplicate id.
    """
    raw = _read_index_document(index_path)

    entries: list[IndexEntry] = []
    seen_ids: set[str] = set()
    for position, item in enumerate(raw["cases"]):
        try:
            entry = IndexEntry.model_validate(item)
        except ValidationError as error:
            # Surface the position so the author can find the bad entry even
            # when it has no usable id to name it by.
            raise CorpusError(
                f"Invalid index entry at position {position} in {index_path}: {error}"
            ) from error

        # A duplicate id would make folder/index pairing ambiguous and could
        # silently score one case twice, so reject it outright.
        if entry.id in seen_ids:
            raise CorpusError(f"Duplicate case id '{entry.id}' in {index_path}")
        seen_ids.add(entry.id)
        entries.append(entry)

    return entries


def _load_ground_truth(case_dir: Path, case_id: str) -> CaseGroundTruth:
    """Load and validate one case's ``meta.yaml`` answer key.

    Args:
        case_dir: The case's folder.
        case_id: The id from the index, used only for clear error messages.

    Returns:
        The parsed `CaseGroundTruth`.

    Raises:
        CorpusError: If ``meta.yaml`` is absent (missing ground truth) or fails
            schema validation.
    """
    meta_path = case_dir / _META_FILENAME
    if not meta_path.is_file():
        raise CorpusError(
            f"Case '{case_id}' is missing its ground-truth file {meta_path}"
        )

    raw = yaml.safe_load(meta_path.read_text(encoding="utf-8"))
    try:
        return CaseGroundTruth.model_validate(raw)
    except ValidationError as error:
        raise CorpusError(
            f"Invalid ground truth in {meta_path}: {error}"
        ) from error


def _check_index_matches_meta(entry: IndexEntry, truth: CaseGroundTruth) -> None:
    """Assert the index entry and the ground truth describe the same case.

    The index (``cases.yaml``) and the per-case ``meta.yaml`` are authored
    separately, so they can drift apart. Any drift is a defect: results would
    report one thing while scoring against another. We compare every field the
    two files share — id, CWE, vulnerability type, and the `layer2_eligible`
    flag — and reject the first mismatch (and the flag agreement
    noted in src/schema.py).

    Raises:
        CorpusError: On the first field that disagrees.
    """
    # (field label, value in index, value in meta) — checked in order.
    comparisons = [
        ("id", entry.id, truth.id),
        ("cwe", entry.cwe, truth.cwe),
        ("vulnerability_type", entry.vulnerability_type, truth.vulnerability_type),
        ("layer2_eligible", entry.layer2_eligible, truth.layer2_eligible),
    ]
    for field, index_value, meta_value in comparisons:
        if index_value != meta_value:
            raise CorpusError(
                f"Case '{entry.id}': index {field}={index_value!r} disagrees with "
                f"meta.yaml {field}={meta_value!r}"
            )


def _check_no_orphan_folders(cases_dir: Path, index_entries: list[IndexEntry]) -> None:
    """Ensure every case folder on disk is registered in the index.

    An orphaned folder — one present under ``cases/`` but absent from the index
    — would be silently ignored by every run, so we treat it as an error rather
    than skipping it ("no orphan cases").

    Args:
        cases_dir: The ``cases/`` directory holding one folder per case.
        index_entries: The validated index entries to check folders against.

    Raises:
        CorpusError: If a folder has no corresponding index entry.
    """
    if not cases_dir.is_dir():
        raise CorpusError(f"Corpus cases directory not found at {cases_dir}")

    indexed_ids = {entry.id for entry in index_entries}
    for child in sorted(cases_dir.iterdir()):
        # Only directories are cases; ignore stray files (e.g. a .gitkeep).
        if child.is_dir() and child.name not in indexed_ids:
            raise CorpusError(
                f"Orphaned case folder {child} is not listed in the corpus index"
            )

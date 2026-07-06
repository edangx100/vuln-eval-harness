"""Deterministic normalization helpers for the scorer.

The scorer normalizes before comparing predicted vs.
ground-truth fields, and does so deterministically so results stay
explainable. This module covers CWE identifiers and vulnerability-type
matching via a curated alias table.
"""

import re
from dataclasses import dataclass

# Matches an optional "cwe" prefix (any case, optional hyphen/whitespace
# separator) followed by the numeric identifier, e.g. "CWE-89", "cwe89",
# "Cwe 89", or a bare "89". Anchored with fullmatch (see below) so trailing
# junk like "89abc" is rejected rather than silently truncated.
_CWE_PATTERN = re.compile(r"(?:cwe[-\s]?)?(\d+)", re.IGNORECASE)


def normalize_cwe(raw: str | None) -> str | None:
    """Normalize a CWE identifier to its canonical `CWE-<number>` form.

    Accepts the equivalent spellings `CWE-89`,
    `cwe89`, and bare `89`. Whitespace/punctuation around the identifier is
    stripped before matching so `" CWE-89 "` and `"cwe 89"` also normalize.

    Args:
        raw: The predicted or ground-truth CWE string, or None.

    Returns:
        The canonical `CWE-<number>` string, or None if `raw` is None, empty,
        or doesn't contain a recognizable CWE identifier (a non-CWE string
        must not falsely match anything, so it normalizes to None rather than
        being passed through unchanged).
    """
    if raw is None:
        return None

    stripped = raw.strip()
    if not stripped:
        return None

    match = _CWE_PATTERN.fullmatch(stripped)
    if match is None:
        return None

    return f"CWE-{int(match.group(1))}"


def normalize_function(raw: str | None) -> str | None:
    """Normalize a function name for case/whitespace-insensitive comparison.

    Function names are normalized before comparison so a
    prediction of `" Login "` or `"LOGIN"` matches a ground-truth `login`.
    Only case and surrounding/interior whitespace are normalized — the
    identifier characters themselves are left intact, since a different name
    is a genuinely different location.

    Args:
        raw: The predicted or ground-truth function name, or None.

    Returns:
        The lowercased, whitespace-stripped function name, or None if `raw`
        is None or blank (blank is treated as "no function reported", never
        as a name that could match).
    """
    if raw is None:
        return None

    # Collapse any internal runs of whitespace to nothing and lowercase, so
    # comparison keys are stable regardless of incidental spacing/casing.
    normalized = re.sub(r"\s+", "", raw).lower()
    return normalized or None


# The curated alias table ("moderate" matching policy). Keys are
# the ten canonical class labels; values are accepted alternate phrasings for
# that class. Canonical labels stay at the specific-class level on purpose —
# sibling injection classes (SQL / OS command / code) must never collapse
# into one another, since distinguishing them is part of what the benchmark
# tests. This table is the scorer's contract: extend it deliberately (see
# module docstring), not by loosening the matching procedure below.
#
# Table version: v2 (extended after the first live evaluation run surfaced
# correct-but-unlisted phrasings via the raw->canonical logging the scorer
# records for exactly this purpose). Two kinds of entries were added, both
# class-level (never collapsing siblings), so leniency stays about *phrasing*,
# not *specificity*:
#   1. The **official MITRE CWE names** for each class (e.g. CWE-327 "Use of a
#      Broken or Risky Cryptographic Algorithm", CWE-330 "Use of Insufficiently
#      Random Values", CWE-502 "Deserialization of Untrusted Data"), so a model
#      answering with the authoritative name matches.
#   2. The **corpus's own ground-truth phrasings** that were not previously
#      mapped to their canonical label — notably "Use of Weak Cryptographic
#      Algorithm" (CASE-07) and "Use of Insufficiently Random Values" (CASE-08),
#      which otherwise could never score type-correct for ANY prediction because
#      even the truth string failed to reach its canonical label.
# Parenthetical qualifiers such as "(XSS)" or "(Denial of Service)" are handled
# generally by `_normalize_key` (stripped before lookup), not by enumerating them
# here.
TYPE_ALIAS_TABLE: dict[str, list[str]] = {
    "SQL Injection": ["SQLi", "SQL query injection"],
    "Cross-Site Scripting": ["XSS", "reflected XSS", "stored XSS"],
    "OS Command Injection": ["command injection", "shell injection"],
    "Code Injection": ["eval injection", "dynamic code execution"],
    "Path Traversal": ["directory traversal"],
    "Unsafe Deserialization": [
        "insecure deserialization",
        "pickle",
        "yaml.load",
        "Deserialization of Untrusted Data",
    ],
    "Weak Cryptography": [
        "broken crypto",
        "MD5",
        "SHA1",
        "Use of Weak Cryptographic Algorithm",
        "Use of a Broken or Risky Cryptographic Algorithm",
        "weak cryptographic hash",
        "weak hash",
    ],
    "Weak Randomness": [
        "insecure randomness",
        "predictable random",
        "Use of Insufficiently Random Values",
        "insufficiently random values",
        "cryptographically weak PRNG",
        "weak PRNG",
    ],
    "Improper Input Validation": ["missing input validation"],
    "Uncontrolled Resource Consumption": [
        "DoS",
        "denial of service",
        "resource exhaustion",
        "unbounded memory allocation",
        "uncontrolled memory allocation",
        "memory exhaustion",
    ],
}


def _normalize_key(raw: str) -> str:
    """Lowercase, drop parenthetical qualifiers, strip punctuation, collapse whitespace (step 1).

    This is the shared key format used both to build `_TYPE_ALIAS_LOOKUP` and
    to look up an input string, so a canonical label and its aliases compare
    on equal footing regardless of case or punctuation (e.g. "yaml.load" and
    "SQLi" both reduce to a bare lowercase/alnum form).

    Parenthetical qualifiers are removed *with their contents* before the rest
    of normalization, so a clarifying suffix does not defeat a match: e.g.
    "Cross-Site Scripting (XSS)" and "Uncontrolled Resource Consumption (Denial
    of Service)" reduce to the same key as the bare canonical label. This is a
    general rule rather than an enumerated alias — the parenthetical is treated
    as supplementary detail, and matching proceeds on the main phrase. A phrasing
    whose *only* specific content is inside the parentheses therefore reduces to
    its (possibly vague) main phrase and stays a conservative non-match, which is
    the intended direction (leniency for phrasing, never for specificity).
    """
    without_parens = re.sub(r"\([^)]*\)", " ", raw.lower())
    no_punctuation = re.sub(r"[^\w\s]", "", without_parens)
    return re.sub(r"\s+", " ", no_punctuation).strip()


# Maps every normalized alias (and every normalized canonical label itself)
# to its canonical class label, so lookup is a single dict access regardless
# of whether the input was already the canonical spelling or an alias.
_TYPE_ALIAS_LOOKUP: dict[str, str] = {
    _normalize_key(alias): canonical
    for canonical, aliases in TYPE_ALIAS_TABLE.items()
    for alias in [canonical, *aliases]
}


def normalize_vulnerability_type(raw: str | None) -> str | None:
    """Map a vulnerability-type string to its canonical class label.

    Three steps: normalize the input, look it up in the
    alias table, and fall back to the normalized input itself when no alias
    matches. That fallback is deliberate — an unrecognized or vague phrasing
    (e.g. a bare "injection") must be a conservative non-match against every
    real class, not a lucky pass, so it only ever equals another identical
    unrecognized phrasing.

    Args:
        raw: The predicted or ground-truth vulnerability-type string, or None.

    Returns:
        The canonical class label if `raw` matches an alias, the normalized
        `raw` string itself if it matches no alias, or None if `raw` is None
        or empty.
    """
    if raw is None:
        return None

    key = _normalize_key(raw)
    if not key:
        return None

    return _TYPE_ALIAS_LOOKUP.get(key, key)


@dataclass(frozen=True)
class TypeMatchResult:
    """Outcome of comparing a predicted vs. ground-truth vulnerability type.

    Carries both the raw and canonical form of each side so the scorer can
    log the raw->canonical mapping alongside the verdict ("Explainability": near-misses must stay visible for the alias table to be
    extended deliberately rather than guessed).

    Attributes:
        predicted_raw: The agent's reported vulnerability type, unmodified.
        predicted_canonical: `predicted_raw` after alias-table normalization,
            or None if `predicted_raw` was None/empty.
        truth_raw: The ground-truth vulnerability type, unmodified.
        truth_canonical: `truth_raw` after alias-table normalization, or None
            if `truth_raw` was None/empty.
        matched: Whether `predicted_canonical` and `truth_canonical` are
            equal and non-None.
    """

    predicted_raw: str | None
    predicted_canonical: str | None
    truth_raw: str | None
    truth_canonical: str | None
    matched: bool


def match_vulnerability_type(
    predicted: str | None, truth: str | None
) -> TypeMatchResult:
    """Compare a predicted vulnerability type against ground truth (step 4).

    Both sides are normalized to a canonical class label via
    `normalize_vulnerability_type`, then compared for exact equality — never
    substring or fuzzy matching. A None canonical (missing input) never
    counts as a match, even against another None, since absence of a
    prediction is not evidence of a correct one.

    Args:
        predicted: The agent's reported vulnerability type, or None.
        truth: The ground-truth vulnerability type, or None.

    Returns:
        A `TypeMatchResult` with both raw/canonical forms and the match
        verdict, for the scorer to record and log.
    """
    predicted_canonical = normalize_vulnerability_type(predicted)
    truth_canonical = normalize_vulnerability_type(truth)

    matched = predicted_canonical is not None and predicted_canonical == truth_canonical

    return TypeMatchResult(
        predicted_raw=predicted,
        predicted_canonical=predicted_canonical,
        truth_raw=truth,
        truth_canonical=truth_canonical,
        matched=matched,
    )

"""Comparison-report entry point: turn saved run files into one Markdown report.

This is the second of the harness's two entry points (the first being ``run_eval.py``, which
*produces* result files). Running ::

    python -m src.cli.compare_results results/model-a.json results/model-b.json

loads two or more per-run result files (the ``results/<run_name>.json`` files written by),
renders a single human-readable comparison, and writes it to ``results/comparison.md``.

**This module is a thin shell, on purpose.** All the real work already lives in two tested pieces:
:meth:`~src.results.RunResult.load` reads a result file back into a validated object, and
:func:`~src.report.generate_comparison` turns a list of those objects into Markdown. This
file only does the two things those pieces deliberately leave to a caller — *choosing which files
to read* and *deciding where to write the output* — so the reporting logic stays a pure,
file-free, unit-tested library and the command-line handling stays here where it belongs.

**Reproducibility.** The report is a pure function of its inputs: the same result files,
passed in the same order, always produce byte-identical output. The command-line argument order is
what fixes the report's *column* order (first file → first column), so re-running the identical
command re-creates the identical report — there is no timestamp, randomness, or hidden state here or
in :func:`~src.report.generate_comparison`.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from src.report import generate_comparison
from src.results import RunResult

# Where the comparison report is written when the caller does not choose otherwise.
# Kept as a named default rather than a bare literal so a test can point
# it at a temp directory, exactly as `run_eval.py` does with its own `DEFAULT_RESULTS_DIR`.
DEFAULT_OUTPUT_PATH = Path("results/comparison.md")


def compare_results(
    result_paths: list[Path],
    output_path: Path = DEFAULT_OUTPUT_PATH,
) -> Path:
    """Load result files, render the comparison, and write it to disk.

    This is the testable core of the entry point: it takes explicit paths and an explicit output
    location (no argument parsing, no ``.env``), so a test can drive the whole load → render → write
    flow against fixture files in a temp directory. It preserves the given order of
    ``result_paths`` because :func:`~src.report.generate_comparison` uses that order for the
    report's columns — passing the files in a fixed order is what makes the output reproducible.

    Args:
        result_paths: The per-run result files to compare (``results/<run_name>.json`` files), in the order their columns should appear. Two or more is the intended use, though
            a single file yields a valid one-column report.
        output_path: Where to write the Markdown report. Parent directories are created if missing.
            Defaults to :data:`DEFAULT_OUTPUT_PATH` (``results/comparison.md``).

    Returns:
        The path the report was written to (the same ``output_path``), for the caller to log.
    """
    # Load each file back into a fully-validated RunResult. `load` re-checks every nested field
    # (including the Layer-2 failure-reason enum), so a corrupt or schema-mismatched file fails
    # here with a clear validation error rather than producing a silently-wrong report.
    runs = [RunResult.load(path) for path in result_paths]

    # All the reporting logic lives in the report library; this module never computes a
    # number itself. Every figure in the Markdown is read straight off the loaded runs.
    report = generate_comparison(runs)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report, encoding="utf-8")
    return output_path


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse the command-line arguments for ``python -m src.cli.compare_results``.

    Args:
        argv: Argument list to parse. ``None`` (the default) uses ``sys.argv``; a test passes an
            explicit list so it never has to touch the real process arguments.

    Returns:
        The parsed arguments, with ``result_files`` (a list of :class:`~pathlib.Path`) and
        ``output`` (a :class:`~pathlib.Path`).
    """
    parser = argparse.ArgumentParser(
        prog="python -m src.cli.compare_results",
        description=(
            "Generate a Markdown comparison report from two or more per-run result files. "
            "Column order follows the file order given."
        ),
    )
    # nargs="+" requires at least one file and preserves the order given — which is exactly the
    # report's column order. `type=Path` converts each argument to a Path for us.
    parser.add_argument(
        "result_files",
        nargs="+",
        type=Path,
        help="Per-run result files to compare, e.g. results/model-a.json results/model-b.json",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help=f"Where to write the report (default: {DEFAULT_OUTPUT_PATH}).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    """Process entry point: ``python -m src.cli.compare_results``.

    Parses the result-file paths and output location from the command line, then delegates the
    actual work to :func:`compare_results`. Kept deliberately tiny — argument parsing plus one call
    plus a confirmation line — so the reusable logic stays in :func:`compare_results`.

    Args:
        argv: Argument list to parse. ``None`` uses the real process arguments; a test passes an
            explicit list to drive ``main`` end-to-end without spawning a subprocess.
    """
    args = _parse_args(argv)
    output = compare_results(args.result_files, args.output)
    print(f"wrote {output}")


if __name__ == "__main__":
    main()

"""The restricted tools exposed to the agent.

The agent's job is "inspect, optionally execute, then submit".
This package groups the tools that back that loop, split by what they do:

  - :mod:`~src.tools.inspection_tools` — the read-only inspection tools
    (``list_files`` / ``read_file`` / ``grep_search``), confined to one case
    workspace and run on the host.
  - :mod:`~src.tools.execution_tools` — the execution tools (``run_python`` /
    ``run_pytest``), which route untrusted code into the Docker sandbox.
  - :mod:`~src.tools.report_tools` — the ``submit_report`` tool, which validates
    the agent's final report against the shared schema and ends the loop.

Public names are re-exported here so callers can import from the package root,
e.g. ``from src.tools import InspectionTools, ExecutionTools, ReportTool``.
"""

from src.tools.execution_tools import ExecutionTools
from src.tools.inspection_tools import (
    GrepMatch,
    InspectionTools,
    WorkspaceViolation,
)
from src.tools.report_tools import (
    InvalidReportError,
    ReportTool,
    SubmittedReport,
)

__all__ = [
    "ExecutionTools",
    "GrepMatch",
    "InspectionTools",
    "InvalidReportError",
    "ReportTool",
    "SubmittedReport",
    "WorkspaceViolation",
]

"""VeriTrace GUI -- single-file desktop application.

A Tkinter-based desktop interface for VeriTrace: lets an analyst pick
EVTX, Registry, Prefetch, and MFT source files, run the correlation
engine against them, and browse/export the resulting anti-forensic
findings -- without needing to use four separate command-line tools.

This module depends on VeriTrace's other single-file modules
(``evtx.py``, ``registry.py``, ``prefetch.py``, ``mft.py``,
``correlation_engine.py``) being importable from the same location.

Uses only the Python standard library (``tkinter``) -- no additional
GUI framework needs to be installed.

Run:
    python veritrace_gui.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the current module directory is in the path
sys.path.insert(0, str(Path(__file__).parent))

import html
import logging
import queue
import threading
import tkinter as tk
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

from Correlation_Engine import (
    CorrelationContext,
    CorrelationFinding,
    Severity,
    load_evtx_entries,
    load_prefetch_entries,
    load_registry_value_entries,
)
from mft import MftParser

logger = logging.getLogger(__name__)

_SEVERITY_COLORS: dict[Severity, str] = {
    Severity.HIGH: "#c0392b",
    Severity.MEDIUM: "#d68910",
    Severity.LOW: "#2471a3",
    Severity.INFO: "#566573",
}

_WINDOW_TITLE = "VeriTrace -- Anti-Forensic Correlation Analysis"
_WINDOW_SIZE = "1150x780"


# --------------------------------------------------------------------------
# Pure helper logic (no Tkinter dependency -- independently testable)
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AnalysisOutcome:
    """The result of a background analysis run.

    Attributes:
        findings: The correlation findings produced, if the run
            succeeded.
        context: The parsed artifact context the findings were
            generated from, if the run succeeded.
        error: A description of what went wrong, if the run failed.
            ``None`` on success.
    """

    findings: tuple[CorrelationFinding, ...]
    context: CorrelationContext | None
    error: str | None


def run_analysis(
    evtx_paths: list[str | Path],
    registry_paths: list[str | Path],
    prefetch_paths: list[str | Path],
) -> AnalysisOutcome:
    """Parse the given artifact sources and run the correlation engine.

    This function has no Tkinter dependency, so it can be unit tested
    directly with synthetic file paths. MFT sources are intentionally
    not accepted here: ``correlation_engine`` does not yet have an
    MFT-aware loader, so MFT files are parsed and converted to
    findings separately (see
    :meth:`VeriTraceApp._analyze_mft_files`) and merged in by the
    caller.

    Args:
        evtx_paths: Paths to ``.evtx`` files.
        registry_paths: Paths to registry hive files.
        prefetch_paths: Paths to ``.pf`` files and/or folders.

    Returns:
        An :class:`AnalysisOutcome` describing the result.
    """
    try:
        context = CorrelationContext(
            evtx_entries=tuple(load_evtx_entries(evtx_paths)),
            registry_value_entries=tuple(load_registry_value_entries(registry_paths)),
            prefetch_entries=tuple(load_prefetch_entries(prefetch_paths)),
        )
        engine =  Correlation_Engine()
        findings = tuple(engine.run(context))
    except Exception as exc:  # noqa: BLE001 pylint: disable=broad-exception-caught
        # Deliberately broad: this is the top-level boundary between the
        # background worker thread and the GUI; any failure here must be
        # reported to the user rather than silently killing the thread.
        logger.exception("Analysis failed")
        return AnalysisOutcome(findings=(), context=None, error=str(exc))

    return AnalysisOutcome(findings=findings, context=context, error=None)


def findings_to_html(findings: list[CorrelationFinding], title: str = "VeriTrace Findings") -> str:
    """Render correlation findings as a self-contained HTML report.

    All text is HTML-escaped to prevent malformed/malicious artifact
    content (e.g. a crafted filename) from breaking the report.

    Args:
        findings: The findings to render, in display order.
        title: A title for the report.

    Returns:
        A complete, self-contained HTML document as a string.
    """
    rows = []
    for finding in findings:
        evidence_html = "<br>".join(html.escape(e) for e in finding.evidence)
        sources_html = "<br>".join(html.escape(s) for s in finding.source_paths)
        rows.append(
            f'<tr class="sev-{finding.severity.value}">'
            f"<td>{html.escape(finding.severity.value.upper())}</td>"
            f"<td>{html.escape(finding.rule_name)}</td>"
            f"<td>{html.escape(finding.description)}</td>"
            f"<td>{evidence_html}</td>"
            f"<td>{sources_html}</td>"
            f"</tr>"
        )
    table_rows = "\n".join(rows) if rows else '<tr><td colspan="5">No findings.</td></tr>'
    generated_at = datetime.now(timezone.utc).isoformat()

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{html.escape(title)}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; margin: 1.5rem;
          background: #fafafa; color: #1a1a1a; }}
  h1 {{ font-size: 1.4rem; margin-bottom: 0.2rem; }}
  .subtitle {{ color: #555; margin-bottom: 1rem; font-size: 0.85rem; }}
  table {{ border-collapse: collapse; width: 100%; background: #fff;
           box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
  th, td {{ border: 1px solid #e0e0e0; padding: 6px 10px; font-size: 0.85rem;
            text-align: left; vertical-align: top; }}
  th {{ background: #2d2d2d; color: #fff; }}
  tr.sev-high {{ background: #fdecea; }}
  tr.sev-medium {{ background: #fff8e1; }}
  tr.sev-low {{ background: #eaf2f8; }}
  tr.sev-info {{ background: #f4f4f4; }}
</style>
</head>
<body>
<h1>{html.escape(title)}</h1>
<div class="subtitle">
Generated {html.escape(generated_at)} &middot; {len(findings)} finding(s)
</div>
<table>
<thead><tr>
<th>Severity</th><th>Rule</th><th>Description</th><th>Evidence</th><th>Sources</th>
</tr></thead>
<tbody>
{table_rows}
</tbody>
</table>
</body>
</html>
"""


def generate_sample_mft_bytes() -> bytes:  # pylint: disable=too-many-statements
    """Build a small, real, parseable synthetic ``$MFT`` file for demo/testing.

    Note:
        ``too-many-statements`` is intentionally suppressed: this
        function hand-assembles real, spec-correct NTFS binary
        records (including a valid fixup/update-sequence-array), the
        same category of justified complexity as the equivalent
        binary-construction code in ``mft.py``'s own test fixtures.

    ``evtx.py``, ``registry.py``, and ``prefetch.py`` all wrap
    read-only third-party parsing libraries, so VeriTrace cannot
    generate valid sample files for those formats. The MFT parser,
    however, is a from-scratch binary implementation (see
    ``mft.py``), so this function can build genuinely valid,
    spec-correct sample records -- including one with real
    timestomping -- to let a user try the GUI's MFT analysis without
    needing a real disk image.

    Returns:
        Bytes for a 3-record synthetic ``$MFT`` file: one ordinary
        file, one directory, and one file with backdated
        ``$STANDARD_INFORMATION`` timestamps (i.e. timestomped).
    """

    def _build_resident_attribute(attr_type: int, content: bytes) -> bytes:
        content_offset = 24
        total_len = content_offset + len(content)
        padding = (8 - total_len % 8) % 8
        total_len += padding
        attr = bytearray(total_len)
        attr[0:4] = attr_type.to_bytes(4, "little")
        attr[4:8] = total_len.to_bytes(4, "little")
        attr[16:20] = len(content).to_bytes(4, "little")
        attr[20:22] = content_offset.to_bytes(2, "little")
        attr[content_offset : content_offset + len(content)] = content
        return bytes(attr)

    def _filetime(dt: datetime) -> bytes:
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        ticks = int((dt - epoch).total_seconds() * 10_000_000)
        return ticks.to_bytes(8, "little")

    def _build_record(  # pylint: disable=too-many-arguments,too-many-locals
        *,
        filename: str,
        si_creation: datetime,
        si_modification: datetime,
        si_mft_modification: datetime,
        si_access: datetime,
        fn_creation: datetime,
        is_directory: bool = False,
    ) -> bytes:
        # Argument/local count intentionally suppressed: each parameter
        # is one distinct timestamp field in the real NTFS record being
        # constructed, and each local is one distinct byte-offset value
        # in that binary layout -- the same justified complexity as the
        # equivalent construction code in mft.py's test fixtures.
        record = bytearray(1024)
        record[0:4] = b"FILE"
        usa_offset = 48
        usa_count = 3
        record[4:6] = usa_offset.to_bytes(2, "little")
        record[6:8] = usa_count.to_bytes(2, "little")
        record[16:18] = (1).to_bytes(2, "little")
        record[18:20] = (1).to_bytes(2, "little")
        first_attr_offset = 56
        record[20:22] = first_attr_offset.to_bytes(2, "little")
        flags = 0x0001 | (0x0002 if is_directory else 0)
        record[22:24] = flags.to_bytes(2, "little")

        usn = b"\x01\x00"
        record[usa_offset : usa_offset + 2] = usn
        record[usa_offset + 2 : usa_offset + 4] = b"\xAB\xCD"
        record[usa_offset + 4 : usa_offset + 6] = b"\xEF\x01"
        record[510:512] = usn
        record[1022:1024] = usn

        si_content = (
            _filetime(si_creation)
            + _filetime(si_modification)
            + _filetime(si_mft_modification)
            + _filetime(si_access)
            + b"\x00" * 24
        )
        si_attr = _build_resident_attribute(0x10, si_content)
        offset = first_attr_offset
        record[offset : offset + len(si_attr)] = si_attr
        offset += len(si_attr)

        name_utf16 = filename.encode("utf-16-le")
        fn_content = (
            (5).to_bytes(8, "little")  # parent record number
            + _filetime(fn_creation) * 4  # FN creation/mod/mft-mod/access all = creation
            + (1024).to_bytes(8, "little")
            + (1024).to_bytes(8, "little")
            + (0).to_bytes(4, "little")
            + (0).to_bytes(4, "little")
            + bytes([len(filename)])
            + bytes([1])
            + name_utf16
        )
        fn_attr = _build_resident_attribute(0x30, fn_content)
        record[offset : offset + len(fn_attr)] = fn_attr
        offset += len(fn_attr)

        record[offset : offset + 4] = (0xFFFFFFFF).to_bytes(4, "little")
        used_size = offset + 4
        record[24:28] = used_size.to_bytes(4, "little")
        record[28:32] = (1024).to_bytes(4, "little")
        return bytes(record)

    ordinary_time = datetime(2024, 1, 10, 9, 0, 0, tzinfo=timezone.utc)
    later_time = datetime(2024, 5, 2, 14, 30, 0, tzinfo=timezone.utc)
    real_creation = datetime(2024, 6, 20, 3, 0, 0, tzinfo=timezone.utc)
    backdated = datetime(2011, 3, 1, 0, 0, 0, tzinfo=timezone.utc)

    ordinary_file = _build_record(
        filename="report.docx",
        si_creation=ordinary_time,
        si_modification=later_time,
        si_mft_modification=later_time,
        si_access=later_time,
        fn_creation=ordinary_time,
    )
    directory = _build_record(
        filename="Documents",
        si_creation=ordinary_time,
        si_modification=ordinary_time,
        si_mft_modification=ordinary_time,
        si_access=ordinary_time,
        fn_creation=ordinary_time,
        is_directory=True,
    )
    timestomped_file = _build_record(
        filename="svchost_updater.exe",
        si_creation=backdated,
        si_modification=backdated,
        si_mft_modification=real_creation,  # tool forgot to fake this one
        si_access=backdated,
        fn_creation=real_creation,
    )

    return ordinary_file + directory + timestomped_file


# --------------------------------------------------------------------------
# Logging bridge: root logger -> GUI text widget (thread-safe via queue)
# --------------------------------------------------------------------------


class QueueLogHandler(logging.Handler):
    """A logging handler that pushes formatted records onto a queue.

    Log records can originate on a background worker thread, but
    Tkinter widgets may only be safely updated from the main thread.
    This handler bridges the two: it only ever touches the
    thread-safe ``queue.Queue``, and the GUI's main-thread poll loop
    is responsible for draining it into the log widget.
    """

    def __init__(self, log_queue: queue.Queue) -> None:
        """Initialize the handler.

        Args:
            log_queue: The queue to push formatted log lines onto.
        """
        super().__init__()
        self._queue = log_queue
        self.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        """Format a log record and push it onto the queue.

        Args:
            record: The log record to handle.
        """
        try:
            message = self.format(record)
            self._queue.put(("log", message))
        except Exception:  # noqa: BLE001 pylint: disable=broad-exception-caught
            # Deliberately broad: logging.Handler.emit must never raise,
            # per the standard library's own handler contract.
            self.handleError(record)


# --------------------------------------------------------------------------
# Reusable widget: one artifact type's source-file picker
# --------------------------------------------------------------------------


class ArtifactSourcePanel(ttk.LabelFrame):  # pylint: disable=too-many-ancestors
    """A labeled panel for picking source files for one artifact type.

    Wraps a listbox of selected paths with "Add File(s)", optionally
    "Add Folder", "Remove Selected", and "Clear" buttons.

    Attributes:
        label: The artifact type name shown on the panel.
    """

    def __init__(
        self,
        parent: tk.Widget,
        label: str,
        file_types: list[tuple[str, str]],
        allow_folder: bool = False,
        folder_glob_pattern: str | None = None,
    ) -> None:
        """Initialize the panel.

        Args:
            parent: The parent Tkinter widget.
            label: The artifact type name shown on the panel (e.g.
                ``"EVTX Files"``).
            file_types: File dialog filter patterns, as accepted by
                ``tkinter.filedialog.askopenfilenames``.
            allow_folder: Whether to show an "Add Folder" button that
                expands a folder into matching files.
            folder_glob_pattern: The glob pattern (e.g. ``"*.evtx"``)
                used to expand a selected folder into individual
                files. Required if ``allow_folder`` is ``True``.
        """
        super().__init__(parent, text=label, padding=6)
        self.label = label
        self._file_types = file_types
        self._folder_glob_pattern = folder_glob_pattern

        self._listbox = tk.Listbox(self, height=4, selectmode=tk.EXTENDED)
        self._listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 6))

        button_frame = ttk.Frame(self)
        button_frame.pack(side=tk.LEFT, fill=tk.Y)

        ttk.Button(button_frame, text="Add File(s)", command=self._add_files).pack(
            fill=tk.X, pady=2
        )
        if allow_folder:
            ttk.Button(button_frame, text="Add Folder", command=self._add_folder).pack(
                fill=tk.X, pady=2
            )
        ttk.Button(button_frame, text="Remove Selected", command=self._remove_selected).pack(
            fill=tk.X, pady=2
        )
        ttk.Button(button_frame, text="Clear", command=self._clear).pack(fill=tk.X, pady=2)

    def get_paths(self) -> list[str]:
        """Return all currently listed source paths.

        Returns:
            The list of paths currently shown in the panel's listbox.
        """
        return list(self._listbox.get(0, tk.END))

    def _add_files(self) -> None:
        """Open a file picker and add the chosen files to the list."""
        selected = filedialog.askopenfilenames(
            title=f"Select {self.label}", filetypes=self._file_types
        )
        for path in selected:
            self._listbox.insert(tk.END, path)

    def _add_folder(self) -> None:
        """Open a folder picker and add all matching files within it."""
        if self._folder_glob_pattern is None:
            return
        folder = filedialog.askdirectory(title=f"Select folder of {self.label}")
        if not folder:
            return
        matches = sorted(Path(folder).glob(self._folder_glob_pattern))
        if not matches:
            messagebox.showinfo(
                "No files found",
                f"No files matching '{self._folder_glob_pattern}' were found in:\n{folder}",
            )
            return
        for match in matches:
            self._listbox.insert(tk.END, str(match))

    def _remove_selected(self) -> None:
        """Remove the currently selected listbox entries."""
        for index in reversed(self._listbox.curselection()):
            self._listbox.delete(index)

    def _clear(self) -> None:
        """Remove all entries from the listbox."""
        self._listbox.delete(0, tk.END)


# --------------------------------------------------------------------------
# Main application
# --------------------------------------------------------------------------


class VeriTraceApp:  # pylint: disable=too-many-instance-attributes,too-few-public-methods
    """The main VeriTrace GUI application.

    Note:
        ``too-many-instance-attributes`` is intentionally suppressed:
        each attribute is a distinct widget this application owns,
        which is inherent to a GUI class of this size, not incidental
        complexity. ``too-few-public-methods`` is also suppressed:
        this is an Application class driven entirely by widget-bound
        callbacks (buttons, selection events), not a library class
        meant to expose a broader public API.

    Owns the Tkinter root window and all top-level widgets. Analysis
    runs on a background thread (see :meth:`_start_analysis`) so the
    UI never freezes; the thread communicates back to the main thread
    exclusively through a thread-safe queue, polled via
    ``root.after``.

    Attributes:
        root: The Tkinter root window.
    """

    def __init__(self, root: tk.Tk) -> None:
        """Initialize the application and build all widgets.

        Args:
            root: The Tkinter root window to build the UI inside.
        """
        self.root = root
        self.root.title(_WINDOW_TITLE)
        self.root.geometry(_WINDOW_SIZE)

        self._queue: queue.Queue = queue.Queue()
        self._last_findings: list[CorrelationFinding] = []
        self._analysis_running = False

        # Widgets are constructed in _build_widgets(); declared here with
        # their types so the full attribute surface of this class is
        # visible in one place.
        self._evtx_panel: ArtifactSourcePanel
        self._registry_panel: ArtifactSourcePanel
        self._prefetch_panel: ArtifactSourcePanel
        self._mft_panel: ArtifactSourcePanel
        self._run_button: ttk.Button
        self._export_button: ttk.Button
        self._status_label: ttk.Label
        self._progress: ttk.Progressbar
        self._tree: ttk.Treeview
        self._detail_text: tk.Text
        self._log_text: scrolledtext.ScrolledText

        self._build_widgets()
        self._attach_logging()
        self.root.after(100, self._poll_queue)

    # -- widget construction -------------------------------------------------

    def _build_widgets(self) -> None:
        """Build and lay out all top-level widgets."""
        self._build_source_panels()
        self._build_controls()
        self._build_results_panel()
        self._build_log_panel()

    def _build_source_panels(self) -> None:
        """Build the four artifact-source selection panels."""
        container = ttk.Frame(self.root, padding=8)
        container.pack(fill=tk.X)

        self._evtx_panel = ArtifactSourcePanel(
            container,
            "EVTX Files",
            file_types=[("EVTX files", "*.evtx"), ("All files", "*.*")],
            allow_folder=True,
            folder_glob_pattern="*.evtx",
        )
        self._evtx_panel.pack(fill=tk.X, pady=2)

        self._registry_panel = ArtifactSourcePanel(
            container,
            "Registry Hive Files",
            file_types=[("All files", "*.*")],
            allow_folder=False,
        )
        self._registry_panel.pack(fill=tk.X, pady=2)

        self._prefetch_panel = ArtifactSourcePanel(
            container,
            "Prefetch (.pf) Files",
            file_types=[("Prefetch files", "*.pf"), ("All files", "*.*")],
            allow_folder=True,
            folder_glob_pattern="*.pf",
        )
        self._prefetch_panel.pack(fill=tk.X, pady=2)

        self._mft_panel = ArtifactSourcePanel(
            container,
            "$MFT Files",
            file_types=[("All files", "*.*")],
            allow_folder=False,
        )
        self._mft_panel.pack(fill=tk.X, pady=2)

    def _build_controls(self) -> None:
        """Build the run/export/sample-data control bar and progress indicator."""
        control_bar = ttk.Frame(self.root, padding=(8, 4))
        control_bar.pack(fill=tk.X)

        self._run_button = ttk.Button(
            control_bar, text="Run Analysis", command=self._start_analysis
        )
        self._run_button.pack(side=tk.LEFT, padx=(0, 6))

        self._export_button = ttk.Button(
            control_bar,
            text="Export Findings to HTML",
            command=self._export_html,
            state=tk.DISABLED,
        )
        self._export_button.pack(side=tk.LEFT, padx=(0, 6))

        ttk.Button(
            control_bar, text="Generate Sample $MFT Data", command=self._generate_sample_mft
        ).pack(side=tk.LEFT, padx=(0, 6))

        self._status_label = ttk.Label(control_bar, text="Ready.")
        self._status_label.pack(side=tk.LEFT, padx=(12, 0))

        self._progress = ttk.Progressbar(control_bar, mode="indeterminate", length=150)
        self._progress.pack(side=tk.RIGHT)

    def _build_results_panel(self) -> None:
        """Build the findings Treeview and its detail pane."""
        frame = ttk.LabelFrame(self.root, text="Findings", padding=6)
        frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        columns = ("severity", "rule", "description")
        self._tree = ttk.Treeview(frame, columns=columns, show="headings", height=10)
        self._tree.heading("severity", text="Severity", command=lambda: self._sort_by("severity"))
        self._tree.heading("rule", text="Rule", command=lambda: self._sort_by("rule"))
        self._tree.heading("description", text="Description")
        self._tree.column("severity", width=90, anchor=tk.W)
        self._tree.column("rule", width=220, anchor=tk.W)
        self._tree.column("description", width=650, anchor=tk.W)

        for severity, color in _SEVERITY_COLORS.items():
            self._tree.tag_configure(severity.value, foreground=color)

        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self._tree.yview)
        self._tree.configure(yscrollcommand=scrollbar.set)
        self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.LEFT, fill=tk.Y)
        self._tree.bind("<<TreeviewSelect>>", self._on_finding_selected)

        detail_frame = ttk.LabelFrame(self.root, text="Finding Detail", padding=6)
        detail_frame.pack(fill=tk.X, padx=8, pady=(0, 4))
        self._detail_text = tk.Text(detail_frame, height=5, wrap=tk.WORD, state=tk.DISABLED)
        self._detail_text.pack(fill=tk.X)

    def _build_log_panel(self) -> None:
        """Build the scrolling log output panel."""
        frame = ttk.LabelFrame(self.root, text="Log", padding=6)
        frame.pack(fill=tk.BOTH, expand=False, padx=8, pady=(0, 8))
        self._log_text = scrolledtext.ScrolledText(frame, height=8, state=tk.DISABLED)
        self._log_text.pack(fill=tk.BOTH, expand=True)

    def _attach_logging(self) -> None:
        """Attach a queue-backed logging handler to the root logger."""
        handler = QueueLogHandler(self._queue)
        logging.getLogger().addHandler(handler)
        logging.getLogger().setLevel(logging.INFO)

    # -- analysis lifecycle ---------------------------------------------------

    def _start_analysis(self) -> None:
        """Validate inputs and start a background analysis run."""
        if self._analysis_running:
            return

        evtx_paths: list[str | Path] = list(self._evtx_panel.get_paths())
        registry_paths: list[str | Path] = list(self._registry_panel.get_paths())
        prefetch_paths: list[str | Path] = list(self._prefetch_panel.get_paths())
        mft_paths: list[str | Path] = list(self._mft_panel.get_paths())

        if not (evtx_paths or registry_paths or prefetch_paths or mft_paths):
            messagebox.showwarning(
                "No sources selected",
                "Add at least one EVTX, Registry, Prefetch, or $MFT file before running analysis.",
            )
            return

        self._analysis_running = True
        self._run_button.configure(state=tk.DISABLED)
        self._export_button.configure(state=tk.DISABLED)
        self._status_label.configure(text="Running analysis...")
        self._progress.start(12)
        self._clear_results()

        thread = threading.Thread(
            target=self._analysis_worker,
            args=(evtx_paths, registry_paths, prefetch_paths, mft_paths),
            daemon=True,
        )
        thread.start()

    def _analysis_worker(
        self,
        evtx_paths: list[str | Path],
        registry_paths: list[str | Path],
        prefetch_paths: list[str | Path],
        mft_paths: list[str | Path],
    ) -> None:
        """Run analysis on a background thread and post the outcome to the queue.

        MFT parsing is handled here directly (rather than inside
        :func:`run_analysis`) since ``correlation_engine`` does not
        yet have an MFT-aware loader; MFT findings are computed
        separately and merged in for display purposes.

        Args:
            evtx_paths: Paths to ``.evtx`` files.
            registry_paths: Paths to registry hive files.
            prefetch_paths: Paths to ``.pf`` files and/or folders.
            mft_paths: Paths to raw ``$MFT`` files.
        """
        outcome = run_analysis(evtx_paths, registry_paths, prefetch_paths)
        mft_findings = self._analyze_mft_files(mft_paths) if outcome.error is None else []
        self._queue.put(("result", outcome, mft_findings))

    @staticmethod
    def _analyze_mft_files(mft_paths: list[str | Path]) -> list[CorrelationFinding]:
        """Parse MFT files and convert timestomped records into findings.

        Args:
            mft_paths: Paths to raw ``$MFT`` files.

        Returns:
            A list of :class:`CorrelationFinding` for every likely
            timestomped record found.
        """
        findings: list[CorrelationFinding] = []
        for path in mft_paths:
            parser = MftParser(path)
            try:
                records = parser.parse()
            except Exception as exc:  # noqa: BLE001 pylint: disable=broad-exception-caught
                # Deliberately broad: one unreadable MFT file must not
                # abort analysis of the other selected artifact sources.
                logger.error("Skipping MFT file '%s': %s", path, exc)
                continue
            for record in records:
                if not record.likely_timestomped:
                    continue
                findings.append(
                    CorrelationFinding(
                        rule_name="mft_timestomping_detected",
                        severity=Severity.HIGH,
                        description=(
                            f"MFT record #{record.record_number} "
                            f"('{record.filename}') has $STANDARD_INFORMATION "
                            f"timestamp(s) that predate its $FILE_NAME creation "
                            f"time -- indicating timestomping."
                        ),
                        evidence=(
                            f"Anomalous fields: {', '.join(record.timestamp_anomalies)}",
                        ),
                        source_paths=(str(path),),
                    )
                )
        return findings

    def _poll_queue(self) -> None:
        """Drain the worker-thread queue and apply updates on the main thread."""
        try:
            while True:
                item = self._queue.get_nowait()
                if item[0] == "log":
                    self._append_log(item[1])
                elif item[0] == "result":
                    self._handle_analysis_result(item[1], item[2])
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _handle_analysis_result(
        self, outcome: AnalysisOutcome, mft_findings: list[CorrelationFinding]
    ) -> None:
        """Apply a completed analysis outcome to the UI.

        Args:
            outcome: The result from :func:`run_analysis`.
            mft_findings: Findings derived from MFT files, computed
                separately from the main correlation engine run.
        """
        self._progress.stop()
        self._run_button.configure(state=tk.NORMAL)
        self._analysis_running = False

        if outcome.error is not None:
            self._status_label.configure(text="Analysis failed.")
            messagebox.showerror("Analysis failed", outcome.error)
            return

        all_findings = list(outcome.findings) + mft_findings
        all_findings.sort(key=lambda f: list(Severity).index(f.severity), reverse=True)
        self._last_findings = all_findings

        self._populate_results(all_findings)
        self._export_button.configure(state=tk.NORMAL if all_findings else tk.DISABLED)
        self._status_label.configure(
            text=f"Done. {len(all_findings)} finding(s)."
        )

    # -- results display --------------------------------------------------

    def _clear_results(self) -> None:
        """Clear the findings table and detail pane."""
        self._tree.delete(*self._tree.get_children())
        self._set_detail_text("")

    def _populate_results(self, findings: list[CorrelationFinding]) -> None:
        """Populate the findings Treeview.

        Args:
            findings: The findings to display, in display order.
        """
        self._clear_results()
        for index, finding in enumerate(findings):
            self._tree.insert(
                "",
                tk.END,
                iid=str(index),
                values=(finding.severity.value.upper(), finding.rule_name, finding.description),
                tags=(finding.severity.value,),
            )

    def _on_finding_selected(self, _event: object) -> None:
        """Show full detail for the selected finding in the detail pane."""
        selection = self._tree.selection()
        if not selection:
            return
        index = int(selection[0])
        finding = self._last_findings[index]
        detail = (
            f"Rule: {finding.rule_name}\n"
            f"Severity: {finding.severity.value.upper()}\n\n"
            f"{finding.description}\n\n"
            f"Evidence:\n"
            + "\n".join(f"  - {e}" for e in finding.evidence)
            + "\n\nSources:\n"
            + "\n".join(f"  - {s}" for s in finding.source_paths)
        )
        self._set_detail_text(detail)

    def _set_detail_text(self, text: str) -> None:
        """Replace the contents of the detail pane.

        Args:
            text: The text to display.
        """
        self._detail_text.configure(state=tk.NORMAL)
        self._detail_text.delete("1.0", tk.END)
        self._detail_text.insert(tk.END, text)
        self._detail_text.configure(state=tk.DISABLED)

    def _sort_by(self, column: str) -> None:
        """Sort the findings table by a given column.

        Args:
            column: The column identifier to sort by (``"severity"``
                or ``"rule"``).
        """
        if column == "severity":
            self._last_findings.sort(
                key=lambda f: list(Severity).index(f.severity), reverse=True
            )
        elif column == "rule":
            self._last_findings.sort(key=lambda f: f.rule_name)
        self._populate_results(self._last_findings)

    # -- log panel ----------------------------------------------------------

    def _append_log(self, message: str) -> None:
        """Append a line to the log panel and scroll to the bottom.

        Args:
            message: The formatted log line to append.
        """
        self._log_text.configure(state=tk.NORMAL)
        self._log_text.insert(tk.END, message + "\n")
        self._log_text.see(tk.END)
        self._log_text.configure(state=tk.DISABLED)

    # -- export / sample data -------------------------------------------------

    def _export_html(self) -> None:
        """Export the current findings to an HTML report file."""
        if not self._last_findings:
            return
        target = filedialog.asksaveasfilename(
            title="Save findings report",
            defaultextension=".html",
            filetypes=[("HTML files", "*.html")],
        )
        if not target:
            return
        try:
            document = findings_to_html(self._last_findings, title="VeriTrace Findings Report")
            Path(target).write_text(document, encoding="utf-8")
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))
            return
        messagebox.showinfo("Export complete", f"Report saved to:\n{target}")

    def _generate_sample_mft(self) -> None:
        """Generate a synthetic sample $MFT file and add it to the MFT panel."""
        target = filedialog.asksaveasfilename(
            title="Save sample $MFT file as",
            defaultextension="",
            initialfile="sample_MFT",
        )
        if not target:
            return
        try:
            Path(target).write_bytes(generate_sample_mft_bytes())
        except OSError as exc:
            messagebox.showerror("Failed to write sample file", str(exc))
            return
        self._mft_panel._listbox.insert(tk.END, target)  # pylint: disable=protected-access
        messagebox.showinfo(
            "Sample data generated",
            "A synthetic $MFT file was created with one ordinary file, one "
            "directory, and one deliberately timestomped file, and has been "
            "added to the $MFT Files list. Click 'Run Analysis' to try it out.",
        )


def _configure_logging() -> None:
    """Configure baseline logging before the GUI attaches its own handler."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def main() -> None:
    """Launch the VeriTrace GUI application."""
    _configure_logging()
    root = tk.Tk()
    VeriTraceApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
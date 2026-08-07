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

# pylint: disable=too-many-lines
# This module's line count is inflated by embedded base64 logo image
# data (see "Embedded brand assets" below), not by code complexity.

from __future__ import annotations

import html
import logging
import queue
import sys
import threading
import tkinter as tk
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

# Ensure the current module's own directory is on sys.path before
# importing VeriTrace's other local modules below. This is normally
# redundant (Python already does this for a directly-run script) but
# some IDE debug launchers (e.g. certain VS Code configurations) can
# start the interpreter with a different sys.path[0], so this makes
# the local imports robust regardless of how the script is launched.
sys.path.insert(0, str(Path(__file__).parent))

from case_ingest import (  # pylint: disable=wrong-import-position
    DiscoveredArtifacts,
    InvalidCasePathError,
    load_case,
)
from correlation_engine import (  # pylint: disable=wrong-import-position
    CorrelationContext,
    CorrelationEngine,
    CorrelationFinding,
    Severity,
    build_context,
)

logger = logging.getLogger(__name__)

_SEVERITY_COLORS: dict[Severity, str] = {
    Severity.HIGH: "#c0392b",
    Severity.MEDIUM: "#d68910",
    Severity.LOW: "#2471a3",
    Severity.INFO: "#566573",
}

_WINDOW_TITLE = "VeriTrace -- Anti-Forensic Correlation Analysis"
_WINDOW_SIZE = "1150x870"


# --------------------------------------------------------------------------
# Embedded brand assets
# --------------------------------------------------------------------------
#
# The VeriTrace logo is embedded here as base64-encoded PNG data rather
# than shipped as a separate image file, so the GUI has no external asset
# to lose track of or resolve a path to -- it works regardless of the
# working directory the script is launched from.
#
# To regenerate these constants from a new source logo image:
#   from PIL import Image
#   import base64, textwrap
#   img = Image.open("new_logo.png").convert("RGB")
#   img.resize((110, 110)).save("banner.png")   # header banner
#   img.resize((64, 64)).save("icon.png")        # window/taskbar icon
#   for name, path in [("_LOGO_BANNER_PNG_B64", "banner.png"),
#                       ("_LOGO_ICON_PNG_B64", "icon.png")]:
#       b64 = base64.b64encode(open(path, "rb").read()).decode("ascii")
#       print(name, "=", repr(textwrap.wrap(b64, 96)))
#

_LOGO_BANNER_PNG_B64 = (
    "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"
    "RK5CYII="
)

_LOGO_ICON_PNG_B64 = (
    "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"
    "P9cIxAAAAABJRU5ErkJggg=="
)

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
    mft_paths: list[str | Path],
) -> AnalysisOutcome:
    """Parse the given artifact sources and run the correlation engine.

    This function has no Tkinter dependency, so it can be unit tested
    directly with synthetic file paths. Delegates entirely to
    ``correlation_engine.build_context`` and
    ``correlation_engine.CorrelationEngine``, which handle all four
    artifact types (including MFT) as first-class citizens.

    Args:
        evtx_paths: Paths to ``.evtx`` files.
        registry_paths: Paths to registry hive files.
        prefetch_paths: Paths to ``.pf`` files and/or folders.
        mft_paths: Paths to raw ``$MFT`` files.

    Returns:
        An :class:`AnalysisOutcome` describing the result.
    """
    try:
        context = build_context(
            evtx_paths=evtx_paths,
            registry_paths=registry_paths,
            prefetch_paths=prefetch_paths,
            mft_paths=mft_paths,
        )
        engine = CorrelationEngine()
        findings = tuple(engine.run(context))
    except Exception as exc:  # pylint: disable=broad-exception-caught
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
    generated_at = datetime.now(UTC).isoformat()

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
        epoch = datetime(1601, 1, 1, tzinfo=UTC)
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

    ordinary_time = datetime(2024, 1, 10, 9, 0, 0, tzinfo=UTC)
    later_time = datetime(2024, 5, 2, 14, 30, 0, tzinfo=UTC)
    real_creation = datetime(2024, 6, 20, 3, 0, 0, tzinfo=UTC)
    backdated = datetime(2011, 3, 1, 0, 0, 0, tzinfo=UTC)

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

    def set_paths(self, paths: list[str], replace: bool = True) -> None:
        """Populate the listbox with a given set of paths.

        Used by case-ingest auto-discovery to fill in this panel
        without the user manually browsing for each file.

        Args:
            paths: The paths to display.
            replace: If ``True`` (the default), any existing entries
                are cleared first. If ``False``, ``paths`` are
                appended to the existing list.
        """
        if replace:
            self._clear()
        for path in paths:
            self._listbox.insert(tk.END, path)

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
        self._maximize_window()

        self._queue: queue.Queue = queue.Queue()
        self._last_findings: list[CorrelationFinding] = []
        self._analysis_running = False

        # Widgets are constructed in _build_widgets(); declared here with
        # their types so the full attribute surface of this class is
        # visible in one place.
        self._icon_image: tk.PhotoImage
        self._banner_image: tk.PhotoImage
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

        self._set_window_icon()
        self._build_widgets()
        self._attach_logging()
        self.root.after(100, self._poll_queue)

    def _maximize_window(self) -> None:
        """Start the window maximized so no panel is cut off on smaller screens.

        The fixed default size in ``_WINDOW_SIZE`` was set generously
        to fit every panel (source lists, controls, findings table,
        detail pane, log) plus the header banner, but that total can
        exceed the visible height of smaller/laptop screens if the
        window isn't maximized -- with the findings table and log
        panel, near the bottom, being the first things to end up
        below the visible screen area. Starting maximized avoids that
        regardless of screen size; the window remains a normal,
        user-resizable window afterward.

        ``wm_state('zoomed')`` is the standard, native way to do this
        on Windows. It depends on window-manager support, though, so
        as a robust fallback that doesn't depend on that at all, this
        also explicitly sizes the window to the screen's own reported
        dimensions -- which works even in environments where the
        'zoomed' state hint is ignored.
        """
        try:
            self.root.state("zoomed")
        except tk.TclError as exc:
            logger.debug("wm_state('zoomed') unavailable: %s", exc)

        # Belt-and-suspenders: if 'zoomed' didn't actually take effect (its
        # success can't be fully determined just from not raising -- some
        # window managers silently ignore it), explicitly size the window
        # to the screen's own reported dimensions instead.
        self.root.update_idletasks()
        if self.root.state() != "zoomed":
            screen_width = self.root.winfo_screenwidth()
            screen_height = self.root.winfo_screenheight()
            self.root.geometry(f"{screen_width}x{screen_height}+0+0")

    def _set_window_icon(self) -> None:
        """Set the window/taskbar icon from the embedded logo badge.

        The image reference is kept on ``self`` -- Tkinter does not
        keep its own strong reference to a ``PhotoImage``, so without
        this the icon would be garbage-collected and silently vanish
        shortly after being set.
        """
        try:
            self._icon_image = tk.PhotoImage(data=_LOGO_ICON_PNG_B64)
            self.root.iconphoto(True, self._icon_image)
        except tk.TclError as exc:
            logger.warning("Could not set window icon: %s", exc)

    # -- widget construction -------------------------------------------------

    def _build_widgets(self) -> None:
        """Build and lay out all top-level widgets.

        Everything is built inside a scrollable canvas (see
        :meth:`_build_scroll_container`) rather than packed directly
        into the root window. On a screen too short to fit every
        panel at once (a real issue on smaller/laptop displays --
        the four source panels plus the header alone can exceed a
        768px-tall screen), the content becomes scrollable instead of
        having its bottom panels (findings, log) silently pushed
        below the visible screen area with no way to reach them.
        """
        content = self._build_scroll_container()
        self._build_header(content)
        self._build_source_panels(content)
        self._build_controls(content)
        self._build_results_panel(content)
        self._build_log_panel(content)

    def _build_scroll_container(self) -> tk.Widget:
        """Build a scrollable canvas that all other widgets are placed inside.

        Returns:
            The frame inside the canvas that subsequent
            ``_build_*`` methods should use as their parent widget,
            instead of ``self.root`` directly.
        """
        canvas = tk.Canvas(self.root, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.root, orient=tk.VERTICAL, command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        content = ttk.Frame(canvas)
        content_window = canvas.create_window((0, 0), window=content, anchor="nw")

        def _sync_scroll_region(_event: object) -> None:
            canvas.configure(scrollregion=canvas.bbox("all"))

        def _sync_content_width(event: object) -> None:
            # Keep the inner frame exactly as wide as the canvas viewport,
            # so widgets that expand horizontally (fill=tk.X) do so
            # correctly instead of being clipped to the frame's natural
            # (unscrolled) size.
            canvas.itemconfigure(content_window, width=event.width)  # type: ignore[attr-defined]

        content.bind("<Configure>", _sync_scroll_region)
        canvas.bind("<Configure>", _sync_content_width)

        def _on_mouse_wheel(event: tk.Event) -> None:
            # Windows reports wheel movement in event.delta (multiples of
            # 120); this converts it to a small number of scroll units.
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas.bind_all("<MouseWheel>", _on_mouse_wheel)

        return content

    def _build_header(self, parent: tk.Widget) -> None:
        """Build the branded header banner at the top of the window.

        Falls back to a plain text title (no crash) if the embedded
        logo image data can't be decoded for any reason -- branding
        is cosmetic and must never prevent the application from
        starting.
        """
        header = tk.Frame(parent, background="#000000")
        header.pack(fill=tk.X)
        try:
            self._banner_image = tk.PhotoImage(data=_LOGO_BANNER_PNG_B64)
            tk.Label(header, image=self._banner_image, background="#000000").pack(
                pady=6
            )
        except tk.TclError as exc:
            logger.warning("Could not load header banner image: %s", exc)
            tk.Label(
                header,
                text="VeriTrace",
                background="#000000",
                foreground="#4a90d9",
                font=("Segoe UI", 18, "bold"),
            ).pack(pady=10)

    def _build_source_panels(self, parent: tk.Widget) -> None:
        """Build the four artifact-source selection panels."""
        container = ttk.Frame(parent, padding=8)
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

    def _build_controls(self, parent: tk.Widget) -> None:
        """Build the run/export/sample-data control bar and progress indicator."""
        control_bar = ttk.Frame(parent, padding=(8, 4))
        control_bar.pack(fill=tk.X)

        ttk.Button(
            control_bar, text="Load Case Folder...", command=self._load_case_folder
        ).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(
            control_bar, text="Load Case ZIP...", command=self._load_case_zip
        ).pack(side=tk.LEFT, padx=(0, 6))

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

    def _build_results_panel(self, parent: tk.Widget) -> None:
        """Build the findings Treeview and its detail pane."""
        frame = ttk.LabelFrame(parent, text="Findings", padding=6)
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

        detail_frame = ttk.LabelFrame(parent, text="Finding Detail", padding=6)
        detail_frame.pack(fill=tk.X, padx=8, pady=(0, 4))
        self._detail_text = tk.Text(detail_frame, height=5, wrap=tk.WORD, state=tk.DISABLED)
        self._detail_text.pack(fill=tk.X)

    def _build_log_panel(self, parent: tk.Widget) -> None:
        """Build the scrolling log output panel."""
        frame = ttk.LabelFrame(parent, text="Log", padding=6)
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

        Args:
            evtx_paths: Paths to ``.evtx`` files.
            registry_paths: Paths to registry hive files.
            prefetch_paths: Paths to ``.pf`` files and/or folders.
            mft_paths: Paths to raw ``$MFT`` files.
        """
        outcome = run_analysis(evtx_paths, registry_paths, prefetch_paths, mft_paths)
        self._queue.put(("result", outcome))

    def _poll_queue(self) -> None:
        """Drain the worker-thread queue and apply updates on the main thread."""
        try:
            while True:
                item = self._queue.get_nowait()
                if item[0] == "log":
                    self._append_log(item[1])
                elif item[0] == "result":
                    self._handle_analysis_result(item[1])
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _handle_analysis_result(self, outcome: AnalysisOutcome) -> None:
        """Apply a completed analysis outcome to the UI.

        Args:
            outcome: The result from :func:`run_analysis`.
        """
        self._progress.stop()
        self._run_button.configure(state=tk.NORMAL)
        self._analysis_running = False

        if outcome.error is not None:
            self._status_label.configure(text="Analysis failed.")
            messagebox.showerror("Analysis failed", outcome.error)
            return

        all_findings = list(outcome.findings)
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

    # -- case ingest ----------------------------------------------------------

    def _load_case_folder(self) -> None:
        """Prompt for a case folder, auto-discover artifacts, and populate panels."""
        folder = filedialog.askdirectory(title="Select case folder")
        if not folder:
            return
        self._load_case_from_path(folder)

    def _load_case_zip(self) -> None:
        """Prompt for a case .zip archive, auto-discover artifacts, and populate panels."""
        zip_path = filedialog.askopenfilename(
            title="Select case .zip archive", filetypes=[("Zip archives", "*.zip")]
        )
        if not zip_path:
            return
        self._load_case_from_path(zip_path)

    def _load_case_from_path(self, path: str) -> None:
        """Discover artifacts at a path and populate all four source panels.

        Args:
            path: A case folder or ``.zip`` archive path, as chosen by
                the user.
        """
        self._status_label.configure(text="Scanning case...")
        self.root.update_idletasks()
        try:
            artifacts = load_case(path)
        except InvalidCasePathError as exc:
            self._status_label.configure(text="Case scan failed.")
            messagebox.showerror("Case scan failed", str(exc))
            return

        self._apply_discovered_artifacts(artifacts)

        self._status_label.configure(
            text=f"Loaded case: {artifacts.total_count} artifact(s) found."
        )
        if artifacts.total_count == 0:
            messagebox.showwarning(
                "No artifacts found",
                f"No recognized EVTX, registry, Prefetch, or MFT files were found "
                f"in:\n{path}\n\n"
                f"({artifacts.unclassified_count} other file(s) were present but "
                f"not recognized.)",
            )

    def _apply_discovered_artifacts(self, artifacts: DiscoveredArtifacts) -> None:
        """Populate all four source panels from a discovery result.

        Args:
            artifacts: The artifacts discovered by :func:`load_case`.
        """
        self._evtx_panel.set_paths(list(artifacts.evtx_paths))
        self._registry_panel.set_paths(list(artifacts.registry_paths))
        self._prefetch_panel.set_paths(list(artifacts.prefetch_paths))
        self._mft_panel.set_paths(list(artifacts.mft_paths))
        logger.info(
            "Case loaded: %d EVTX, %d registry, %d Prefetch, %d MFT "
            "(%d file(s) unclassified).",
            len(artifacts.evtx_paths),
            len(artifacts.registry_paths),
            len(artifacts.prefetch_paths),
            len(artifacts.mft_paths),
            artifacts.unclassified_count,
        )

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
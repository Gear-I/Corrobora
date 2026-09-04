"""Corrobora GUI -- single-file desktop application.

A PyQt5-based desktop interface for Corrobora, styled after the
*LEAPP family's GUI conventions: an analyst points it at one evidence
source (a folder or ``.zip``, auto-classified via ``case_ingest.py``),
picks which artifact categories and validation rule categories to
run, and gets back a scored, browsable set of anti-forensic findings
-- without needing to use several separate command-line tools.

This module depends on Corrobora's other single-file modules
(``evtx.py``, ``registry.py``, ``prefetch.py``, ``mft.py``,
``correlation_engine.py``) and on ``corrobora.rules`` being importable
from the same location.

Requires the ``PyQt5`` package (see ``pyproject.toml``).

Run:
    python corrobora_gui.py
"""

# pylint: disable=too-many-lines
# This module's line count is inflated by embedded base64 logo image
# data (see "Embedded brand assets" below), not by code complexity.

from __future__ import annotations

import base64
import html
import logging
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from PyQt5.QtCore import QModelIndex, QObject, QRect, Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QIcon, QPainter, QPixmap
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

# Ensure the current module's own directory is on sys.path before
# importing Corrobora's other local modules below. This is normally
# redundant (Python already does this for a directly-run script) but
# some IDE debug launchers (e.g. certain VS Code configurations) can
# start the interpreter with a different sys.path[0], so this makes
# the local imports robust regardless of how the script is launched.
sys.path.insert(0, str(Path(__file__).parent))

from .case_ingest import (  # pylint: disable=wrong-import-position
    DiscoveredArtifacts,
    InvalidCasePathError,
    load_case,
)
from .correlation_engine import (  # pylint: disable=wrong-import-position
    CorrelationContext,
    CorrelationEngine,
    CorrelationFinding,
    Severity,
    build_context,
)
from ..rules.base import CorrelationRule  # pylint: disable=wrong-import-position
from ..rules.rule_registry import RULE_REGISTRY  # pylint: disable=wrong-import-position

logger = logging.getLogger(__name__)

_SEVERITY_COLORS: dict[Severity, str] = {
    Severity.HIGH: "#c0392b",
    Severity.MEDIUM: "#d68910",
    Severity.LOW: "#2471a3",
    Severity.INFO: "#566573",
}

_WINDOW_TITLE = "Corrobora -- Cross-Artifact Validation Framework"
_WINDOW_SIZE = (1150, 870)

# Maps each DiscoveredArtifacts path-tuple field to the display label
# shown in the "Artifact Categories" checklist. Only artifact types
# Corrobora actually parses today are listed -- no placeholders for
# types that don't exist yet (e.g. Amcache, Jump Lists, SRUM).
_ARTIFACT_CATEGORIES: tuple[tuple[str, str], ...] = (
    ("evtx_paths", "Event Logs (EVTX)"),
    ("registry_paths", "Registry"),
    ("prefetch_paths", "Prefetch"),
    ("mft_paths", "MFT"),
)

# Display labels for known rule categories. A category not listed here
# (e.g. a future addition to corrobora.rules) still gets a checkbox --
# _rule_category_label() falls back to a title-cased version of the
# raw category name, so new categories appear automatically.
_RULE_CATEGORY_LABELS: dict[str, str] = {
    "program_execution": "Program Execution",
    "persistence": "Persistence",
    "integrity": "Integrity",
}


def _rule_category_label(category: str) -> str:
    """Return the display label for a rule category.

    Args:
        category: A :attr:`CorrelationRule.category` value.

    Returns:
        The configured label, or a title-cased fallback derived from
        the raw category name if none is configured.
    """
    return _RULE_CATEGORY_LABELS.get(category, category.replace("_", " ").title())


# --------------------------------------------------------------------------
# Embedded brand assets
# --------------------------------------------------------------------------
#
# The Corrobora logo is embedded here as base64-encoded PNG data rather
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
    "7zHsJAoI5D0RDQ4M/M3f/C0aDHNRnU4HANBk4MuiKGIEgvBnf/anH/3oR1utjicPas/RPLfvfOc7xxYubLWajUbD"
    "OdfptBE8sWiIqCiKd7/rXQ8+8ODOnbvRhLicwuuiPcFZZ5110UUXFUUn2i3L15P33pOusVf4IgEjAC/vMtaUZXnO"
    "OeecddZZT27bltkaAAWCjc3Kor1u3SprM61A1eX3BILQopbScwjepLSU4k2iGI9yhBcBMip/WhetXHMwL6p8ZSfy"
    "jW98493vfleo2szMzDztaWc8/enfh//LY+fOncceeyyRA4D77nsw8KnT6YyMjFx+2WUTExMBwERI3vvBwcEsy9rt"
    "TgCAe+69FwCIfNjKOax8SClkXLkdqwTVUBQ8I253zgQgTgbR7tu3b+eOnWvWri1Lh4if+MQn/upDH+q02wBgrJXo"
    "oqenp7+/v9lsBoW+7777ACDPjCvp/vseeNaznhVWBbzqVa+66KIXlmUBgNHwPBFRo9EYHBxstZrh1eW7du2anp62"
    "WVYWcP/994eCUVEUJ5100vXX/2ZiYjziosoPRkdGy7LsFB1EbLVa9973AIAB8IFCr3FXFrolNKYQp+3bty/My7Rb"
    "7dVrVl933XXj4+OefGYtADrngMBYk+c5WnSF9higECB+Y98vmWjoFSOEddXHCQDJiLmInoo3Qw6LohZzDBDAD4Gz"
    "KALvnbH5Qw89+Bd/8Vf1ep0IytJNTU1NTEyGY0I+TU7O82licnJy8vDhw86573z3exMTE9bWjK3ffMtNP/3pZX19"
    "fZ1Op9Vqzc7O9vT09Pb21ur1LMvzvNZoNPr6+jvtzvT0dLvdGhgcuOuuu37+X/9lTA5A3petVit40la7FR7J4EIY"
    "MXinRDKuOCnLoig5dGOkj5k2EJCx2ezM1CWXfKFWy9FAp9M5cuQIAvb29vX29tbyvFar9fT09vf3A8CRI+Ptdruv"
    "r6/ZbH75K18BwNIVAPiVf/lys9nq7+/vdIrx8XEiX6vXa7VavV6v13t6e/sG+gestePj451Okec5In7yk58iIoAM"
    "jf3BD35wzz33DQ8PFUUxMTExMz1Trzd64tHb09vX09PbqDfGxydmZ2eLTtHX1/eTn/zn/ffdk+UZAACasowryNqd"
    "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"
)

_LOGO_ICON_PNG_B64 = (
    "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"
    "/4D/AAhd1aPhtkeJAAAAAElFTkSuQmCC"
)

# --------------------------------------------------------------------------
# Pure helper logic (no GUI-framework dependency -- independently testable)
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
    rules: list[CorrelationRule] | None = None,
) -> AnalysisOutcome:
    """Parse the given artifact sources and run the correlation engine.

    This function has no GUI-framework dependency, so it can be unit
    tested directly with synthetic file paths. Delegates entirely to
    ``correlation_engine.build_context`` and
    ``correlation_engine.CorrelationEngine``, which handle all four
    artifact types (including MFT) as first-class citizens.

    Args:
        evtx_paths: Paths to ``.evtx`` files.
        registry_paths: Paths to registry hive files.
        prefetch_paths: Paths to ``.pf`` files and/or folders.
        mft_paths: Paths to raw ``$MFT`` files.
        rules: The correlation rules to run. Defaults to
            :data:`corrobora.rules.rule_registry.DEFAULT_RULES` (via
            :class:`CorrelationEngine`'s own default) if not provided.

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
        engine = CorrelationEngine(rules=rules)
        findings = tuple(engine.run(context))
    except Exception as exc:  # pylint: disable=broad-exception-caught
        # Deliberately broad: this is the top-level boundary between the
        # background worker thread and the GUI; any failure here must be
        # reported to the user rather than silently killing the thread.
        logger.exception("Analysis failed")
        return AnalysisOutcome(findings=(), context=None, error=str(exc))

    return AnalysisOutcome(findings=findings, context=context, error=None)


def findings_to_html(findings: list[CorrelationFinding], title: str = "Corrobora Findings") -> str:
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
            f"<td>{finding.score}</td>"
            f"<td>{html.escape(finding.rule_name)}</td>"
            f"<td>{html.escape(finding.description)}</td>"
            f"<td>{evidence_html}</td>"
            f"<td>{sources_html}</td>"
            f"</tr>"
        )
    table_rows = "\n".join(rows) if rows else '<tr><td colspan="6">No findings.</td></tr>'
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
<th>Severity</th><th>Score</th><th>Rule</th><th>Description</th><th>Evidence</th><th>Sources</th>
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
    read-only third-party parsing libraries, so Corrobora cannot
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
# Logging bridge: root logger -> GUI text widget (thread-safe via Qt signals)
# --------------------------------------------------------------------------


class QtLogHandler(QObject, logging.Handler):
    """A logging handler that emits formatted records as a Qt signal.

    Log records can originate on a background worker thread, but Qt
    widgets may only be safely updated from the GUI thread. Qt's
    signal/slot mechanism auto-queues delivery when the emitting
    thread differs from the receiving (slot-owning) object's thread,
    so this handler needs no manual queue or polling loop -- it just
    emits, and Qt handles getting the call onto the GUI thread safely.

    Note:
        ``QObject`` must be the first base class: PyQt5's ``sip``
        metaclass requires it for this style of multiple inheritance.
    """

    log_emitted = pyqtSignal(str)

    def __init__(self) -> None:
        """Initialize the handler."""
        QObject.__init__(self)
        logging.Handler.__init__(self)
        self.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        """Format a log record and emit it.

        Args:
            record: The log record to handle.
        """
        try:
            self.log_emitted.emit(self.format(record))
        except Exception:  # noqa: BLE001 pylint: disable=broad-exception-caught
            # Deliberately broad: logging.Handler.emit must never raise,
            # per the standard library's own handler contract.
            self.handleError(record)


# --------------------------------------------------------------------------
# Background analysis worker
# --------------------------------------------------------------------------


class AnalysisWorker(QObject):  # pylint: disable=too-few-public-methods
    """Runs :func:`run_analysis` on a background ``QThread``.

    Note:
        ``too-few-public-methods`` is intentionally suppressed: this
        is a minimal QThread worker with a single ``run`` entry
        point, the standard PyQt5 pattern for offloading work off
        the GUI thread.

    Attributes:
        finished: Emitted with the resulting :class:`AnalysisOutcome`
            once the run completes.
    """

    finished = pyqtSignal(object)

    def __init__(
        self,
        evtx_paths: list[str | Path],
        registry_paths: list[str | Path],
        prefetch_paths: list[str | Path],
        mft_paths: list[str | Path],
        rules: list[CorrelationRule] | None,
    ) -> None:
        """Initialize the worker with the arguments to pass to :func:`run_analysis`."""
        super().__init__()
        self._args = (evtx_paths, registry_paths, prefetch_paths, mft_paths, rules)

    def run(self) -> None:
        """Run the analysis and emit :attr:`finished` with the outcome."""
        self.finished.emit(run_analysis(*self._args))


class _SortableItem(QTableWidgetItem):  # pylint: disable=too-few-public-methods
    """A table item that sorts by a stored numeric key, not its displayed text.

    ``QTableWidgetItem``'s default sort compares displayed text, which
    would sort severities alphabetically ("HIGH" before "LOW") and
    scores lexicographically ("9" after "10") instead of by their real
    ordering.

    Note:
        ``too-few-public-methods`` is intentionally suppressed: this
        class only needs to override ``__lt__`` (a dunder method, not
        counted as "public" by this check) to change sort behavior --
        it isn't missing an API, it has exactly the one it needs.
    """

    def __init__(self, text: str, sort_key: float) -> None:
        """Initialize the item.

        Args:
            text: The text to display.
            sort_key: The numeric value to sort by instead of ``text``.
        """
        super().__init__(text)
        self._sort_key = sort_key

    def __lt__(self, other: object) -> bool:
        if isinstance(other, _SortableItem):
            return self._sort_key < other._sort_key
        return super().__lt__(other)


# Corroboration-score fill colors, bucketed by strength. Deliberately the
# same palette as _SEVERITY_COLORS for visual consistency, but keyed by
# score magnitude rather than the Severity enum -- score and severity are
# independent axes (see CorrelationFinding.score's docstring), so a
# HIGH-severity finding can still have a low score and vice versa.
_SCORE_BAR_COLORS: tuple[tuple[int, str], ...] = (
    (75, "#c0392b"),
    (50, "#d68910"),
    (25, "#2471a3"),
    (0, "#566573"),
)


def _score_bar_color(score: int) -> QColor:
    """Return the fill color for a given corroboration score.

    Args:
        score: A 0-100 corroboration score.

    Returns:
        The color for the highest threshold ``score`` meets or exceeds.
    """
    for threshold, color in _SCORE_BAR_COLORS:
        if score >= threshold:
            return QColor(color)
    return QColor(_SCORE_BAR_COLORS[-1][1])


class _ScoreBarDelegate(QStyledItemDelegate):
    """Paints a table cell as a filled bar followed by a percentage label.

    Renders each finding's corroboration score visually (e.g. a mostly
    filled bar for a strong score) rather than as a bare number, while
    leaving the underlying :class:`_SortableItem` untouched -- sorting
    still works exactly as before, since this only changes how the
    existing item is painted, not what data or sort key it holds.
    """

    _BAR_HEIGHT = 14
    _EMPTY_COLOR = QColor("#e5e8ec")

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index: QModelIndex) -> None:
        """Paint the score bar and label for one cell.

        Args:
            painter: The active painter.
            option: Style options for this cell (position, size, etc.).
            index: The model index being painted.
        """
        try:
            score = int(index.data())
        except (TypeError, ValueError):
            super().paint(painter, option, index)
            return

        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)

        label = f"{score}%"
        label_width = painter.fontMetrics().horizontalAdvance(label)
        cell = option.rect
        bar_width = max(cell.width() - label_width - 16, 10)
        bar_rect = QRect(
            cell.left() + 4,
            cell.top() + (cell.height() - self._BAR_HEIGHT) // 2,
            bar_width,
            self._BAR_HEIGHT,
        )

        painter.setPen(Qt.NoPen)
        painter.setBrush(self._EMPTY_COLOR)
        painter.drawRoundedRect(bar_rect, 3, 3)

        fill_width = int(bar_rect.width() * min(max(score, 0), 100) / 100)
        if fill_width > 0:
            fill_rect = QRect(bar_rect.x(), bar_rect.y(), fill_width, bar_rect.height())
            painter.setBrush(_score_bar_color(score))
            painter.drawRoundedRect(fill_rect, 3, 3)

        painter.setPen(QColor("#1a1a1a"))
        label_rect = QRect(bar_rect.right() + 8, cell.top(), label_width + 4, cell.height())
        painter.drawText(label_rect, Qt.AlignVCenter | Qt.AlignLeft, label)

        painter.restore()


# --------------------------------------------------------------------------
# Styling
# --------------------------------------------------------------------------

_STYLESHEET = """
QMainWindow {
    background-color: #f5f6f8;
}
QGroupBox {
    font-weight: bold;
    border: 1px solid #c7cdd6;
    border-radius: 6px;
    margin-top: 10px;
    padding-top: 10px;
    background-color: #ffffff;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
    color: #2d2d2d;
}
QPushButton {
    padding: 6px 14px;
    border: 1px solid #b0b6bf;
    border-radius: 4px;
    background-color: #ffffff;
}
QPushButton:hover {
    background-color: #eef2f7;
}
QPushButton:disabled {
    color: #9aa0a6;
}
QPushButton#runButton {
    background-color: #2d6cdf;
    color: #ffffff;
    font-weight: bold;
    font-size: 11pt;
    padding: 10px 24px;
    border: none;
}
QPushButton#runButton:hover {
    background-color: #245bc0;
}
QPushButton#runButton:disabled {
    background-color: #9fb7e8;
    color: #eef2f7;
}
QTableWidget {
    border: 1px solid #c7cdd6;
    background-color: #ffffff;
    gridline-color: #e5e8ec;
}
QHeaderView::section {
    background-color: #2d2d2d;
    color: #ffffff;
    padding: 4px;
    border: none;
}
"""


# --------------------------------------------------------------------------
# Main application
# --------------------------------------------------------------------------


class CorroboraMainWindow(  # pylint: disable=too-many-instance-attributes,too-few-public-methods
    QMainWindow
):
    """The main Corrobora GUI window.

    Note:
        ``too-many-instance-attributes`` is intentionally suppressed:
        each attribute is a distinct widget or piece of state this
        window owns, which is inherent to a GUI class of this size,
        not incidental complexity. ``too-few-public-methods`` is also
        suppressed: this is a window class driven entirely by
        widget-bound callbacks (buttons, selection events), all
        intentionally private (leading underscore) since none are
        meant to be called from outside the class, not a library
        class meant to expose a broader public API.

    An analyst points this window at one evidence source (a folder or
    ``.zip``), picks which artifact categories and validation rule
    categories to run, and runs the analysis on a background
    ``QThread`` (see :meth:`_start_analysis`) so the UI never freezes.
    The thread communicates back to the GUI thread exclusively via Qt
    signals (see :class:`AnalysisWorker`, :class:`QtLogHandler`).
    """

    def __init__(self) -> None:
        """Initialize the window and build all widgets."""
        super().__init__()
        self.setWindowTitle(_WINDOW_TITLE)
        self.resize(*_WINDOW_SIZE)
        self._set_window_icon()

        self._discovered: DiscoveredArtifacts | None = None
        self._last_findings: list[CorrelationFinding] = []
        self._analysis_running = False
        self._category_checkboxes: dict[str, QCheckBox] = {}
        self._rule_category_checkboxes: dict[str, QCheckBox] = {}
        self._worker: AnalysisWorker | None = None
        self._thread: QThread | None = None
        self._log_handler: QtLogHandler | None = None

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(8, 0, 8, 8)
        layout.setSpacing(10)

        self._build_header(layout)
        self._build_evidence_section(layout)
        self._build_output_section(layout)
        self._build_artifact_categories_section(layout)
        self._build_validation_rules_section(layout)
        self._build_run_controls(layout)
        self._build_results_panel(layout)
        self._build_log_panel(layout)
        layout.addStretch(1)

        scroll_area.setWidget(content)
        self.setCentralWidget(scroll_area)

        self._attach_logging()
        self.setStyleSheet(_STYLESHEET)
        self.showMaximized()

    def _set_window_icon(self) -> None:
        """Set the window/taskbar icon from the embedded logo badge."""
        try:
            pixmap = QPixmap()
            pixmap.loadFromData(base64.b64decode(_LOGO_ICON_PNG_B64))
        except ValueError as exc:
            logger.warning("Could not set window icon: %s", exc)
            return
        if not pixmap.isNull():
            self.setWindowIcon(QIcon(pixmap))

    # -- widget construction -------------------------------------------------

    _HEADER_BANNER_HEIGHT = 64
    """Fixed display height for the header banner.

    The embedded artwork's native size is much taller than a header
    needs; left unscaled, it ate a large share of vertical space and
    pushed the checkboxes/results below the fold on common laptop and
    1080p-class screens, forcing more scrolling than the content
    otherwise requires.
    """

    def _build_header(self, layout: QVBoxLayout) -> None:
        """Build the branded header banner at the top of the window.

        Falls back to a plain text title (no crash) if the embedded
        logo image data can't be decoded for any reason -- branding
        is cosmetic and must never prevent the application from
        starting.

        Args:
            layout: The top-level content layout to add the header to.
        """
        header = QWidget()
        header.setStyleSheet("background-color: #000000;")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(0, 8, 0, 8)
        try:
            pixmap = QPixmap()
            pixmap.loadFromData(base64.b64decode(_LOGO_BANNER_PNG_B64))
            if pixmap.isNull():
                raise ValueError("banner image data decoded to an empty pixmap")
        except ValueError as exc:
            logger.warning("Could not load header banner image: %s", exc)
            fallback = QLabel("Corrobora")
            fallback.setStyleSheet("color: #4a90d9; font-size: 18pt; font-weight: bold;")
            header_layout.addWidget(fallback, alignment=Qt.AlignCenter)
        else:
            scaled = pixmap.scaledToHeight(
                self._HEADER_BANNER_HEIGHT, Qt.SmoothTransformation
            )
            banner_label = QLabel()
            banner_label.setPixmap(scaled)
            header_layout.addWidget(banner_label, alignment=Qt.AlignCenter)
        layout.addWidget(header)

    def _build_evidence_section(self, layout: QVBoxLayout) -> None:
        """Build the "Evidence Source" section: one folder/zip field + browse buttons."""
        group = QGroupBox("Evidence Source")
        group_layout = QHBoxLayout(group)
        self._evidence_path_edit = QLineEdit()
        self._evidence_path_edit.setReadOnly(True)
        self._evidence_path_edit.setPlaceholderText(
            "Select an evidence folder or a case .zip archive..."
        )
        group_layout.addWidget(self._evidence_path_edit, stretch=1)
        browse_folder_button = QPushButton("Browse Folder...")
        browse_folder_button.clicked.connect(self._browse_evidence_folder)
        group_layout.addWidget(browse_folder_button)
        browse_zip_button = QPushButton("...or a ZIP")
        browse_zip_button.clicked.connect(self._browse_evidence_zip)
        group_layout.addWidget(browse_zip_button)
        layout.addWidget(group)

    def _build_output_section(self, layout: QVBoxLayout) -> None:
        """Build the "Output Directory" section: where reports auto-save to."""
        group = QGroupBox("Output Directory")
        group_layout = QHBoxLayout(group)
        self._output_dir_edit = QLineEdit()
        self._output_dir_edit.setReadOnly(True)
        self._output_dir_edit.setPlaceholderText(
            "Optional -- select a folder to auto-save each report to..."
        )
        group_layout.addWidget(self._output_dir_edit, stretch=1)
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self._browse_output_dir)
        group_layout.addWidget(browse_button)
        layout.addWidget(group)

    def _build_artifact_categories_section(self, layout: QVBoxLayout) -> None:
        """Build the "Artifact Categories" checkbox list.

        Only the artifact types Corrobora actually parses today are
        listed (see :data:`_ARTIFACT_CATEGORIES`) -- no placeholders
        for types that don't exist yet.
        """
        group = QGroupBox("Artifact Categories")
        group_layout = QVBoxLayout(group)
        for field, label in _ARTIFACT_CATEGORIES:
            checkbox = QCheckBox(label)
            checkbox.setChecked(True)
            self._category_checkboxes[field] = checkbox
            group_layout.addWidget(checkbox)
        layout.addWidget(group)

    def _build_validation_rules_section(self, layout: QVBoxLayout) -> None:
        """Build the "Validation Rules" checkbox list.

        One checkbox per actual rule category in
        :data:`~corrobora.rules.rule_registry.RULE_REGISTRY` (today:
        Program Execution, Persistence, Integrity) -- not an
        illustrative list, so a new rule category appears here
        automatically without a code change.
        """
        group = QGroupBox("Validation Rules")
        group_layout = QVBoxLayout(group)
        categories = sorted({cls.category for cls in RULE_REGISTRY.values()})
        for category in categories:
            checkbox = QCheckBox(_rule_category_label(category))
            checkbox.setChecked(True)
            self._rule_category_checkboxes[category] = checkbox
            group_layout.addWidget(checkbox)
        layout.addWidget(group)

    def _build_run_controls(self, layout: QVBoxLayout) -> None:
        """Build the run/export/sample-data control bar and progress indicator."""
        control_bar = QWidget()
        control_layout = QHBoxLayout(control_bar)
        control_layout.setContentsMargins(0, 0, 0, 0)

        self._run_button = QPushButton("RUN CORROBORA")
        self._run_button.setObjectName("runButton")
        self._run_button.clicked.connect(self._start_analysis)
        control_layout.addWidget(self._run_button)

        self._export_button = QPushButton("Export a Copy...")
        self._export_button.clicked.connect(self._export_html)
        self._export_button.setEnabled(False)
        control_layout.addWidget(self._export_button)

        sample_button = QPushButton("Generate Sample $MFT Data...")
        sample_button.clicked.connect(self._generate_sample_mft)
        control_layout.addWidget(sample_button)

        self._status_label = QLabel("Ready.")
        control_layout.addWidget(self._status_label, stretch=1)

        self._progress = QProgressBar()
        self._progress.setRange(0, 1)
        self._progress.setValue(0)
        self._progress.setFixedWidth(150)
        control_layout.addWidget(self._progress)

        layout.addWidget(control_bar)

    def _build_results_panel(self, layout: QVBoxLayout) -> None:
        """Build the findings table and its detail pane."""
        group = QGroupBox("Findings")
        group_layout = QVBoxLayout(group)

        self._results_table = QTableWidget(0, 4)
        self._results_table.setHorizontalHeaderLabels(["Severity", "Score", "Rule", "Description"])
        self._results_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._results_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self._results_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._results_table.setSortingEnabled(True)
        self._results_table.horizontalHeader().setStretchLastSection(True)
        self._results_table.setColumnWidth(1, 140)
        # Kept as an instance attribute, not a local: PyQt5 doesn't keep its
        # own strong reference to a delegate, so without this it would be
        # garbage-collected and the column would silently fall back to
        # plain-text rendering.
        self._score_delegate = _ScoreBarDelegate(self._results_table)
        self._results_table.setItemDelegateForColumn(1, self._score_delegate)
        self._results_table.itemSelectionChanged.connect(self._on_finding_selected)
        group_layout.addWidget(self._results_table)

        layout.addWidget(group)

        detail_group = QGroupBox("Finding Detail")
        detail_layout = QVBoxLayout(detail_group)
        self._detail_text = QPlainTextEdit()
        self._detail_text.setReadOnly(True)
        self._detail_text.setFixedHeight(110)
        detail_layout.addWidget(self._detail_text)
        layout.addWidget(detail_group)

    def _build_log_panel(self, layout: QVBoxLayout) -> None:
        """Build the scrolling log output panel."""
        group = QGroupBox("Log")
        group_layout = QVBoxLayout(group)
        self._log_text = QPlainTextEdit()
        self._log_text.setReadOnly(True)
        self._log_text.setFixedHeight(150)
        group_layout.addWidget(self._log_text)
        layout.addWidget(group)

    def _attach_logging(self) -> None:
        """Attach a Qt-signal-backed logging handler to the root logger."""
        self._log_handler = QtLogHandler()
        self._log_handler.log_emitted.connect(self._append_log)
        logging.getLogger().addHandler(self._log_handler)
        logging.getLogger().setLevel(logging.INFO)

    # -- evidence source / case ingest ----------------------------------------

    def _browse_evidence_folder(self) -> None:
        """Prompt for an evidence folder and scan it."""
        folder = QFileDialog.getExistingDirectory(self, "Select case folder")
        if not folder:
            return
        self._evidence_path_edit.setText(folder)
        self._scan_evidence(folder)

    def _browse_evidence_zip(self) -> None:
        """Prompt for an evidence .zip archive and scan it."""
        zip_path, _selected_filter = QFileDialog.getOpenFileName(
            self, "Select case .zip archive", filter="Zip archives (*.zip)"
        )
        if not zip_path:
            return
        self._evidence_path_edit.setText(zip_path)
        self._scan_evidence(zip_path)

    def _scan_evidence(self, path: str) -> None:
        """Discover artifacts at a path and update the category checklist.

        Args:
            path: A case folder or ``.zip`` archive path, as chosen by
                the user.
        """
        self._status_label.setText("Scanning case...")
        QApplication.processEvents()
        try:
            artifacts = load_case(path)
        except InvalidCasePathError as exc:
            self._status_label.setText("Case scan failed.")
            QMessageBox.critical(self, "Case scan failed", str(exc))
            return

        self._discovered = artifacts
        self._update_category_labels()
        self._status_label.setText(f"Loaded case: {artifacts.total_count} artifact(s) found.")
        logger.info(
            "Case loaded: %d EVTX, %d registry, %d Prefetch, %d MFT "
            "(%d file(s) unclassified).",
            len(artifacts.evtx_paths),
            len(artifacts.registry_paths),
            len(artifacts.prefetch_paths),
            len(artifacts.mft_paths),
            artifacts.unclassified_count,
        )
        if artifacts.total_count == 0:
            QMessageBox.warning(
                self,
                "No artifacts found",
                f"No recognized EVTX, registry, Prefetch, or MFT files were found "
                f"in:\n{path}\n\n"
                f"({artifacts.unclassified_count} other file(s) were present but "
                f"not recognized.)",
            )

    def _update_category_labels(self) -> None:
        """Refresh each artifact-category checkbox's label with its discovered count."""
        for field, label in _ARTIFACT_CATEGORIES:
            count = len(getattr(self._discovered, field)) if self._discovered else 0
            self._category_checkboxes[field].setText(f"{label} — {count} found")

    def _browse_output_dir(self) -> None:
        """Prompt for an output directory for auto-saved reports."""
        folder = QFileDialog.getExistingDirectory(self, "Select output directory")
        if folder:
            self._output_dir_edit.setText(folder)

    # -- checkbox-driven filtering ---------------------------------------------

    def _filtered_artifact_paths(
        self,
    ) -> tuple[list[str], list[str], list[str], list[str]]:
        """Return discovered artifact paths, gated by the category checkboxes.

        Returns:
            A ``(evtx_paths, registry_paths, prefetch_paths,
            mft_paths)`` tuple, in the same order as
            :data:`_ARTIFACT_CATEGORIES`. Any category whose checkbox
            is unchecked -- or before any evidence source has been
            scanned -- contributes an empty list.
        """
        filtered: list[list[str]] = []
        for field, _label in _ARTIFACT_CATEGORIES:
            if self._discovered is not None and self._category_checkboxes[field].isChecked():
                filtered.append(list(getattr(self._discovered, field)))
            else:
                filtered.append([])
        return filtered[0], filtered[1], filtered[2], filtered[3]

    def _selected_rules(self) -> list[CorrelationRule]:
        """Return one instance of every rule whose category checkbox is checked.

        Returns:
            Freshly instantiated rules from
            :data:`~corrobora.rules.rule_registry.RULE_REGISTRY`.
        """
        return [
            rule_cls()
            for rule_cls in RULE_REGISTRY.values()
            if self._rule_category_checkboxes[rule_cls.category].isChecked()
        ]

    # -- analysis lifecycle ---------------------------------------------------

    def _start_analysis(self) -> None:
        """Validate inputs and start a background analysis run."""
        if self._analysis_running:
            return
        if self._discovered is None:
            QMessageBox.warning(
                self,
                "No evidence source",
                "Select an evidence source (folder or ZIP) before running analysis.",
            )
            return

        evtx_paths, registry_paths, prefetch_paths, mft_paths = self._filtered_artifact_paths()
        if not (evtx_paths or registry_paths or prefetch_paths or mft_paths):
            QMessageBox.warning(
                self,
                "No sources selected",
                "Enable at least one Artifact Category that has discovered files "
                "before running analysis.",
            )
            return

        self._analysis_running = True
        self._run_button.setEnabled(False)
        self._export_button.setEnabled(False)
        self._status_label.setText("Running analysis...")
        self._progress.setRange(0, 0)
        self._clear_results()

        self._thread = QThread(self)
        self._worker = AnalysisWorker(
            evtx_paths, registry_paths, prefetch_paths, mft_paths, self._selected_rules()
        )
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.finished.connect(self._handle_analysis_result)
        self._worker.finished.connect(self._thread.quit)
        self._worker.finished.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._thread.deleteLater)
        self._thread.start()

    def _handle_analysis_result(self, outcome: AnalysisOutcome) -> None:
        """Apply a completed analysis outcome to the UI.

        Args:
            outcome: The result from :func:`run_analysis`.
        """
        self._progress.setRange(0, 1)
        self._progress.setValue(0)
        self._run_button.setEnabled(True)
        self._analysis_running = False

        if outcome.error is not None:
            self._status_label.setText("Analysis failed.")
            QMessageBox.critical(self, "Analysis failed", outcome.error)
            return

        all_findings = list(outcome.findings)
        all_findings.sort(
            key=lambda f: (list(Severity).index(f.severity), f.score), reverse=True
        )
        self._last_findings = all_findings

        self._populate_results(all_findings)
        self._export_button.setEnabled(bool(all_findings))
        self._status_label.setText(f"Done. {len(all_findings)} finding(s).")
        self._auto_export(all_findings)

    def _auto_export(self, findings: list[CorrelationFinding]) -> None:
        """Auto-save a report to the configured output directory, if any and non-empty.

        Args:
            findings: The findings from the just-completed run.
        """
        if not findings:
            return
        output_dir = self._output_dir_edit.text().strip()
        if not output_dir:
            logger.info(
                "No output directory set; skipping auto-export. "
                "Use 'Export a Copy...' to save a report manually."
            )
            return
        target = Path(output_dir) / f"corrobora_report_{datetime.now(UTC):%Y%m%dT%H%M%SZ}.html"
        try:
            target.write_text(
                findings_to_html(findings, title="Corrobora Findings Report"), encoding="utf-8"
            )
        except OSError as exc:
            logger.error("Auto-export to %s failed: %s", target, exc)
            return
        logger.info("Report saved to %s", target)

    # -- results display --------------------------------------------------

    def _clear_results(self) -> None:
        """Clear the findings table and detail pane."""
        self._results_table.setRowCount(0)
        self._set_detail_text("")

    def _populate_results(self, findings: list[CorrelationFinding]) -> None:
        """Populate the findings table.

        Args:
            findings: The findings to display, in display order.
        """
        self._results_table.setSortingEnabled(False)
        self._results_table.setRowCount(len(findings))
        for index, finding in enumerate(findings):
            severity_item = _SortableItem(
                finding.severity.value.upper(), list(Severity).index(finding.severity)
            )
            severity_item.setForeground(QColor(_SEVERITY_COLORS[finding.severity]))
            severity_item.setData(Qt.UserRole, index)
            score_item = _SortableItem(str(finding.score), finding.score)
            self._results_table.setItem(index, 0, severity_item)
            self._results_table.setItem(index, 1, score_item)
            self._results_table.setItem(index, 2, QTableWidgetItem(finding.rule_name))
            self._results_table.setItem(index, 3, QTableWidgetItem(finding.description))
        self._results_table.setSortingEnabled(True)

    def _on_finding_selected(self) -> None:
        """Show full detail for the selected finding in the detail pane."""
        row = self._results_table.currentRow()
        if row < 0:
            return
        severity_item = self._results_table.item(row, 0)
        if severity_item is None:
            return
        finding = self._last_findings[severity_item.data(Qt.UserRole)]
        detail = (
            f"Rule: {finding.rule_name}\n"
            f"Severity: {finding.severity.value.upper()}\n"
            f"Score: {finding.score}/100\n\n"
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
        self._detail_text.setPlainText(text)

    # -- log panel ----------------------------------------------------------

    def _append_log(self, message: str) -> None:
        """Append a line to the log panel.

        Args:
            message: The formatted log line to append.
        """
        self._log_text.appendPlainText(message)

    # -- export / sample data -------------------------------------------------

    def _export_html(self) -> None:
        """Save a copy of the current findings to an HTML report file."""
        if not self._last_findings:
            return
        target, _selected_filter = QFileDialog.getSaveFileName(
            self, "Save findings report", "corrobora_report.html", "HTML files (*.html)"
        )
        if not target:
            return
        try:
            document = findings_to_html(self._last_findings, title="Corrobora Findings Report")
            Path(target).write_text(document, encoding="utf-8")
        except OSError as exc:
            QMessageBox.critical(self, "Export failed", str(exc))
            return
        QMessageBox.information(self, "Export complete", f"Report saved to:\n{target}")

    def _generate_sample_mft(self) -> None:
        """Generate a synthetic sample $MFT file and offer to re-scan the evidence source."""
        initial_dir = self._evidence_path_edit.text()
        initial_path = str(Path(initial_dir) / "sample_MFT") if initial_dir else "sample_MFT"
        target, _selected_filter = QFileDialog.getSaveFileName(
            self, "Save sample $MFT file as", initial_path
        )
        if not target:
            return
        try:
            Path(target).write_bytes(generate_sample_mft_bytes())
        except OSError as exc:
            QMessageBox.critical(self, "Failed to write sample file", str(exc))
            return

        message = (
            "A synthetic $MFT file was created with one ordinary file, one "
            "directory, and one deliberately timestomped file."
        )
        if self._evidence_path_edit.text():
            reply = QMessageBox.question(
                self,
                "Sample data generated",
                message + "\n\nRe-scan the evidence source to include it now?",
                QMessageBox.Yes | QMessageBox.No,
            )
            if reply == QMessageBox.Yes:
                self._scan_evidence(self._evidence_path_edit.text())
        else:
            QMessageBox.information(self, "Sample data generated", message)


def _configure_logging() -> None:
    """Configure baseline logging before the GUI attaches its own handler."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def main() -> None:
    """Launch the Corrobora GUI application."""
    _configure_logging()
    app = QApplication(sys.argv)
    window = CorroboraMainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()

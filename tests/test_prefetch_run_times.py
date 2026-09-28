"""Tests for reading Prefetch last-run-time slots.

A stand-in for ``pyscca.file`` returns exactly what libscca does: real run
times first, then 1601-01-01 (a zero FILETIME) for each unused slot.
"""

# pylint: disable=missing-function-docstring,too-few-public-methods,protected-access

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from corrobora.parsers.prefetch import PrefetchExtractor

_EMPTY_SLOT = datetime(1601, 1, 1)  # naive, as libscca returns it
_RUN = datetime(2026, 9, 27, 9, 12, 5)


class _FakeSccaFile:
    """Returns the given slot values from get_last_run_time(index)."""

    def __init__(self, slots):
        self._slots = slots

    def get_last_run_time(self, index):
        return self._slots[index]


def _read(slots):
    return PrefetchExtractor()._extract_last_run_times(_FakeSccaFile(slots))


def test_unused_slots_are_not_run_times():
    # Regression test: a program run fewer than 8 times used to get
    # 1601-01-01 "runs" for its empty slots.
    runs = [_RUN - timedelta(hours=hour) for hour in range(4)]
    times = _read(runs + [_EMPTY_SLOT] * 4)
    assert times == [run.replace(tzinfo=UTC) for run in runs]


def test_all_slots_empty():
    assert not _read([_EMPTY_SLOT] * 8)


def test_all_eight_slots_used():
    runs = [_RUN - timedelta(days=day) for day in range(8)]
    assert len(_read(runs)) == 8


def test_none_still_ends_the_list():
    assert _read([_RUN, None, _RUN]) == [_RUN.replace(tzinfo=UTC)]

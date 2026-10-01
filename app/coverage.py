"""评估区间覆盖（断档）计算。

所有区间均为半开区间 [start, end)：前一区间的 end 与后一区间的 start
相接（相等）时视为连续，不构成断档。
"""
from __future__ import annotations

from datetime import datetime


def compute_gaps(
    eval_start: datetime,
    eval_end: datetime,
    intervals: list[tuple[datetime, datetime]],
) -> list[tuple[datetime, datetime]]:
    """返回 [eval_start, eval_end) 内未被 intervals 覆盖的全部断档区间。"""
    gaps: list[tuple[datetime, datetime]] = []
    cursor = eval_start
    for start, end in sorted(intervals):
        start = max(start, eval_start)
        end = min(end, eval_end)
        if end <= cursor:
            continue
        if start > cursor:
            gaps.append((cursor, start))
        cursor = max(cursor, end)
        if cursor >= eval_end:
            break
    if cursor < eval_end:
        gaps.append((cursor, eval_end))
    return gaps


def intersect(
    a: list[tuple[datetime, datetime]],
    b: list[tuple[datetime, datetime]],
) -> list[tuple[datetime, datetime]]:
    """两个半开区间列表的逐对交集（端点相接产生空区间，自动丢弃）。"""
    out: list[tuple[datetime, datetime]] = []
    i = j = 0
    a, b = sorted(a), sorted(b)
    while i < len(a) and j < len(b):
        s, e = max(a[i][0], b[j][0]), min(a[i][1], b[j][1])
        if s < e:
            out.append((s, e))
        if a[i][1] <= b[j][1]:
            i += 1
        else:
            j += 1
    return out

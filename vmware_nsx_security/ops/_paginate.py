"""Shared name-filter + limit/offset helpers for list ops.

Enforces the family "default limit=50, support filter" rule so list ops
don't flood agent context on large estates. The connection layer's
``get_all`` safety cap stays intact; this trims the result before it is
returned to the caller.
"""

from __future__ import annotations

import fnmatch

DEFAULT_LIMIT = 50


def filter_by_name(items: list[dict], name_filter: str | None) -> list[dict]:
    """Narrow ``items`` to those whose ``display_name`` matches ``name_filter``.

    Matching is case-insensitive and supports both substring and glob
    (``*``/``?``) patterns. A None/empty filter returns ``items`` unchanged.
    """
    if not name_filter:
        return items
    needle = name_filter.lower()
    matched: list[dict] = []
    for item in items:
        name = str(item.get("display_name", "")).lower()
        if needle in name or fnmatch.fnmatch(name, needle):
            matched.append(item)
    return matched


def paginate(items: list[dict], limit: int, offset: int) -> list[dict]:
    """Return the ``limit``-sized window of ``items`` starting at ``offset``.

    Negative offsets are clamped to 0; a non-positive limit yields an empty
    list.
    """
    start = max(offset, 0)
    if limit <= 0:
        return []
    return items[start : start + limit]

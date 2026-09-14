#!/usr/bin/env python3
"""Fail-closed ordering checks for direct-profile business ingress."""

from __future__ import annotations

import sys


def check_direct_business_order(
    direct_promoted_ms: int | None,
    relay_confirmed_ms: int | None,
    direct_business_ms: int | None,
) -> tuple[bool, bool, bool]:
    """Return timestamp validity, Direct-promotion order, and Relay order."""
    timestamps = (direct_promoted_ms, relay_confirmed_ms, direct_business_ms)
    if any(type(value) is not int or value < 0 for value in timestamps):
        return False, False, False

    return (
        True,
        direct_promoted_ms <= direct_business_ms,
        relay_confirmed_ms <= direct_business_ms,
    )


def _parse_timestamp(value: str) -> int | None:
    try:
        timestamp = int(value, 10)
    except (TypeError, ValueError):
        return None
    return timestamp if timestamp >= 0 else None


def main(argv: list[str] | None = None) -> int:
    values = sys.argv[1:] if argv is None else argv
    if len(values) != 3:
        checks = (False, False, False)
    else:
        checks = check_direct_business_order(*(_parse_timestamp(value) for value in values))
    print(" ".join("1" if check else "0" for check in checks))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

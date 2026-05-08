"""
APO License Checker — Free Edition
Free version: all features unlocked, no license required.
"""
from __future__ import annotations


def activate(key: str) -> dict:
    return {"product": "APO-FREE", "tier": "free"}


def is_licensed() -> bool:
    return True


def get_license_info() -> dict | None:
    return {"product": "APO-FREE", "tier": "free"}

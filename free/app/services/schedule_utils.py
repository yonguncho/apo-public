import re
from datetime import date


def is_expired_schedule(schedule_val: str, today: date) -> bool:
    if not schedule_val or str(schedule_val).lower() == "always":
        return False
    s = str(schedule_val).strip()
    if re.match(r'^\d{6}$', s):
        try:
            yy, mm, dd = int(s[:2]), int(s[2:4]), int(s[4:6])
            return date(2000 + yy, mm, dd) < today
        except Exception:
            return False
    return False


def is_always_schedule(schedule_val: str) -> bool:
    if not schedule_val:
        return True
    return str(schedule_val).lower().strip() == "always"


def get_schedule_date(schedule_val: str):
    """YYMMDD -> date, 그 외 -> None"""
    if not schedule_val:
        return None
    s = str(schedule_val).strip()
    if re.match(r'^\d{6}$', s):
        try:
            yy, mm, dd = int(s[:2]), int(s[2:4]), int(s[4:6])
            return date(2000 + yy, mm, dd)
        except Exception:
            pass
    return None

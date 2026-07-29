from __future__ import annotations

import csv
import io
import math
import re
from typing import Any

# csv 모듈 기본 필드 상한(131072)을 넘으면 _csv.Error로 죽는다. FortiGate GUI가
# 아주 긴 주소/서비스 목록을 한 셀에 넣는 경우가 있어 상한을 넉넉히 올린다.
# sys.maxsize를 그대로 쓰면 방어가 사라지므로 유한한 값으로 둔다.
_CSV_FIELD_LIMIT = 8 * 1024 * 1024
try:
    if csv.field_size_limit() < _CSV_FIELD_LIMIT:
        csv.field_size_limit(_CSV_FIELD_LIMIT)
except (OverflowError, ValueError):
    pass


class PolicyStatsCsvParser:
    COLUMN_ALIASES = {
        "policy_id": {"id", "policy id", "policyid", "#", "no", "no.", "seq", "seq#",
                      "sequence", "policy_id", "rule id", "rule_id"},
        "hit_count": {"hit count", "hitcount", "hits", "hit", "count",
                      "packets", "pkts", "traffic count"},
        "last_used": {"last used", "lastused", "last hit", "lasthit",
                      "last access", "last_used", "last_hit"},
        "status":    {"status", "enabled", "state"},
        "name":      {"policy", "name", "policy name", "rule name", "rulename"},
    }

    def parse_text(self, text: str) -> dict[str, dict[str, Any]]:
        if not text.strip():
            return {}

        text = text.lstrip("\ufeff")
        delimiter = self._sniff_delimiter(text)
        # newline="" \uc744 \uc8fc\uc9c0 \uc54a\uc73c\uba74 StringIO\uac00 \uac1c\ud589\uc744 \ubcc0\ud658\ud574, \uad6c\ud615 Mac \uc2a4\ud0c0\uc77c\uc758
        # \ub2e8\ub3c5 \r \uac1c\ud589 CSV\uc5d0\uc11c csv \ubaa8\ub4c8\uc774 "new-line character seen in unquoted
        # field" \ub85c \uc8fd\ub294\ub2e4. \uc2e4\uc81c GUI \ub0b4\ubcf4\ub0b4\uae30\uc5d0\uc11c \ub098\uc62c \uc218 \uc788\ub294 \ud615\ud0dc\ub2e4.
        reader = csv.DictReader(io.StringIO(text, newline=""), delimiter=delimiter)
        try:
            fieldnames = reader.fieldnames
        except csv.Error:
            return {}
        if not fieldnames:
            return {}

        header_map = self._build_header_map(fieldnames)
        result: dict[str, dict[str, Any]] = {}

        # 기형 행 하나 때문에 전체 임포트가 실패하지 않도록, 반복 자체를 감싼다.
        row_iter = iter(reader)
        while True:
            try:
                row = next(row_iter)
            except StopIteration:
                break
            except csv.Error:
                continue

            policy_id = self._extract_policy_id(row, header_map)
            if not policy_id:
                continue

            stats: dict[str, Any] = {}
            stats["hit_count"] = self._extract_hit_count(row, header_map)
            stats["last_used"] = self._extract_last_used(row, header_map)
            stats["status"] = self._extract_status(row, header_map)
            name = self._extract_name(row, header_map)
            if name:
                stats["csv_name"] = name

            result[str(policy_id)] = stats

        return result

    def _build_header_map(self, fieldnames: list[str]) -> dict[str, str]:
        lowered = {self._norm(name): name for name in fieldnames}
        header_map: dict[str, str] = {}
        for key, aliases in self.COLUMN_ALIASES.items():
            for alias in aliases:
                actual = lowered.get(self._norm(alias))
                if actual:
                    header_map[key] = actual
                    break
        return header_map

    def _extract_policy_id(self, row: dict[str, Any], header_map: dict[str, str]) -> str | None:
        header = header_map.get("policy_id")
        if header and row.get(header) not in (None, ""):
            return str(row[header]).strip()

        name_header = header_map.get("name")
        if name_header:
            name_value = str(row.get(name_header, "")).strip()
            match = re.search(r"\((\d+)\)\s*$", name_value)
            if match:
                return match.group(1)
        return None

    def _extract_hit_count(self, row: dict[str, Any], header_map: dict[str, str]) -> int:
        header = header_map.get("hit_count")
        raw = str(row.get(header, "")).strip() if header else ""
        if not raw:
            return 0
        raw = raw.replace(",", "")
        try:
            value = float(raw)
        except (ValueError, OverflowError):
            return 0
        # float("1e400") -> inf, int(inf) -> OverflowError. nan도 마찬가지.
        if not math.isfinite(value):
            return 0
        try:
            return int(value)
        except (ValueError, OverflowError):
            return 0

    def _extract_last_used(self, row: dict[str, Any], header_map: dict[str, str]) -> str:
        header = header_map.get("last_used")
        raw = str(row.get(header, "")).strip() if header else ""
        if not raw or raw.lower() == "nan":
            return "-"
        return raw

    def _extract_status(self, row: dict[str, Any], header_map: dict[str, str]) -> str:
        header = header_map.get("status")
        raw = str(row.get(header, "")).strip() if header else ""
        if not raw or raw.lower() == "nan":
            return ""
        value = raw.lower()
        if value in {"enabled", "enable"}:
            return "Enabled"
        if value in {"disabled", "disable"}:
            return "Disabled"
        return raw

    def _extract_name(self, row: dict[str, Any], header_map: dict[str, str]) -> str:
        header = header_map.get("name")
        if not header:
            return ""
        return str(row.get(header, "")).strip()

    @staticmethod
    def _sniff_delimiter(text: str) -> str:
        """헤더 줄 기준으로 구분자를 추정. 콤마 고정 시 세미콜론/탭 CSV가 전멸하므로 방어."""
        first_line = ""
        for line in text.splitlines():
            if line.strip():
                first_line = line
                break
        best, best_count = ",", first_line.count(",")
        for cand in (";", "\t", "|"):
            c = first_line.count(cand)
            if c > best_count:
                best, best_count = cand, c
        return best

    @staticmethod
    def _norm(value: str) -> str:
        return re.sub(r"\s+", " ", str(value).strip().lower())

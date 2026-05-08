from __future__ import annotations

import csv
import io
import re
from typing import Any


class PolicyStatsCsvParser:
    COLUMN_ALIASES = {
        "policy_id": {"id", "policy id", "policyid"},
        "hit_count": {"hit count", "hitcount"},
        "last_used": {"last used", "lastused"},
        "status": {"status"},
        "name": {"policy", "name", "policy name"},
    }

    def parse_text(self, text: str) -> dict[str, dict[str, Any]]:
        if not text.strip():
            return {}

        text = text.lstrip("\ufeff")
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            return {}

        header_map = self._build_header_map(reader.fieldnames)
        result: dict[str, dict[str, Any]] = {}

        for row in reader:
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
            return int(float(raw))
        except ValueError:
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
    def _norm(value: str) -> str:
        return re.sub(r"\s+", " ", str(value).strip().lower())

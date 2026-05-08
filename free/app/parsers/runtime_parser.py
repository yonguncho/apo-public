from __future__ import annotations

import re
from typing import Any


class RuntimeStatsParser:
    POLICY_ID_PATTERNS = [
        re.compile(r"^idx\s*:\s*(\d+)", re.IGNORECASE | re.MULTILINE),
        re.compile(r"policy\s+id\s*[:=]?\s*(\d+)", re.IGNORECASE),
        re.compile(r"\bpolicyid\b\s*[:=]?\s*(\d+)", re.IGNORECASE),
        re.compile(r"\bedit\s+(\d+)", re.IGNORECASE),
        re.compile(r"show\s+00100004\s+(\d+)", re.IGNORECASE),
    ]
    HIT_COUNT_PATTERNS = [
        re.compile(r"hit\s*count\s*[:=]\s*(\d+)", re.IGNORECASE),
        re.compile(r"\bhit_count\b\s*[:=]\s*(\d+)", re.IGNORECASE),
    ]
    LAST_USED_PATTERNS = [
        re.compile(r"last\s*hit\s*[:=]\s*([0-9:\- ]+)", re.IGNORECASE),
        re.compile(r"last\s*used\s*[:=]\s*([0-9:\- ]+)", re.IGNORECASE),
    ]

    def parse_text(self, text: str) -> dict[str, dict[str, Any]]:
        blocks = self._split_blocks(text)
        results: dict[str, dict[str, Any]] = {}

        for block in blocks:
            policy_id = self._extract_first(block, self.POLICY_ID_PATTERNS)
            hit_count = self._extract_first(block, self.HIT_COUNT_PATTERNS)
            last_used = self._extract_first(block, self.LAST_USED_PATTERNS)

            if not policy_id:
                continue

            results[str(policy_id)] = {
                "hit_count": int(hit_count) if hit_count and str(hit_count).isdigit() else 0,
                "last_used": last_used.strip() if isinstance(last_used, str) else None,
                "raw": block,
            }

        return results

    @staticmethod
    def _split_blocks(text: str) -> list[str]:
        lines = text.splitlines()
        blocks: list[list[str]] = []
        current: list[str] = []
        for line in lines:
            if re.match(r"^idx\s*:\s*\d+", line.strip(), re.IGNORECASE):
                if current:
                    blocks.append(current)
                current = [line]
            else:
                current.append(line)
        if current:
            blocks.append(current)
        cleaned = ["\n".join(b).strip() for b in blocks if "\n".join(b).strip()]
        if len(cleaned) <= 1:
            return [b.strip() for b in re.split(r"\n\s*\n+", text) if b.strip()]
        return cleaned

    @staticmethod
    def _extract_first(text: str, patterns: list[re.Pattern[str]]) -> str | None:
        for pattern in patterns:
            match = pattern.search(text)
            if match:
                return match.group(1).strip()
        return None

from __future__ import annotations

import re
from typing import Any


# 정수 문자열 상한. Python 3.11+는 4300자리를 넘는 int(str)에서 ValueError를
# 던진다. 정책 hit count가 이만큼 길 일은 없으므로 파싱 단계에서 잘라낸다.
_MAX_INT_DIGITS = 18


def _safe_int(value, default: int = 0) -> int:
    """자릿수/형식이 비정상이면 default. 예외를 밖으로 내보내지 않는다."""
    s = str(value).strip() if value is not None else ""
    if not s.isdigit() or len(s) > _MAX_INT_DIGITS:
        return default
    try:
        return int(s)
    except ValueError:
        return default


class RuntimeStatsParser:
    # 주의: `\s*[:=]?\s*` 처럼 선택적 구분자를 두 개의 \s* 사이에 두면,
    # 구분자가 빈 문자열로 매칭될 때 두 \s* 가 공백 런을 나누는 경우의 수가
    # O(n^2)로 늘어나 매칭 실패 시 폭발한다(19KB 입력에 19초 측정).
    # 구분자가 있는 경우와 공백만 있는 경우를 배타적으로 분리해 모호성을 없앤다.
    POLICY_ID_PATTERNS = [
        re.compile(r"^idx\s*:\s*(\d+)", re.IGNORECASE | re.MULTILINE),
        re.compile(r"policy\s+id(?:\s*[:=]\s*|\s+)(\d+)", re.IGNORECASE),
        re.compile(r"\bpolicyid\b(?:\s*[:=]\s*|\s+)(\d+)", re.IGNORECASE),
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
                "hit_count": _safe_int(hit_count),
                "last_used": last_used.strip() if isinstance(last_used, str) else None,
                "raw": block,
            }

        return results

    @staticmethod
    def _split_blocks(text: str) -> list[str]:
        lines = text.splitlines()
        blocks: list[list[str]] = []
        current: list[str] = []
        found_idx = False
        for line in lines:
            if re.match(r"^idx\s*:\s*\d+", line.strip(), re.IGNORECASE):
                found_idx = True
                if current:
                    blocks.append(current)
                current = [line]
            else:
                current.append(line)
        if current:
            blocks.append(current)
        cleaned = ["\n".join(b).strip() for b in blocks if "\n".join(b).strip()]
        # idx: 블록을 하나라도 찾았으면(단 1개여도) 그대로 사용.
        # idx: 라인이 전혀 없을 때만 빈 줄 기준 폴백 분할을 쓴다.
        if not found_idx:
            return [b.strip() for b in re.split(r"\n\s*\n+", text) if b.strip()]
        return cleaned

    @staticmethod
    def _extract_first(text: str, patterns: list[re.Pattern[str]]) -> str | None:
        for pattern in patterns:
            match = pattern.search(text)
            if match:
                return match.group(1).strip()
        return None

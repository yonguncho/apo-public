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

# 정책 번호로 인정하는 표기: '5', '05', '5.0', '5.000'. ASCII 숫자만 본다.
_DECIMAL_ID = re.compile(r"^([0-9]+)(?:\.0*)?$")
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

    @staticmethod
    def _canonical_id(raw: str) -> str:
        """숫자로 읽히는 정책 번호를 한 가지 표기로 모은다.

        같은 장비의 CSV인데도 앞자리 0('01')이나 엑셀·pandas가 붙인 소수점
        ('1.0') 때문에 config의 정책 1번과 매칭되지 않아, 사용량이 조용히
        버려지고 미사용 판정으로 이어졌다. 숫자가 아닌 ID는 손대지 않는다.
        """
        text = raw.strip()
        if not text:
            return text
        # float()로 판단하면 '1e3'·'1_0'·전각/아랍숫자·NBSP까지 흡수해 서로
        # 다른 두 ID가 한 키로 합쳐지고 나중 행이 앞 행을 조용히 덮는다.
        # 받아들일 표기를 명시한다: 10진 정수, 그리고 소수부가 0뿐인 것.
        m = _DECIMAL_ID.match(text)
        if not m:
            return text
        return str(int(m.group(1)))

    def _extract_policy_id(self, row: dict[str, Any], header_map: dict[str, str]) -> str | None:
        header = header_map.get("policy_id")
        if header and row.get(header) not in (None, ""):
            return self._canonical_id(str(row[header]))

        name_header = header_map.get("name")
        if name_header:
            name_value = str(row.get(name_header, "")).strip()
            match = re.search(r"\((\d+)\)\s*$", name_value)
            if match:
                # 형제 분기도 **같은 정규화**를 지나야 한다. 여기만 빠져 있어,
                # 이름에서 뽑은 '05'가 config의 5번과 매칭되지 않고 그 정책의
                # 사용량이 조용히 버려졌다(판정 사유가 '사용량 없음'으로 바뀜).
                return self._canonical_id(match.group(1))
        return None

    def _extract_hit_count(self, row: dict[str, Any], header_map: dict[str, str]) -> int | None:
        # 빈 셀·쓰레기를 0으로 돌려주면 "데이터 없음"이 "미사용 확정(Hit=0)"으로
        # 승격돼 Critical 오판으로 이어진다(감사 A5 잔여, 재비판 SUSPECT).
        header = header_map.get("hit_count")
        raw = str(row.get(header, "")).strip() if header else ""
        if not raw or raw in ("-", "N/A", "n/a"):
            return None
        raw = raw.replace(",", "")
        try:
            value = float(raw)
        except (ValueError, OverflowError):
            return None
        # float("1e400") -> inf, int(inf) -> OverflowError. nan도 마찬가지.
        if not math.isfinite(value):
            return None
        try:
            return int(value)
        except (ValueError, OverflowError):
            return None

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

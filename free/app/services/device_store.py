# -*- coding: utf-8 -*-
"""장비·고객사 보관소 — 로컬 SQLite 파일 하나.

왜 로컬 파일인가: 이 제품의 약속은 "모든 분석은 이 컴퓨터 안에서만 돌고
아무것도 밖으로 나가지 않는다"이다. 외부 DB를 붙이면 그 약속이 깨진다.
설치도 필요 없어야 하므로(단일 exe) SQLite가 유일하게 맞는 선택이다.

저장 위치는 라이선스·브랜딩과 같은 규칙을 쓴다. frozen exe에서 _MEIPASS는
실행마다 새로 풀렸다가 종료 시 지워지므로 그 아래에 두면 등록한 장비가
매번 사라진다(브랜딩에서 실제로 겪은 실패다).

교차 오염 방지가 이 모듈의 존재 이유다. 장비는 **config SHA**로 갈리고,
한 장비의 통계·대역·FQDN은 그 장비 행에만 쓰인다. 고객사 배정은 별도
컬럼이며, 배정이 판정에 영향을 주지 않는다(보고서를 묶는 용도일 뿐).
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS customers (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
    device_id       TEXT PRIMARY KEY,
    name            TEXT,
    config_filename TEXT,
    config_text     TEXT,
    config_sha256   TEXT,
    runtime_stats   TEXT,
    user_ranges     TEXT,
    fqdn_cache      TEXT,
    customer_id     TEXT,
    registered_at   TEXT,
    updated_at      TEXT
);
-- **APO 가 발급한 검증 표본을 기억한다.**
-- 표본은 사용자가 엑셀로 고치는 표라, 그 안의 어떤 값도 신원의 근거가 될 수
-- 없었다. 장비 이름(표지)은 한 줄 지우면 사라지고, 정책 이름·번호는 다른
-- 고객 장비에도 똑같이 있다(MSP 템플릿·이름 없는 정책). 일곱 라운드 동안
-- 그 값들로 판정하려다 매번 다른 편집으로 열렸다.
-- 그래서 **APO 가 스스로 발급한 값**을 행마다 넣고, 발급 사실은 여기 둔다.
-- 파일 안의 토큰은 이 표를 가리키는 열쇠일 뿐이고, 그 토큰이 어느 장비의
-- 것이었는지는 사용자가 고칠 수 없는 곳에 적혀 있다.
CREATE TABLE IF NOT EXISTS verification_samples (
    token       TEXT PRIMARY KEY,
    device_id   TEXT NOT NULL,
    device_name TEXT,
    label       TEXT,
    -- **어떤 행을 발급했는지도 적는다.** 토큰만 대조하면, 그 토큰이 붙은 행을
    -- 복사해 정책 번호 칸만 바꾸는 것으로 분모를 얼마든지 부풀릴 수 있다
    -- (1개 정책 대조가 '100건 대조 정확도 100%' 로 인쇄됐다 — 라운드 40 실측).
    -- 발급한 (VDOM, 종류, 번호) 목록을 여기 두면, 파일 쪽 값이 무엇이든
    -- 우리가 낸 행만 세어진다.
    rows_json   TEXT,
    issued_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_devices_customer ON devices(customer_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_customers_name ON customers(name COLLATE NOCASE);
"""


def store_path() -> Path:
    if os.environ.get("APO_STORE_DIR"):
        base = Path(os.environ["APO_STORE_DIR"])
    elif getattr(sys, "frozen", False):
        base = Path(sys.executable).parent
    else:
        base = Path(__file__).resolve().parents[2]
    base.mkdir(parents=True, exist_ok=True)
    p = base / "apo_devices.db"
    # **여기는 뜨거운 경로다.** `_conn()` 이 DB 작업마다 store_path() 를 부르고,
    # 화면 요청 한 번에 get_device 가 여러 번 불린다. 처음엔 여기서 무조건
    # 권한을 좁혔더니 Windows 에서 요청마다 icacls 프로세스가 떴다 — 상시
    # 지연이고, icacls 가 늦으면 그 시간만큼 통째로 멈춘다(게이트 correctness
    # 검출: 이전엔 mkdir 뿐이던 자리에 생긴 회귀). 경로당 한 번만 한다.
    # **한 번 성공할 때까지는 다시 시도한다.** 성공 여부와 무관하게 '했음'으로
    # 표시했더니, 첫 시도가 icacls 타임아웃으로 실패하면 그 세션 내내 미적용
    # 상태로 남았다(fail-open, 게이트 security 지적). 그렇다고 매번 재시도하면
    # 위의 성능 회귀가 돌아오므로 몇 번만 해 보고 접는다 — 실패는 매번
    # 콘솔에 남으므로 조용히 넘어가지는 않는다.
    key = str(p)
    if not _perm_ok.get(key) and _perm_tries.get(key, 0) < _PERM_MAX_TRIES:
        _perm_tries[key] = _perm_tries.get(key, 0) + 1
        if _restrict_permissions(p):
            _perm_ok[key] = True
    return p


# 경로별 상태. 경로별로 두는 이유는 한 프로세스가 여러 보관소를 열 수 있기
# 때문이다(APO_STORE_DIR 전환·테스트).
_perm_ok: dict[str, bool] = {}
_perm_tries: dict[str, int] = {}
_PERM_MAX_TRIES = 3


def _restrict_permissions(path: Path) -> bool:
    """보관소를 **이 사용자만** 읽게 좁힌다 (B-80).

    이 파일에는 FortiGate config 원문이 그대로 들어 있다 — 토폴로지·주소
    객체, 실백업이면 IPSec PSK 까지. 지금까지는 `mkdir` 만 하고 권한을
    건드리지 않아, 다중 사용자 호스트(터미널 서버·공용 점검 PC)에서 OS
    umask 대로 다른 사용자가 그대로 읽을 수 있었다.

    **실패해도 앱을 멈추지 않는다.** 권한 설정은 방어 심화이고, 여기서
    예외를 올리면 읽기전용 위치·특이한 파일시스템에서 앱이 통째로 못 뜬다
    (라운드 39 에서 라이선스 파일이 같은 이유로 500 을 냈다). 다만 **조용히
    넘기지도 않는다** — 못 좁혔다는 사실은 콘솔에 남긴다.
    """
    try:
        if not path.exists():
            # 아직 없으면 빈 파일로 만들어 두고 좁힌다 — sqlite 가 만들게
            # 두면 그 순간의 umask 대로 열린 채 잠깐이라도 노출된다.
            path.touch(mode=0o600, exist_ok=True)
        # **디렉터리도 함께 좁힌다.** DB 파일만 막으면 sqlite 가 트랜잭션마다
        # 만드는 `apo_devices.db-journal`(WAL 이면 -wal/-shm)이 남는데, 그건
        # 새 파일이라 우리 ACL 이 아니라 **디렉터리 기본 ACL 을 상속**한다.
        # 그 안에 config 원문 페이지가 잠깐 들어앉으므로, 다중 사용자 호스트
        # 에서는 쓰기 창(window) 동안 옆 사용자가 읽을 수 있다 — DB 만 막는
        # 것은 목적을 부분적으로만 이룬다(게이트 security 지적).
        targets = [path.parent, path]
        if os.name == "nt":
            # Windows 는 POSIX 모드 비트를 무시한다. 소유자·SYSTEM 만 남기고
            # 상속을 끊는다 — icacls 가 없는 환경은 아래 except 로 떨어진다.
            import subprocess
            user = os.environ.get("USERNAME") or ""
            if not user:
                return False
            for t in targets:
                # 타임아웃을 짧게 — 이건 방어 심화지 필수 경로가 아니다.
                # 늦는 icacls 때문에 앱 시작이 멈추면 손해가 더 크다.
                # 디렉터리에는 상속(OI/CI)을 걸어 이후 저널 파일이 물려받게 한다.
                grant = (f"{user}:(OI)(CI)F" if t.is_dir() else f"{user}:F")
                system = ("SYSTEM:(OI)(CI)F" if t.is_dir() else "SYSTEM:F")
                subprocess.run(
                    ["icacls", str(t), "/inheritance:r",
                     "/grant:r", grant, "/grant:r", system],
                    capture_output=True, timeout=5, check=False)
        else:
            path.parent.chmod(0o700)   # 디렉터리는 실행 비트가 있어야 들어간다
            path.chmod(0o600)
        return True
    except Exception as exc:
        print(f"[APO] could not restrict permissions on the device store "
              f"({path}): {exc!r} - it holds configuration text, so check "
              f"who can read it on this host.", flush=True)
        return False


# 나중에 늘어난 컬럼. CREATE TABLE IF NOT EXISTS 는 **이미 있는 표를 바꾸지
# 않으므로**, 앞 버전에서 만든 파일에는 새 컬럼이 없다. 그 상태로 SELECT 하면
# 앱 전체가 죽는다 — 열 때마다 없는 컬럼만 채운다(값은 전부 NULL 허용).
_ADDED_COLUMNS = {
    # updated_at 은 분 단위 문자열이라 같은 분의 작업이 전부 동률이 된다.
    # '가장 최근에 손댄 장비'를 그걸로 고르면 정렬이 판별을 못 해 삽입 순서
    # (=가장 먼저 등록한 장비)가 나왔다 — 앱을 켜면 어제 마지막에 보던 장비가
    # 아니라 엉뚱한 고객 장비가 열렸다(라운드 20 실측). 단조 증가 순번을 둔다.
    # remediation_serial — 이 장비에 실제로 연결됐던 FortiGate 의 시리얼.
    # hostname 은 두 고객이 같은 이름을 쓰는 일이 정상이라(FGT-HQ, fw01) 신원
    # 증명이 못 된다 — 라운드 27~29에서 세 번 연속 그 구멍으로 남의 방화벽에
    # PUT 이 나갔다. 시리얼은 장비마다 고유하므로 여기 고정해 두고 다음
    # 연결부터 대조한다. **토큰은 여기 저장하지 않는다** — 그 규칙은 그대로다.
    # **객체 명명 관례는 고객마다 다르다.** 관리망을 ADMIN 이라 부르는 곳도,
    # MGMT·NOC·OPS 라 부르는 곳도 있다. 그동안 이 목록이 코드와 납품 프로파일
    # 파일에 박혀 있어서, 새 고객은 자기 환경을 APO 에 말할 방법이 없었다 —
    # 그 결과 아무 값도 일치하지 않거나(예외가 통째로 안 걸린다) 두 글자
    # 값('F1')이 단어 속에 우연히 걸렸다(실 설정에서 17건). 장비별 입력으로
    # 받는다 — 사용자 IP 대역과 같은 성격의 '환경 지식'이다.
    # tls_fingerprint — 검증을 끈 장비가 내밀던 인증서의 SHA-256 지문(B-79).
    # FortiGate 는 대부분 자체 서명이라 'Skip SSL Verify' 가 정상 경로인데,
    # 그 채널로 관리자 토큰이 나간다. 처음 본 지문을 고정해 두고 다음부터
    # 대조하면(SSH 의 TOFU) 인증서 교체 = MITM 시도를 잡을 수 있다.
    # 시리얼 pin 과 같은 성격이라 같은 자리에 둔다.
    "devices": {"csv_meta": "TEXT", "touch_seq": "INTEGER",
        # **인입에서 버려진 바이트 수.** 설정 텍스트와 함께 따라다녀야
        # 한다 — 보관된 장비를 다시 열면 이 사실이 사라져, 한글 주석이
        # 지워진 파일이 경고 없이 나갔다(라운드 4 실측).
        "decode_lost": "INTEGER",
                "remediation_serial": "TEXT", "tls_fingerprint": "TEXT",
                "object_rules": "TEXT",
                # 장비 수집의 사용량 커버리지(ns별 got/total) — 워크북
                # 문서정보로 나가는 사실이라 세션이 아니라 장비에 남는다
                # (라운드 70 R70-2).
                "collect_coverage": "TEXT"},
    # 대장 표 자체가 v106 에서 처음 생겼으므로 지켜 줄 구 발급분은 없다.
    # 그래도 개발 중 만들어진 DB 를 위해 칸은 추가해 둔다 — 값이 비면 그
    # 토큰은 **쓸 수 없는 것으로 다룬다**(채점부 참조). 비었을 때 통과시키는
    # 갈래를 두면 대장 한 칸을 비우는 것만으로 규칙이 꺼진다(라운드 41).
    "verification_samples": {"rows_json": "TEXT"},
}


def _migrate(con) -> None:
    for table, cols in _ADDED_COLUMNS.items():
        have = {r["name"] for r in con.execute(f"PRAGMA table_info({table})")}
        for name, decl in cols.items():
            if name not in have:
                # **동시 첫 접근의 레이스를 삼킨다.** _conn() 은 연결마다
                # _migrate 를 돌리는데, 신선/구형 DB 에 요청이 동시에 몰리면
                # (MSP 배치·신규 설치 첫 화면) 두 연결이 같은 컬럼 부재를
                # 보고 둘 다 ALTER 를 시도한다. 먼저 성공한 쪽이 커밋하면
                # 나중 쪽은 'duplicate column name' 으로 500 을 낸다 — 저장이
                # 실사용에서만 깨지는 부류(24 스레드 동시 접근으로 재현됨).
                # SQLite 에는 ADD COLUMN IF NOT EXISTS 가 없으므로, **이미
                # 있어서** 나는 예외만 성공으로 취급한다. 락·디스크 등 다른
                # OperationalError 는 그대로 올려 저장 실패를 숨기지 않는다.
                try:
                    con.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")
                except sqlite3.OperationalError as e:
                    if "duplicate column name" not in str(e).lower():
                        raise


@contextmanager
def _conn():
    con = sqlite3.connect(store_path())
    con.row_factory = sqlite3.Row
    # **지웠다고 말했으면 바이트도 지워야 한다.**
    # sqlite 는 기본적으로 삭제한 행의 내용을 파일에 남긴다(빈 페이지로 표시만
    # 한다). 이 보관소에는 config 원문이 통째로 들어 있다 — 토폴로지·주소 객체,
    # 실백업이면 IPSec PSK 까지. 그래서 장비 삭제 확인창이 "이 컴퓨터에서
    # 지워집니다" 라고 말한 **뒤에도 그 문자열이 .db 에서 그대로 읽혔다**
    # (2026-09-14 실측). 확인창이 거짓을 말하고 있었던 것이다.
    # `secure_delete` 는 해제되는 페이지를 0 으로 덮는다.
    con.execute("PRAGMA secure_delete = ON")
    try:
        con.executescript(_SCHEMA)
        _migrate(con)
        yield con
        con.commit()
    finally:
        con.close()


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def _next_seq(con) -> int:
    """장비를 만지는 순서. 시계가 아니라 순번이라 같은 분에도 뒤섞이지 않는다."""
    row = con.execute("SELECT COALESCE(MAX(touch_seq), 0) + 1 AS n FROM devices").fetchone()
    return int(row["n"])


def _loads(raw, default):
    try:
        return json.loads(raw) if raw else default
    except Exception:
        return default


# ── 장비 ────────────────────────────────────────────────────────────────
def upsert_device(device_id: str, *, name: str, config_filename: str,
                  config_text: str, config_sha256: str,
                  decode_lost: int = 0) -> None:
    """설정 등록 = 장비 등록. 같은 config를 다시 올리면 같은 행을 갱신한다.

    통계·대역·FQDN은 여기서 건드리지 않는다 — 새 config를 올렸다고 이전에
    붙여둔 그 장비의 CSV까지 지우면, 같은 장비를 다시 연 것뿐인데 입력이
    사라진다. 반대로 **다른** 장비면 애초에 device_id가 달라 섞이지 않는다.
    """
    with _conn() as con:
        def _touch_existing():
            # 이미 있는 장비 행을 갱신한다. **입력 컬럼(runtime_stats·user_ranges·
            # fqdn_cache 등)은 건드리지 않는다** — 같은 장비를 다시 연 것뿐인데
            # 붙여둔 CSV·대역이 사라지면 안 된다(docstring 참조).
            con.execute(
                "UPDATE devices SET name=?, config_filename=?, config_text=?,"
                " config_sha256=?, decode_lost=?, updated_at=?, touch_seq=?"
                " WHERE device_id=?",
                (name, config_filename, config_text, config_sha256,
                 int(decode_lost or 0), _now(), _next_seq(con), device_id))

        cur = con.execute("SELECT device_id FROM devices WHERE device_id=?",
                          (device_id,)).fetchone()
        if cur:
            _touch_existing()
        else:
            try:
                con.execute(
                    "INSERT INTO devices (device_id, name, config_filename, config_text,"
                    " config_sha256, decode_lost, runtime_stats, user_ranges,"
                    " fqdn_cache, customer_id,"
                    " registered_at, updated_at, touch_seq)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (device_id, name, config_filename, config_text, config_sha256,
                     int(decode_lost or 0),
                     "{}", "[]", "", None, _now(), _now(), _next_seq(con)))
            except sqlite3.IntegrityError:
                # **SELECT→INSERT 사이의 레이스.** 같은 config 를 두 탭에서
                # 동시에 열면 두 요청이 모두 '행 없음'을 보고 둘 다 INSERT 한다.
                # 먼저 든 쪽이 커밋하면 나중 쪽은 UNIQUE 제약으로 500 이 된다
                # (저장이 실사용에서만 깨지는 부류). 그 행은 이미 생겼으니
                # UPDATE 로 돌린다 — 입력 컬럼을 건드리지 않으므로 먼저 넣은
                # 기본값이 보존돼 SELECT 분기와 의미가 같다.
                _touch_existing()


def update_device_inputs(device_id: str, *, runtime_stats=None,
                         user_ranges=None, fqdn_cache=None, csv_meta=None,
                         object_rules=None,
                         remediation_serial=None, tls_fingerprint=None,
                         collect_coverage=None) -> None:
    """이 장비의 입력만 갱신한다. 지정하지 않은 항목은 건드리지 않는다."""
    sets, vals = [], []
    if remediation_serial is not None:
        sets.append("remediation_serial=?"); vals.append(str(remediation_serial))
    if tls_fingerprint is not None:
        sets.append("tls_fingerprint=?"); vals.append(str(tls_fingerprint))
    if runtime_stats is not None:
        sets.append("runtime_stats=?"); vals.append(json.dumps(runtime_stats))
    if user_ranges is not None:
        sets.append("user_ranges=?"); vals.append(json.dumps(user_ranges))
    if object_rules is not None:
        sets.append("object_rules=?"); vals.append(json.dumps(object_rules,
                                                             ensure_ascii=False))
    if fqdn_cache is not None:
        sets.append("fqdn_cache=?"); vals.append(json.dumps(fqdn_cache))
    if csv_meta is not None:
        sets.append("csv_meta=?"); vals.append(json.dumps(csv_meta))
    if collect_coverage is not None:
        sets.append("collect_coverage=?")
        vals.append(json.dumps(collect_coverage))
    if not sets:
        return
    sets.append("updated_at=?"); vals.append(_now())
    with _conn() as con:
        sets.append("touch_seq=?"); vals.append(_next_seq(con))
        vals.append(device_id)
        con.execute(f"UPDATE devices SET {', '.join(sets)} WHERE device_id=?", vals)


def get_device(device_id: str) -> dict | None:
    with _conn() as con:
        row = con.execute("SELECT * FROM devices WHERE device_id=?",
                          (device_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["runtime_stats"] = _loads(d.get("runtime_stats"), {})
    d["user_ranges"] = _loads(d.get("user_ranges"), [])
    d["fqdn_cache"] = _loads(d.get("fqdn_cache"), None)
    d["csv_meta"] = _loads(d.get("csv_meta"), [])
    d["object_rules"] = _loads(d.get("object_rules"), {})
    d["collect_coverage"] = _loads(d.get("collect_coverage"), {})
    return d


def list_devices() -> list[dict]:
    """목록에는 config 원문을 싣지 않는다 — 화면 목록 하나 그리자고 수십 MB를
    직렬화할 이유가 없다."""
    with _conn() as con:
        rows = con.execute(
            "SELECT device_id, name, config_filename, config_sha256, customer_id,"
            " registered_at, updated_at, runtime_stats, user_ranges, fqdn_cache"
            " FROM devices ORDER BY registered_at").fetchall()
    out = []
    for r in rows:
        d = dict(r)
        stats = _loads(d.pop("runtime_stats"), {})
        ranges = _loads(d.pop("user_ranges"), [])
        fqdn = _loads(d.pop("fqdn_cache"), None)
        # `_vdom` 꼬리표(VDOM 귀속 메타, 라운드 55)는 정책 행이 아니다 —
        # 세면 평평한 통계의 usage_count 가 1 부푼다(라운드 56 계약 렌즈).
        counts = (len(stats.get("firewall") or {}) + len(stats.get("proxy") or {})) \
            if ("firewall" in stats or "proxy" in stats) \
            else sum(1 for k in stats if k != "_vdom")
        d["usage_count"] = counts
        d["range_count"] = len(ranges)
        d["has_fqdn"] = bool(fqdn)
        out.append(d)
    return out


def touch_device(device_id: str) -> None:
    """이 장비를 방금 만졌다고 기록한다.

    '쓰기'만 순번을 올렸더니, 장비를 열어 판정하고 리포트만 뽑은 세션(읽기만
    하는 전형적인 컨설팅 작업)이 기록되지 않았다. 그래서 앱을 다시 켜면 마지막에
    본 장비가 아니라 다른 고객 장비가 열렸다(라운드 21 실측).
    """
    with _conn() as con:
        con.execute("UPDATE devices SET touch_seq=? WHERE device_id=?",
                    (_next_seq(con), device_id))


def most_recent_device_id() -> str | None:
    """가장 최근에 손댄 장비. 앱을 다시 켰을 때 이어받을 후보다.

    프로세스가 죽으면 '지금 열린 장비'는 메모리와 함께 사라지지만, 사용자가
    어제 하던 일은 사라지지 않는다. 그런데 첫 화면은 '등록된 것이 없다'고
    말했다 — 보관소에 세 대가 들어 있는데도(라운드 19 실측).
    """
    with _conn() as con:
        row = con.execute(
            "SELECT device_id FROM devices"
            # touch_seq 가 없던 시절의 행(NULL)은 시각으로 줄을 세운다.
            " ORDER BY COALESCE(touch_seq, 0) DESC,"
            " COALESCE(updated_at, registered_at) DESC, rowid DESC"
            " LIMIT 1").fetchone()
    return row["device_id"] if row else None


def delete_device(device_id: str) -> None:
    with _conn() as con:
        con.execute("DELETE FROM devices WHERE device_id=?", (device_id,))
    # **`secure_delete` 만으로는 이미 남아 있던 것을 못 지운다.** 이 릴리스
    # 이전에 만들어진 보관소에는 그 시절 삭제분이 평문으로 남아 있고, 그건
    # 지금 쓰는 사람이 "지웠다" 고 알고 있는 것들이다. VACUUM 이 파일을 다시
    # 써서 해제된 페이지를 통째로 떨어낸다.
    #
    # 둘 중 **하나만 있어도 새로 지우는 것은 사라진다** — 그래서 하나씩
    # 되돌리는 변이로는 계약이 안 깨진다(둘 다 빼면 깨진다, 실측). 굳이 둘 다
    # 두는 이유는 서로 다른 것을 막기 때문이다: pragma 는 앞으로의 삭제를
    # 싸게, VACUUM 은 **옛 보관소에 이미 남은 것**을.
    #
    # 삭제는 사람이 누르는 드문 동작이라 비용을 들여도 된다(읽기 경로가
    # 아니다). 실패해도 삭제는 이미 커밋됐으므로 막지 않되, 조용히 넘기지
    # 않는다(보관소 권한 조치와 같은 규칙).
    try:
        con2 = sqlite3.connect(store_path())
        try:
            con2.execute("VACUUM")
        finally:
            con2.close()
    except Exception as exc:                                   # pragma: no cover
        print(f"[APO] store vacuum after delete failed: {exc!r}", flush=True)


# ── 고객사 ──────────────────────────────────────────────────────────────
def add_customer(name: str) -> dict:
    name = (name or "").strip()
    if not name:
        raise ValueError("Customer name is required")
    cid = "c" + datetime.now().strftime("%Y%m%d%H%M%S%f")[:18]
    with _conn() as con:
        dup = con.execute("SELECT id FROM customers WHERE name=? COLLATE NOCASE",
                          (name,)).fetchone()
        if dup:
            raise ValueError("A customer with that name already exists")
        con.execute("INSERT INTO customers (id, name, created_at) VALUES (?,?,?)",
                    (cid, name, _now()))
    return {"id": cid, "name": name}


def rename_customer(customer_id: str, name: str) -> None:
    name = (name or "").strip()
    if not name:
        raise ValueError("Customer name is required")
    with _conn() as con:
        dup = con.execute(
            "SELECT id FROM customers WHERE name=? COLLATE NOCASE AND id<>?",
            (name, customer_id)).fetchone()
        if dup:
            raise ValueError("A customer with that name already exists")
        con.execute("UPDATE customers SET name=? WHERE id=?", (name, customer_id))


def delete_customer(customer_id: str) -> None:
    """고객사를 지워도 **장비는 남긴다** — 배정만 푼다. 고객사 행 하나를
    지웠다고 그 고객의 장비 분석이 통째로 사라지면 복구할 길이 없다."""
    with _conn() as con:
        con.execute("UPDATE devices SET customer_id=NULL WHERE customer_id=?",
                    (customer_id,))
        con.execute("DELETE FROM customers WHERE id=?", (customer_id,))


def list_customers() -> list[dict]:
    with _conn() as con:
        rows = con.execute(
            "SELECT c.id, c.name, c.created_at,"
            " (SELECT COUNT(*) FROM devices d WHERE d.customer_id=c.id) AS device_count"
            " FROM customers c ORDER BY c.name COLLATE NOCASE").fetchall()
    return [dict(r) for r in rows]


def assign_device(device_id: str, customer_id: str | None) -> None:
    """장비를 고객사에 배정한다(None이면 배정 해제).

    배정은 **보고서를 묶는 라벨**일 뿐 판정 입력이 아니다. 판정에 영향을 주면
    "어느 고객사에 넣었느냐에 따라 심각도가 달라지는" 설명 불가능한 도구가 된다.
    """
    with _conn() as con:
        if customer_id:
            ok = con.execute("SELECT id FROM customers WHERE id=?",
                             (customer_id,)).fetchone()
            if not ok:
                raise ValueError("No such customer")
        cur = con.execute(
            "UPDATE devices SET customer_id=?, updated_at=? WHERE device_id=?",
            (customer_id, _now(), device_id))
        # 0행이면 그 장비는 없다. 성공을 돌려주면 다른 탭에서 지워진 장비를
        # 끌어다 놓았을 때 배정된 것처럼 보이고, 새로고침하면 사라진다.
        if cur.rowcount == 0:
            raise ValueError("No such device")


def devices_for_scope(scope: str, target_id: str | None) -> list[dict]:
    """리포트 범위 → 장비 목록. scope: 'device' | 'customer' | 'all'"""
    if scope == "device":
        d = get_device(target_id or "")
        return [d] if d else []
    with _conn() as con:
        if scope == "customer":
            rows = con.execute(
                "SELECT device_id FROM devices WHERE customer_id=? ORDER BY name",
                (target_id,)).fetchall()
        else:
            rows = con.execute(
                "SELECT device_id FROM devices ORDER BY name").fetchall()
    out = []
    for r in rows:
        d = get_device(r["device_id"])
        if d:
            out.append(d)
    return out


# ── 검증 표본 발급 대장 ─────────────────────────────────────────────────
def record_sample(token: str, device_id: str, device_name: str, label: str,
                  row_keys: list | None = None) -> None:
    """표본을 발급했다는 사실과 **발급한 행 목록**을 남긴다.

    채점은 이 기록만 믿는다 — 파일 안의 값은 이 기록을 가리키는 열쇠일 뿐이다.
    """
    with _conn() as con:
        con.execute(
            "INSERT OR REPLACE INTO verification_samples"
            " (token, device_id, device_name, label, rows_json, issued_at)"
            " VALUES (?,?,?,?,?,?)",
            (str(token), str(device_id), str(device_name or ""), str(label or ""),
             json.dumps(list(row_keys or []), ensure_ascii=False),
             datetime.now().isoformat(timespec="seconds")))


def get_sample(token: str) -> dict | None:
    if not token:
        return None
    with _conn() as con:
        row = con.execute(
            "SELECT token, device_id, device_name, label, rows_json, issued_at"
            " FROM verification_samples WHERE token=?", (str(token),)).fetchone()
    if not row:
        return None
    out = dict(row)
    try:
        out["row_keys"] = {tuple(k) for k in json.loads(out.get("rows_json") or "[]")}
    except Exception:
        out["row_keys"] = set()
    return out

"""
APO License Checker
오프라인 서명 검증 — Python 내장 모듈만 사용 (외부 DLL 불필요)

키 형식은 APO2- 하나뿐이다: RSA-2048 / PKCS#1 v1.5 / SHA-256.
클라이언트는 공개키만 보유하므로 EXE를 분해해도 키를 위조할 수 없다.

v67에서 구형 APO- (HMAC-SHA256) 형식 지원을 제거했다. 그 방식은 대칭키가
바이너리에 내장돼 있어, 추출하면 누구나 영구 라이선스를 위조할 수 있었다.
발급 이력을 확인한 결과 유통된 구형 키가 없어(유료 주문 0건) 하위호환을
유지할 이유가 없었고, 남겨두면 RSA 전환의 이득이 그대로 상쇄되는 상태였다.
혹시 구형 키를 가진 사용자가 나타나면 APO2- 키를 재발급한다.
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
import sys
from datetime import date, datetime, timedelta
from pathlib import Path

from ._license_pubkey import E as _PUB_E, N as _PUB_N

# EMSA-PKCS1-v1_5 의 SHA-256 DigestInfo 접두 (RFC 8017 §9.2)
_SHA256_DIGEST_INFO = bytes.fromhex('3031300d060960864801650304020105000420')


def _rsa_verify(message: bytes, signature: bytes) -> bool:
    """RSASSA-PKCS1-v1_5 (SHA-256) 검증. 내장 모듈만 사용."""
    k = (_PUB_N.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    s = int.from_bytes(signature, 'big')
    if s >= _PUB_N:
        return False
    em = pow(s, _PUB_E, _PUB_N).to_bytes(k, 'big')

    digest = hashlib.sha256(message).digest()
    pad_len = k - 3 - len(_SHA256_DIGEST_INFO) - len(digest)
    if pad_len < 8:          # RFC 8017: PS는 최소 8바이트
        return False
    expected = (b'\x00\x01' + b'\xff' * pad_len + b'\x00'
                + _SHA256_DIGEST_INFO + digest)
    return hmac.compare_digest(em, expected)


def _machine_id() -> str:
    """MAC 주소 기반의 안정적인 기기 식별자(해시). 기기 바인딩 키 검증용."""
    import uuid
    node = uuid.getnode()
    return hashlib.sha256(str(node).encode()).hexdigest()[:16]


# NTP 보정·시간대 변경 같은 정상적인 소폭 되감기까지 막으면 오탐이 난다.
# 만료 우회에 의미 있는 폭은 아니므로 며칠은 허용한다.
_CLOCK_GRACE = timedelta(days=2)

# ── 업데이트 자격 (B-09) ────────────────────────────────────────────────
# 일회성 구매 + "구매 후 1년 업데이트 포함". 구매한 시점까지의 버전은 영구
# 사용이고, 발급일+365일 이후에 나온 릴리스에서만 잠긴다.
#
# RELEASE_DATE는 이 빌드의 릴리스일이다. server.APO_VERSION의 날짜와 반드시
# 일치해야 하며, 테스트(test_release_date_matches_version)가 이를 강제한다 —
# 버전 올릴 때 이 상수를 잊으면 스위트가 깨진다.
#
# UPDATE_POLICY_START 이전에 발급된 키(기존 구매자 전원)는 영구 업데이트로
# 조부 조항 처리한다. 판매 후 약관을 소급 변경하지 않기 위해서다.
RELEASE_DATE = date(2026, 9, 21)
UPDATE_POLICY_START = date(2026, 8, 6)
UPDATE_WINDOW = timedelta(days=365)


class LicenseMessage(ValueError):
    """사용자에게 **그대로 보여도 되는** 문장을 담은 오류.

    base64/JSON 파싱 실패도 ValueError 다 — 라이브러리 예외를 우리 문장과 같은
    바구니에 담으면 `Invalid base64-encoded string: ...` 이 그대로 화면에 뜬다
    (실측). 우리 문장만 이 타입으로 던지고, 나머지는 콘솔로 보낸다.
    ValueError 를 상속하므로 기존 호출부(except ValueError)는 그대로 동작한다.
    """


def _check_update_entitlement(payload: dict) -> None:
    issued_raw = payload.get('issued')
    if not issued_raw:
        return                       # 발급일 없는 키(비정상)는 여기서 막지 않는다
    try:
        issued = datetime.strptime(str(issued_raw), '%Y-%m-%d').date()
    except ValueError:
        return
    if issued < UPDATE_POLICY_START:
        return                       # 조부 조항 — 기존 구매자
    if RELEASE_DATE > issued + UPDATE_WINDOW:
        window_end = issued + UPDATE_WINDOW
        raise LicenseMessage(
            f'Your one year of included updates ended on {window_end}. '
            f'This version was released after that date. Your key keeps '
            f'working forever on releases from before {window_end} — '
            f'or renew your license to use the latest version.')


def _high_water_path() -> Path:
    return _license_path().with_suffix('.state')


def _read_high_water():
    """지금까지 관측한 가장 늦은 날짜. 없거나 손상되면 None."""
    try:
        raw = _high_water_path().read_text(encoding='utf-8').strip()
        return datetime.strptime(raw, '%Y-%m-%d').date()
    except Exception:
        return None


def _update_high_water(today) -> None:
    """앞으로만 전진시킨다. 쓰기 실패는 무시한다(읽기 전용 매체 등)."""
    prev = _read_high_water()
    if prev and prev >= today:
        return
    try:
        _high_water_path().write_text(today.isoformat(), encoding='utf-8')
    except OSError:
        pass


def _license_path() -> Path:
    if os.environ.get("APO_LICENSE_DIR"):
        base = Path(os.environ["APO_LICENSE_DIR"])
    elif getattr(sys, 'frozen', False):
        base = Path(sys.executable).parent
    else:
        base = Path(__file__).resolve().parents[2]
    return base / 'license.dat'


def verify_key(key: str) -> dict:
    """서명 검증. 성공 시 payload dict 반환, 실패 시 ValueError."""
    key = (key or '').strip()
    if key.startswith('APO2-'):
        body = key[5:]
    elif key.startswith('APO-'):
        # 구형 형식은 v67부터 받지 않는다. 위조 가능한 대칭키 기반이었다.
        raise LicenseMessage(
            'This key uses a retired format. Please contact support (choiceguidelab@gmail.com) for a replacement key.'
        )
    else:
        raise LicenseMessage(
            'That does not look like an APO licence key. Paste the whole key, '
            'including the APO2- prefix at the front.'
        )

    # **서명 검증은 광범위 except 밖에 둔다** (B-82, 방어심화).
    # 전에는 `if not _rsa_verify(...)` 가 `try/except Exception` 안에 있었다.
    # 지금 동작은 안전했지만(어떤 예외든 deny 로 떨어졌다), 그 안전이
    # '아래 except 가 계속 deny 로 끝난다'는 우연에 기대고 있었다. 나중에
    # 누가 except 를 세분화하거나 `_rsa_verify` 가 bool 아닌 값을 돌려주면
    # 조용히 fail-open 이 된다 — 유료 게이트가 조용히 열리는 자리다.
    # 그래서 **깨진 입력 파싱만** try 로 감싸고, 검증 자체는 본류에서 분기한다.
    try:
        combined = base64.b64decode(body).decode()
        data_b64, sig_b64 = combined.split('.', 1)
        data = base64.b64decode(data_b64)
        sig  = base64.b64decode(sig_b64)
    except LicenseMessage:
        raise
    except Exception as e:
        print(f"[APO] licence key could not be read: {e!r}", flush=True)
        raise LicenseMessage(
            'This key could not be read. Paste the whole key exactly as it '
            'was sent to you — if it still fails, contact support (choiceguidelab@gmail.com).'
        )

    # 여기서부터는 예외로 뭉개지 않는다. `is True` 로 받는 이유도 같다 —
    # 진위 판정이 truthy 한 무엇('', 0 아닌 객체)으로 통과하지 않게 한다.
    if _rsa_verify(data, sig) is not True:
        raise LicenseMessage(
            'This key did not pass the signature check. It may have been '
            'altered in transit — copy it again from the purchase e-mail.'
        )

    try:
        payload = json.loads(data)
        if payload.get('product') != 'APO-EXPORT':
            raise LicenseMessage('This key was issued for a different product.')

        # 만료 검증: exp 필드가 있는 키에만 적용 (기존 perpetual 키는 exp 없음 → 하위호환)
        exp = payload.get('exp')
        if exp:
            try:
                exp_date = datetime.strptime(str(exp), '%Y-%m-%d').date()
            except ValueError:
                exp_date = None
            if exp_date:
                today = date.today()
                # 오프라인 검증이라 시계를 그대로 믿으면 만료된 키도 날짜를
                # 되돌리는 것만으로 되살아난다. 지금까지 본 가장 늦은 날짜
                # (high-water)를 기록해 두고, **만료 비교를 시계와 그 기록 중
                # 늦은 쪽으로** 한다.
                #
                # 예전에는 시계가 기록보다 뒤면 하드락("clock has been set
                # back")을 걸었는데, 리뷰 게이트가 자기중독을 잡았다: 시계가
                # 잠깐 미래로 튀면(만료 전 범위) 그 미래가 기록되고, 시계가
                # 정상으로 돌아온 순간부터 **정상 결제 키가 상태 파일을
                # 지우기 전까지 영구 거부**됐다. max() 비교는 벽돌이 없고,
                # 막던 것(기록 이전으로 되돌려 수명 연장)은 같게 막는다 —
                # 유효한 키는 시계를 어디로 돌려도 유효하고, 관측된 수명
                # 밖으로는 늘어나지 않는다.
                # 구버전(v68~v110)이 미래로 튄 시계 값을 그대로 기록해 둔
                # 상태 파일이 있을 수 있다 — exp 상한으로 읽어 **자가치유**
                # 한다(이미 중독된 정상 사용자가 이 업데이트로 풀린다).
                last_seen = _read_high_water()
                if last_seen and last_seen > exp_date:
                    last_seen = exp_date
                eff_today = max(today, last_seen) if last_seen else today
                if eff_today > exp_date:
                    raise LicenseMessage(
                        'This licence key has expired. Contact support '
                        '(choiceguidelab@gmail.com) to renew it.'
                    )
                # 기록은 exp 를 상한으로 — 미래로 튄 값이 그대로 적히면 위
                # max() 비교가 유효 키를 조기 만료시킨다(구버전 하드락의
                # 자기중독과 같은 얼굴). 이 상한 아래에서 기록이 만들 수 있는
                # 최대 효과는 '만료일 당일까지 유효'라는 원래 계약 그대로다.
                _update_high_water(min(today, exp_date))

        # 기기 바인딩 검증: machine 필드가 있는 키에만 적용 (하위호환)
        machine = payload.get('machine')
        if machine and str(machine) != _machine_id():
            raise LicenseMessage(
                'This licence key is registered to a different computer. '
                'Contact support (choiceguidelab@gmail.com) to move it to this one.'
            )

        _check_update_entitlement(payload)
        return payload
    except LicenseMessage:
        raise
    except Exception as e:
        # 파이썬 예외 문자열은 사용자에게 보일 문장이 아니다 — base64/JSON 오류가
        # 그대로 화면에 뜨면 읽는 사람이 할 수 있는 일이 없다. 상세는 콘솔로 보내고
        # 화면에는 '무엇을 하면 되는지'만 남긴다.
        print(f"[APO] licence key could not be read: {e!r}", flush=True)
        raise LicenseMessage(
            'This key could not be read. Paste the whole key exactly as it '
            'was sent to you — if it still fails, contact support (choiceguidelab@gmail.com).'
        )


def activate(key: str) -> dict:
    data = verify_key(key)
    _license_path().write_text(key.strip(), encoding='utf-8')
    return data


def is_licensed() -> bool:
    try:
        key = _license_path().read_text(encoding='utf-8').strip()
        verify_key(key)
        return True
    except Exception:
        return False


def license_problem() -> str | None:
    """**등록된 키가 있는데 왜 안 통하는가.** 없으면 None.

    `is_licensed()` 가 사유를 통째로 삼켜서, 돈을 낸 고객이 자격을 잃는 순간
    (업데이트 창 경과·만료·기기 불일치) 화면이 그냥 **"Free"** 로 바뀌고
    "라이선스를 등록하세요" 만 말했다. 잘 쓰인 안내 문구는 **키를 다시
    붙여넣어야만** 나온다 — $699 를 낸 MSP 가 새 버전을 받고 자기가 왜
    무료 사용자가 됐는지 알 수 없는 상태가 된다(2026-09-10 상용화 검토).
    환불·이탈·CS 가 여기서 난다.

    반환 규칙:
      · None  — 키 파일이 아예 없다(미구매) **또는** 정상이다.
                이 둘은 `is_licensed()` 로 갈린다.
      · str   — 키는 있는데 통하지 않는다. 그 사유(고객에게 보여줄 문장).
    """
    try:
        key = _license_path().read_text(encoding='utf-8').strip()
    except Exception:
        return None                      # 키 파일 없음 = 미구매
    if not key:
        return None
    try:
        verify_key(key)
        return None                      # 정상
    except LicenseMessage as exc:        # 정책상 거절(사유가 고객용 문장)
        return str(exc)
    except Exception:
        # 서명 불일치·손상 등. 내부 예외 문구를 그대로 노출하지 않는다.
        return ('The saved license key could not be verified. It may be '
                'damaged — paste it again, or contact support.')


def update_window_end() -> date | None:
    """이 키의 업데이트 포함 기간이 끝나는 날. 해당 없으면 None.

    고객이 **잠기기 전에** 알 수 있어야 갱신이 일어난다. 예전에는 이 값을
    어디서도 주지 않아, 창이 언제 끝나는지 화면으로 알 방법이 없었다.
    """
    info = get_license_info()
    if not info:
        return None
    raw = info.get('issued')
    if not raw:
        return None
    try:
        issued = datetime.strptime(str(raw), '%Y-%m-%d').date()
    except ValueError:
        return None
    if issued < UPDATE_POLICY_START:
        return None                      # 조부 조항 — 영구 업데이트
    return issued + UPDATE_WINDOW


def get_license_info() -> dict | None:
    try:
        key = _license_path().read_text(encoding='utf-8').strip()
        return verify_key(key)
    except Exception:
        return None

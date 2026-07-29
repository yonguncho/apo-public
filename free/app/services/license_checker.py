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
        raise ValueError(
            'This key uses a retired format. Please contact support for a replacement key.'
        )
    else:
        raise ValueError('Invalid key format')

    try:
        combined = base64.b64decode(body).decode()
        data_b64, sig_b64 = combined.split('.', 1)
        data = base64.b64decode(data_b64)
        sig  = base64.b64decode(sig_b64)

        if not _rsa_verify(data, sig):
            raise ValueError('Signature mismatch')

        payload = json.loads(data)
        if payload.get('product') != 'APO-EXPORT':
            raise ValueError('Invalid product')

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
                # 되돌리는 것만으로 되살아난다. 지금까지 본 가장 늦은 날짜를
                # 기록해 두고, 그보다 뒤로 돌아간 흔적이 있으면 거부한다.
                last_seen = _read_high_water()
                if last_seen and today < last_seen - _CLOCK_GRACE:
                    raise ValueError('System clock inconsistency detected')
                if today > exp_date:
                    raise ValueError('License expired')
                _update_high_water(today)

        # 기기 바인딩 검증: machine 필드가 있는 키에만 적용 (하위호환)
        machine = payload.get('machine')
        if machine and str(machine) != _machine_id():
            raise ValueError('License is bound to a different machine')

        return payload
    except (ValueError, KeyError):
        raise
    except Exception as e:
        raise ValueError(f'License verification failed: {e}')


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


def get_license_info() -> dict | None:
    try:
        key = _license_path().read_text(encoding='utf-8').strip()
        return verify_key(key)
    except Exception:
        return None

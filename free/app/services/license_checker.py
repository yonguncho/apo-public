"""
APO License Checker
오프라인 서명 검증 — Python 내장 모듈만 사용 (외부 DLL 불필요)

두 가지 키 형식을 지원한다:

  APO2-...  RSA-2048 / PKCS#1 v1.5 / SHA-256 서명 (현행)
            클라이언트는 공개키만 보유하므로 EXE를 분해해도 키를 위조할 수 없다.

  APO-...   HMAC-SHA256 서명 (구형, 하위호환)
            대칭키가 바이너리에 내장돼 있어 추출 시 위조가 가능하다. 이미 발급된
            키를 계속 쓰기 위해 검증만 남겨두며, 신규 발급은 전부 APO2- 형식이다.
            기존 구형 키 사용자가 모두 교체되면 _LEGACY_HMAC_ENABLED를 꺼서
            이 경로를 제거할 수 있다.
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
import sys
from pathlib import Path

from ._license_pubkey import E as _PUB_E, N as _PUB_N

# 구형 HMAC 대칭키는 배포 빌드에만 포함되는 별도 모듈에서 읽는다.
# 공개 소스 트리에는 이 모듈이 없으므로 구형 키 경로가 자동으로 꺼진다.
# (대칭키는 EXE에 내장돼 추출이 가능하다는 성질 자체는 변하지 않는다. 다만
#  공개 저장소에서 grep 한 번으로 얻어지는 상태는 피한다.)
try:
    from ._license_legacy_secret import SECRET_HEX as _LEGACY_SECRET_HEX
    _SECRET_KEY = bytes.fromhex(_LEGACY_SECRET_HEX)
except ImportError:
    _SECRET_KEY = None

# 구형 HMAC 키 수용 여부. 기존 판매분 호환을 위해 켜 두지만, 대칭키가 없으면
# 어차피 검증할 수 없으므로 함께 꺼진다.
# TODO: 구형 APO- 키 사용자가 모두 APO2-로 교체되면 이 경로를 완전히 제거한다.
#       그때까지는 대칭키를 추출한 공격자가 APO- 키를 위조할 수 있어,
#       RSA 전환의 이득이 이 플래그만큼 상쇄된다.
_LEGACY_HMAC_ENABLED = _SECRET_KEY is not None

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
        body, is_rsa = key[5:], True
    elif key.startswith('APO-'):
        if not _LEGACY_HMAC_ENABLED:
            raise ValueError('Legacy key format is no longer accepted')
        body, is_rsa = key[4:], False
    else:
        raise ValueError('Invalid key format')

    try:
        combined = base64.b64decode(body).decode()
        data_b64, sig_b64 = combined.split('.', 1)
        data = base64.b64decode(data_b64)
        sig  = base64.b64decode(sig_b64)

        if is_rsa:
            if not _rsa_verify(data, sig):
                raise ValueError('Signature mismatch')
        else:
            expected = hmac.new(_SECRET_KEY, data, hashlib.sha256).digest()
            if not hmac.compare_digest(expected, sig):
                raise ValueError('Signature mismatch')

        payload = json.loads(data)
        if payload.get('product') != 'APO-EXPORT':
            raise ValueError('Invalid product')

        # 만료 검증: exp 필드가 있는 키에만 적용 (기존 perpetual 키는 exp 없음 → 하위호환)
        exp = payload.get('exp')
        if exp:
            from datetime import date, datetime
            try:
                exp_date = datetime.strptime(str(exp), '%Y-%m-%d').date()
            except ValueError:
                exp_date = None
            if exp_date and date.today() > exp_date:
                raise ValueError('License expired')

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

"""
APO License Checker
HMAC-SHA256 기반 오프라인 검증 — Python 내장 모듈만 사용 (DLL 불필요)
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
import sys
from pathlib import Path

# HMAC 비밀키 (EXE 내장)
# 주의: 대칭키가 바이너리에 내장되어 있어 추출 시 키 위조가 가능하다(오프라인 검증의 한계).
# 근본 강화는 비대칭 서명(클라는 공개키만 보유) 또는 서버측 검증으로의 전환이 필요하며,
# 이는 발급측(webhook)과의 동시 마이그레이션이 필요하므로 별도 작업으로 분리한다.
_SECRET_KEY = bytes.fromhex('8ec1b65000e416bd062663416f231e683fb809f66e0e5ddfd8decf35e73808cf')


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
    """HMAC 서명 검증. 성공 시 payload dict 반환, 실패 시 ValueError."""
    if not key or not key.startswith('APO-'):
        raise ValueError('Invalid key format')
    try:
        combined = base64.b64decode(key[4:]).decode()
        data_b64, sig_b64 = combined.split('.', 1)
        data = base64.b64decode(data_b64)
        sig  = base64.b64decode(sig_b64)

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

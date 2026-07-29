"""
ai_analyzer.py
==============
로컬 Ollama API(hermes3)를 사용한 방화벽 정책 AI 분석.
Anthropic API 미사용 — 완전 로컬 실행.
"""
from __future__ import annotations
import json
import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "hermes3:latest"
TIMEOUT_SEC = 120


def _call_ollama(prompt: str, model: str = DEFAULT_MODEL) -> str:
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.3, "num_predict": 1024},
    }
    try:
        resp = requests.post(OLLAMA_URL, json=payload, timeout=TIMEOUT_SEC)
        resp.raise_for_status()
        return resp.json().get("response", "").strip()
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Ollama 연결 실패: {e}") from e


def analyze_policies(policies: list[dict], model: str = DEFAULT_MODEL) -> str:
    """정책 목록을 hermes3에 전달해 자연어 분석 결과 반환."""
    if not policies:
        return "분석할 정책이 없습니다."

    lines = []
    for p in policies[:30]:  # 최대 30개 (토큰 초과 방지)
        lines.append(
            f"- [Severity {p.get('urgency','?')}] {p.get('name','(unnamed)')} "
            f"| {p.get('traffic_type','?')} | Hit:{p.get('hit_count','?')} "
            f"| {p.get('reason','')}"
        )
    policy_text = "\n".join(lines)

    prompt = f"""You are a network security engineer reviewing firewall policies.
Below is a list of FortiGate firewall policies with their severity classifications.
Analyze the policies and provide:
1. A concise summary of the overall risk posture (2-3 sentences)
2. The top 3 most critical issues to address immediately
3. Key recommendations for cleanup

Respond in Korean. Be concise and actionable.

Policies:
{policy_text}

Analysis:"""

    return _call_ollama(prompt, model)


def analyze_single_policy(policy: dict, model: str = DEFAULT_MODEL) -> str:
    """단일 정책에 대한 상세 AI 분석 반환."""
    prompt = f"""You are a network security engineer. Analyze this firewall policy and explain:
1. Why it was classified as Severity {policy.get('urgency','?')} ({policy.get('risk_level','?')})
2. The specific security risk it poses
3. Recommended action in detail

Respond in Korean. Be specific and practical.

Policy details:
- Name: {policy.get('name','(unnamed)')}
- Action: {policy.get('action','')}
- Status: {policy.get('status','')}
- Schedule: {policy.get('schedule','')}
- Source: {', '.join(policy.get('srcaddr_display') or [])}
- Destination: {', '.join(policy.get('dstaddr_display') or [])}
- Service: {', '.join(policy.get('service_display') or [])}
- Hit Count: {policy.get('hit_count','N/A')}
- Last Used: {policy.get('last_used','N/A')}
- Traffic Type: {policy.get('traffic_type','?')}
- Severity: {policy.get('urgency','?')} — {policy.get('reason','')}

Analysis:"""

    return _call_ollama(prompt, model)


def check_ollama_available(model: str = DEFAULT_MODEL) -> bool:
    """Ollama 서버 및 모델 사용 가능 여부 확인."""
    try:
        resp = requests.get("http://localhost:11434/api/tags", timeout=5)
        if resp.status_code != 200:
            return False
        data = resp.json()
        models = [m.get("name", "") for m in data.get("models", []) if isinstance(m, dict)]
        models = [m for m in models if m]
        return any(model.split(":")[0] in m for m in models)
    except requests.exceptions.RequestException:
        return False

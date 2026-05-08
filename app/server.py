from __future__ import annotations



def parse_config_text(raw_text):
    """Parse FortiGate config text without using Flask route handlers."""
    text = raw_text if isinstance(raw_text, str) else str(raw_text or "")
    parser = FortiGateConfigParser(text)
    return parser.parse()



def _normalize_items(items):
    """Return a safe list of dictionaries for diff comparison."""
    if items is None:
        return []
    if isinstance(items, dict):
        return [items]
    if isinstance(items, list):
        return [item for item in items if isinstance(item, dict)]
    return []

def _build_policy_map(items):
    result = {}
    for item in _normalize_items(items):
        pid = str(item.get("policy_id") or item.get("id") or item.get("_edit") or "").strip()
        if pid:
            result[pid] = item
    return result


def _index_named_items(items, name_key="name"):
    result = {}
    for item in _normalize_items(items):
        name = str(item.get(name_key) or item.get("_edit") or item.get("policy_id") or item.get("id") or "").strip()
        if name:
            result[name] = item
    return result


def _simplify_policy_for_compare(policy):
    if not isinstance(policy, dict):
        return {}
    ignored_keys = {"hit_count", "last_used", "status"}
    return {k: v for k, v in policy.items() if k not in ignored_keys}




def _section_signature(items):
    result = {}
    for item in _normalize_items(items):
        key = str(item.get("name") or item.get("_edit") or item.get("policy_id") or item.get("id") or "").strip()
        if key:
            cleaned = {k: v for k, v in item.items() if k not in {"uuid"}}
            result[key] = cleaned
    return result

def _compute_config_diff(old_data, new_data):
    old_policies = _build_policy_map(old_data.get("firewall_policy") or old_data.get("policies") or [])
    new_policies = _build_policy_map(new_data.get("firewall_policy") or new_data.get("policies") or [])

    added_policies = []
    removed_policies = []
    changed_policies = []

    for pid, policy in new_policies.items():
        if pid not in old_policies:
            added_policies.append(policy)
        else:
            if _simplify_policy_for_compare(old_policies[pid]) != _simplify_policy_for_compare(policy):
                changed_policies.append({
                    "policy_id": pid,
                    "name": policy.get("name") or old_policies[pid].get("name") or "",
                    "before": old_policies[pid],
                    "after": policy,
                })

    for pid, policy in old_policies.items():
        if pid not in new_policies:
            removed_policies.append(policy)

    object_sections = [
        "firewall_address",
        "firewall_addrgrp",
        "firewall_proxy_address",
        "firewall_proxy_addrgrp",
        "firewall_service_custom",
        "firewall_service_group",
        "system_interface",
    ]

    added_objects = []
    removed_objects = []

    for section in object_sections:
        old_map = _index_named_items(old_data.get(section) or [])
        new_map = _index_named_items(new_data.get(section) or [])

        for name, item in new_map.items():
            if name not in old_map:
                added_objects.append({
                    "section": section,
                    "name": name,
                    "item": item,
                })

        for name, item in old_map.items():
            if name not in new_map:
                removed_objects.append({
                    "section": section,
                    "name": name,
                    "item": item,
                })


    known_sections = {
        "firewall_policy",
        "policies",
        "firewall_address",
        "firewall_addrgrp",
        "firewall_proxy_address",
        "firewall_proxy_addrgrp",
        "firewall_service_custom",
        "firewall_service_group",
        "system_interface",
    }
    other_changes = []
    all_sections = set(old_data.keys()) | set(new_data.keys())
    for section in sorted(all_sections):
        if section in known_sections:
            continue
        old_sig = _section_signature(old_data.get(section) or [])
        new_sig = _section_signature(new_data.get(section) or [])
        added = [name for name in new_sig if name not in old_sig]
        removed = [name for name in old_sig if name not in new_sig]
        changed = [name for name in new_sig if name in old_sig and new_sig[name] != old_sig[name]]
        if added or removed or changed:
            other_changes.append({
                "section": section,
                "added": added,
                "removed": removed,
                "changed": changed,
            })

    return {
        "summary": {
            "added_policies": len(added_policies),
            "removed_policies": len(removed_policies),
            "changed_policies": len(changed_policies),
            "added_objects": len(added_objects),
            "removed_objects": len(removed_objects),
            "other_changes": len(other_changes),
        },
        "added_policies": added_policies,
        "removed_policies": removed_policies,
        "changed_policies": changed_policies,
        "added_objects": added_objects,
        "removed_objects": removed_objects,
        "other_changes": other_changes,
    }
import json
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template, request, send_from_directory, send_file

from app.parsers.config_parser import FortiGateConfigParser
from app.parsers.policy_csv_parser import PolicyStatsCsvParser
from app.parsers.runtime_parser import RuntimeStatsParser
from app.services.policy_renderer import build_view_model

from app.services.workbook_exporter import build_workbook
from datetime import date as _date
from app.services.severity_engine import evaluate_severity
from app.services.ai_analyzer import analyze_policies, analyze_single_policy, check_ollama_available
from io import BytesIO

import sys as _sys
APO_VERSION = "v23.0-2026-05-05"
if getattr(_sys, 'frozen', False) and hasattr(_sys, '_MEIPASS'):
    BASE_DIR = Path(_sys._MEIPASS)
else:
    BASE_DIR = Path(__file__).resolve().parent.parent

print(f"[APO] Version: {APO_VERSION}", flush=True)
print(f"[APO] Frozen: {getattr(_sys, 'frozen', False)}", flush=True)
print(f"[APO] BASE_DIR: {BASE_DIR}", flush=True)
print(f"[APO] Templates: {BASE_DIR / 'app' / 'templates'} "
      f"(exists={(BASE_DIR / 'app' / 'templates' / 'index.html').exists()})", flush=True)

IMPORT_DIR = BASE_DIR / "imports"
EXPORT_DIR = BASE_DIR / "exports"
DATA_DIR = BASE_DIR / "data"


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder=str(BASE_DIR / "app" / "templates"),
        static_folder=str(BASE_DIR / "app" / "static"),
    )

    for d in (IMPORT_DIR, EXPORT_DIR, DATA_DIR):
        d.mkdir(parents=True, exist_ok=True)

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/version")
    def version():
        templates_dir = BASE_DIR / "app" / "templates"
        return jsonify({
            "version": APO_VERSION,
            "frozen": bool(getattr(_sys, 'frozen', False)),
            "base_dir": str(BASE_DIR),
            "templates_dir": str(templates_dir),
            "templates_exists": templates_dir.exists(),
            "index_html_exists": (templates_dir / "index.html").exists(),
        })

    @app.post("/api/config/parse")
    def parse_config():
        uploaded = request.files.get("config_file")
        if not uploaded:
            return jsonify({"error": "config_file is required"}), 400

        filename = uploaded.filename or "fortigate.conf"
        save_path = IMPORT_DIR / filename
        uploaded.save(save_path)

        raw = save_path.read_text(encoding="utf-8", errors="ignore")
        parser = FortiGateConfigParser(raw)
        parsed = parser.parse()
        view = build_view_model(parsed, runtime_stats={})

        export_name = f"{Path(filename).stem}.parsed.json"
        export_path = EXPORT_DIR / export_name
        export_path.write_text(json.dumps({"parsed": parsed, "view": view}, indent=2), encoding="utf-8")
        app.config['last_parsed'] = parsed

        return jsonify(
            {
                "message": "Config parsed successfully",
                "filename": filename,
                "parsed": parsed,
                "view": view,
                "export_json": export_name,
            }
        )

    @app.post("/api/runtime/import")
    def import_runtime():
        parser = RuntimeStatsParser()
        merged: dict[str, dict[str, Any]] = {}

        uploaded_files = request.files.getlist("runtime_files")
        pasted_text = request.form.get("runtime_text", "")

        for file in uploaded_files:
            text = file.read().decode("utf-8", errors="ignore")
            stats = parser.parse_text(text)
            merged.update(stats)

        if pasted_text.strip():
            stats = parser.parse_text(pasted_text)
            merged.update(stats)

        return jsonify({"runtime_stats": merged})

    @app.post("/api/policy-stats/import")
    def import_policy_stats_csv():
        parser = PolicyStatsCsvParser()
        merged: dict[str, dict[str, Any]] = {}
        uploaded_files = request.files.getlist("policy_stats_files")
        pasted_text = request.form.get("policy_stats_text", "")

        for file in uploaded_files:
            text = file.read().decode("utf-8", errors="ignore")
            stats = parser.parse_text(text)
            merged.update(stats)

        if pasted_text.strip():
            stats = parser.parse_text(pasted_text)
            merged.update(stats)

        app.config['last_runtime_stats'] = merged
        summary = {
            "count": len(merged),
            "matched_policy_ids": sorted(merged.keys(), key=lambda x: int(x) if x.isdigit() else x),
        }
        return jsonify({"runtime_stats": merged, "summary": summary})

    @app.post("/api/policies/render")
    def render_policies():
        payload = request.get_json(silent=True) or {}
        parsed = payload.get("parsed")
        runtime_stats = payload.get("runtime_stats", {})
        if not parsed:
            return jsonify({"error": "parsed payload is required"}), 400

        view = build_view_model(parsed, runtime_stats)
        return jsonify({"view": view})

    @app.post("/api/export/workbook")
    def export_workbook():
        payload = request.get_json(silent=True) or {}
        sheets = payload.get("sheets") or {}
        workbook_name = payload.get("workbook_name", "firewall_policy_optimizer_export")
        output_path = EXPORT_DIR / f"{workbook_name}.xlsx"
        build_workbook(output_path, sheets)
        return send_file(output_path, as_attachment=True, download_name=output_path.name)

    @app.get("/exports/<path:filename>")
    def download_export(filename: str):
        return send_from_directory(EXPORT_DIR, filename, as_attachment=True)

    @app.post("/api/config/diff")
    def api_config_diff():
        old_file = request.files.get("old_config")
        new_file = request.files.get("new_config")

        if not old_file or not new_file:
            return jsonify({"error": "Both baseline and target config files are required."}), 400

        try:
            old_text = old_file.read().decode("utf-8", errors="ignore")
            new_text = new_file.read().decode("utf-8", errors="ignore")

            old_data = parse_config_text(old_text)
            new_data = parse_config_text(new_text)

            result = _compute_config_diff(old_data, new_data)
            return jsonify(result)
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    app.config.setdefault('user_ranges', [])

    @app.get("/api/user-ranges")
    def get_user_ranges():
        return jsonify({"user_ranges": app.config.get('user_ranges', [])})

    @app.post("/api/user-ranges/set")
    def set_user_ranges():
        payload = request.get_json(silent=True) or {}
        ranges = [{"cidr": str(r).strip()} for r in payload.get("ranges", []) if str(r).strip()]
        app.config['user_ranges'] = ranges
        return jsonify({"ok": True, "count": len(ranges)})

    @app.post("/api/severity/classify")
    def severity_classify():
        parsed = app.config.get('last_parsed')
        if not parsed:
            return jsonify({"error": "No config loaded. Upload a config file first."}), 400
        service_groups = parsed.get("service_groups", {})
        user_ranges = app.config.get('user_ranges', [])
        context = {
            "service_groups": service_groups,
            "user_ranges": user_ranges,
            "today": _date.today(),
        }
        def classify_list(policies):
            result = []
            for p in (policies or []):
                if (p.get("action") or "").lower() == "deny":
                    continue
                sev = evaluate_severity(p, context)
                result.append({**p, **sev})
            return result

        from app.services.policy_renderer import build_view_model
        runtime_stats = app.config.get('last_runtime_stats', {})
        view = build_view_model(parsed, runtime_stats)
        return jsonify({
            "firewall":  classify_list(view.get("firewall_policy", [])),
            "proxy":     classify_list(view.get("firewall_proxy_policy", [])),
            "multicast": classify_list(view.get("firewall_multicast_policy", [])),
        })

    # ── AI 분석 (Ollama/hermes3 로컬) ──────────────────────────────────────
    @app.get("/api/ai/status")
    def ai_status():
        available = check_ollama_available()
        return jsonify({"available": available, "model": "hermes3:latest"})

    @app.post("/api/ai/analyze")
    def ai_analyze():
        payload = request.get_json(silent=True) or {}
        policies = payload.get("policies", [])
        mode = payload.get("mode", "summary")   # "summary" | "single"
        model = payload.get("model", "hermes3:latest")
        try:
            if mode == "single" and policies:
                result = analyze_single_policy(policies[0], model)
            else:
                result = analyze_policies(policies, model)
            return jsonify({"result": result, "model": model})
        except RuntimeError as e:
            return jsonify({"error": str(e)}), 503

    @app.post("/api/export/severity-workbook")
    def export_severity_workbook():
        from app.services.workbook_exporter import build_severity_workbook
        payload = request.get_json(silent=True) or {}
        xlsx_bytes = build_severity_workbook(payload)
        return app.response_class(
            response=xlsx_bytes,
            status=200,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={"Content-Disposition": "attachment; filename=severity_export.xlsx"}
        )

    return app


# ── AI 기능 (Electron 앱 전용) ─────────────────────────────────

import requests as _ai_req


def _call_ollama(prompt: str, model: str = 'llama3.2:3b') -> str:
    """Ollama API 공통 호출"""
    try:
        r = _ai_req.post(
            'http://localhost:11434/api/generate',
            json={'model': model, 'prompt': prompt, 'stream': False},
            timeout=60
        )
        return r.json().get('response', 'No response from AI.')
    except Exception as e:
        return f'AI unavailable: {str(e)}'


def _register_ai_routes(app):
    from flask import request, jsonify

    @app.route('/api/ai/explain', methods=['POST'])
    def ai_explain_policy():
        """단일 정책 위험도 설명 및 CLI 제안"""
        data = request.get_json()
        p = data.get('policy_data', {})
        prompt = f"""You are a FortiGate firewall security expert.
Analyze this firewall policy and provide a concise technical assessment.

Policy Name : {p.get('name', 'Unknown')}
Action      : {p.get('action', 'Unknown')}
Source      : {p.get('srcaddr', 'Unknown')}
Destination : {p.get('dstaddr', 'Unknown')}
Service     : {p.get('service', 'Unknown')}
Status      : {p.get('status', 'Unknown')}
Hit Count   : {p.get('hit_count', 'Unknown')}
Severity    : {p.get('severity', 'Unknown')}

Provide exactly 3 sections:
1. Risk: (2 sentences, technical)
2. Recommendation: Keep / Modify / Delete
3. CLI: exact FortiGate command

Audience: network security engineer. Be concise."""
        return jsonify({'explanation': _call_ollama(prompt)})

    @app.route('/api/ai/cli', methods=['POST'])
    def ai_generate_cli():
        """선택 정책 일괄 CLI 명령어 생성"""
        data = request.get_json()
        policies = data.get('policies', [])
        lines = '\n'.join([
            f"  ID:{p.get('policyid','?')}  "
            f"Name:{p.get('name','?')}  "
            f"Action:{p.get('action','?')}  "
            f"Status:{p.get('status','?')}  "
            f"HitCount:{p.get('hit_count','?')}"
            for p in policies
        ])
        prompt = f"""You are a FortiGate CLI expert.
Generate exact FortiGate CLI commands for these policies.
Use 'delete' for disabled/expired/zero-hit policies.
Use 'set status disable' for risky but active policies.

Policies:
{lines}

Output ONLY CLI commands. No explanation. No markdown fences.

Format:
config firewall policy
    delete <id>
    edit <id>
        set status disable
    next
end"""
        return jsonify({'cli_commands': _call_ollama(prompt)})

    @app.route('/api/ai/report', methods=['POST'])
    def ai_generate_report():
        """경영진용 감사 보고서 HTML 생성"""
        import datetime
        data = request.get_json()
        summary = data.get('severity_summary', {})
        total = sum(summary.values()) if summary else 0
        prompt = f"""You are a cybersecurity consultant.
Write a professional executive summary for a FortiGate firewall policy audit.

Total Policies Analyzed : {total}
Severity Breakdown      : {summary}

Structure:
1. Executive Summary (3 sentences)
2. Key Findings (top 3 risks, bullet points)
3. Immediate Actions Required
4. Cleanup Effort Estimate (Low / Medium / High + reason)

Professional tone. Suitable for CISO or IT Manager. Under 300 words."""
        text = _call_ollama(prompt)
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
        report_html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>APO Tool — Audit Report</title>
<style>
  body {{font-family:sans-serif;max-width:820px;
         margin:48px auto;padding:0 24px;color:#1a1a2e;}}
  h1   {{border-bottom:3px solid #EE2228;padding-bottom:12px;}}
  .body{{line-height:1.85;white-space:pre-wrap;font-size:15px;}}
  .foot{{color:#999;font-size:12px;margin-top:36px;
         border-top:1px solid #eee;padding-top:12px;}}
</style></head><body>
<h1>FortiGate Policy Audit — Executive Summary</h1>
<div class="body">{text}</div>
<div class="foot">Generated by APO Tool AI · {now}</div>
</body></html>"""
        return jsonify({'report_html': report_html})

    @app.route('/health')
    def health():
        return jsonify({'status': 'ok'}), 200


# create_app() 래핑 — AI 라우트 자동 등록
_original_create_app = create_app

def create_app():
    _app = _original_create_app()
    _register_ai_routes(_app)
    return _app

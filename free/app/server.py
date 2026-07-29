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
from app.services.license_checker import activate, is_licensed, get_license_info
from io import BytesIO

import sys as _sys
APO_VERSION = "v65-2026-07-28"
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


def _license_required():
    """라이선스 미보유 시 402 응답을 반환, 보유 시 None.
    유료 Export 계열 라우트의 서버측 게이트 (클라이언트 게이트 우회 차단)."""
    if not is_licensed():
        return jsonify({"error": "License required. Please activate your Export license."}), 402
    return None


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder=str(BASE_DIR / "app" / "templates"),
        static_folder=str(BASE_DIR / "app" / "static"),
    )

    from datetime import datetime as _dt

    @app.context_processor
    def inject_year():
        return {'current_year': _dt.now().year}

    for d in (IMPORT_DIR, EXPORT_DIR, DATA_DIR):
        d.mkdir(parents=True, exist_ok=True)

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/version")
    def version():
        # 절대경로 등 내부 파일시스템 정보는 노출하지 않는다.
        return jsonify({
            "version": APO_VERSION,
            "frozen": bool(getattr(_sys, 'frozen', False)),
        })

    @app.post("/api/config/parse")
    def parse_config():
        uploaded = request.files.get("config_file")
        if not uploaded:
            return jsonify({"error": "config_file is required"}), 400

        from werkzeug.utils import secure_filename
        filename = secure_filename(uploaded.filename or "") or "fortigate.conf"
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
        app.config['last_raw_config'] = raw      # Version Advisor 기능 감지용
        app.config['last_runtime_stats'] = {}   # 새 Config 로드 시 CSV stats 초기화

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

        existing = app.config.get('last_runtime_stats') or {}
        existing.update(merged)
        app.config['last_runtime_stats'] = existing

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

        # 기존 stats에 병합 (FW CSV → Proxy CSV 순서로 올려도 둘 다 유지)
        existing = app.config.get('last_runtime_stats') or {}
        existing.update(merged)
        app.config['last_runtime_stats'] = existing
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
        gate = _license_required()
        if gate:
            return gate
        from werkzeug.utils import secure_filename
        payload = request.get_json(silent=True) or {}
        sheets = payload.get("sheets") or {}
        workbook_name = secure_filename(payload.get("workbook_name", "firewall_policy_optimizer_export")) or "firewall_policy_optimizer_export"
        output_path = EXPORT_DIR / f"{workbook_name}.xlsx"
        try:
            build_workbook(output_path, sheets)
        except Exception as exc:
            print(f"[APO] workbook export failed: {exc}", flush=True)
            return jsonify({"error": "Failed to build workbook export"}), 400
        return send_file(output_path, as_attachment=True, download_name=output_path.name)

    @app.get("/exports/<path:filename>")
    def download_export(filename: str):
        from werkzeug.utils import secure_filename
        safe_name = secure_filename(filename)
        if not safe_name or safe_name != filename:
            return jsonify({"error": "Invalid filename"}), 400
        # 무료 산출물(파싱 결과 JSON)만 이 경로로 제공. 유료 산출물(.xlsx 등)은
        # 라이선스 게이트가 걸린 전용 라우트로만 내려가야 하므로 여기서 차단.
        if not safe_name.endswith(".parsed.json"):
            return jsonify({"error": "Not available"}), 404
        return send_from_directory(EXPORT_DIR, safe_name, as_attachment=True)

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
            print(f"[APO] config diff failed: {exc}", flush=True)
            return jsonify({"error": "Failed to compare configs. Check that both files are valid FortiGate configs."}), 500

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
                sev = evaluate_severity(p, context)
                result.append({**p, **sev})
            return result

        from app.services.policy_renderer import build_view_model
        runtime_stats = app.config.get('last_runtime_stats', {})
        view = build_view_model(parsed, runtime_stats)
        return jsonify({
            "firewall": classify_list(view.get("firewall_policy", [])),
            "proxy":    classify_list(view.get("firewall_proxy_policy", [])),
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
        gate = _license_required()
        if gate:
            return gate
        from app.services.workbook_exporter import build_severity_workbook
        payload = request.get_json(silent=True) or {}
        try:
            xlsx_bytes = build_severity_workbook(payload)
        except Exception as exc:
            print(f"[APO] severity workbook export failed: {exc}", flush=True)
            return jsonify({"error": "Failed to build severity export"}), 400
        return app.response_class(
            response=xlsx_bytes,
            status=200,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={"Content-Disposition": "attachment; filename=severity_export.xlsx"}
        )

    # ── Version Advisor ────────────────────────────────────────────────────
    @app.get("/api/version-advisor")
    def version_advisor():
        from app.services.version_advisor import run_advisor
        parsed = app.config.get('last_parsed')
        if not parsed:
            return jsonify({"error": "No config loaded. Upload a config file first."}), 400
        meta = parsed.get("meta", {})
        raw_config = app.config.get('last_raw_config', '')
        result = run_advisor(meta, raw_config)
        return jsonify(result)

    # ── Remediation ───────────────────────────────────────────────────────
    app.config.setdefault('remediation_device', {})

    @app.post("/api/remediation/device")
    def remediation_device_save():
        payload = request.get_json(silent=True) or {}
        try:
            port = int(payload.get("port", 443) or 443)
        except (TypeError, ValueError):
            return jsonify({"error": "port must be a number"}), 400
        if not (1 <= port <= 65535):
            return jsonify({"error": "port out of range"}), 400
        device = {
            "ip":         str(payload.get("ip", "")).strip(),
            "port":       port,
            "token":      str(payload.get("token", "")).strip(),
            "vdom":       str(payload.get("vdom", "root")).strip() or "root",
            "verify_ssl": bool(payload.get("verify_ssl", False)),
        }
        if not device["ip"] or not device["token"]:
            return jsonify({"error": "ip and token are required"}), 400
        app.config['remediation_device'] = device
        return jsonify({"ok": True})

    @app.get("/api/remediation/device/test")
    def remediation_device_test():
        from app.services.remediation_service import test_connection
        device = app.config.get('remediation_device', {})
        if not device.get("ip"):
            return jsonify({"ok": False, "message": "No device registered"}), 400
        return jsonify(test_connection(device))

    @app.get("/api/remediation/candidates")
    def remediation_candidates():
        from app.services.remediation_service import get_candidates
        from app.services.severity_engine import evaluate_severity
        from app.services.policy_renderer import build_view_model
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
        runtime_stats = app.config.get('last_runtime_stats', {})
        view = build_view_model(parsed, runtime_stats)
        def classify(policies):
            return [{**p, **evaluate_severity(p, context)} for p in (policies or [])]
        fw_classified  = classify(view.get("firewall_policy", []))
        prx_classified = classify(view.get("firewall_proxy_policy", []))
        severity_results = {"firewall": fw_classified, "proxy": prx_classified}

        # Severity 탭과 동일한 urgency 분포 계산 → 카운트 불일치 디버그용
        all_classified = fw_classified + prx_classified
        urgency_dist = {}
        for p in all_classified:
            u = p.get("urgency", 0)
            urgency_dist[str(u)] = urgency_dist.get(str(u), 0) + 1

        candidates = get_candidates(parsed, severity_results)
        candidates["_debug"] = {
            "total_policies": len(all_classified),
            "urgency_distribution": urgency_dist,
            "critical_high_total": urgency_dist.get("1", 0) + urgency_dist.get("2", 0),
        }
        return jsonify(candidates)

    @app.post("/api/remediation/apply")
    def remediation_apply():
        from app.services.remediation_service import disable_policies
        device = app.config.get('remediation_device', {})
        if not device.get("ip"):
            return jsonify({"error": "No device registered"}), 400
        payload = request.get_json(silent=True) or {}
        policies = payload.get("policies", [])
        if not policies:
            return jsonify({"error": "No policies selected"}), 400
        results = disable_policies(device, policies)
        return jsonify({"results": results})

    @app.post("/api/remediation/export/postman")
    def remediation_export_postman():
        gate = _license_required()
        if gate:
            return gate
        from app.services.remediation_service import export_postman
        from io import BytesIO
        device = app.config.get('remediation_device', {})
        payload = request.get_json(silent=True) or {}
        policies = payload.get("policies", [])
        json_str = export_postman(policies, device)
        buf = BytesIO(json_str.encode("utf-8"))
        today = _date.today().isoformat()
        return app.response_class(
            response=buf.read(),
            status=200,
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename=apo_remediation_{today}.postman_collection.json"},
        )

    @app.post("/api/remediation/export/csv")
    def remediation_export_csv():
        gate = _license_required()
        if gate:
            return gate
        from app.services.remediation_service import export_csv
        from io import BytesIO
        payload = request.get_json(silent=True) or {}
        csv_bytes = export_csv(
            payload.get("to_disable", []),
            payload.get("already_disabled", []),
        )
        today = _date.today().isoformat()
        return app.response_class(
            response=csv_bytes,
            status=200,
            mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": f"attachment; filename=apo_remediation_{today}.csv"},
        )

    # ── License ────────────────────────────────────────────────────────────
    @app.get("/api/license/status")
    def license_status():
        info = get_license_info()
        if info:
            return jsonify({"licensed": True, "email": info.get("email"), "issued": info.get("issued")})
        return jsonify({"licensed": False})

    @app.post("/api/license/activate")
    def license_activate():
        payload = request.get_json(silent=True) or {}
        key = str(payload.get("key", "")).strip()
        if not key:
            return jsonify({"error": "key is required"}), 400
        try:
            data = activate(key)
            return jsonify({"ok": True, "email": data.get("email"), "issued": data.get("issued")})
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

    return app

"""What the panel page reads from the API (index.html, browser-diagnostics.js) and what the deploy tool relies on.

Key: "METHOD /path" (templates in <angle brackets>); "key#field[]" names the elements of a list field, "key#field"
the object in a field. "*" applies to every JSON answer. The page is tolerant of absent fields it reads behind a
guard (``d.x||...``, ``if(d.x)``), so a field is listed in FRONTEND_CONTRACT only when every successful answer of the
endpoint has it, idle ones included; the fields that exist only in some state (a job was started, it failed, a
download happened) are in FRONTEND_CONDITIONAL with the state. FRONTEND_CONTRACT | FRONTEND_CONDITIONAL is the
set of names this contract tracks for an endpoint. Curated PAGE_READERS in test_panel_contract.py checks the
immutable endpoint readers against this table. Line numbers below are in
tools/router/kdn/web/assets/index.html unless another file is named.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

# Answers with ok: false must say why in one of these (index.html:315 readJson shows output, then error).
ERROR_FIELDS = ("error", "output")

FRONTEND_CONTRACT: dict[str, set[str]] = {
    "*": {"ok"},  # :315
    'GET /api/dns': {'supported','mode','interface','detail','pending','recovery_mode','host_overrides'},
    'POST /api/dns/<mode>': {'job_id'},
    'GET /api/notifications': {'enabled','topic','token_set','events','choices','url','pending','last_delivery','error'},
    'GET /api/notifications#choices[]': {'id','title'},
    'POST /api/notifications/save': {'enabled','topic','token_set','events','choices','url','pending','last_delivery','error'},
    'POST /api/notifications/test': {'queued'},
    'POST /api/notifications/topic': {'topic'},
    'GET /api/inspection/status': {'status', 'active', 'results'},
    'GET /api/vpn-monitor': {'config', 'state', 'identity', 'expected', 'verdict', 'active'},
    'POST /api/inspection/check/<kind>': {'job_id', 'kind', 'status', 'active'},
    'POST /api/inspection/setup': {'job_id'},
    'POST /api/vpn-monitor/save': {'config', 'state', 'identity', 'expected', 'verdict', 'active'},
    'POST /api/vpn-monitor/approve': {'config', 'state', 'identity', 'expected', 'verdict', 'active'},
    # Deploy tool (tools/dev/deploy-remote.sh panel_ready): the page answers 200 HTML (content type: text/html).
    "GET /": set(),
    "GET /api/status": {  # :317
        "discord_tcp_route", "discord_voice_route", "youtube_route", "telegram_route", "xkeen_runtime",
    },
    "GET /api/route/status": {"active", "status", "output"},  # :314, :369-377, :385
    "GET /api/route/result": {"job_id", "status", "result_ok", "active", "output"},  # outcome nullable until terminal
    "GET /api/route/result#node": {"health"},
    "GET /api/history": {"items"},  # :393
    "GET /api/history#items[]": {  # :398-406
        "operation", "created_utc", "status", "before_routes", "service", "rollback_available", "job_id",
    },
    "GET /api/vpn-nodes": {  # :323-327; deploy tool: ok == true
        "active", "nodes", "drift", "warning", "canonical_tag", "recovery_needed",
    },
    "GET /api/vpn-nodes#nodes[]": {  # :330-342, :351
        "id", "name", "active", "protocol", "endpoint", "network", "security", "health", "created_utc",
    },
    "GET /api/vpn-nodes#nodes[].health": {"ok", "checked_utc"},  # :335-336 (health is null until the first check)
    "GET /api/tuner/status": {"status", "active", "log_tail", "result_available"},  # :452, :458; idle included
    "GET /api/diagnostics/status": {"active", "status", "progress", "results"},  # :417-418; browser-diagnostics.js:81-82
    "GET /api/checks/config": {"checks"},  # :411
    "GET /api/checks/config#checks[]": {"ok", "status", "name", "detail"},  # :411
    # Beyond the first list: further reads of the page and of browser-diagnostics.js.
    "GET /api/diagnostics/targets": {"standard", "dpi"},  # browser-diagnostics.js:85-86
    "GET /api/diagnostics/targets#standard[]": {"name", "url"},  # browser-diagnostics.js:48, :51
    "GET /api/diagnostics/targets#dpi[]": {"name", "url"},  # browser-diagnostics.js:48, :51
    "GET /api/imported": {"profiles", "rollback_available"},  # :357
    "GET /api/imported#profiles[]": {"service", "installed"},  # :357
    "GET /api/profile-versions": {"versions"},  # :427
    "GET /api/profile-versions#versions[]": {  # :427
        "id", "service", "created_utc", "active", "reason", "family", "candidate_id", "commit",
    },
    "GET /api/updates": {"status"},  # :429
    "GET /api/tuner/sources": {"status", "commit", "sources"},  # :441
    "GET /api/tuner/sources#sources[]": {"name", "services"},  # :440
    "GET /api/tuner/voice-endpoint": {"endpoint"},  # :445
    "GET /api/tuner/voice-endpoint#endpoint": {"ip", "port", "learned_utc"},  # :444 (endpoint may be null)
    # active here means "a run holds AUTOMATION_RUN_LOCK", not "the schedule is enabled": the deploy tool's busy check.
    "GET /api/automation": {"config", "state", "active", "next_run"},  # :434-437
    "GET /api/automation#config": {"enabled", "times", "services"},  # :434
    "GET /api/automation#config.services[]": {"enabled", "mix_level", "max_candidates", "source_file"},
    "GET /api/automation#state": {"status"},
    "POST /api/route/<svc>/<mode>": {"job_id"},  # :384
    "POST /api/vpn-nodes/activate/<n>": {"job_id"},  # :353
    "POST /api/vpn-nodes/recover": {"job_id"},  # :354
    "POST /api/history/rollback/<id>": {"job_id"},  # :386
    "POST /api/vpn-nodes/check/<id>": {"job_id"},
    "POST /api/vpn-nodes/add": {"node"},
    "POST /api/vpn-nodes/ping/<id>": {"ping"},
    "POST /api/vpn-nodes/ping": {"results"},
    "POST /api/import/apply": {"job_id"},
    "POST /api/import/clear/<service>": {"job_id"},
    "POST /api/import/rollback": {"job_id"},
    "POST /api/profiles/apply/<service>/<version_id>": {"job_id"},
    "POST /api/updates/check": {"status", "source_count", "downloaded_commit", "checked_utc"},  # :429, :431
    "POST /api/diagnostics/start/health": {"job_id", "kind", "status", "active", "progress", "results"},  # :417, :420
    "POST /api/tuner/apply": {"job_id"},
    "POST /api/xkeen/<action>": {"job_id"},
}

# Names the page reads behind a guard that exist only in some state of the endpoint: key -> field -> the state.
FRONTEND_CONDITIONAL: dict[str, dict[str, str]] = {
    "GET /api/route/status": {  # :314, :369-377
        "job_id": "a job was started",
        "stage": "a job was started",
        "stage_label": "a job was started",
        "progress": "a job was started",
        "operation": "a job was started",
        "service": "a job was started",
        "error": "the job failed or its worker died",
    },
    "GET /api/history#items[]": {  # :398-406, route history and VPN switch records
        "snapshot": "the job finished or its worker died",
        "after_routes": "the job finished and captured its routes",
        "requested_routes": "a switch was requested",
        "outbound_tag": "a VPN outbound was selected",
        "output_tail": "the worker wrote output",
        "finished_utc": "the job finished",
        "error": "the job failed",
    },
    "GET /api/tuner/status": {  # :453, :455, :457, :460
        "error": "the job failed",
        "service": "a job was started",
        "candidate_count": "the job listed its candidates",
        "found": "status is found",
        "current_candidate": "a candidate is being tested",
        "source_file": "a source file was selected",
        "commit": "Flowseal sources were resolved",
        "last_probe_detail": "a detailed network probe completed",
        "baseline_result": "the baseline probe suite completed",
        "last_suite_result": "a candidate probe suite completed",
        "voice_traffic_baseline": "voice traffic baseline was inspected",
        "last_voice_traffic": "voice traffic was inspected for a candidate",
        "voice_auto_mode": "voice calibration completed",
        "last_voice_auto": "automatic voice probe completed",
        "voice_unconfirmed": "audio still requires manual confirmation",
        "voice_calibration": "voice endpoint was calibrated",
    },
    "GET /api/automation#state": {
        "phase": "a schedule run was started",
        "current_service": "a schedule run selected a service",
        "events": "a schedule run recorded events",
        "error": "a run finished or reported an error",
    },
    "GET /api/diagnostics/status": {  # :417-418
        "job_id": "a job was started",
        "kind": "a job was started",
        "summary": "the job completed",
        "error": "the job failed",
    },
    "GET /api/updates": {  # :429
        "error": "status is error",
        "downloaded_commit": "sources were downloaded",
        "source_count": "sources were downloaded",
        "checked_utc": "an update check ran",
    },
    "GET /api/tuner/sources": {"error": "status is error"},  # :441
    "GET /api/imported#profiles[]": {  # :357
        "family": "the profile is installed",
        "candidate_id": "the profile is installed",
        "installed_utc": "the profile is installed",
        "error": "the profile file is damaged",
    },
    "GET /api/vpn-nodes#nodes[]": {
        'ping': 'a quick HTTP ping was recorded',
        "flow": "extended connection metadata; null when absent",
        "fingerprint": "extended connection metadata; null when absent",
        "sni": "extended connection metadata; null when absent",
    },
    "GET /api/vpn-nodes#nodes[].health": {  # :336
        "latency_ms": "the check passed",
        "http_code": "the check passed",
        "detail": "the check failed",
    },
    "GET /api/route/result": {
        "error": "the operation failed", "code": "the operation finished",
        "health": "an apply/clear/rollback succeeded and health ran", "node": "a VPN node was added",
        "health_error": "the operation succeeded but its health check raised", "snapshot": "the operation has a snapshot field",
    },
}

# Fields that must be JSON booleans: the deploy tool tests `.active == true` (tools/dev/deploy-remote.sh check_idle).
BOOLEAN_FIELDS: dict[str, set[str]] = {
    "GET /api/route/status": {"active"},
    "GET /api/route/result": {"active"},
    "GET /api/tuner/status": {"active"},
    "GET /api/diagnostics/status": {"active"},
    "GET /api/automation": {"active"},
}


def all_fields(key: str) -> set[str]:
    """Every name the page knows about the endpoint (the contract plus the conditional fields)."""
    return FRONTEND_CONTRACT.get(key, set()) | set(FRONTEND_CONDITIONAL.get(key, {}))


def missing_fields(key: str, payload: Mapping[str, Any], also: Iterable[str] = ()) -> list[str]:
    """What the answer lacks: "*" rules, the contract of `key`, `also` (conditional fields expected in this state).

    A boolean field of BOOLEAN_FIELDS with another type is reported as "<name> (bool)".
    """
    unknown = set(also) - set(FRONTEND_CONDITIONAL.get(key, {}))
    if unknown:
        raise KeyError(f"not conditional fields of {key!r}: {sorted(unknown)}")
    answer = "#" not in key  # "*" is about whole answers, not about the objects inside them
    expected = FRONTEND_CONTRACT.get(key, set()) | set(also) | (FRONTEND_CONTRACT["*"] if answer else set())
    problems = [name for name in sorted(expected) if name not in payload]
    if answer and payload.get("ok") is False and not any(name in payload for name in ERROR_FIELDS):
        problems.append("|".join(ERROR_FIELDS))
    problems.extend(f"{name} (bool)" for name in sorted(BOOLEAN_FIELDS.get(key, set()))
                    if name in payload and not isinstance(payload[name], bool))
    return problems

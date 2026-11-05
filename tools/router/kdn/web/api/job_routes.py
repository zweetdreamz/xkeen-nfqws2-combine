"""Job status/result, starts and cancellation; domain modules own all process work."""
from kdn.common import errors
from kdn.web.api import router
from kdn.web.infra import config as cfg
from kdn.web.infra import jobfiles
from kdn.web.domain import automation
from kdn.web.domain import diagnostic_jobs
from kdn.web.domain import refusals
from kdn.web.domain import route_jobs
from kdn.web.domain import tuner_jobs
from kdn.web.domain import vpn


def get_route_status(request):
    return router.json_response(200, route_jobs.route_status())


def get_route_result(request):
    return router.json_response(200, route_jobs.route_result(request.query.get("job_id")))


def get_tuner_status(request):
    return router.json_response(200, tuner_jobs.tuner_status())


def get_diagnostic_status(request):
    return router.json_response(200, diagnostic_jobs.diagnostic_status())


def get_automation(request):
    return router.json_response(200, automation.automation_status())


def post_route_start(request):
    return router.json_response(202, route_jobs.start_route_job(request.params["service"], request.params["mode"]))


def post_history_rollback(request):
    return router.json_response(202, route_jobs.start_history_rollback(request.params["job_id"]))


def post_vpn_activate(request):
    return router.json_response(202, vpn.start_vpn_node_job(request.params["name"]))


def post_vpn_recover(request):
    return router.json_response(202, vpn.start_vpn_recovery_job())


def post_tuner_start(request):
    if not cfg.AUTOTUNER.is_file():
        return router.error_response(500, f"autotuner not found: {cfg.AUTOTUNER}")
    jobfiles.COORDINATOR.ensure_idle(refusals.TUNER_START)
    settings = tuner_jobs.validate_tuner_request(request.body)
    tuner_jobs.start_tuner_job(settings)
    payload = tuner_jobs.tuner_status()
    payload["active"] = True
    payload.setdefault("service", settings["service"])
    return router.json_response(202, payload)


def post_tuner_cancel(request):
    tuner_jobs.cancel_tuner_job()
    return router.json_response(202, {**tuner_jobs.tuner_status(), "ok": True, "status": "cancelling", "active": True})


def post_tuner_verdict(request):
    body = request.body
    if not isinstance(body, dict) or set(body) != {"works"} or not isinstance(body["works"], bool):
        return router.error_response(400, "ожидается единственный bool-параметр works")
    tuner_jobs.submit_voice_verdict(body["works"])
    return router.json_response(202, tuner_jobs.tuner_status())


def post_diagnostic_start(request):
    if not cfg.DIAGNOSTICS.is_file():
        return router.error_response(500, f"diagnostics not found: {cfg.DIAGNOSTICS}")
    return router.json_response(202, diagnostic_jobs.start_diagnostic_job(request.params["kind"]))


def post_diagnostic_cancel(request):
    diagnostic_jobs.cancel_diagnostic_job()
    return router.json_response(202, {**diagnostic_jobs.diagnostic_status(), "ok": True, "status": "cancelling", "active": True})


JOB_ROUTES = (
    router.Route("GET", "/api/route/status", get_route_status, errors=()),
    router.Route("GET", "/api/route/result", get_route_result, errors=((errors.NotFound, 404),)),
    router.Route("GET", "/api/tuner/status", get_tuner_status, errors=()),
    router.Route("GET", "/api/diagnostics/status", get_diagnostic_status, errors=()),
    router.Route("GET", "/api/automation", get_automation, errors=((OSError, 500), (ValueError, 500))),
    router.Route("POST", "/api/route/<service>/<mode>", post_route_start,
                 choices={"service": cfg.ROUTE_REQUEST_SERVICES, "mode": {"direct", "zapret", "vpn", "ws", "unmanaged"}}),
    router.Route("POST", "/api/history/rollback/<job_id>", post_history_rollback),
    router.Route("POST", "/api/vpn-nodes/activate/<name>", post_vpn_activate, errors=router.DEFAULT_ERRORS + ((TypeError, 400),)),
    router.Route("POST", "/api/vpn-nodes/recover", post_vpn_recover, errors=router.DEFAULT_ERRORS + ((TypeError, 400),)),
    router.Route("POST", "/api/tuner/start", post_tuner_start),
    router.Route("POST", "/api/tuner/cancel", post_tuner_cancel, errors=((OSError, 409), (RuntimeError, 409))),
    router.Route("POST", "/api/tuner/verdict", post_tuner_verdict,
                 errors=((OSError, 409), (RuntimeError, 409), (ValueError, 409))),
    router.Route("POST", "/api/diagnostics/start/<kind>", post_diagnostic_start),
    router.Route("POST", "/api/diagnostics/cancel", post_diagnostic_cancel, errors=((OSError, 409), (RuntimeError, 409))),
)

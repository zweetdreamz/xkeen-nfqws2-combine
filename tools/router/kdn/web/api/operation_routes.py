"""Live-changing actions enqueue (202); metadata-only VPN addition returns 200."""
from kdn.web.api import router
from kdn.web.infra import config as cfg
from kdn.web.infra import jobfiles
from kdn.web.domain import operations
from kdn.web.domain import refusals
from kdn.web.domain import validation
from kdn.web.domain import vpn


def post_xkeen(request):
    return router.json_response(202, operations.start_xkeen_job(request.params["action"]))


def post_import_apply(request):
    profile = validation.validate_report(request.body)
    jobfiles.COORDINATOR.ensure_idle(refusals.PROFILE_APPLY)
    return router.json_response(202, operations.start_apply_job(profile))


def post_tuner_apply(request):
    jobfiles.COORDINATOR.ensure_idle(refusals.TUNER_APPLY)
    return router.json_response(202, operations.start_tuner_apply_job())


def post_version_apply(request):
    jobfiles.COORDINATOR.ensure_idle(refusals.VERSION_APPLY)
    return router.json_response(202, operations.start_version_apply_job(request.params["service"], request.params["version_id"]))


def post_import_clear(request):
    jobfiles.COORDINATOR.ensure_idle(refusals.PROFILE_CLEAR)
    return router.json_response(202, operations.start_import_clear_job(request.params["service"]))


def post_import_rollback(request):
    jobfiles.COORDINATOR.ensure_idle(refusals.IMPORT_ROLLBACK)
    return router.json_response(202, operations.start_import_rollback_job())


def post_vpn_add(request):
    body = request.body
    if (not isinstance(body, dict) or set(body) - {'name', 'source', 'name_hint'}
            or not isinstance(body.get('source'), str) or len(body['source']) > 32768
            or ('name' in body and not isinstance(body['name'], str))
            or ('name_hint' in body and not isinstance(body['name_hint'], str))
            or ('name' in body and 'name_hint' in body)):
        return router.error_response(400, "ожидается ссылка/JSON outbound до 32 КиБ")
    if 'name' in body:
        return router.json_response(200, vpn.add_node(body['name'], body['source']))
    return router.json_response(200, vpn.add_node(body.get('name_hint', ''), body['source'], auto_name=True))


def post_vpn_check(request):
    return router.json_response(202, operations.start_vpn_check_job(request.params["node_id"]))


OPERATION_ROUTES = tuple(router.Route("POST", path, callback, errors=router.DEFAULT_ERRORS + ((TypeError, 400),), choices=choices)
    for path, callback, choices in (
        ("/api/xkeen/<action>", post_xkeen, {"action": {"start", "stop", "restart"}}),
        ("/api/import/apply", post_import_apply, {}), ("/api/tuner/apply", post_tuner_apply, {}),
        ("/api/profiles/apply/<service>/<version_id>", post_version_apply, {}),
        ("/api/import/clear/<service>", post_import_clear, {"service": cfg.SERVICES}),
        ("/api/import/rollback", post_import_rollback, {}), ("/api/vpn-nodes/add", post_vpn_add, {}),
        ("/api/vpn-nodes/check/<node_id>", post_vpn_check, {}),
    ))

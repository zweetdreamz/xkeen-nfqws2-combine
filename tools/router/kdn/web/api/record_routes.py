"""Synchronous record operations; router-changing commands belong to job routes."""
from kdn.common import errors
from kdn.web.api import router
from kdn.web.domain import automation
from kdn.web.domain import flowseal
from kdn.web.domain import history
from kdn.web.domain import profiles
from kdn.web.domain import validation
from kdn.web.domain import vpn


def post_history_delete(request):
    return router.json_response(200, history.delete_history_record(request.params["job_id"]))


def post_version_delete(request):
    return router.json_response(200, profiles.delete_profile_version(request.params["service"], request.params["version_id"]))


def post_vpn_delete(request):
    return router.json_response(200, vpn.remove_node(request.params["node_id"]))


def post_vpn_sync(request):
    return router.json_response(200, vpn.sync_current())


def post_vpn_update(request):
    return router.json_response(200, vpn.update_node(request.params['node_id'], request.body))


def post_updates_check(request):
    return router.json_response(200, flowseal.check_flowseal_update())


def post_import_validate(request):
    return router.json_response(200, {"ok": True, "profile": validation.validate_report(request.body)})


def post_automation_save(request):
    config = automation.validate_automation_config(request.body)
    return router.json_response(200, automation.save_automation_config(config))


def post_automation_cancel(request):
    if not automation.AUTOMATION_RUN_LOCK.locked():
        raise errors.Busy("задание расписания не выполняется")
    if automation.automation_state().get("phase") == "recovering":
        raise errors.Busy("автоматическое восстановление нельзя остановить")
    automation.AUTOMATION_CANCEL.set()
    return router.json_response(202, {"ok": True, "status": "cancelling"})


RECORD_ROUTES = (
    router.Route("POST", "/api/history/delete/<job_id>", post_history_delete),
    router.Route("POST", "/api/profile-versions/delete/<service>/<version_id>", post_version_delete),
    router.Route("POST", "/api/vpn-nodes/delete/<node_id>", post_vpn_delete, errors=router.DEFAULT_ERRORS + ((TypeError, 400),)),
    router.Route("POST", "/api/vpn-nodes/sync-current", post_vpn_sync, errors=router.DEFAULT_ERRORS + ((TypeError, 400),)),
    router.Route("POST", "/api/vpn-nodes/update/<node_id>", post_vpn_update, errors=router.DEFAULT_ERRORS + ((TypeError, 400),)),
    router.Route("POST", "/api/updates/check", post_updates_check, errors=((OSError, 502), (RuntimeError, 502), (ValueError, 502))),
    router.Route("POST", "/api/import/validate", post_import_validate, errors=((ValueError, 400),)),
    router.Route("POST", "/api/automation/save", post_automation_save, errors=((ValueError, 400), (OSError, 400))),
    router.Route("POST", "/api/automation/cancel", post_automation_cancel, automation_blocks=False),
)

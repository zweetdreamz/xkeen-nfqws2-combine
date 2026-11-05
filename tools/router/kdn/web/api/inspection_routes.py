"""Independent route/resource checks and explicit VPN IP policy controls."""
from kdn.web.api import router
from kdn.web.domain import inspection, operations, vpn_monitor, notifications
from kdn.web.infra import engine


def get_inspection_status(request):
    return router.json_response(200, inspection.inspection_status())


def get_monitor(request):
    return router.json_response(200, vpn_monitor.vpn_monitor_status())


def post_check(request):
    return router.json_response(202, inspection.start(request.params['kind'], request.body))


def post_save(request):
    if not isinstance(request.body, dict) or set(request.body) != {'identity', 'changes'}:
        raise ValueError('ожидаются identity и changes')
    return router.json_response(200, vpn_monitor.save(request.body['changes'], request.body['identity']))


def post_approve(request):
    if not isinstance(request.body, dict) or set(request.body) != {'families', 'identity', 'observation_id'}:
        raise ValueError('ожидаются family, identity и ID показанного наблюдения')
    return router.json_response(200, vpn_monitor.approve_vpn_monitor_ips(
        request.body['families'], request.body['identity'], request.body['observation_id']))


def post_setup(request):
    if request.body != {'confirm': True}:
        raise ValueError('подтвердите настройку loopback API/SOCKS и перезапуск Xray с той же нодой')
    return router.json_response(202, operations.start_inspection_setup())


def get_notifications(request):
    return router.json_response(200, notifications.notification_status())


def get_dns_status(request):
    engine.require_supported_target()
    return router.json_response(200, engine.read_dns_mode())


def post_dns_switch(request):
    if not isinstance(request.body, dict) or set(request.body) != {'confirm'} or request.body['confirm'] is not True:
        raise ValueError('подтвердите переключение DNS и сохранение конфигурации Keenetic')
    return router.json_response(202, operations.start_dns_switch(request.params['mode']))


def post_notifications_save(request):
    return router.json_response(200, notifications.save_notifications(request.body))


def post_notifications_test(request):
    if request.body != {}:
        raise ValueError('ожидается пустой объект')
    return router.json_response(202, notifications.notification_test())


def post_notifications_topic(request):
    import secrets
    if request.body != {}:
        raise ValueError('ожидается пустой объект')
    return router.json_response(200, {'ok': True, 'topic': 'kdn-' + secrets.token_hex(24)})


ROUTES = (
    router.Route('GET', '/api/dns', get_dns_status,
                 errors=router.DEFAULT_ERRORS[:1]+((RuntimeError,500),(ValueError,500),(OSError,500))),
    router.Route('POST', '/api/dns/<mode>', post_dns_switch, choices={'mode': ('vless', 'doh')}),
    router.Route('GET', '/api/notifications', get_notifications),
    router.Route('POST', '/api/notifications/save', post_notifications_save),
    router.Route('POST', '/api/notifications/test', post_notifications_test),
    router.Route('POST', '/api/notifications/topic', post_notifications_topic),
    router.Route('GET', '/api/inspection/status', get_inspection_status),
    router.Route('GET', '/api/vpn-monitor', get_monitor),
    router.Route('POST', '/api/inspection/check/<kind>', post_check, choices={'kind': ('route', 'resources', 'vpn')}),
    router.Route('POST', '/api/inspection/setup', post_setup),
    router.Route('POST', '/api/vpn-monitor/save', post_save),
    router.Route('POST', '/api/vpn-monitor/approve', post_approve),
)

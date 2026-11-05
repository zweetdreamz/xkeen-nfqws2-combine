"""Checks every request passes before its route: the client, the control header, the Host and the Origin."""

import ipaddress
from urllib.parse import urlsplit

from kdn.web.api import router


def private_client(address):
    try:
        ip = ipaddress.ip_address(address)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


def check_request(request, *, bind_host, port):
    """None when the request may go on, else the 403 Response.

    Order: client, control header (POST), Host, Origin (POST).
    """
    if not private_client(request.client):
        return router.error_response(403, "client is outside LAN")
    post = request.method == "POST"
    if post and request.header("X-XKeen-Control") != "1":
        return router.error_response(403, "control header missing")
    origin = request.header("Origin")
    host = request.header("Host")
    if host not in {bind_host, f"{bind_host}:{port}"}:
        return router.error_response(403, "unexpected Host header")
    if post and origin and urlsplit(origin).netloc != host:
        return router.error_response(403, "cross-origin request denied")
    return None

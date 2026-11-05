"""Tests of kdn.web.api.router and kdn.web.api.security: routing, error mapping and the request checks.

The routes run through ``Router.dispatch(Request(...))``, without sockets. ``SecurityEquivalenceTests`` runs one
request matrix against the Handler of kdn.web.app (a real server on 127.0.0.1) and against ``check_request``.
"""

from __future__ import annotations

import ast
import dataclasses
import importlib
import itertools
import json
import socket
import threading
import unittest

import panel_harness


class RouterCase(panel_harness.PanelTestCase):
    """Shared helpers of the tests that take router and security on their own."""

    modules = ("kdn.web.api.router", "kdn.web.api.security")

    def request(self, method="GET", path="/", **fields):
        return self.ns["Request"](method, path, **fields)

    def route(self, method, pattern, handler=None, **fields):
        return self.ns["Route"](method, pattern, handler or self.answer(pattern), **fields)

    def answer(self, label, status=200):
        def handler(request):
            return self.ns["json_response"](status, {"label": label, "params": request.params})

        return handler

    def router(self, *routes):
        return self.ns["Router"](routes)

    def body(self, response):
        return json.loads(response.body.decode("utf-8"))

    def assertError(self, response, status, message):
        self.assertEqual(response.status, status)
        self.assertEqual(response.content_type, "application/json; charset=utf-8")
        self.assertEqual(response.body, json.dumps({"ok": False, "error": message}, ensure_ascii=False).encode("utf-8"))


class MatchTests(RouterCase):
    ns_name = "panel_api_match_test"

    def test_literal_and_parameter_segments(self):
        root = self.route("GET", "/")
        status = self.route("GET", "/api/status")
        delete = self.route("GET", "/api/history/delete/<job_id>")
        start = self.route("GET", "/api/route/<service>/<mode>")
        router = self.router(root, status, delete, start)
        cases = (
            ("/", root, {}),
            ("/api/status", status, {}),
            ("/api/history/delete/abc-1", delete, {"job_id": "abc-1"}),
            ("/api/route/youtube/zapret", start, {"service": "youtube", "mode": "zapret"}),
        )
        for path, route, params in cases:
            with self.subTest(path=path):
                match = router.match("GET", path)
                self.assertIs(match.route, route)
                self.assertEqual(match.params, params)
        for path in ("/api/Status", "/api/statu", "/api/status/x", "/api/history/delete", "api/status", "", "/x"):
            with self.subTest(no_route=path):
                self.assertIsNone(router.match("GET", path))

    def test_parameter_captures_one_segment_only(self):
        router = self.router(self.route("GET", "/x/<a>"), self.route("GET", "/y/<a>/z"))
        self.assertEqual(router.match("GET", "/x/1").params, {"a": "1"})
        self.assertEqual(router.match("GET", "/y/1/z").params, {"a": "1"})
        for path in ("/x", "/x/1/2", "/y/1", "/y/1/2/z", "/y/z"):
            with self.subTest(path=path):
                self.assertIsNone(router.match("GET", path))
        # Nothing is percent-decoded: an encoded slash stays inside the one segment.
        self.assertEqual(router.match("GET", "/x/a%2Fb").params, {"a": "a%2Fb"})
        # A path that does not start with / is no path, not a path with its first character cut off.
        self.assertIsNone(router.match("GET", "Zx/1"))

    def test_trailing_slash_and_empty_segment_do_not_match(self):
        router = self.router(
            self.route("GET", "/"),
            self.route("GET", "/api/status"),
            self.route("GET", "/x/<a>"),
            self.route("GET", "/y/<a>/z"),
        )
        for path in ("/api/status/", "/x/1/", "/x/", "/y//z", "/y/1/z/", "//", "/api//status", "//api/status"):
            with self.subTest(path=path):
                self.assertIsNone(router.match("GET", path))
        self.assertIsNotNone(router.match("GET", "/"))

    def test_literal_wins_over_a_parameter_in_either_order(self):
        literal = self.route("POST", "/api/vpn-nodes/recover")
        parameter = self.route("POST", "/api/vpn-nodes/<name>")
        for routes in ((literal, parameter), (parameter, literal)):
            router = self.router(*routes)
            self.assertIs(router.match("POST", "/api/vpn-nodes/recover").route, literal)
            self.assertIs(router.match("POST", "/api/vpn-nodes/other").route, parameter)

    def test_the_query_does_not_take_part_in_matching(self):
        router = self.router(self.route("GET", "/api/route/result"), self.route("GET", "/api/history/delete/<job_id>"))
        for target, route_path in (
            ("/api/route/result?job_id=1", "/api/route/result"),
            ("/api/history/delete/a?x=y", "/api/history/delete/<job_id>"),
        ):
            with self.subTest(target=target):
                path, _query = self.ns["split_target"](target)
                self.assertEqual(router.match("GET", path).route.pattern, route_path)

    def test_method_is_part_of_the_key(self):
        get = self.route("GET", "/api/x")
        post = self.route("POST", "/api/x")
        router = self.router(get, post)
        self.assertIs(router.match("GET", "/api/x").route, get)
        self.assertIs(router.match("POST", "/api/x").route, post)
        for method in ("PUT", "DELETE", "HEAD", "get", ""):
            with self.subTest(method=method):
                self.assertIsNone(router.match(method, "/api/x"))
        only_get = self.router(get)
        self.assertEqual(only_get.dispatch(self.request("POST", "/api/x")).status, 404)
        get_item = self.route("GET", "/api/item/<id>")
        post_item = self.route("POST", "/api/item/<id>")
        items = self.router(get_item, post_item)
        self.assertIs(items.match("GET", "/api/item/1").route, get_item)
        self.assertIs(items.match("POST", "/api/item/1").route, post_item)
        self.assertIsNone(items.match("PUT", "/api/item/1"))
        self.assertIsNone(self.router(get_item).match("POST", "/api/item/1"))

    def test_duplicate_route_is_refused(self):
        with self.assertRaisesRegex(ValueError, "duplicate route GET /api/x"):
            self.router(self.route("GET", "/api/x"), self.route("GET", "/api/x"))
        with self.assertRaisesRegex(ValueError, "duplicate route POST /api/<a>"):
            self.router(self.route("POST", "/api/<a>"), self.route("GET", "/api/<a>"), self.route("POST", "/api/<a>"))
        # The same pattern under another method, and the same shape under another parameter name, are no duplicates.
        self.router(self.route("GET", "/api/x"), self.route("POST", "/api/x"))

    def test_malformed_patterns_are_refused(self):
        for pattern in (
            "api/x", "", "/api/x/", "/api//x", "//", "/api/<>", "/api/<1a>", "/api/<a-b>", "/api/a<b>", "/api/<a>b",
            "/api/<a", "/api/a>", "/api/<a>/<a>",
        ):
            with self.subTest(pattern=pattern):
                with self.assertRaises(ValueError):
                    self.route("GET", pattern)
        with self.assertRaisesRegex(ValueError, "no such parameter"):
            self.route("GET", "/api/<a>", choices={"b": ("x",)})

    def test_choices_restrict_a_parameter(self):
        route = self.route(
            "POST",
            "/api/route/<service>/<mode>",
            choices={"service": ("discord-tcp", "youtube"), "mode": frozenset({"direct", "zapret"})},
        )
        router = self.router(route)
        self.assertEqual(router.match("POST", "/api/route/youtube/direct").params, {"service": "youtube", "mode": "direct"})
        for path in ("/api/route/telegram/direct", "/api/route/youtube/vpn", "/api/route/youtube/", "/api/route//direct"):
            with self.subTest(path=path):
                self.assertIsNone(router.match("POST", path))
        self.assertError(router.dispatch(self.request("POST", "/api/route/youtube/vpn")), 404, "unknown action")
        self.assertEqual(self.body(router.dispatch(self.request("POST", "/api/route/youtube/zapret")))["params"],
                         {"service": "youtube", "mode": "zapret"})

    def test_choices_limit_only_the_named_parameter(self):
        router = self.router(self.route("GET", "/a/<kind>/<name>", choices={"kind": ("x",)}))
        self.assertEqual(router.match("GET", "/a/x/anything").params, {"kind": "x", "name": "anything"})
        self.assertIsNone(router.match("GET", "/a/y/anything"))

    def test_a_failed_choice_lets_a_later_route_of_the_same_shape_match(self):
        narrow = self.route("GET", "/a/<kind>", choices={"kind": ("x",)})
        wide = self.route("GET", "/a/<other>")
        router = self.router(narrow, wide)
        self.assertIs(router.match("GET", "/a/x").route, narrow)
        self.assertIs(router.match("GET", "/a/y").route, wide)

    def test_route_and_request_defaults(self):
        route = self.route("GET", "/x")
        self.assertIsNone(route.errors)
        self.assertIs(route.automation_blocks, True)
        self.assertIs(route.heavy, False)
        self.assertEqual(route.choices, {})
        self.assertIsNot(route.choices, self.route("GET", "/y").choices)
        request = self.request()
        self.assertEqual(
            (request.method, request.path, request.query, request.headers, request.client, request.body, request.params),
            ("GET", "/", {}, {}, "", None, {}),
        )
        other = self.request()
        for name in ("query", "headers", "params"):
            with self.subTest(field=name):
                self.assertIsNot(getattr(request, name), getattr(other, name))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            request.path = "/other"
        response = self.ns["Response"](200, b"", "text/plain")
        self.assertEqual(response.headers, {})
        self.assertIsNot(response.headers, self.ns["Response"](200, b"", "text/plain").headers)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            response.status = 500


class SplitTargetTests(RouterCase):
    ns_name = "panel_api_target_test"

    def test_split_target_separates_the_query(self):
        split = self.ns["split_target"]
        cases = {
            "/api/x": ("/api/x", {}),
            "/api/x?": ("/api/x", {}),
            "/": ("/", {}),
            "/?": ("/", {}),
            "/api/route/result?job_id=abc": ("/api/route/result", {"job_id": "abc"}),
            "/p?a=1&a=2&b=3": ("/p", {"a": "1", "b": "3"}),
            "/p?a=2&a=1": ("/p", {"a": "2"}),
            "/p?a=": ("/p", {"a": ""}),
            "/p?a=&a=2": ("/p", {"a": ""}),
            "/p?a": ("/p", {"a": ""}),
            "/p?a=1&&b=2": ("/p", {"a": "1", "b": "2"}),
            "/p?q=%D0%BF%D1%80+x": ("/p", {"q": "пр x"}),
            "/p?a=1?b=2": ("/p", {"a": "1?b=2"}),
            "//x?a=1": ("//x", {"a": "1"}),
            "/p/": ("/p/", {}),
        }
        for target, expected in cases.items():
            with self.subTest(target=target):
                self.assertEqual(split(target), expected)

    def test_split_target_keeps_the_path_as_it_came(self):
        # The path is neither decoded nor trimmed: the router compares it whole.
        self.assertEqual(self.ns["split_target"]("/a%2Fb/%D0%BF/"), ("/a%2Fb/%D0%BF/", {}))


class RequestTests(RouterCase):
    ns_name = "panel_api_request_test"

    def test_header_lookup_ignores_the_case_of_the_name(self):
        request = self.request(headers={"Host": "a", "x-xkeen-control": "1", "ORIGIN": ""})
        self.assertEqual(request.header("host"), "a")
        self.assertEqual(request.header("HOST"), "a")
        self.assertEqual(request.header("X-XKeen-Control"), "1")
        self.assertEqual(request.header("Origin"), "")
        self.assertIsNone(request.header("Content-Type"))
        self.assertIsNone(self.request().header("Host"))

    def test_the_first_header_of_a_name_wins(self):
        request = self.request(headers={"host": "first", "Host": "second"})
        self.assertEqual(request.header("HOST"), "first")


class DispatchTests(RouterCase):
    ns_name = "panel_api_dispatch_test"

    def test_dispatch_404_texts_for_get_and_post(self):
        router = self.router(self.route("GET", "/api/known"))
        self.assertError(router.dispatch(self.request("GET", "/api/other")), 404, "unknown endpoint")
        self.assertError(router.dispatch(self.request("POST", "/api/other")), 404, "unknown action")
        # A known path under another method is unknown too; everything that is not GET is an "action".
        self.assertError(router.dispatch(self.request("POST", "/api/known")), 404, "unknown action")
        for method in ("PUT", "DELETE", "HEAD"):
            with self.subTest(method=method):
                self.assertError(router.dispatch(self.request(method, "/api/other")), 404, "unknown action")

    def test_default_error_table(self):
        ns = self.ns
        decode = json.JSONDecodeError("bad json", "{", 1)
        cases = (
            (ns["Busy"]("занято"), 409),
            (RuntimeError("runtime"), 409),
            (ns["BadRequest"]("плохо"), 400),
            (ValueError("value"), 400),
            (decode, 400),
            (UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad byte"), 400),
            (FileNotFoundError("missing"), 400),
            (OSError("os"), 400),
            (ns["NotFound"]("нет"), 404),
            (ns["Upstream"]("upstream"), 502),
            (ns["PanelError"]("panel"), 500),
        )
        for exc, status in cases:
            with self.subTest(exc=type(exc).__name__, message=str(exc)):
                router = self.router(self.route("POST", "/x", self.raising(exc)))
                self.assertError(router.dispatch(self.request("POST", "/x")), status, str(exc))

    def raising(self, exc):
        def handler(_request):
            raise exc

        return handler

    def test_status_of_a_panel_error_wins_over_the_builtin_base(self):
        class Teapot(self.ns["PanelError"], ValueError):
            status = 418

        self.assertEqual(self.ns["status_for"](Teapot("t"), self.ns["DEFAULT_ERRORS"]), 418)
        router = self.router(self.route("GET", "/x", self.raising(Teapot("чайник"))))
        self.assertError(router.dispatch(self.request("GET", "/x")), 418, "чайник")

    def test_status_for_walks_the_table_in_order(self):
        status_for = self.ns["status_for"]
        table = ((ValueError, 418), (self.ns["BadRequest"], 400), (self.ns["PanelError"], None))
        self.assertEqual(status_for(self.ns["BadRequest"]("x"), table), 418)
        self.assertEqual(status_for(self.ns["Upstream"]("x"), table), 502)
        self.assertIsNone(status_for(KeyError("x"), table))
        self.assertIsNone(status_for(ValueError("x"), ()))
        self.assertEqual(status_for(self.ns["Busy"]("x"), self.ns["DEFAULT_ERRORS"]), 409)
        self.assertEqual(
            self.ns["DEFAULT_ERRORS"],
            ((self.ns["PanelError"], None), (RuntimeError, 409), (ValueError, 400), (OSError, 400)),
        )

    def test_route_error_table_overrides_the_default(self):
        table = ((OSError, 500), (RuntimeError, 502))

        def failing(exc):
            return self.router(self.route("GET", "/x", self.raising(exc), errors=table))

        self.assertError(failing(OSError("диск")).dispatch(self.request("GET", "/x")), 500, "диск")
        self.assertError(failing(FileNotFoundError("нет")).dispatch(self.request("GET", "/x")), 500, "нет")
        self.assertError(failing(RuntimeError("r")).dispatch(self.request("GET", "/x")), 502, "r")
        # Busy is a RuntimeError, and this table has no PanelError entry: the route's table decides, not exc.status.
        self.assertError(failing(self.ns["Busy"]("занято")).dispatch(self.request("GET", "/x")), 502, "занято")
        # ValueError is in the default table but not in this one: it is not mapped.
        with self.assertRaises(ValueError):
            failing(ValueError("v")).dispatch(self.request("GET", "/x"))

    def test_a_none_status_in_a_route_table_takes_the_exception_status(self):
        table = ((self.ns["PanelError"], None), (OSError, 409))
        router = self.router(self.route("GET", "/x", self.raising(self.ns["Upstream"]("u")), errors=table))
        self.assertError(router.dispatch(self.request("GET", "/x")), 502, "u")

    def test_an_empty_route_table_maps_nothing(self):
        router = self.router(self.route("GET", "/x", self.raising(RuntimeError("r")), errors=()))
        with self.assertRaises(RuntimeError):
            router.dispatch(self.request("GET", "/x"))

    def test_unlisted_exception_propagates(self):
        for exc in (KeyError("k"), TypeError("t"), ZeroDivisionError("z"), AttributeError("a"), LookupError("l")):
            with self.subTest(exc=type(exc).__name__):
                router = self.router(self.route("POST", "/x", self.raising(exc)))
                with self.assertRaises(type(exc)) as caught:
                    router.dispatch(self.request("POST", "/x"))
                self.assertIs(caught.exception, exc)

    def test_a_handler_error_text_with_cyrillic_stays_readable(self):
        router = self.router(self.route("POST", "/x", self.raising(self.ns["Busy"]("сначала завершите диагностику"))))
        response = router.dispatch(self.request("POST", "/x"))
        self.assertIn("сначала завершите диагностику".encode("utf-8"), response.body)
        self.assertNotIn(b"\\u", response.body)

    def test_handler_receives_params_and_the_original_request_fields(self):
        seen = []

        def handler(request):
            seen.append(request)
            return self.ns["json_response"](202, {"ok": True})

        router = self.router(self.route("POST", "/api/item/<kind>/<name>", handler))
        original = self.request(
            "POST",
            "/api/item/a/b",
            query={"q": "1"},
            headers={"Host": "h", "X-XKeen-Control": "1"},
            client="192.168.2.10",
            body={"k": [1, 2]},
        )
        response = router.dispatch(original)
        self.assertEqual(response.status, 202)
        (received,) = seen
        self.assertEqual(received.params, {"kind": "a", "name": "b"})
        for name in ("method", "path", "query", "headers", "client", "body"):
            with self.subTest(field=name):
                self.assertEqual(getattr(received, name), getattr(original, name))
        self.assertEqual(original.params, {})
        self.assertIsNot(received, original)

    def test_dispatch_uses_the_match_it_is_given(self):
        seen = []

        def handler(request):
            seen.append(request.params)
            return self.ns["json_response"](200, {})

        route = self.route("GET", "/api/a/<id>", handler)
        router = self.router(route)
        match = self.ns["Match"](route, {"id": "given"})
        self.assertEqual(router.dispatch(self.request("GET", "/somewhere/else"), match).status, 200)
        self.assertEqual(seen, [{"id": "given"}])
        self.assertEqual(router.dispatch(self.request("GET", "/somewhere/else")).status, 404)

    def test_route_flags_are_carried_in_the_match(self):
        route = self.route("GET", "/x", automation_blocks=False, heavy=True)
        match = self.router(route).match("GET", "/x")
        self.assertIs(match.route.automation_blocks, False)
        self.assertIs(match.route.heavy, True)


class ResponseTests(RouterCase):
    ns_name = "panel_api_response_test"

    def test_json_response_keeps_cyrillic(self):
        response = self.ns["json_response"](200, {"ok": True, "error": "Привет, мир"})
        self.assertEqual(response.status, 200)
        self.assertEqual(response.content_type, "application/json; charset=utf-8")
        self.assertEqual(response.body, '{"ok": true, "error": "Привет, мир"}'.encode("utf-8"))
        self.assertEqual(response.headers, {})
        self.assertEqual(self.ns["json_response"](404, [1, "я"]).body, '[1, "я"]'.encode("utf-8"))

    def test_error_response_shape(self):
        response = self.ns["error_response"](409, "занято")
        self.assertEqual((response.status, response.content_type), (409, "application/json; charset=utf-8"))
        self.assertEqual(response.body, '{"ok": false, "error": "занято"}'.encode("utf-8"))

    def test_text_response_is_utf8_with_the_given_type(self):
        response = self.ns["text_response"](200, "<p>Привет</p>", "text/html; charset=utf-8")
        self.assertEqual(response.body, "<p>Привет</p>".encode("utf-8"))
        self.assertEqual((response.status, response.content_type, response.headers), (200, "text/html; charset=utf-8", {}))


LAN = "192.168.2.10"
BIND = "192.168.2.1"
PORT = 8088
# The matrix is run for a named bind host, so that the case of the Host and of the Origin can differ.
MATRIX_BIND = "router.lan"
OLD_TEXTS = ("client is outside LAN", "control header missing", "unexpected Host header", "cross-origin request denied")


class SecurityTests(RouterCase):
    ns_name = "panel_api_security_test"

    def check(self, method="POST", *, client=LAN, control="1", host=f"{BIND}:{PORT}", origin=None):
        headers = {}
        if control is not None:
            headers["X-XKeen-Control"] = control
        if host is not None:
            headers["Host"] = host
        if origin is not None:
            headers["Origin"] = origin
        request = self.request(method, "/api/x", headers=headers, client=client)
        return self.ns["check_request"](request, bind_host=BIND, port=PORT)

    def test_a_clean_request_passes(self):
        self.assertIsNone(self.check("POST"))
        self.assertIsNone(self.check("GET"))
        self.assertIsNone(self.check("POST", origin=f"http://{BIND}:{PORT}"))
        self.assertIsNone(self.check("POST", host=BIND, origin=f"http://{BIND}"))
        self.assertIsNone(self.check("POST", origin=""))

    def test_security_order_and_texts(self):
        foreign = "8.8.8.8"
        cases = (
            # (kwargs, expected text): the first wrong thing in the order client, control header, Host, Origin.
            ({"client": foreign, "control": None, "host": "evil", "origin": "http://evil"}, "client is outside LAN"),
            ({"client": foreign}, "client is outside LAN"),
            ({"client": "", "control": None}, "client is outside LAN"),
            ({"control": None, "host": "evil", "origin": "http://evil"}, "control header missing"),
            ({"control": "0", "host": None}, "control header missing"),
            ({"control": "1 ", "origin": "http://evil"}, "control header missing"),
            ({"host": "evil", "origin": "http://evil"}, "unexpected Host header"),
            ({"host": None, "origin": f"http://{BIND}"}, "unexpected Host header"),
            ({"origin": "http://evil"}, "cross-origin request denied"),
            ({"origin": f"http://{BIND}"}, "cross-origin request denied"),
            ({"origin": "null"}, "cross-origin request denied"),
            ({"host": BIND, "origin": f"http://{BIND}:{PORT}"}, "cross-origin request denied"),
        )
        for kwargs, text in cases:
            with self.subTest(**{key: str(value) for key, value in kwargs.items()}):
                response = self.check("POST", **kwargs)
                self.assertIsNotNone(response)
                self.assertEqual(response.status, 403)
                self.assertEqual(response.content_type, "application/json; charset=utf-8")
                self.assertEqual(response.body, json.dumps({"ok": False, "error": text}).encode("utf-8"))
        self.assertEqual({text for _kwargs, text in cases}, set(OLD_TEXTS))

    def test_a_malformed_origin_is_not_swallowed(self):
        # The old Handler let urlsplit's ValueError reach its last-resort 500; the check keeps that.
        with self.assertRaises(ValueError):
            self.check("POST", origin="http://[")

    def test_get_checks_the_host_but_not_the_control_header_or_origin(self):
        self.assertIsNone(self.check("GET", control=None, origin="http://evil"))
        self.assertIsNone(self.check("GET", control="0", host=BIND, origin="null"))
        for host in ("evil", f"{BIND}:1", "", None):
            with self.subTest(host=host):
                response = self.check("GET", control=None, host=host)
                self.assertEqual(response.status, 403)
                self.assertEqual(self.body(response), {"ok": False, "error": "unexpected Host header"})
        self.assertEqual(self.body(self.check("GET", client="8.8.8.8", host="evil"))["error"], "client is outside LAN")

    def test_other_methods_are_checked_like_get(self):
        for method in ("PUT", "DELETE", "HEAD", "OPTIONS"):
            with self.subTest(method=method):
                self.assertIsNone(self.check(method, control=None, origin="http://evil"))
                self.assertEqual(self.body(self.check(method, host="evil"))["error"], "unexpected Host header")

    def test_header_names_are_matched_in_any_case(self):
        request = self.request(
            "POST", "/x", headers={"host": f"{BIND}", "x-xkeen-control": "1", "origin": f"http://{BIND}"}, client=LAN
        )
        self.assertIsNone(self.ns["check_request"](request, bind_host=BIND, port=PORT))
        request = self.request("POST", "/x", headers={"host": BIND, "ORIGIN": "http://evil"}, client=LAN)
        self.assertEqual(self.body(self.ns["check_request"](request, bind_host=BIND, port=PORT))["error"],
                         "control header missing")

    def test_host_forms(self):
        for host, allowed in (
            (BIND, True),
            (f"{BIND}:{PORT}", True),
            (f"{BIND}:1", False),
            (f"{BIND}:{PORT}0", False),
            (f"{BIND}:0{PORT}", False),
            (f"{BIND}.", False),
            ("evil", False),
            ("evil.example:8088", False),
            ("localhost", False),
            ("127.0.0.1", False),
            (f"{BIND}:{PORT}:{PORT}", False),
            ("", False),
            (None, False),
        ):
            with self.subTest(host=host):
                response = self.check("GET", host=host)
                self.assertEqual(response is None, allowed)

    def test_host_uses_the_bind_host_and_port_it_is_given(self):
        request = self.request("GET", "/", headers={"Host": "router.lan:9000"}, client=LAN)
        check = self.ns["check_request"]
        self.assertIsNone(check(request, bind_host="router.lan", port=9000))
        self.assertEqual(check(request, bind_host="router.lan", port=9001).status, 403)
        self.assertEqual(check(request, bind_host="other.lan", port=9000).status, 403)
        # Both sides are compared exactly: no case folding of the Host, of the Origin or between them.
        upper = self.request("GET", "/", headers={"Host": "ROUTER.LAN:9000"}, client=LAN)
        self.assertEqual(check(upper, bind_host="router.lan", port=9000).status, 403)
        origin = self.request(
            "POST", "/", headers={"Host": "router.lan:9000", "X-XKeen-Control": "1", "Origin": "http://ROUTER.LAN:9000"},
            client=LAN,
        )
        self.assertEqual(self.body(check(origin, bind_host="router.lan", port=9000))["error"],
                         "cross-origin request denied")

    def test_private_client_table(self):
        cases = {
            "192.168.2.10": True,
            "10.0.0.1": True,
            "172.16.5.4": True,
            "127.0.0.1": True,
            "::1": True,
            "fd00::1": True,
            "8.8.8.8": False,
            "2001:4860:4860::8888": False,
            "not-an-ip": False,
            "": False,
        }
        for address, expected in cases.items():
            with self.subTest(address=address):
                self.assertIs(self.ns["private_client"](address), expected)

    def test_modules_do_not_touch_sockets(self):
        forbidden = {"socket", "socketserver", "ssl", "select", "selectors", "http"}
        for name in ("router.py", "security.py"):
            path = panel_harness.PACKAGE_DIR / "web" / "api" / name
            with self.subTest(module=name):
                found = set()
                for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), filename=str(path))):
                    if isinstance(node, ast.Import):
                        found.update(alias.name.split(".")[0] for alias in node.names)
                    elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                        found.add(node.module.split(".")[0])
                self.assertEqual(found & forbidden, set())


def exchange(port, method, headers, body=b""):
    """One raw HTTP/1.0 exchange: (status, Content-Type, body). Header names and values go out as given."""
    lines = [f"{method} /api/nonexistent HTTP/1.0", *(f"{name}: {value}" for name, value in headers)]
    with socket.create_connection(("127.0.0.1", port), timeout=10) as connection:
        connection.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body)
        chunks = []
        while chunk := connection.recv(65536):
            chunks.append(chunk)
    head, _, payload = b"".join(chunks).partition(b"\r\n\r\n")
    status_line, *header_lines = head.decode("iso-8859-1").split("\r\n")
    content_type = next(
        (line.split(":", 1)[1].strip() for line in header_lines if line.lower().startswith("content-type:")), None
    )
    return int(status_line.split(" ", 2)[1]), content_type, payload


def json_body(message):
    return json.dumps({"ok": False, "error": message}, ensure_ascii=False).encode("utf-8")


class SecurityEquivalenceTests(panel_harness.PanelTestCase):
    """The checks of the current Handler (kdn.web.app) and security.check_request answer the same, request by request.

    The old side is the real Handler on a real server on 127.0.0.1:0, its peer address replaced per request so that
    it can be a client outside the LAN; the request line goes to /api/nonexistent, which only the checks can stop:
    anything they let through is 404 "unknown endpoint"/"unknown action". The new side is check_request on the same
    client, method and headers. A request the checks let through is None on the new side.

    The one intended difference: GET with a Host that is not the bind host (phase-2 Handler: let through; new: 403).
    Once the Handler of kdn.web.app is the table Handler (task 22) it answers 403 there too, and the matrix then
    shows that the server applies check_request as it is.
    """

    ns_name = "panel_api_equivalence_test"
    clients = {"192.168.2.10": True, "::1": True, "8.8.8.8": False, "2001:4860:4860::8888": False, "": False}
    controls = (("X-XKeen-Control", "1"), None, ("X-XKeen-Control", "0"), ("x-xkeen-control", "1"), ("X-XKeen-Control", "true"))
    hosts = (
        MATRIX_BIND, f"{MATRIX_BIND}:{PORT}", f"{MATRIX_BIND}:80", MATRIX_BIND.upper(), f"{MATRIX_BIND.upper()}:{PORT}",
        "evil.example", f"{LAN}:{PORT}", "", None,
    )
    origins = (
        None, "", f"http://{MATRIX_BIND}:{PORT}", f"http://{MATRIX_BIND}", f"http://{MATRIX_BIND.upper()}:{PORT}",
        f"HTTP://{MATRIX_BIND}:{PORT}", "http://evil.example", "null", "http://[",
    )

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.router = importlib.import_module("kdn.web.api.router")
        cls.security = importlib.import_module("kdn.web.api.security")
        cls.patch_class(BIND_HOST=MATRIX_BIND, PORT=PORT)

        class PeerHandler(cls.ns["Handler"]):
            peer = LAN

            def log_message(self, *_args):
                pass

            @property
            def client_address(self):
                return (PeerHandler.peer, 0)

            @client_address.setter
            def client_address(self, _value):
                pass

        cls.handler = PeerHandler
        cls.server = cls.ns["ThreadingHTTPServer"](("127.0.0.1", 0), PeerHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
            kwargs={"poll_interval": 0.02}, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def rows(self):
        return itertools.product(self.clients, ("GET", "POST"), self.controls, self.hosts, self.origins)

    def old_outcome(self, client, method, control, host, origin):
        """(status, Content-Type, body) of the check that stopped the request in the old Handler, None if none did."""
        headers = [pair for pair in (("Host", host) if host is not None else None, control) if pair is not None]
        if origin is not None:
            headers.append(("Origin", origin))
        body = b""
        if method == "POST":
            body = b"{}"
            headers += [("Content-Type", "application/json"), ("Content-Length", str(len(body)))]
        self.handler.peer = client
        outcome = exchange(self.port, method, headers, body)
        passed = json_body("unknown endpoint" if method == "GET" else "unknown action")
        if outcome == (404, "application/json; charset=utf-8", passed):
            return None
        return outcome

    def new_outcome(self, client, method, control, host, origin):
        headers = {}
        if host is not None:
            headers["Host"] = host
        if control is not None:
            headers[control[0]] = control[1]
        if origin is not None:
            headers["Origin"] = origin
        request = self.router.Request(method, "/api/nonexistent", headers=headers, client=client)
        try:
            response = self.security.check_request(request, bind_host=MATRIX_BIND, port=PORT)
        except Exception as exc:  # what the server's last-resort handler answers to an unexpected error
            text = f"внутренняя ошибка панели: {type(exc).__name__}: {exc}"[:500]
            return 500, "application/json; charset=utf-8", json_body(text)
        return None if response is None else (response.status, response.content_type, response.body)

    def documented_change(self, client, method, host):
        return method == "GET" and self.clients[client] and host not in (MATRIX_BIND, f"{MATRIX_BIND}:{PORT}")

    def test_the_matrix_answers_like_the_current_handler(self):
        host_denied = (403, "application/json; charset=utf-8", json_body("unexpected Host header"))
        mismatches, changed, seen, total = [], 0, set(), 0
        for row in self.rows():
            total += 1
            old, new = self.old_outcome(*row), self.new_outcome(*row)
            client, method, _control, host, _origin = row
            if self.documented_change(client, method, host):
                # Documented change: GET + a Host that is not the bind host is let through by the phase-2 Handler.
                changed += 1
                if old not in (None, host_denied) or new != host_denied:
                    mismatches.append((row, old, new))
                continue
            seen.add((method, None if old is None else "500" if old[0] == 500 else json.loads(old[2])["error"]))
            if old != new:
                mismatches.append((row, old, new))
        self.assertEqual(mismatches[:5], [])
        self.assertEqual(total, len(self.clients) * 2 * len(self.controls) * len(self.hosts) * len(self.origins))
        self.assertGreater(changed, 0)
        # The matrix reaches every answer the checks have, for both methods where the method can get it.
        self.assertEqual(
            seen,
            {("GET", None), ("GET", OLD_TEXTS[0]), ("POST", None), ("POST", "500"), *(("POST", text) for text in OLD_TEXTS)},
        )

    def test_malformed_origin_reaches_the_last_resort_500_on_both_sides(self):
        row = (LAN, "POST", ("X-XKeen-Control", "1"), f"{MATRIX_BIND}:{PORT}", "http://[")
        old, new = self.old_outcome(*row), self.new_outcome(*row)
        self.assertEqual(old[0], 500)
        self.assertIn("внутренняя ошибка панели: ValueError", json.loads(old[2])["error"])
        self.assertEqual(old, new)

    def test_private_client_equals_the_old_function(self):
        old = self.ns["private_client"]
        addresses = (
            "192.168.2.10", "192.168.0.1", "10.0.0.1", "10.255.255.255", "172.16.5.4", "172.31.255.1", "172.32.0.1",
            "127.0.0.1", "127.1.2.3", "0.0.0.0", "11.0.0.1", "8.8.8.8", "1.1.1.1", "169.254.1.1",
            "::1", "::", "fd00::1", "fe80::1", "2001:4860:4860::8888", "2606:4700::1111",
            "100.64.0.1", "::ffff:192.168.1.1", "::ffff:8.8.8.8",
            "", " ", "not-an-ip", "192.168.2", "192.168.2.10.1", "192.168.2.256", "10.0.0.1/8", " 10.0.0.1", "localhost",
        )
        for address in addresses:
            with self.subTest(address=address):
                self.assertIs(self.security.private_client(address), old(address))


if __name__ == "__main__":
    unittest.main()

"""Tests of kdn.web.infra.config: the limits of phase 3 and the single definition of the 512 KiB file limit."""

from __future__ import annotations

import ast

import panel_harness


class ConfigConstantsTests(panel_harness.PanelTestCase):
    ns_name = "panel_config_test"
    modules = ("kdn.web.infra.config", "kdn.common.fsutil")

    def test_log_and_http_limits(self):
        ns = self.ns
        self.assertEqual(ns["LOG_FILE"], ns.root / "opt" / "var" / "log" / "xkeen-web.log")
        self.assertEqual(
            {name: ns[name] for name in (
                "LOG_MAX_BYTES", "LOG_BACKUPS", "MAX_HTTP_THREADS", "MAX_HTTP_CONNECTIONS", "HTTP_FIRST_LINE_TIMEOUT",
                "HEAVY_GET_SLOTS",
            )},
            {
                "LOG_MAX_BYTES": 1024 * 1024,
                "LOG_BACKUPS": 3,
                "MAX_HTTP_THREADS": 16,
                "MAX_HTTP_CONNECTIONS": 64,
                "HTTP_FIRST_LINE_TIMEOUT": 10,
                "HEAVY_GET_SLOTS": 2,
            },
        )
        # A request waiting for a slot is a connection too, and the heavy GETs share the slots of the pool.
        self.assertLessEqual(ns["HEAVY_GET_SLOTS"], ns["MAX_HTTP_THREADS"])
        self.assertLessEqual(ns["MAX_HTTP_THREADS"], ns["MAX_HTTP_CONNECTIONS"])

    def test_report_limit_is_the_json_limit(self):
        fsutil = self.ns.module("common.fsutil")
        self.assertEqual(self.ns["MAX_REPORT_BYTES"], fsutil.MAX_JSON_BYTES)
        self.assertEqual(fsutil.MAX_JSON_BYTES, 512 * 1024)

    def test_the_file_size_limit_is_defined_once(self):
        # 512 * 1024 (or 524288) appears in the panel's code only as fsutil.MAX_JSON_BYTES; everything else refers to it.
        # kdn/engine, kdn/state and the like have their own limits and are not scanned.
        fsutil = self.ns.module("common.fsutil")
        problems = []
        scanned = sorted(
            path
            for directory in ("common", "web")
            for path in (panel_harness.PACKAGE_DIR / directory).rglob("*.py")
        )
        self.assertIn(panel_harness.PACKAGE_DIR / "web" / "infra" / "config.py", scanned)
        for path in scanned:
            if path.samefile(fsutil.__spec__.origin):
                continue
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), filename=str(path))):
                literal = isinstance(node, ast.Constant) and node.value == 512 * 1024
                product = (
                    isinstance(node, ast.BinOp)
                    and isinstance(node.op, ast.Mult)
                    and isinstance(node.left, ast.Constant)
                    and isinstance(node.right, ast.Constant)
                    and node.left.value * node.right.value == 512 * 1024
                )
                if literal or product:
                    problems.append(f"{path.relative_to(panel_harness.ROOT)}:{node.lineno}: {ast.unparse(node)}")
        self.assertEqual(problems, [])

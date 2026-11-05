from __future__ import annotations

import contextlib
import dataclasses
import importlib.util
import inspect
import json
import io
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

import panel_harness


ROOT = Path(__file__).resolve().parents[1]


def load_tuner():
    path = ROOT / "tools" / "windows" / "zapret_tuner.py"
    spec = importlib.util.spec_from_file_location("panel_test_tuner", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PanelImportTests(panel_harness.PanelTestCase):
    ns_name = "panel_import_test"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.panel = cls.ns
        cls.tuner = load_tuner()
        cls.source = cls.tuner.SourceFile(
            "general (ALT11).bat",
            "",
            "fixture-sha",
            "https://example.invalid/general-alt11.bat",
        )

    def report_for(self, service):
        candidate = self.tuner.known_candidate(service, [self.source])
        report = {
            "report_format": 1,
            "created_utc": "2026-07-23T00:00:00Z",
            "repository": "fixture/repository",
            "ref": "main",
            "commit": "abc123",
            "search_seed": 123456,
            "service": service,
            "found": dataclasses.asdict(candidate),
        }
        return json.loads(json.dumps(report))

    def test_accepts_all_tuner_service_families(self):
        for service in ("youtube", "discord-tcp", "discord-voice"):
            with self.subTest(service=service):
                profile = self.panel["validate_report"](self.report_for(service))
                self.assertEqual(profile["service"], service)
                self.assertEqual(profile["format"], 1)
                self.assertEqual(profile["report"]["search_seed"], 123456)

    def test_panel_imports_sys_for_background_tuner_launch(self):
        self.assertIs(self.panel["sys"], sys)

    def test_route_switch_is_allowlisted_and_backgrounded(self):
        with self.assertRaisesRegex(ValueError, "только в браузере"):
            self.panel["start_diagnostic_job"]("standard")
        with self.assertRaisesRegex(ValueError, "только в браузере"):
            self.panel["start_diagnostic_job"]("dpi")
        self.assertEqual(
            self.panel["validate_route"]("discord", "vpn"),
            ("discord", "vpn"),
        )
        with self.assertRaises(ValueError):
            self.panel["validate_route"]("discord", "custom")
        # A route switch may run 15 minutes; the endpoint /api/route/status is checked by test_panel_endpoints.
        self.assertEqual(inspect.signature(self.panel["run_route_command"]).parameters["timeout"].default, 900)

    def test_route_worker_runs_in_its_own_session(self):
        job_id = "0123456789abcdef"
        state = {"job_id": job_id, "operation": "switch", "status": "queued"}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            job_dir = root / "route-job"
            with self.patched(
                PROJECT_DIR=root,
                ROUTE_JOB_DIR=job_dir,
                ROUTE_STATE=job_dir / "state.json",
                ROUTE_PID=job_dir / "worker.pid",
                ROUTE_LOG=job_dir / "process.log",
                ROUTE_APPLY_LOG=job_dir / "apply.log",
                ROUTE_HISTORY_DIR=root / "history",
            ):
                with mock.patch.object(self.panel["subprocess"], "Popen", return_value=mock.Mock(pid=4321)) as popen:
                    self.panel["launch_route_worker"](state, ["switch", "discord", "vpn"])
                # The worker is a child of its own session: a panel restart or a TERM of the panel's group spares it.
                self.assertIs(popen.call_args.kwargs["start_new_session"], True)
                self.assertEqual(popen.call_args.args[0][2:], ["--route-job", job_id, "switch", "discord", "vpn"])
                # The engine call of the worker runs in a session of its own too: a timeout stops the whole group.
                process = mock.Mock(returncode=0)
                process.wait.return_value = 0
                with mock.patch.object(self.panel["subprocess"], "Popen", return_value=process) as popen:
                    result = self.panel["run_route_command"](["/bin/true"], job_id, "switch")
                self.assertTrue(result["ok"], result)
                self.assertIs(popen.call_args.kwargs["start_new_session"], True)

    def test_command_timeout_terminates_the_process_group(self):
        result = self.panel["run_command"](
            [sys.executable, "-c", "import time; time.sleep(2)"],
            timeout=0.05,
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], 124)
        self.assertIn("TERM", result["output"])

    def test_command_env_is_laid_over_the_router_environment(self):
        probe = "import os; print(os.environ.get('XKEEN_FOREGROUND', '-'), os.environ['PATH'])"
        plain = self.panel["run_command"]([sys.executable, "-c", probe], timeout=5)
        self.assertEqual(plain["output"], "- " + self.panel["command_env"]()["PATH"])
        result = self.panel["run_command"]([sys.executable, "-c", probe], timeout=5, env={"XKEEN_FOREGROUND": "1"})
        self.assertEqual(result["output"], "1 " + self.panel["command_env"]()["PATH"])

    def test_command_does_not_wait_for_descendant_holding_output(self):
        started = time.monotonic()
        result = self.panel["run_command"](
            [
                sys.executable,
                "-c",
                (
                    "import subprocess,sys; "
                    "subprocess.Popen([sys.executable,'-c',"
                    "'import time; time.sleep(8)']); print('parent-done')"
                ),
            ],
            timeout=4,
        )
        elapsed = time.monotonic() - started
        self.assertTrue(result["ok"], result)
        self.assertIn("parent-done", result["output"])
        # MIPS Python startup can exceed a second under router load. Still
        # finish well before the descendant closes inherited output at 8s.
        self.assertLess(elapsed, 4)

    def test_route_history_keeps_snapshot_and_orders_by_date(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.patched(ROUTE_HISTORY_DIR=root / "history", SNAPSHOT_DIR=root / "snapshots"):
                snapshot = self.panel["SNAPSHOT_DIR"] / "20260815-010203-42"
                snapshot.mkdir(parents=True)
                (snapshot / "STATE.tsv").write_text("PURPOSE\tpre-apply\n", encoding="utf-8")
                (snapshot / "MANIFEST").write_text("fixture\n", encoding="utf-8")
                first = {
                    "job_id": "1111111111111111",
                    "operation": "switch",
                    "status": "completed",
                    "created_utc": "2026-08-15T01:00:00Z",
                    "snapshot": str(snapshot),
                }
                second = {
                    "job_id": "2222222222222222",
                    "operation": "switch",
                    "status": "completed",
                    "created_utc": "2026-08-15T02:00:00Z",
                    "snapshot": str(snapshot),
                }
                self.panel["write_history"](first)
                self.panel["write_history"](second)
                history = self.panel["route_history"]()
                self.assertEqual(history[0]["job_id"], second["job_id"])
                self.assertTrue(history[0]["rollback_available"])
                parsed = self.panel["parse_snapshot_from_output"](
                    f"Snapshot created: {snapshot}\nApply complete."
                )
                self.assertEqual(parsed, str(snapshot))

    def test_dated_profile_version_is_valid_and_detected_as_active(self):
        profile = self.panel["validate_report"](self.report_for("youtube"))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.patched(IMPORTED_PROFILE_DIR=root / "imported", PROFILE_VERSION_DIR=root / "versions"):
                self.panel["IMPORTED_PROFILE_DIR"].mkdir()
                active = self.panel["IMPORTED_PROFILE_DIR"] / "youtube.json"
                active.write_text(json.dumps(profile), encoding="utf-8")
                directory = self.panel["PROFILE_VERSION_DIR"] / "youtube"
                directory.mkdir(parents=True)
                version_id = (
                    f"20260815T020304Z-{profile['candidate_id']}-applied-123"
                )
                (directory / f"{version_id}.json").write_text(
                    json.dumps(profile),
                    encoding="utf-8",
                )
                versions = self.panel["profile_versions"]()
                self.assertEqual(len(versions), 1)
                self.assertEqual(versions[0]["created_utc"], "2026-08-15T02:03:04Z")
                self.assertTrue(versions[0]["active"])
                path, restored = self.panel["profile_version_path"](
                    "youtube",
                    version_id,
                )
                self.assertEqual(path.name, f"{version_id}.json")
                self.assertEqual(restored["candidate_id"], profile["candidate_id"])
                collision_id = version_id + "-1"
                (directory / f"{collision_id}.json").write_text(
                    json.dumps(profile),
                    encoding="utf-8",
                )
                collision_path, _restored = self.panel["profile_version_path"](
                    "youtube",
                    collision_id,
                )
                self.assertEqual(collision_path.name, f"{collision_id}.json")

    def test_route_progress_stages_and_new_api_are_present(self):
        stage = self.panel["route_stage"](
            "Snapshot created: /fixture\nPatching Xray routing: /fixture\n"
            "Restarting XKeen...\nRestarting nfqws2 only\nStarted NFQWS2 service",
            "switch",
        )
        self.assertEqual(stage, ("verify", "Проверка служб", 94))
        # The endpoints and the routes by path parts (/api/history, /api/history/delete/<id>, /api/updates/check,
        # /api/diagnostics/cancel, /tools/reset-discord-cache.ps1, ...) are requested by test_panel_endpoints.
        snapshot = Path("/fixture/snapshot")
        self.assertEqual(self.panel["rollback_snapshot_command"](snapshot)[2], "--rollback-snapshot")
        helper = self.panel["DISCORD_CACHE_HELPER"].relative_to(self.panel["PROJECT_DIR"])
        self.assertTrue((ROOT / helper).is_file(), helper)
        page = (ROOT / "tools" / "router" / "kdn" / "web" / "assets" / "index.html").read_text(encoding="utf-8")
        self.assertIn('box.classList.toggle("visible",!!d.active&&show)', page)
        self.assertIn('data-tab="vpn-nodes"', page)
        self.assertIn('data-tab="diagnostics"', page)
        self.assertIn('data-diag-kind="standard"', page)
        self.assertIn('data-diag-kind="dpi"', page)

    def test_rejects_candidate_tampering(self):
        report = self.report_for("youtube")
        report["found"]["args"][-1] = (
            "--lua-desync=fake:blob=youtube_quic:repeats=99"
        )
        with self.assertRaisesRegex(ValueError, "candidate_id"):
            self.panel["validate_report"](report)

    def test_old_router_network_reports_are_hidden_but_health_is_kept(self):
        for kind in ("standard", "dpi", "health"):
            saved = {"kind": kind, "status": "completed", "progress": 100,
                     "results": [{"name": "old"}], "finished_utc": "2026-10-20T12:00:00Z"}
            with self.patched(
                safe_json_file=lambda _path, saved=saved: saved,
                diagnostic_active=lambda: False,
            ):
                state = self.panel["diagnostic_status"]()
            if kind == "health":
                self.assertEqual(state["results"], saved["results"])
                self.assertEqual(state["finished_utc"], saved["finished_utc"])
            else:
                self.assertEqual(state["status"], "idle")
                self.assertEqual(state["results"], [])
                self.assertNotIn("summary", state)

    def test_rejects_cross_service_hostlist(self):
        report = self.report_for("discord-tcp")
        report["found"]["args"][2] = (
            "--hostlist=/opt/etc/nfqws2/lists/youtube.list"
        )
        with self.assertRaises(ValueError):
            self.panel["validate_report"](report)

    def test_flowseal_download_noop_and_failed_update_preserves_cache(self):
        latest = "c" * 40
        source = self.tuner.SourceFile("general (ALT).bat", "@echo off\n", "d" * 40,
                                      "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/" + latest + "/general.bat")
        metadata = {"sha": latest, "commit": {"committer": {"date": "2026-10-20T00:00:00Z"}}}
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "sources.json"
            with self.patched(FLOWSEAL_SOURCE_CACHE=cache,
                    FLOWSEAL_UPDATE_STATE=Path(directory) / "update.json",
                    flowseal_source_module=lambda: self.tuner):
                with mock.patch.object(self.panel["urllib"].request, "urlopen",
                        side_effect=lambda *_a, **_k: io.BytesIO(json.dumps(metadata).encode())):
                    with mock.patch.object(self.tuner, "fetch_sources", return_value=([source], latest)) as fetch:
                        first = self.panel["check_flowseal_update"]()
                        self.assertEqual(first["status"], "downloaded")
                        second = self.panel["check_flowseal_update"]()
                        self.assertEqual(second["status"], "up_to_date")
                        fetch.assert_called_once_with("Flowseal/zapret-discord-youtube", latest)
                    saved = cache.read_bytes()
                    metadata["sha"] = "e" * 40
                    with mock.patch.object(self.tuner, "fetch_sources", side_effect=OSError("offline")):
                        with self.assertRaises(OSError):
                            self.panel["check_flowseal_update"]()
                    self.assertEqual(cache.read_bytes(), saved)
                    self.assertEqual(self.panel["cached_flowseal_update"]()["status"], "error")

    @contextlib.contextmanager
    def flowseal_github(self, directory, *, latest, cached, fetched):
        """GitHub names commit `latest`, the cache holds `cached`, the tool downloads `fetched`; yields (urlopen, cache, state)."""
        source = self.tuner.SourceFile("general (ALT).bat", "@echo off\n", "d" * 40, "https://example.invalid/general.bat")
        metadata = {"sha": latest, "commit": {"committer": {"date": "2026-10-20T00:00:00Z"}}}
        cache, state = Path(directory) / "sources.json", Path(directory) / "update.json"
        self.tuner.save_source_cache(cache, [source], cached)
        with self.patched(FLOWSEAL_SOURCE_CACHE=cache, FLOWSEAL_UPDATE_STATE=state, flowseal_source_module=lambda: self.tuner), \
                mock.patch.object(self.panel["urllib"].request, "urlopen",
                                  side_effect=lambda *_a, **_k: io.BytesIO(json.dumps(metadata).encode())) as urlopen, \
                mock.patch.object(self.tuner, "fetch_sources", return_value=([source], fetched)):
            yield urlopen, cache, state

    def test_flowseal_update_check_gives_github_30_seconds(self):
        with tempfile.TemporaryDirectory() as directory, self.flowseal_github(
            directory, latest="c" * 40, cached="c" * 40, fetched="c" * 40,
        ) as (urlopen, _cache, _state):
            self.assertEqual(self.panel["check_flowseal_update"]()["status"], "up_to_date")
        urlopen.assert_called_once()
        self.assertEqual(urlopen.call_args.kwargs["timeout"], 30)

    def test_flowseal_download_of_another_commit_is_refused_and_keeps_the_cache(self):
        with tempfile.TemporaryDirectory() as directory, self.flowseal_github(
            directory, latest="c" * 40, cached="a" * 40, fetched="e" * 40,
        ) as (_urlopen, cache, state):
            saved = cache.read_bytes()
            with self.assertRaisesRegex(RuntimeError, "скачанный commit не совпал с запрошенным"):
                self.panel["check_flowseal_update"]()
            self.assertEqual(cache.read_bytes(), saved)
            self.assertEqual(json.loads(state.read_text(encoding="utf-8"))["status"], "error")
            self.assertEqual(self.panel["cached_flowseal_update"]()["downloaded_commit"], "a" * 40)

    def test_home_service_configs_show_live_profiles_and_hide_vless_details(self):
        import_source = ROOT / "tools" / "router" / "xkeen_diagnostics.py"
        spec = importlib.util.spec_from_file_location("panel_profile_diagnostics", import_source)
        diagnostics = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = diagnostics
        spec.loader.exec_module(diagnostics)
        config = '''# Active routes: DiscordTCP=zapret, DiscordVoice=zapret, YouTube=zapret, Telegram=vless.
NFQWS_ARGS_CUSTOM="--filter-tcp=443 --hostlist=/opt/etc/nfqws2/lists/youtube.list --lua-desync=fake --new --filter-udp=443 --hostlist=/opt/etc/nfqws2/lists/youtube.list --lua-desync=fake"
NFQWS_ARGS_UDP="--filter-udp=19294-19344 --filter-l7=stun,discord --lua-desync=fake"
NFQWS_ARGS_QUIC="--filter-udp=443 --filter-l7=quic --lua-desync=fake"
NFQWS_ARGS_IPSET=""
NFQWS_ARGS="--filter-tcp=443 --hostlist=/opt/etc/nfqws2/lists/user.list --lua-desync=fake"
NFQWS_EXTRA_ARGS="--hostlist=/opt/etc/nfqws2/lists/user.list"
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nfqws2.conf"
            path.write_text(config, encoding="utf-8")
            with self.patched(NFQWS_CONFIG=path, diagnostics_module=lambda: diagnostics):
                result = self.panel["current_service_configs"]()["services"]
        self.assertEqual(len(result["youtube"]["profiles"]), 2)
        self.assertTrue(any("user.list" in " ".join(p["args"]) for p in result["discord-tcp"]["profiles"]))
        self.assertEqual(len(result["discord-voice"]["profiles"]), 1)
        self.assertEqual(result["telegram"]["profiles"], [])
        self.assertIn("VPN-ноду", result["telegram"]["note"])

    def test_home_configuration_is_server_rendered_when_javascript_does_not_run(self):
        services = {service: {"route": "vless", "profiles": [], "note": "Через VPN"}
                    for service in ("discord-tcp", "discord-voice", "youtube", "telegram")}
        with self.patched(current_service_configs=lambda: {"services": services}):
            page = self.panel["initial_service_configs_html"]()
        self.assertIn('id="service-configs"', page)
        self.assertEqual(page.count('<details class="service-config"'), 4)
        self.assertNotIn("__SERVICE_CONFIG_", page)
        self.assertIn("Через VPN", page)

    def test_automation_schedule_validation_and_defaults(self):
        config = self.panel["default_automation_config"]()
        self.assertFalse(config["enabled"])
        config["enabled"] = True
        config["times"] = ["15:00", "03:00"]
        saved = self.panel["validate_automation_config"](config)
        self.assertEqual(saved["times"], ["03:00", "15:00"])
        config["times"] = ["03:00", "03:00"]
        with self.assertRaisesRegex(ValueError, "повторов"):
            self.panel["validate_automation_config"](config)
        config["times"] = ["03:00"]
        config["services"]["youtube"]["max_candidates"] = 65
        with self.assertRaisesRegex(ValueError, "1–64"):
            self.panel["validate_automation_config"](config)

    def test_automation_status_marks_interrupted_run_after_panel_restart(self):
        import threading
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.patched(
                AUTOMATION_CONFIG=root / "config.json", AUTOMATION_STATE=root / "state.json",
                AUTOMATION_RUN_LOCK=threading.Lock(),
            ):
                self.panel["save_automation_state"]({"status": "running", "active": True,
                                                        "last_slot": "2026-10-26T03:00+0300"})
                result = self.panel["automation_status"]()
                self.assertEqual(result["state"]["status"], "interrupted")
                self.assertFalse(result["state"]["active"])

    def test_automation_clock_runs_each_moscow_slot_only_once(self):
        from datetime import datetime, timezone, timedelta
        current = datetime(2026, 10, 26, 3, 0, tzinfo=timezone(timedelta(hours=3)))

        class Clock:
            @staticmethod
            def now(_zone):
                return current

        config = self.panel["default_automation_config"]()
        config["enabled"] = True
        launches = []
        stop = mock.Mock(side_effect=StopIteration)
        with self.patched(
            datetime=Clock, automation_config=lambda: config,
            automation_state=lambda: {"last_slot": ""},
            launch_automation_slot=lambda slot, _config: launches.append(slot),
        ), mock.patch.object(self.panel["time"], "sleep", stop):
            with self.assertRaises(StopIteration):
                self.panel["automation_loop"]()
        self.assertEqual(launches, ["2026-10-26T03:00+0300"])
        with self.patched(
            datetime=Clock, automation_config=lambda: config,
            automation_state=lambda: {"last_slot": launches[0]},
            launch_automation_slot=lambda slot, _config: launches.append(slot),
        ), mock.patch.object(self.panel["time"], "sleep", stop):
            with self.assertRaises(StopIteration):
                self.panel["automation_loop"]()
        self.assertEqual(len(launches), 1)

    def test_automation_skips_search_for_healthy_profiles(self):
        import threading
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = threading.Lock()
            lock.acquire()
            config = self.panel["default_automation_config"]()
            config["enabled"] = True
            apply_profile = mock.Mock()
            with self.patched(
                AUTOMATION_STATE=root / "state.json", AUTOMATION_RUN_LOCK=lock,
                AUTOMATION_STATE_LOCK=threading.Lock(), AUTOMATION_CANCEL=threading.Event(),
                check_flowseal_update=lambda: {"downloaded_commit": "a" * 40},
                current_routes_fast=lambda: {"youtube": "zapret", "discord-tcp": "zapret"},
                automation_check_service=lambda *_args: ("healthy", {"baseline_quic_replies": 1}),
                run_command=lambda *_args, **_kwargs: {"ok": True},
                apply_profile=apply_profile,
            ):
                self.panel["run_automation_slot"]("2026-10-26T03:00+0300", config)
                state = self.panel["automation_state"]()
                self.assertEqual(state["status"], "completed")
                self.assertEqual(state["results"], {"youtube": "healthy", "discord-tcp": "healthy"})
                apply_profile.assert_not_called()
                self.assertFalse(lock.locked())

    def test_automation_does_not_search_on_mixed_probe_results(self):
        import threading
        with tempfile.TemporaryDirectory() as directory:
            lock = threading.Lock()
            lock.acquire()
            config = self.panel["default_automation_config"]()
            config["enabled"] = True
            config["services"]["discord-tcp"]["enabled"] = False
            search = mock.Mock()
            with self.patched(
                AUTOMATION_STATE=Path(directory) / "state.json",
                AUTOMATION_RUN_LOCK=lock, AUTOMATION_STATE_LOCK=threading.Lock(),
                AUTOMATION_CANCEL=threading.Event(),
                check_flowseal_update=lambda: {"downloaded_commit": "a" * 40},
                current_routes_fast=lambda: {"youtube": "zapret"},
                automation_check_service=lambda *_args: ("unstable", {}),
                start_tuner_job=search,
                run_command=lambda *_args, **_kwargs: {"ok": True},
            ):
                self.panel["run_automation_slot"]("2026-10-26T03:00+0300", config)
                self.assertEqual(self.panel["automation_state"]()["results"]["youtube"], "unstable")
                search.assert_not_called()

    def test_automation_rolls_back_when_applied_profile_fails_postcheck(self):
        import threading
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = threading.Lock()
            lock.acquire()
            config = self.panel["default_automation_config"]()
            config["enabled"] = True
            config["services"]["discord-tcp"]["enabled"] = False
            report = root / "result-report.json"
            report.write_text(json.dumps(self.report_for("youtube")), encoding="utf-8")
            check = mock.Mock(side_effect=[("unhealthy", {}), ("unhealthy", {})])
            operation_id, fingerprint = 'd' * 32, 'e' * 64
            pending = {'schema': 2, 'operation_id': operation_id}
            rollback = mock.Mock(return_value={'ok': True,
                'output': 'FOCUSED_RECOVERED|' + operation_id + '|' + fingerprint + '\nRESULT|ok'})
            cleanup = mock.Mock(return_value={'ok': True})
            with self.patched(
                AUTOMATION_STATE=root / "state.json", TUNER_RESULT=report,
                AUTOMATION_RUN_LOCK=lock, AUTOMATION_STATE_LOCK=threading.Lock(),
                AUTOMATION_CANCEL=threading.Event(),
                check_flowseal_update=lambda: {"downloaded_commit": "a" * 40},
                current_routes_fast=lambda: {"youtube": "zapret"},
                automation_check_service=check,
                start_tuner_job=lambda *_args, **_kwargs: 123,
                wait_automation_tuner=lambda *_args: {"status": "found", "result_available": True},
                apply_profile=lambda *_args, **_kwargs: {"ok": True},
                new_import_transaction=lambda _profile: pending,
                recovery_source=lambda _state: ("new-pointer", fingerprint),
                cleanup_import_history=cleanup,
                import_process_active=lambda: False,
                config_health=lambda: {"all_ok": True},
                run_command=rollback,
                nfqws_config_hash=mock.Mock(side_effect=["a" * 64, "b" * 64, "a" * 64]),
                import_pointer_value=mock.Mock(side_effect=["old-pointer", "new-pointer", "new-pointer"]),
                imported_candidate_id=lambda _service: self.report_for("youtube")["found"]["candidate_id"],
            ):
                self.panel["run_automation_slot"]("2026-10-26T03:00+0300", config)
                state = self.panel["automation_state"]()
                self.assertEqual(state["status"], "error")
                self.assertIn("откат", state["error"])
                self.assertEqual(check.call_count, 2)
                self.assertEqual(rollback.call_count, 3)
                self.assertIn("--rollback-import", rollback.call_args.args[0])
                self.assertIn("--recover-import-source", rollback.call_args.args[0])
                self.assertIsNone(state["transaction"])
                cleanup.assert_called_once()
                self.assertFalse(lock.locked())

    def test_legacy_automation_recovery_preserves_evidence_and_disables_schedule(self):
        import hashlib
        import threading
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nfqws = root / "nfqws2.conf"
            nfqws.write_text("old profile\n", encoding="utf-8")
            before_hash = hashlib.sha256(nfqws.read_bytes()).hexdigest()
            nfqws.write_text("new profile\n", encoding="utf-8")
            pointer = root / "import.ptr"
            pointer.write_text("new-snapshot\n", encoding="utf-8")
            imported = root / "imported"
            imported.mkdir()
            (imported / "youtube.json").write_text(json.dumps({"candidate_id": "a" * 12}), encoding="utf-8")
            lock = threading.Lock()
            lock.acquire()
            config = self.panel["default_automation_config"]()
            config["enabled"] = True

            def rollback(_command, timeout):
                self.assertEqual(timeout, 300)
                nfqws.write_text("old profile\n", encoding="utf-8")
                return {"ok": True, "output": "restored"}

            with self.patched(
                AUTOMATION_CONFIG=root / "config.json", AUTOMATION_STATE=root / "state.json",
                AUTOMATION_STATE_LOCK=threading.Lock(), AUTOMATION_RUN_LOCK=lock,
                NFQWS_CONFIG=nfqws, IMPORT_ROLLBACK_POINTER=pointer,
                IMPORTED_PROFILE_DIR=imported,
                import_process_active=lambda: False, run_command=rollback,
            ):
                self.panel["atomic_text"](self.panel["AUTOMATION_CONFIG"], json.dumps(config))
                self.panel["save_automation_state"]({
                    "status": "running", "phase": "verifying", "active": True,
                    "transaction": {"service": "youtube", "candidate_id": "a" * 12,
                                    "before_hash": before_hash, "before_pointer": "old-snapshot"},
                })
                with mock.patch.object(self.panel["time"], "sleep"):
                    self.panel["recover_automation_transaction"]()
                state = self.panel["automation_state"]()
                self.assertEqual(state["status"], "recovery-failed", state)
                self.assertEqual(state["transaction"]["before_hash"], before_hash)
                self.assertEqual(nfqws.read_text(), "new profile\n")
                self.assertFalse(self.panel["automation_config"]()["enabled"])
                self.assertFalse(lock.locked())

    def test_legacy_automation_recovery_never_undoes_another_profile(self):
        import hashlib
        import threading
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nfqws = root / "nfqws2.conf"
            nfqws.write_text("changed outside automation\n", encoding="utf-8")
            pointer = root / "import.ptr"
            pointer.write_text("new-snapshot\n", encoding="utf-8")
            imported = root / "imported"
            imported.mkdir()
            (imported / "youtube.json").write_text(json.dumps({"candidate_id": "b" * 12}), encoding="utf-8")
            rollback = mock.Mock()
            with self.patched(
                AUTOMATION_STATE=root / "state.json", AUTOMATION_STATE_LOCK=threading.Lock(),
                NFQWS_CONFIG=nfqws, IMPORT_ROLLBACK_POINTER=pointer,
                IMPORTED_PROFILE_DIR=imported, run_command=rollback,
            ):
                self.panel["save_automation_state"]({"status": "running", "transaction": {
                    "service": "youtube", "candidate_id": "a" * 12,
                    "before_hash": hashlib.sha256(b"old profile").hexdigest(),
                    "before_pointer": "old-snapshot", "applied_pointer": "new-snapshot",
                }})
                with self.assertRaisesRegex(RuntimeError, "legacy recovery"):
                    self.panel["automation_rollback_import"]("test")
                rollback.assert_not_called()


if __name__ == "__main__":
    unittest.main()

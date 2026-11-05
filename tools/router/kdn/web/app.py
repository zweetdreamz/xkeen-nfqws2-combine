import os
import sys


def _package_path(path, app_file):
    """tools/router first, never this file's directory (which could shadow the stdlib)."""
    script_dir = os.path.dirname(os.path.realpath(app_file))
    kept = [entry for entry in path if os.path.realpath(entry or os.curdir) != script_dir]
    router_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(app_file))))
    if os.path.isfile(os.path.join(router_dir, "kdn", "__init__.py")):
        kept = [router_dir, *(entry for entry in kept if entry != router_dir)]
    return kept


sys.path[:] = _package_path(sys.path, __file__)

from pathlib import Path
import threading

from kdn.common import logsetup
from kdn.web.api import server
from kdn.web.api import table
from kdn.web.domain import automation
from kdn.web.domain import job_ops
from kdn.web.domain import vpn_monitor
from kdn.web.domain import notifications
from kdn.web.infra import config as cfg


cfg.ENTRY = Path(__file__).absolute()


def main(argv=None):
    argv = sys.argv if argv is None else argv
    if len(argv) == 6 and argv[1] == "--route-job":
        return job_ops.run_job(*argv[2:6])
    if not all(path.is_file() for path in (cfg.ENGINE, cfg.SERVICE_SWITCH, cfg.VPN_MANAGER_SCRIPT, cfg.AUTOTUNER, cfg.DIAGNOSTICS)):
        raise SystemExit(
            f"Project scripts are missing. Expected {cfg.ENGINE}, {cfg.SERVICE_SWITCH}, {cfg.VPN_MANAGER_SCRIPT}, "
            f"{cfg.AUTOTUNER} and {cfg.DIAGNOSTICS}"
        )
    logger = logsetup.configure_logging(cfg.LOG_FILE, max_bytes=cfg.LOG_MAX_BYTES, backups=cfg.LOG_BACKUPS,
                                        console=sys.stderr.isatty())
    logsetup.redirect_std_streams(logger)
    print(f"XKeen Control: http://{cfg.BIND_HOST}:{cfg.PORT}")
    # Bind before any recovery/scheduler side effects: a second panel on the
    # same address must fail without launching its own background operations.
    httpd = server.PanelServer((cfg.BIND_HOST, cfg.PORT), table.Handler, max_threads=cfg.MAX_HTTP_THREADS,
                               max_connections=cfg.MAX_HTTP_CONNECTIONS, first_line_timeout=cfg.HTTP_FIRST_LINE_TIMEOUT)
    try:
        try:
            job_ops.reconcile_jobs()
        except Exception:
            logsetup.panel_logger().exception("startup reconciliation failed")
        automation.start_automation_recovery()
        threading.Thread(target=automation.automation_loop, daemon=True, name="zapret-automation").start()
        threading.Thread(target=job_ops.reconcile_loop, daemon=True, name="xkeen-job-reconcile").start()
        threading.Thread(target=vpn_monitor.loop, daemon=True, name='vpn-node-monitor').start()
        threading.Thread(target=notifications.notification_loop, daemon=True, name='notification-delivery').start()
        httpd.serve_forever()
    finally:
        httpd.server_close()


if __name__ == "__main__":
    raise SystemExit(main())

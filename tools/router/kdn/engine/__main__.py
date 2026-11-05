"""python3 -m kdn.engine: runs one mode. The signal handlers and the final cleanups of the process live here."""

from kdn.engine import cli, lifecycle


def main():
    lifecycle.install_signal_handlers()
    try:
        code = cli.main()
    finally:
        lifecycle.run_cleanups()
    raise SystemExit(code)


if __name__ == "__main__":
    main()

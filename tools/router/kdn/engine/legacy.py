"""Hand-over of a run to the shell engine (apply-discord-nfqws2.sh): modes that are not ported, and failures."""

import os


SCRIPT_NAME = "apply-discord-nfqws2.sh"
SHELL = "/bin/sh"
# Set by the dispatcher of the script when it starts this engine; the shell engine must not inherit them.
SCRIPT_ENV = "KDN_ENGINE_SCRIPT"
SCRIPT_DIR_ENV = "KDN_ENGINE_SCRIPT_DIR"
ADDED_PYTHONPATH_ENV = "KDN_ENGINE_ADDED_PYTHONPATH"
ADDED_ENV_ENV = "KDN_ENGINE_ADDED_ENV"
ENGINE_ENV = "KDN_ENGINE"


def shell_path(environ):
    """/bin/sh, as the panel runs the script; else the first executable ``sh`` of the PATH of ``environ``."""
    if os.path.isfile(SHELL) and os.access(SHELL, os.X_OK):
        return SHELL
    for directory in environ.get("PATH", "").split(":"):
        if directory:
            candidate = os.path.join(directory, "sh")
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
    return SHELL


def script_path(environ):
    """The script the dispatcher started from, else the one next to the project this package lives in."""
    script = environ.get(SCRIPT_ENV)
    if script:
        return script
    directory = environ.get(SCRIPT_DIR_ENV)
    if directory:
        return os.path.join(directory, SCRIPT_NAME)
    package_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(package_dir)))), SCRIPT_NAME)


def fallback_environ(environ):
    """A copy of ``environ`` without what the dispatcher added, and with KDN_ENGINE=legacy."""
    env = dict(environ)
    added = env.get(ADDED_PYTHONPATH_ENV, "")
    if added and "PYTHONPATH" in env:
        parts = env["PYTHONPATH"].split(":")
        if parts[0] == added:
            rest = ":".join(parts[1:])
            if rest:
                env["PYTHONPATH"] = rest
            else:
                del env["PYTHONPATH"]
    # The names are separated by spaces (or commas).
    for name in env.get(ADDED_ENV_ENV, "").replace(",", " ").split():
        env.pop(name, None)
    for name in (SCRIPT_ENV, SCRIPT_DIR_ENV, ADDED_PYTHONPATH_ENV, ADDED_ENV_ENV):
        env.pop(name, None)
    env[ENGINE_ENV] = "legacy"
    return env


def fallback_command(environ, argv):
    """(path, args, env) for execve: the shell running the script with the original arguments."""
    path = shell_path(environ)
    return path, [path, script_path(environ), *argv], fallback_environ(environ)


def exec_legacy(ctx):
    """Replace the process with the shell engine. Returns only if the exec fails, or in a test with a double."""
    path, args, env = fallback_command(ctx.environ, ctx.argv)
    ctx.console.flush()
    try:
        ctx.execve(path, args, env)
    except OSError as error:
        ctx.console.err(f"ERROR: cannot start the shell engine: {error}")
        return 127
    return 0

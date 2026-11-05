"""Router tools the panel loads as modules, once: xkeen_diagnostics.py and the Flowseal parser of zapret_tuner.py."""

import importlib.util
import sys
import threading

from kdn.web.infra import config as cfg


# xkeen_diagnostics.py holds the checks shared with the router health job.
DIAGNOSTICS_MODULE_LOCK = threading.Lock()
DIAGNOSTICS_MODULES = {}
# Request threads load zapret_tuner.py once; the module is in sys.modules
# before it has finished executing, so other threads wait for the loader.
FLOWSEAL_MODULE_LOCK = threading.Lock()


def flowseal_source_module():
    name = "xkeen_flowseal_sources"
    with FLOWSEAL_MODULE_LOCK:
        if name not in sys.modules:
            spec = importlib.util.spec_from_file_location(name, cfg.PROJECT_DIR / "tools/windows/zapret_tuner.py")
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            try:
                spec.loader.exec_module(module)
            except Exception:
                sys.modules.pop(name, None)
                raise
        return sys.modules[name]


def diagnostics_module():
    """xkeen_diagnostics.py, loaded once per path: the checks shared with the router health job."""
    key = str(cfg.DIAGNOSTICS)
    with DIAGNOSTICS_MODULE_LOCK:
        module = DIAGNOSTICS_MODULES.get(key)
        if module is None:
            spec = importlib.util.spec_from_file_location("xkeen_diagnostics_shared", cfg.DIAGNOSTICS)
            if spec is None or spec.loader is None:
                raise ImportError(f"не удалось загрузить {cfg.DIAGNOSTICS}")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            DIAGNOSTICS_MODULES[key] = module
        return module

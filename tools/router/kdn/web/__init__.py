"""Web panel of the XKeen control tools.

Layers, lowest first. A module imports only modules of its own or a lower layer, and nothing imports kdn.web.app.

    L0  kdn.common.{paths,fsutil,jsonc,proc,timeutil,lock}   stdlib only: paths, files, JSON, processes, time, lock
    L1  kdn.state.nfqws                                      parsers of the nfqws2.conf header
    L2  kdn.web.infra.config                                 router paths and settings of the panel
    L3  kdn.web.infra.{jobfiles,toolmods,statestore}         job files, router tools as modules, state files
    L4  kdn.web.infra.engine                                 adapter of the engine script
    L5  kdn.web.domain.{validation,history,profiles,flowseal,health,route_jobs,tuner_jobs,diagnostic_jobs,vpn,
        automation}
    L6  kdn.web.app                                          entry: sys.path bootstrap, HTTP Handler, main()

Cross-module access goes through the module attribute at call time (``proc.run_command(...)``, ``cfg.NFQWS_CONFIG``),
never through a name copied at import, so a patch of the attribute on the module that owns it reaches every caller.
tests/test_panel_structure.py checks these rules.
"""

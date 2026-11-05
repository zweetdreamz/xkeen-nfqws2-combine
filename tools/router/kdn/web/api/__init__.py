"""HTTP layer of the web panel (L6): requests and answers as data, a route table, the checks, the socket server.

    router          Request, Response, Route and Router: matching and dispatch without sockets, errors mapped to codes
    security        the checks every request passes before its route (client, control header, Host, Origin)
    server          the request handler and the thread-limited server around the Router
    read_routes     GET routes of pages and reference data
    job_routes      status, result and start/cancel routes of the jobs
    record_routes   quick POST routes over the panel's own records
    operation_routes  POST routes that start router-changing operations as jobs
    table           the route table and the single Handler class of the panel

The package is not called ``http``: a module or package named like a stdlib module would shadow it for the scripts
the panel starts from this tree (kdn.web.app runs as a script, and tests/test_panel_structure.py refuses such names).
A route handler is a function ``handler(request) -> Response`` of its module: no ``self``, no socket, no state of its
own; the domain work stays in kdn.web.domain.
"""

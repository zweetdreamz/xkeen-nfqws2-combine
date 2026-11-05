"""The sole assembled route table and public Handler class."""
from kdn.web.api import job_routes
from kdn.web.api import inspection_routes
from kdn.web.api import operation_routes
from kdn.web.api import read_routes
from kdn.web.api import record_routes
from kdn.web.api import router
from kdn.web.api import server
from kdn.web.infra import jobfiles


ROUTER = router.Router((*read_routes.READ_ROUTES, *job_routes.JOB_ROUTES,
                        *record_routes.RECORD_ROUTES, *operation_routes.OPERATION_ROUTES,
                        *inspection_routes.ROUTES))
Handler = server.handler_for(ROUTER, jobfiles.COORDINATOR.held)
Handler.__module__ = __name__

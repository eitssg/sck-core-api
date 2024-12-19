from collections.abc import Callable

from core_db.response import Response
from .actions import ApiActions

ActionHandler = Callable[..., Response]

ActionHandlerRoutes = dict[str, ActionHandler]

ApiActionsClass = type[ApiActions]

ApiActionsRoutes = dict[str, ApiActionsClass]

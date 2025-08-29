from ..request import Role, RouteEndpoint

from .upload import upload_package
from .compile import compile_templates
from .verify import verify_package
from .plan import create_change_set
from .apply import apply_change_set
from .deploy import deploy_package
from .release import release_build
from .rolleback import rollback_release
from .teardown import teardown_environment

actions: dict[str, RouteEndpoint] = {
    # Read operations (safe, cacheable)
    "GET:/api/v1/{portfolio}/{app}/{branch}/{build}/plan": RouteEndpoint(create_change_set, permissions=[Role.VIEWER, Role.ADMIN]),
    "GET:/api/v1/{portfolio}/{app}/{branch}/{build}/verify": RouteEndpoint(verify_package, permissions=[Role.READONLY, Role.ADMIN]),
    # Create/Deploy operations (not idempotent)
    "POST:/api/v1/{portfolio}/{app}/{branch}/{build}/compile": RouteEndpoint(compile_templates, permissions=[Role.ADMIN]),
    "POST:/api/v1/{portfolio}/{app}/{branch}/{build}/deploy": RouteEndpoint(deploy_package, permissions=[Role.ADMIN]),
    "POST:/api/v1/{portfolio}/{app}/{branch}/{build}/upload": RouteEndpoint(upload_package, permissions=[Role.ADMIN]),
    "POST:/api/v1/{portfolio}/{app}/{branch}/{build}/release": RouteEndpoint(release_build, permissions=[Role.ADMIN]),
    # Update operations (idempotent)
    "PUT:/api/v1/{portfolio}/{app}/{branch}/{build}/apply": RouteEndpoint(apply_change_set, permissions=[Role.ADMIN]),
    "PUT:/api/v1/{portfolio}/{app}/{branch}/{build}/rollback": RouteEndpoint(rollback_release, permissions=[Role.ADMIN]),
    # Delete operations
    "DELETE:/api/v1/{portfolio}/{app}/{branch}/{build}/teardown": RouteEndpoint(teardown_environment, permissions=[Role.ADMIN]),
}

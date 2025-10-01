from enum import Enum
from typing import Set, Optional, Dict, Any, Union, Callable
from dataclasses import dataclass

import core_logging as log
import core_framework as util

from core_helper.aws_models import AwsCredentials

from core_db.exceptions import UnauthorizedException

from .auth.auth_creds import get_credentials

from .auth.tools import JwtPayload, get_authenticated_user
from .request import ProxyEvent, RouteEndpoint


class Permission(str, Enum):
    """System permissions that can be granted to users."""

    # Wildcard permissions
    WILDCARD_READ = "*:read"  # view
    WILDCARD_WRITE = "*:write"  # edit/view
    WILDCARD_ADMIN = "*:admin"  # create/delete/edit/view

    # User Profile permissions
    PROFILE_READ = "profile:read"  # view
    PROFILE_WRITE = "profile:write"  # edit/view
    PROFILE_ADMIN = "profile:admin"  # create/delete/edit/view

    # All Deployment permissions (all deployed items... portfolios, apps, branches, builds, components)
    DEPLOYMENT_ITEM_READ = "item:*:read"  # view
    DEPLOYMENT_ITEM_WRITE = "item:*:write"  # edit/view
    DEPLOYMENT_ITEM_ADMIN = "item:*:admin"  # create/delete/edit/view

    # Deployed Portfolio permissions
    ITEM_PORTFOLIO_READ = "item:portfolio:read"  # view
    ITEM_PORTFOLIO_WRITE = "item:portfolio:write"  # edit/view
    ITEM_PORTFOLIO_ADMIN = "item:portfolio:admin"  # create/delete/edit/view

    # Deployed App permissions
    ITEM_APP_READ = "item:app:read"  # view
    ITEM_APP_WRITE = "item:app:write"  # edit/view
    ITEM_APP_ADMIN = "item:app:admin"  # create/delete/edit/view

    # Deployed Branch permissions
    ITEM_BRANCH_READ = "item:branch:read"  # view
    ITEM_BRANCH_WRITE = "item:branch:write"  # edit/view
    ITEM_BRANCH_ADMIN = "item:branch:admin"  # create/delete/edit/view

    # Deployed Build permissions
    ITEM_BUILD_READ = "item:build:read"  # view
    ITEM_BUILD_WRITE = "item:build:write"  # edit/view
    ITEM_BUILD_ADMIN = "item:build:admin"  # create/delete/edit/view

    # Deployed Component permissions
    ITEM_COMPONENT_READ = "item:component:read"  # view
    ITEM_COMPONENT_WRITE = "item:component:write"  # edit/view
    ITEM_COMPONENT_ADMIN = "item:component:admin"  # create/delete/edit/view

    # Registry permissions
    REGISTRY_READ = "registry:*:read"  # view
    REGISTRY_WRITE = "registry:*:write"  # edit/view
    REGISTRY_ADMIN = "registry:*:admin"  # create/delete/edit/view

    # Registry Client permissions
    REGISTRY_CLIENT_READ = "registry:client:read"  # view
    REGISTRY_CLIENT_WRITE = "registry:client:write"  # edit/view
    REGISTRY_CLIENT_ADMIN = "registry:client:admin"  # create/delete/edit/view

    # Registry Portfolio permissions
    REGISTRY_PORTFOLIO_READ = "registry:portfolio:read"  # view
    REGISTRY_PORTFOLIO_WRITE = "registry:portfolio:write"  # edit/view
    REGISTRY_PORTFOLIO_MANAGE = "registry:portfolio:manage"  # edit approvers, etc.
    REGISTRY_PORTFOLIO_ADMIN = "registry:portfolio:admin"  # create/delete/edit/view

    # Registry App permissions
    REGISTRY_APP_READ = "registry:app:read"  # view
    REGISTRY_APP_MANAGE = "registry:app:manage"  # deploy, run pipeline, etc.
    REGISTRY_APP_WRITE = "registry:app:write"  # edit/view
    REGISTRY_APP_ADMIN = "registry:app:admin"  # create/delete/edit/view

    # Registry Zone permissions
    REGISTRY_ZONE_READ = "registry:zone:read"  # view
    REGISTRY_ZONE_WRITE = "registry:zone:write"  # edit/view
    REGISTRY_ZONE_ADMIN = "registry:zone:admin"  # create/delete/edit/view

    # User management permissions
    USER_READ = "user:read"  # view
    USER_WRITE = "user:write"  # edit/view
    USER_MANAGE = "user:manage"  # edit roles/permissions
    USER_ADMIN = "user:admin"  # create/delete/edit/view

    # System permissions
    SYSTEM_CONFIG = "system:config"  # edit/view system config
    SYSTEM_AUDIT = "system:audit"  # view audit logs
    SYSTEM_MONITOR = "system:monitor"  # view system metrics
    SYSTEM_ADMIN = "system:admin"  # full system access (same as *:admin)??

    # SPA Oauth Client Registry permissions
    OAUTH_CLIENT_READ = "client:read"  # view spa/web/app oauth clients
    OAUTH_CLIENT_WRITE = "client:write"  # edit/view spa/web/app oauth clients
    OAUTH_CLIENT_MANAGE = "client:manage"  # manage spa/web/app oauth clients

    # OLD - to be removed
    DATA_READ = "data:read"
    DATA_WRITE = "data:write"
    DATA_ADMIN = "data:admin"


class Role(str, Enum):
    """System roles that can be assigned to users."""

    USER = "user"
    ADMIN = "admin"
    APPROVER = "approver"
    SERVICE = "service"


@dataclass
class EnhancedSecurityContext:
    """Enhanced security context with AWS credentials and clients."""

    permissions: Set[str]
    roles: Set[str]
    jwt_payload: JwtPayload
    aws_credentials: Optional[AwsCredentials] = None
    role_arn: Optional[str] = None

    @property
    def client(self) -> str:
        return self.jwt_payload.cnm or "core" if self.jwt_payload else "core"

    @property
    def user_id(self) -> str:
        """Get user ID from JWT payload."""
        return self.jwt_payload.sub or "anonymous" if self.jwt_payload else "anonymous"

    @property
    def client_id(self) -> Optional[str]:
        """Get client ID from JWT payload."""
        return self.jwt_payload.cid if self.jwt_payload else None

    @property
    def token_type(self) -> str:
        """Get token type from JWT payload."""
        return self.jwt_payload.typ or "unknown" if self.jwt_payload else "unknown"

    @property
    def session_token(self) -> str | None:
        """Get AWS session token."""
        return self.aws_credentials.session_token if self.aws_credentials else None

    def has_permission(self, permission: Union[Permission, str]) -> bool:
        """Check if the user has a specific permission."""
        if isinstance(permission, Permission):
            permission_str = permission.value
        else:
            permission_str = str(permission)

        # Direct permission match
        if permission_str in self.permissions:
            return True

        # Check wildcard permissions
        if Permission.WILDCARD_ADMIN.value in self.permissions:
            return True

        # Check resource-specific wildcards
        if ":" in permission_str:
            resource, action = permission_str.split(":", 1)
            if f"{resource}:*" in self.permissions:
                return True
            if f"*:{action}" in self.permissions:
                return True

        return False

    def has_role(self, role: Union[Role, str]) -> bool:
        """Check if the user has a specific role."""
        if isinstance(role, Role):
            role_str = role.value
        else:
            role_str = str(role)

        return role_str in self.roles


def get_allowed_permissions() -> Set[str]:
    """Get all defined permission strings."""
    return {perm.value for perm in Permission}


def get_permissions_from_scopes(scopes: str) -> Set[str]:
    """Convert OAuth scopes to permission strings, supporting wildcard permissions."""
    if not scopes:
        return set()

    scope_list = scopes.split()
    permissions = set()
    wildcard_permissions = set()

    for scope in scope_list:
        if scope.startswith("*:"):
            # Handle wildcard permissions: "*:read", "*:write", etc.
            wildcard_action = scope[2:]  # Remove "*:" prefix
            wildcard_permissions.add(wildcard_action)
        else:
            # Handle specific permissions: "registry:read", "aws:write", etc.
            permissions.add(scope)

    # If we have wildcard permissions, generate all possible permissions
    if wildcard_permissions:
        permissions.update(generate_wildcard_permissions(wildcard_permissions))

    return permissions


def generate_wildcard_permissions(wildcard_actions: Set[str]) -> Set[str]:
    """Generate all possible permissions for wildcard actions."""
    all_permissions = set()

    for permission in Permission:
        permission_parts = permission.value.split(":")
        if len(permission_parts) >= 2:
            action = permission_parts[-1]
            if action in wildcard_actions:
                all_permissions.add(permission.value)

    return all_permissions


def derive_roles_from_permissions(permissions: Set[str]) -> Set[str]:
    """Derive user roles from their permissions."""
    roles = {"user"}  # Default role

    # Admin role if they have admin permissions
    admin_perms = {"user:manage", "client:manage", "*:admin", "system:config"}
    if admin_perms.intersection(permissions):
        roles.add("admin")

    # Service role if they have service-specific permissions
    service_perms = {"service:*", "registry:client:write", "registry:portfolio:write"}
    if service_perms.intersection(permissions):
        roles.add("service")

    # Billing admin role
    if "aws:billing:read" in permissions:
        roles.add("billing_admin")

    # Read-only role
    read_only_perms = {"*:read", "portfolio:read", "app:read", "component:read"}
    if read_only_perms.intersection(permissions) and not admin_perms.intersection(permissions):
        roles.add("readonly")

    return roles


def has_permission_with_wildcard(user_permissions: Set[str], required_permission: str) -> bool:
    """Check if user has required permission, considering wildcard permissions."""
    # Direct permission match
    if required_permission in user_permissions:
        return True

    # Check for admin wildcard
    if Permission.WILDCARD_ADMIN.value in user_permissions:
        return True

    # Check resource and action wildcards
    if ":" in required_permission:
        resource, action = required_permission.split(":", 1)
        if f"{resource}:*" in user_permissions:
            return True
        if f"*:{action}" in user_permissions:
            return True

    return False


def check_permissions_with_wildcard(user_permissions: Set[str], required_permissions: Set[str]) -> Set[str]:
    """Check which required permissions are missing, considering wildcards."""
    missing_permissions = set()

    for required_perm in required_permissions:
        if not has_permission_with_wildcard(user_permissions, required_perm):
            missing_permissions.add(required_perm)

    return missing_permissions


def validate_client_access(security_context: EnhancedSecurityContext, request: ProxyEvent) -> None:
    """Validate client isolation for multi-tenant endpoints."""

    def extract_client_from_dict(data: dict) -> Optional[str]:
        """Extract client value from dict, checking both cases."""
        if not data:
            return None
        return data.get("client") or data.get("Client")

    # Check all possible locations for client identifier
    client_slug = None

    # 1. Path parameters
    if request.pathParameters:
        client_slug = extract_client_from_dict(request.pathParameters)

    # 2. Query parameters
    if not client_slug and request.queryStringParameters:
        client_slug = extract_client_from_dict(request.queryStringParameters)

    # 3. Request body (already parsed to dict by ProxyEvent)
    if not client_slug and request.body and isinstance(request.body, dict):
        client_slug = extract_client_from_dict(request.body)

    # If no client found, skip validation
    if not client_slug:
        log.debug("No client identifier found in request, skipping client isolation")
        return

    log.debug(f"Validating client access for '{client_slug}' by user {security_context.user_id}")

    # Admins can access any client
    if "admin" in security_context.roles:
        log.debug(f"Admin user {security_context.user_id} granted access to client '{client_slug}'")
        return

    # Service accounts can access any client
    if "service" in security_context.roles:
        log.debug(f"Service account {security_context.user_id} granted access to client '{client_slug}'")
        return

    # Regular users: client slug must match their context
    user_client_id = security_context.client_id.lower() if security_context.client_id else ""
    user_client_name = security_context.client.lower() if security_context.client else ""
    requested_client = client_slug.lower()

    if requested_client not in [user_client_id, user_client_name]:
        log.warning(
            f"Client access denied for user {security_context.user_id}",
            details={
                "requested_client": client_slug,
                "user_client": security_context.client,
                "client_id": security_context.client_id,
            },
        )
        raise PermissionError(f"Access denied to client '{client_slug}'. User belongs to '{security_context.client}'")

    log.debug(f"Client access granted for user {security_context.user_id} to client '{client_slug}'")


def extract_security_context(
    request: ProxyEvent, endpoint: RouteEndpoint, require_aws_credentials: bool = False
) -> Optional[EnhancedSecurityContext]:
    """Extract security context from JWT token with optional AWS role assumption.

    Args:
        request: ProxyEvent object from API Gateway
        role_arn: Full role ARN to assume, or callable that returns full role ARN.
                 If None, no role assumption is performed.
        require_aws_credentials: Whether AWS credentials are required in JWT token

    Returns:
        EnhancedSecurityContext with AWS clients if role assumption succeeded
    """
    # Extract JWT from cookies or headers
    if endpoint.required_token_type == "session":
        jwt_payload, _ = get_authenticated_user(cookies=request.parsed_cookies)
    elif endpoint.required_token_type == "access":
        jwt_payload, _ = get_authenticated_user(headers=request.headers)

    if not jwt_payload:
        log.debug("No valid JWT token found in request")
        return None

    # Extract permissions from OAuth scopes
    scopes = jwt_payload.scp or ""
    permissions = get_permissions_from_scopes(scopes)
    roles = derive_roles_from_permissions(permissions)

    # Handle AWS credentials if needed
    aws_credentials = None

    if require_aws_credentials:

        aws_credentials = get_credentials(jwt_payload)

        method = request.httpMethod.lower()
        need_write_role = method != "get"
        # Determine role ARN if needed
        # If no role ARN resolved and none provided, use default from util
        resolved_role_arn = util.get_automation_api_role_arn(write=need_write_role)

    return EnhancedSecurityContext(
        permissions=permissions,
        roles=roles,
        jwt_payload=jwt_payload,
        aws_credentials=AwsCredentials.model_validate(aws_credentials),
        role_arn=resolved_role_arn if require_aws_credentials else None,
    )

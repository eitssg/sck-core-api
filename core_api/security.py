from enum import Enum
from typing import Set, Optional, Dict, Any, Union, Callable
from dataclasses import dataclass
import boto3
from botocore.exceptions import ClientError

import core_logging as log
import core_framework as util

import core_helper.aws as aws

from core_db.exceptions import UnauthorizedException

from .oauth.auth_creds import get_credentials

from .oauth.tools import JwtPayload, get_authenticated_user
from .request import ProxyEvent


class Permission(str, Enum):
    """System permissions that can be granted to users."""

    # Wildcard permissions
    WILDCARD_ADMIN = "*:admin"
    WILDCARD_READ = "*:read"
    WILDCARD_WRITE = "*:write"

    # Profile permissions
    PROFILE_READ = "profile:read"  # Maps to read:profile OAuth scope
    PROFILE_WRITE = "profile:write"  # Maps to write:profile OAuth scope

    # Portfolio permissions
    PORTFOLIO_READ = "portfolio:read"
    PORTFOLIO_WRITE = "portfolio:write"
    PORTFOLIO_ADMIN = "portfolio:admin"

    # Registry permissions
    REGISTRY_READ = "registry:read"
    REGISTRY_WRITE = "registry:write"
    REGISTRY_ADMIN = "registry:admin"
    REGISTRY_CLIENT_READ = "registry:client:read"
    REGISTRY_CLIENT_WRITE = "registry:client:write"
    REGISTRY_PORTFOLIO_READ = "registry:portfolio:read"
    REGISTRY_PORTFOLIO_WRITE = "registry:portfolio:write"

    # App permissions
    APP_READ = "app:read"
    APP_WRITE = "app:write"
    APP_ADMIN = "app:admin"

    # Component permissions
    COMPONENT_READ = "component:read"
    COMPONENT_WRITE = "component:write"
    COMPONENT_ADMIN = "component:admin"

    # User management permissions
    USER_READ = "user:read"
    USER_WRITE = "user:write"
    USER_MANAGE = "user:manage"

    # Client management permissions
    CLIENT_READ = "client:read"
    CLIENT_WRITE = "client:write"
    CLIENT_MANAGE = "client:manage"

    # AWS permissions
    AWS_READ = "aws:read"
    AWS_WRITE = "aws:write"
    AWS_ADMIN = "aws:admin"
    AWS_BILLING_READ = "aws:billing:read"

    # System permissions
    SYSTEM_CONFIG = "system:config"
    SYSTEM_MONITOR = "system:monitor"

    DATA_READ = "data:read"
    DATA_WRITE = "data:write"
    DATA_ADMIN = "data:admin"


class Role(str, Enum):
    """System roles that can be assigned to users."""

    USER = "user"
    ADMIN = "admin"
    SERVICE = "service"
    READONLY = "readonly"
    BILLING_ADMIN = "billing_admin"


@dataclass
class AwsCredentials:
    """AWS credentials from assumed role."""

    access_key_id: str
    secret_access_key: str
    session_token: str
    region: str = "ap-southeast-1"


@dataclass
class SecurityContext:
    """Security context for the current request."""

    user_id: str
    client_id: Optional[str]
    client: Optional[str]
    permissions: Set[str]
    roles: Set[str]
    token_type: str
    custom_attributes: Dict[str, Any]
    jwt_payload: Optional[JwtPayload] = None

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

    def has_any_permission(self, permissions: Set[Union[Permission, str]]) -> bool:
        """Check if the user has any of the specified permissions."""
        for permission in permissions:
            if self.has_permission(permission):
                return True
        return False

    def has_all_permissions(self, permissions: Set[Union[Permission, str]]) -> bool:
        """Check if the user has all of the specified permissions."""
        for permission in permissions:
            if not self.has_permission(permission):
                return False
        return True


@dataclass
class EnhancedSecurityContext:
    """Enhanced security context with AWS credentials and clients."""

    permissions: Set[str]
    roles: Set[str]
    jwt_payload: JwtPayload
    aws_credentials: Optional[AwsCredentials] = None
    role_arn: Optional[str] = None

    @property
    def user_id(self) -> str:
        """Get user ID from JWT payload."""
        return self.jwt_payload.sub if self.jwt_payload else "anonymous"

    @property
    def client_id(self) -> Optional[str]:
        """Get client ID from JWT payload."""
        return self.jwt_payload.cid if self.jwt_payload else None

    @property
    def token_type(self) -> str:
        """Get token type from JWT payload."""
        return self.jwt_payload.typ if self.jwt_payload else "unknown"

    @property
    def session_token(self) -> str:
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


def validate_client_access(security_context: SecurityContext, request: ProxyEvent) -> None:
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
    if not client_slug and request.body:
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


def extract_security_context(request: ProxyEvent, require_aws_credentials: bool = False) -> Optional[EnhancedSecurityContext]:
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
    jwt_payload, _ = get_authenticated_user(request.parsed_cookies, request.headers)
    if not jwt_payload:
        log.debug("No valid JWT token found in request")
        return None

    if jwt_payload.typ != "access":
        log.warning(f"Invalid token type for API: {jwt_payload.typ}")
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
        aws_credentials=aws_credentials,
        role_arn=resolved_role_arn if require_aws_credentials else None,
    )

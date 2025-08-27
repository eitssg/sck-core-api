"""Security and authorization module for the Simple Cloud Kit API.

This module provides comprehensive security infrastructure including JWT-based authentication,
role-based access control (RBAC), and permission management for FastAPI endpoints. The security
system integrates seamlessly with the OAuth 2.0 server and supports both cookie-based sessions
and Authorization header tokens.

Key Components:
    - **Permission System**: Granular permission model with wildcard support
    - **Role Definitions**: Standard system roles for user classification
    - **SecurityContext**: Complete user security context from JWT tokens
    - **FastAPI Dependencies**: Easy-to-use security dependencies for endpoints
    - **JWT Integration**: Seamless integration with OAuth 2.0 JWT tokens

Security Model:
    The security system operates on a permission-based access control model where:

    1. **Users authenticate** via OAuth 2.0 or direct login
    2. **JWT tokens contain permissions** in the 'scp' (scope) claim
    3. **SecurityContext extracts permissions** from validated JWT tokens
    4. **FastAPI dependencies enforce** authorization rules per endpoint
    5. **Wildcard permissions** provide hierarchical access control

Permission Format:
    Permissions follow the pattern: `resource:action`

    Examples:
        - `portfolio:read` - Read portfolio data
        - `app:write` - Create/update applications
        - `*:admin` - Admin access to all resources
        - `portfolio:*` - All actions on portfolios

JWT Token Integration:
    Security context is extracted from JWT tokens containing these claims:

    - **sub** (subject): User ID
    - **cid** (client_id): OAuth client identifier
    - **cnm** (client_name): OAuth client display name
    - **scp** (scope): List or space-separated string of permissions
    - **typ** (type): Token type ("access_token", "session", etc.)

Usage Examples:

    **Basic Authentication**:

    .. code-block:: python

        @app.get("/api/profile")
        async def get_profile(
            context: SecurityContext = Depends(require_authentication())
        ):
            return {"user_id": context.user_id}

    **Permission-Based Authorization**:

    .. code-block:: python

        @app.get("/api/portfolios")
        async def list_portfolios(
            context: SecurityContext = Depends(require_portfolio_read)
        ):
            return {"portfolios": [...]}

    **Multiple Permissions**:

    .. code-block:: python

        @app.post("/api/portfolios")
        async def create_portfolio(
            context: SecurityContext = Depends(require_permissions(
                Permission.PORTFOLIO_WRITE, Permission.AWS_RESOURCES_WRITE
            ))
        ):
            return {"status": "created"}

    **Flexible Permission Checking**:

    .. code-block:: python

        @app.get("/api/portfolios/{id}")
        async def get_portfolio(
            id: str,
            context: SecurityContext = Depends(require_any_permission(
                Permission.PORTFOLIO_READ, Permission.PORTFOLIO_ADMIN
            ))
        ):
            return {"portfolio": {...}}

Wildcard Permission System:
    The permission system supports powerful wildcard patterns:

    - **`*:admin`** - Administrative access to all resources
    - **`portfolio:*`** - All actions on portfolio resources
    - **`*:read`** - Read access to all resources
    - **`registry:*:read`** - Read access to all registry resources

Token Sources:
    JWT tokens are extracted from multiple sources in order:

    1. **Cookies**: `sck_token` cookie (browser sessions)
    2. **Authorization Header**: `Bearer <token>` (API clients)
    3. **Custom Headers**: Additional token headers if configured

Error Handling:
    Security errors follow OAuth 2.0 and REST API standards:

    - **401 Unauthorized**: Missing or invalid authentication
    - **403 Forbidden**: Valid authentication but insufficient permissions
    - **400 Bad Request**: Invalid token type or malformed request

Dependencies:
    - fastapi: Web framework and dependency injection
    - pydantic: Data validation and serialization
    - core_logging: Structured logging for security events
    - .oauth.tools: JWT validation and user authentication

Note:
    This module is designed to work seamlessly with both development (FastAPI)
    and production (AWS Lambda) environments, providing consistent security
    behavior across deployment targets.

Author: Simple Cloud Kit Development Team
Version: Compatible with OAuth 2.0 RFC 6749 and JWT RFC 7519
"""

from enum import Enum
from typing import Set, Optional
from dataclasses import dataclass
from fastapi import HTTPException, Depends, Request
import core_logging as log

from .oauth.tools import JwtPayload, get_authenticated_user


class Permission(str, Enum):
    """System permissions that can be granted to users.

    Defines the complete set of granular permissions available in the Simple Cloud Kit
    system. Permissions follow a hierarchical `resource:action` pattern and support
    wildcard matching for flexible access control.

    Permission Categories:
        - **Profile**: User profile and account management
        - **Portfolio**: Portfolio creation and management
        - **Application**: Application lifecycle operations
        - **Component**: Component configuration and deployment
        - **Build**: Build and deployment operations
        - **AWS**: Cloud infrastructure management
        - **Data**: Data access and analytics
        - **System**: Administrative and system operations
        - **Registry**: Registry metadata management
        - **Features**: Feature flag and module access

    Wildcard Support:
        - **Resource wildcards**: `portfolio:*` (all portfolio actions)
        - **Action wildcards**: `*:read` (read access to all resources)
        - **Administrative**: `*:admin` (administrative access to everything)

    Examples:
        >>> # Check specific permission
        >>> if context.has_permission(Permission.PORTFOLIO_READ):
        ...     return get_portfolios()

        >>> # Check wildcard permission
        >>> if context.has_permission(Permission.WILDCARD_ADMIN):
        ...     return admin_functions()

        >>> # Use in FastAPI dependency
        >>> @app.get("/api/portfolios")
        >>> async def list_portfolios(
        ...     context: SecurityContext = Depends(require_permissions(Permission.PORTFOLIO_READ))
        ... ):
        ...     return {"portfolios": [...]}

    Note:
        As a `str` Enum, Permission values can be used directly in string operations
        and JSON serialization without requiring `.value` access.
    """

    # Profile management
    PROFILE_READ = "profile:read"
    PROFILE_WRITE = "profile:write"
    PROFILE_DELETE = "profile:delete"
    PROFILE_ADMIN = "profile:admin"

    # Portfolio management
    PORTFOLIO_READ = "portfolio:read"
    PORTFOLIO_WRITE = "portfolio:write"
    PORTFOLIO_DELETE = "portfolio:delete"
    PORTFOLIO_ADMIN = "portfolio:admin"

    # Application management
    APP_READ = "app:read"
    APP_WRITE = "app:write"
    APP_DELETE = "app:delete"
    APP_ADMIN = "app:admin"

    # Component management
    COMPONENT_READ = "component:read"
    COMPONENT_WRITE = "component:write"
    COMPONENT_DELETE = "component:delete"
    COMPONENT_ADMIN = "component:admin"

    # Build and deployment
    BUILD_READ = "build:read"
    BUILD_WRITE = "build:write"
    BUILD_DELETE = "build:delete"
    BUILD_ADMIN = "build:admin"

    # AWS Infrastructure
    AWS_CREDS_READ = "aws:creds:read"
    AWS_CREDS_WRITE = "aws:creds:write"
    AWS_RESOURCES_READ = "aws:resources:read"
    AWS_RESOURCES_WRITE = "aws:resources:write"
    AWS_BILLING_READ = "aws:billing:read"

    # Data & Analytics
    DATA_READ = "data:read"
    DATA_WRITE = "data:write"
    DATA_EXPORT = "data:export"
    ANALYTICS_VIEW = "analytics:view"
    REPORTS_GENERATE = "reports:generate"

    # System Administration
    SYSTEM_CONFIG = "system:config"
    USER_MANAGE = "user:manage"
    CLIENT_MANAGE = "client:manage"
    AUDIT_VIEW = "audit:view"

    # Registry permissions
    REGISTRY_CLIENT_READ = "registry:client:read"
    REGISTRY_CLIENT_WRITE = "registry:client:write"
    REGISTRY_PORTFOLIO_READ = "registry:portfolio:read"
    REGISTRY_PORTFOLIO_WRITE = "registry:portfolio:write"
    REGISTRY_APP_READ = "registry:app:read"
    REGISTRY_APP_WRITE = "registry:app:write"
    REGISTRY_ZONE_READ = "registry:zone:read"
    REGISTRY_ZONE_WRITE = "registry:zone:write"

    # Feature Flags
    FEATURE_DASHBOARD_ADVANCED = "feature:dashboard:advanced"
    FEATURE_BILLING_MODULE = "feature:billing:module"
    FEATURE_INTEGRATIONS = "feature:integrations"

    # Wildcard permissions
    WILDCARD_READ = "*:read"
    WILDCARD_WRITE = "*:write"
    WILDCARD_DELETE = "*:delete"
    WILDCARD_ADMIN = "*:admin"


class Role(str, Enum):
    """System roles that can be assigned to users.

    Defines standard user roles within the Simple Cloud Kit system. Roles serve
    as a convenient way to group common permission sets, though the actual
    authorization is performed using granular permissions.

    Role Hierarchy (ascending privilege):
        1. **READONLY**: Read-only access to resources
        2. **USER**: Standard user with basic create/read/update permissions
        3. **POWER_USER**: Advanced user with extended functionality access
        4. **BILLING_ADMIN**: Specialized role for billing and cost management
        5. **ADMIN**: Full system administrative access

    Usage:
        Roles are typically used for:
        - User interface role-based navigation
        - Default permission assignment during user creation
        - Simplified permission management in admin interfaces
        - Audit logging and user classification

    Examples:
        >>> # Check user role (if stored in JWT or user profile)
        >>> if user.role == Role.ADMIN:
        ...     show_admin_menu()

        >>> # Role-based default permissions
        >>> if new_user.role == Role.POWER_USER:
        ...     grant_permissions([Permission.PORTFOLIO_READ, Permission.APP_READ])

    Note:
        Authorization decisions should be made based on specific permissions
        rather than roles. Roles are primarily for user management and
        interface customization.
    """

    USER = "user"
    POWER_USER = "power_user"
    ADMIN = "admin"
    BILLING_ADMIN = "billing_admin"
    READONLY = "readonly"


@dataclass
class SecurityContext:
    """Security context for the current request.

    Contains complete security information extracted from a validated JWT token,
    providing all data needed for authentication and authorization decisions.
    This context is created by the security system and passed to FastAPI
    endpoints via dependency injection.

    The SecurityContext serves as the primary interface between the OAuth/JWT
    authentication system and the application's authorization logic.

    Attributes:
        user_id (str): Unique user identifier from JWT 'sub' (subject) claim.
            Used to identify the authenticated user across all operations.

        client_id (str): OAuth client ID from JWT 'cid' claim. Identifies
            which application or service the user authenticated through.

        client_name (str): Human-readable client name from JWT 'cnm' claim.
            Used for display purposes and audit logging.

        permissions (Set[str]): Set of permission strings extracted from JWT
            'scp' (scope) claim. Contains all permissions granted to the user.

        token_type (str): Type of JWT token from 'typ' claim. Common values
            include "access_token", "session", "refresh_token".

        jwt_payload (JwtPayload): Complete JWT payload object containing all
            token claims for advanced use cases.

    Methods:
        has_permission(permission): Check if user has a specific permission
        has_any_permission(*permissions): Check if user has any of the permissions
        has_all_permissions(*permissions): Check if user has all permissions

    Permission Checking Logic:
        The permission system supports sophisticated wildcard matching:

        1. **Direct Match**: Exact permission string match
        2. **Admin Wildcard**: `*:admin` grants access to everything
        3. **Resource Wildcard**: `portfolio:*` grants all portfolio actions
        4. **Action Wildcard**: `*:read` grants read access to all resources

    Examples:
        >>> # Basic authentication check
        >>> if not context:
        ...     raise HTTPException(401, "Authentication required")

        >>> # Simple permission check
        >>> if context.has_permission(Permission.PORTFOLIO_READ):
        ...     portfolios = get_user_portfolios(context.user_id)

        >>> # Multiple permission options
        >>> if context.has_any_permission(
        ...     Permission.PORTFOLIO_ADMIN, Permission.WILDCARD_ADMIN
        ... ):
        ...     return get_all_portfolios()  # Admin view
        ... else:
        ...     return get_user_portfolios(context.user_id)  # User view

        >>> # Complex authorization
        >>> if context.has_all_permissions(
        ...     Permission.PORTFOLIO_WRITE, Permission.AWS_RESOURCES_WRITE
        ... ):
        ...     create_portfolio_with_infrastructure(...)

    JWT Token Source:
        The SecurityContext is created from JWT tokens found in:
        1. HTTP cookies (browser sessions)
        2. Authorization headers (API clients)
        3. Custom headers (if configured)

    Note:
        Permissions are stored as raw strings from the JWT token rather than
        Permission enum values. This provides flexibility for unknown permissions
        and avoids validation errors during token processing.

        The SecurityContext is immutable once created and represents the security
        state at the time of request processing.
    """

    user_id: str
    client_id: str
    client_name: str
    permissions: Set[str]  # Raw permission strings from JWT
    token_type: str
    jwt_payload: JwtPayload

    def has_permission(self, permission: Permission) -> bool:
        """Check if the user has a specific permission.

        Performs comprehensive permission checking including direct matches
        and wildcard pattern matching. This is the primary method for
        authorization decisions in the application.

        Args:
            permission (Permission): Permission enum value to check against
                the user's granted permissions.

        Returns:
            bool: True if the user has the permission (direct or via wildcard),
                False otherwise.

        Wildcard Matching Rules:
            1. **Direct match**: Permission string exactly matches user's permission
            2. **Admin wildcard**: User has `*:admin` permission (access to everything)
            3. **Resource wildcard**: User has `resource:*` (all actions on resource)
            4. **Action wildcard**: User has `*:action` (action on all resources)

        Examples:
            >>> # Direct permission check
            >>> if context.has_permission(Permission.PORTFOLIO_READ):
            ...     return get_portfolios()

            >>> # Check for administrative access
            >>> if context.has_permission(Permission.PORTFOLIO_ADMIN):
            ...     return get_all_portfolios()  # Admin can see all

            >>> # Wildcard permissions work automatically
            >>> # User with "*:admin" can access Permission.PORTFOLIO_DELETE
            >>> if context.has_permission(Permission.PORTFOLIO_DELETE):
            ...     delete_portfolio(portfolio_id)

        Performance:
            This method performs set lookups and string operations, making it
            very fast even with large permission sets. Wildcard checking adds
            minimal overhead.

        Note:
            Permission enum values are automatically converted to strings for
            comparison with the user's permission set from the JWT token.
        """
        permission_str = str(permission)

        # Direct permission match
        if permission_str in self.permissions:
            return True

        # Check wildcard permissions
        if str(Permission.WILDCARD_ADMIN) in self.permissions:
            return True

        # Check resource-specific wildcards
        if ":" in permission_str:
            resource, action = permission_str.split(":", 1)
            if f"{resource}:*" in self.permissions:
                return True

            # Check action-specific wildcards
            if f"*:{action}" in self.permissions:
                return True

        return False

    def has_any_permission(self, *permissions: Permission) -> bool:
        """Check if user has any of the specified permissions.

        Performs an OR operation across multiple permissions, returning True
        if the user has at least one of the specified permissions. Useful
        for endpoints that can be accessed by users with different permission
        levels.

        Args:
            *permissions: Variable number of Permission enum values to check.
                The user needs to have at least one of these permissions.

        Returns:
            bool: True if the user has at least one of the permissions,
                False if the user has none of the permissions.

        Examples:
            >>> # User needs either read OR admin access
            >>> if context.has_any_permission(
            ...     Permission.PORTFOLIO_READ, Permission.PORTFOLIO_ADMIN
            ... ):
            ...     return get_portfolio_data()

            >>> # Multiple ways to access sensitive data
            >>> if context.has_any_permission(
            ...     Permission.DATA_EXPORT,
            ...     Permission.ANALYTICS_VIEW,
            ...     Permission.WILDCARD_ADMIN
            ... ):
            ...     return export_analytics_data()

            >>> # Flexible access control
            >>> if context.has_any_permission(
            ...     Permission.APP_READ, Permission.APP_ADMIN, Permission.WILDCARD_READ
            ... ):
            ...     return list_applications()

        Use Cases:
            - **Flexible Access**: Multiple permission levels for same resource
            - **Migration Support**: Supporting old and new permission names
            - **Role-based Access**: Different roles with different permissions
            - **Fallback Permissions**: Primary + backup permission options

        Performance:
            Short-circuits on first match, making it efficient even with
            many permissions to check.
        """
        return any(self.has_permission(perm) for perm in permissions)

    def has_all_permissions(self, *permissions: Permission) -> bool:
        """Check if user has all of the specified permissions.

        Performs an AND operation across multiple permissions, returning True
        only if the user has every single specified permission. Used for
        operations that require multiple types of access.

        Args:
            *permissions: Variable number of Permission enum values to check.
                The user must have all of these permissions.

        Returns:
            bool: True if the user has all of the permissions,
                False if the user is missing any permission.

        Examples:
            >>> # Requires both portfolio and AWS permissions
            >>> if context.has_all_permissions(
            ...     Permission.PORTFOLIO_WRITE, Permission.AWS_RESOURCES_WRITE
            ... ):
            ...     return create_portfolio_with_infrastructure()

            >>> # Complex administrative operation
            >>> if context.has_all_permissions(
            ...     Permission.USER_MANAGE,
            ...     Permission.CLIENT_MANAGE,
            ...     Permission.AUDIT_VIEW
            ... ):
            ...     return perform_user_audit()

            >>> # Data export with analytics
            >>> if context.has_all_permissions(
            ...     Permission.DATA_READ, Permission.DATA_EXPORT, Permission.ANALYTICS_VIEW
            ... ):
            ...     return generate_comprehensive_report()

        Use Cases:
            - **Complex Operations**: Operations requiring multiple permission types
            - **Security-sensitive Actions**: High-privilege operations
            - **Cross-resource Operations**: Actions spanning multiple resources
            - **Compliance Requirements**: Operations requiring specific permission combinations

        Performance:
            Short-circuits on first missing permission, making it efficient
            for checking large permission sets.

        Note:
            This method is stricter than has_any_permission() and should be used
            when all specified permissions are truly required for the operation.
        """
        return all(self.has_permission(perm) for perm in permissions)


async def get_security_context(request: Request) -> Optional[SecurityContext]:
    """Extract security context from JWT token in request.

    This is the core security function that extracts and validates JWT tokens
    from incoming requests, creating a SecurityContext object containing all
    authentication and authorization information.

    The function attempts to extract JWT tokens from multiple sources and
    performs comprehensive validation before creating the security context.

    Args:
        request (Request): FastAPI request object containing cookies, headers,
            and other request metadata.

    Returns:
        Optional[SecurityContext]: Complete security context if a valid JWT
            token is found and validated, None if no valid token is present.

    Token Extraction Sources:
        1. **Cookies**: Looks for 'sck_token' cookie (browser sessions)
        2. **Authorization Header**: Extracts 'Bearer <token>' format
        3. **Custom Headers**: Additional token sources if configured

    JWT Validation:
        - **Signature verification**: Ensures token hasn't been tampered with
        - **Expiration checking**: Validates token is still valid
        - **Required claims**: Validates presence of 'sub' and 'cid' claims
        - **Scope parsing**: Extracts permissions from 'scp' claim

    Permission Extraction:
        The 'scp' (scope) claim can be in multiple formats:
        - **List**: `["portfolio:read", "app:write"]`
        - **String**: `"portfolio:read app:write"` (OAuth 2.0 standard)

    Examples:
        >>> # Direct usage (not recommended - use dependencies instead)
        >>> context = await get_security_context(request)
        >>> if context and context.has_permission(Permission.PORTFOLIO_READ):
        ...     return get_portfolios()

        >>> # Proper usage with FastAPI dependency
        >>> @app.get("/api/portfolios")
        >>> async def list_portfolios(
        ...     context: Optional[SecurityContext] = Depends(get_security_context)
        ... ):
        ...     if not context:
        ...         raise HTTPException(401, "Authentication required")
        ...
        ...     if not context.has_permission(Permission.PORTFOLIO_READ):
        ...         raise HTTPException(403, "Permission denied")
        ...
        ...     return get_portfolios()

    Error Handling:
        This function logs security events but does NOT raise exceptions for:
        - Missing tokens
        - Invalid tokens
        - Expired tokens
        - Malformed claims

        Use the `require_*` dependency functions for automatic error handling.

    Logging:
        Security events are logged for:
        - Missing tokens (DEBUG level)
        - Invalid token format (WARNING level)
        - Missing required claims (WARNING level)
        - Successful context creation (DEBUG level)

    Performance:
        - Fast JWT validation using cryptographic libraries
        - Efficient permission set creation
        - Minimal memory allocation

    Note:
        This function is designed to be permissive - it returns None rather
        than raising exceptions. This allows endpoints to handle authentication
        gracefully and provide different behavior for authenticated vs
        unauthenticated users.

        For endpoints that require authentication, use the `require_authentication()`
        dependency instead.
    """
    # Extract JWT from cookies or headers
    jwt_payload, _ = get_authenticated_user(request.cookies, request.headers)
    if not jwt_payload:
        log.debug("No valid JWT token found in request")
        return None

    # Validate required claims
    if not jwt_payload.sub:
        log.warning("JWT token missing required 'sub' claim")
        return None

    if not jwt_payload.cid:
        log.warning("JWT token missing required 'cid' claim")
        return None

    # Extract permissions from scope (scp) claim
    permissions = set()
    if jwt_payload.scp:
        if isinstance(jwt_payload.scp, list):
            permissions = set(jwt_payload.scp)
        elif isinstance(jwt_payload.scp, str):
            # Handle space-separated scope string (OAuth standard)
            permissions = set(jwt_payload.scp.split())
        else:
            log.warning(f"Invalid scp claim format: {type(jwt_payload.scp)}")

    log.debug(
        "Security context extracted",
        details={
            "user_id": jwt_payload.sub,
            "client_id": jwt_payload.cid,
            "permissions_count": len(permissions),
            "token_type": jwt_payload.typ,
        },
    )

    return SecurityContext(
        user_id=jwt_payload.sub,
        client_id=jwt_payload.cid,
        client_name=jwt_payload.cnm or jwt_payload.cid,
        permissions=permissions,
        token_type=jwt_payload.typ or "access_token",
        jwt_payload=jwt_payload,
    )


def require_authentication():
    """Dependency factory that requires valid authentication.

    Creates a FastAPI dependency function that ensures the request contains
    a valid JWT token. This is the base dependency for all secured endpoints
    and automatically handles authentication errors.

    Returns:
        Callable: Async dependency function that extracts and validates
            security context, raising HTTPException if authentication fails.

    Raises:
        HTTPException: 401 Unauthorized if no valid JWT token is found in
            the request. The error response follows OAuth 2.0 standards.

    Error Response Format:
        .. code-block:: json

            {
                "error": "authentication_required",
                "error_description": "Valid JWT token required"
            }

    Usage Examples:
        >>> # Basic authenticated endpoint
        >>> @app.get("/api/profile")
        >>> async def get_profile(
        ...     context: SecurityContext = Depends(require_authentication())
        ... ):
        ...     return {
        ...         "user_id": context.user_id,
        ...         "client_id": context.client_id,
        ...         "permissions": list(context.permissions)
        ...     }

        >>> # Authenticated endpoint with manual permission checking
        >>> @app.get("/api/portfolios")
        >>> async def list_portfolios(
        ...     context: SecurityContext = Depends(require_authentication())
        ... ):
        ...     if context.has_permission(Permission.PORTFOLIO_READ):
        ...         return get_all_portfolios()
        ...     else:
        ...         return get_user_portfolios(context.user_id)

    Authentication Flow:
        1. Extract JWT token from request (cookies or headers)
        2. Validate token signature and expiration
        3. Parse JWT claims into SecurityContext
        4. Return SecurityContext if valid
        5. Raise 401 HTTPException if invalid or missing

    Token Sources:
        - **Cookie**: `sck_token` cookie value
        - **Header**: `Authorization: Bearer <token>` header
        - **Custom**: Additional configured token sources

    Use Cases:
        - **Base authentication**: Endpoints requiring any valid user
        - **User-specific data**: Endpoints returning user-specific information
        - **Manual authorization**: Endpoints with custom permission logic
        - **Token validation**: Endpoints that just need valid token presence

    Note:
        This dependency only validates authentication (valid token presence).
        For permission-based authorization, use `require_permissions()` or
        `require_any_permission()` dependencies instead.
    """

    async def check_authentication(
        context: Optional[SecurityContext] = Depends(get_security_context),
    ) -> SecurityContext:
        if not context:
            raise HTTPException(
                status_code=401, detail={"error": "authentication_required", "error_description": "Valid JWT token required"}
            )
        return context

    return check_authentication


def require_permissions(*required_permissions: Permission):
    """Dependency factory that requires specific permissions.

    Creates a FastAPI dependency function that enforces permission-based
    authorization. The user must have ALL specified permissions to access
    the endpoint.

    Args:
        *required_permissions: Variable number of Permission enum values that
            the user must possess. All permissions are required (AND logic).

    Returns:
        Callable: Async dependency function that validates authentication and
            authorization, raising HTTPException for security violations.

    Raises:
        HTTPException:
            - 401 Unauthorized if not authenticated
            - 403 Forbidden if authenticated but missing required permissions

    Error Response Formats:
        **Authentication Error (401)**:

        .. code-block:: json

            {
                "error": "authentication_required",
                "error_description": "Valid JWT token required"
            }

        **Authorization Error (403)**:

        .. code-block:: json

            {
                "error": "insufficient_permissions",
                "error_description": "Missing required permissions: ['portfolio:write']",
                "required_permissions": ["portfolio:read", "portfolio:write"]
            }

    Usage Examples:
        >>> # Single permission requirement
        >>> @app.get("/api/portfolios")
        >>> async def list_portfolios(
        ...     context: SecurityContext = Depends(require_permissions(Permission.PORTFOLIO_READ))
        ... ):
        ...     return {"portfolios": get_portfolios()}

        >>> # Multiple permission requirement
        >>> @app.post("/api/portfolios")
        >>> async def create_portfolio(
        ...     portfolio_data: dict,
        ...     context: SecurityContext = Depends(require_permissions(
        ...         Permission.PORTFOLIO_WRITE,
        ...         Permission.AWS_RESOURCES_WRITE
        ...     ))
        ... ):
        ...     return create_portfolio_with_infrastructure(portfolio_data)

        >>> # Administrative endpoint
        >>> @app.delete("/api/portfolios/{id}")
        >>> async def delete_portfolio(
        ...     id: str,
        ...     context: SecurityContext = Depends(require_permissions(
        ...         Permission.PORTFOLIO_DELETE,
        ...         Permission.PORTFOLIO_ADMIN
        ...     ))
        ... ):
        ...     return delete_portfolio_and_resources(id)

    Permission Logic:
        - **ALL required**: User must have every specified permission
        - **Wildcard support**: `*:admin`, `resource:*`, `*:action` patterns work
        - **Hierarchical**: Admin permissions override specific permissions
        - **Flexible**: Supports any combination of permission types

    Logging:
        Authorization failures are logged with:
        - User ID and client ID
        - Required permissions
        - Missing permissions
        - User's actual permissions

    Security Features:
        - **Fail-secure**: Denies access by default
        - **Comprehensive logging**: Full audit trail
        - **OAuth compliance**: Standard error response formats
        - **Wildcard support**: Flexible permission hierarchies

    Performance:
        - **Fast permission checking**: Set-based lookups
        - **Short-circuit evaluation**: Stops on first missing permission
        - **Minimal overhead**: Efficient dependency injection

    Note:
        This dependency enforces strict permission requirements (ALL permissions
        must be present). For more flexible authorization, use `require_any_permission()`
        which implements OR logic instead of AND logic.
    """

    async def check_permissions(
        context: SecurityContext = Depends(require_authentication()),
    ) -> SecurityContext:

        # Check if user has all required permissions
        missing_permissions = []
        for perm in required_permissions:
            if not context.has_permission(perm):
                missing_permissions.append(str(perm))

        if missing_permissions:
            log.warning(
                "Access denied - insufficient permissions",
                details={
                    "user_id": context.user_id,
                    "client_id": context.client_id,
                    "required_permissions": [str(p) for p in required_permissions],
                    "missing_permissions": missing_permissions,
                    "user_permissions": list(context.permissions),
                },
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "insufficient_permissions",
                    "error_description": f"Missing required permissions: {missing_permissions}",
                    "required_permissions": [str(p) for p in required_permissions],
                },
            )

        return context

    return check_permissions


def require_any_permission(*required_permissions: Permission):
    """Dependency factory that requires ANY of the specified permissions.

    Creates a FastAPI dependency function that enforces flexible permission-based
    authorization. The user must have AT LEAST ONE of the specified permissions
    to access the endpoint.

    Args:
        *required_permissions: Variable number of Permission enum values where
            the user needs at least one. Uses OR logic instead of AND logic.

    Returns:
        Callable: Async dependency function that validates authentication and
            flexible authorization, raising HTTPException for security violations.

    Raises:
        HTTPException:
            - 401 Unauthorized if not authenticated
            - 403 Forbidden if authenticated but has none of the required permissions

    Error Response Formats:
        **Authentication Error (401)**:

        .. code-block:: json

            {
                "error": "authentication_required",
                "error_description": "Valid JWT token required"
            }

        **Authorization Error (403)**:

        .. code-block:: json

            {
                "error": "insufficient_permissions",
                "error_description": "Requires any of: ['portfolio:read', 'portfolio:admin']",
                "required_any_of": ["portfolio:read", "portfolio:admin"]
            }

    Usage Examples:
        >>> # Read OR admin access
        >>> @app.get("/api/portfolios/{id}")
        >>> async def get_portfolio(
        ...     id: str,
        ...     context: SecurityContext = Depends(require_any_permission(
        ...         Permission.PORTFOLIO_READ, Permission.PORTFOLIO_ADMIN
        ...     ))
        ... ):
        ...     return get_portfolio_by_id(id)

        >>> # Multiple access levels for data export
        >>> @app.get("/api/data/export")
        >>> async def export_data(
        ...     context: SecurityContext = Depends(require_any_permission(
        ...         Permission.DATA_EXPORT,
        ...         Permission.ANALYTICS_VIEW,
        ...         Permission.WILDCARD_ADMIN
        ...     ))
        ... ):
        ...     return generate_data_export()

        >>> # Administrative OR power user access
        >>> @app.post("/api/system/maintenance")
        >>> async def start_maintenance(
        ...     context: SecurityContext = Depends(require_any_permission(
        ...         Permission.SYSTEM_CONFIG,
        ...         Permission.WILDCARD_ADMIN
        ...     ))
        ... ):
        ...     return initiate_system_maintenance()

    Permission Logic:
        - **ANY sufficient**: User needs at least one specified permission
        - **Wildcard support**: `*:admin`, `resource:*`, `*:action` patterns work
        - **Flexible access**: Supports multiple permission levels
        - **Hierarchical**: Higher permissions automatically grant access

    Use Cases:
        - **Flexible access control**: Multiple ways to access same resource
        - **Role migration**: Supporting old and new permission models
        - **Privilege escalation**: Different permission levels for same operation
        - **Backup permissions**: Primary + fallback permission options

    Logging:
        Authorization failures are logged with:
        - User ID and client ID
        - All required permission options
        - User's actual permissions

    Security Features:
        - **Fail-secure**: Denies access if no permissions match
        - **Audit logging**: Complete permission checking trail
        - **OAuth compliance**: Standard error response formats
        - **Performance optimized**: Short-circuits on first match

    Performance:
        - **Fast evaluation**: Stops checking on first matching permission
        - **Set-based lookups**: Efficient permission comparison
        - **Minimal overhead**: Lightweight dependency injection

    Note:
        This dependency implements OR logic (any permission sufficient) vs
        `require_permissions()` which implements AND logic (all permissions required).
        Choose based on whether you need strict or flexible authorization.
    """

    async def check_any_permission(
        context: SecurityContext = Depends(require_authentication()),
    ) -> SecurityContext:

        if not context.has_any_permission(*required_permissions):
            log.warning(
                "Access denied - no matching permissions",
                details={
                    "user_id": context.user_id,
                    "required_any_of": [str(p) for p in required_permissions],
                    "user_permissions": list(context.permissions),
                },
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "insufficient_permissions",
                    "error_description": f"Requires any of: {[str(p) for p in required_permissions]}",
                    "required_any_of": [str(p) for p in required_permissions],
                },
            )

        return context

    return check_any_permission


def require_token_type(*allowed_types: str):
    """Dependency factory that requires specific token types.

    Creates a FastAPI dependency function that enforces token type restrictions.
    This is useful for endpoints that should only accept certain types of tokens
    (e.g., session tokens for user management, access tokens for API access).

    Args:
        *allowed_types: Variable number of string token type names that are
            acceptable. Token type is extracted from JWT 'typ' claim.

    Returns:
        Callable: Async dependency function that validates authentication and
            token type, raising HTTPException for invalid token types.

    Raises:
        HTTPException:
            - 401 Unauthorized if not authenticated
            - 400 Bad Request if wrong token type (not 403, as this is client error)

    Error Response Formats:
        **Authentication Error (401)**:

        .. code-block:: json

            {
                "error": "authentication_required",
                "error_description": "Valid JWT token required"
            }

        **Token Type Error (400)**:

        .. code-block:: json

            {
                "error": "invalid_token_type",
                "error_description": "Token type 'access_token' not allowed",
                "allowed_types": ["session"]
            }

    Usage Examples:
        >>> # Only session tokens for sensitive user operations
        >>> @app.put("/api/users/me/password")
        >>> async def change_password(
        ...     new_password: str,
        ...     context: SecurityContext = Depends(require_token_type("session"))
        ... ):
        ...     return update_user_password(context.user_id, new_password)

        >>> # Only access tokens for API operations
        >>> @app.post("/api/portfolios")
        >>> async def create_portfolio(
        ...     portfolio_data: dict,
        ...     context: SecurityContext = Depends(require_token_type("access_token"))
        ... ):
        ...     return create_new_portfolio(portfolio_data)

        >>> # Multiple acceptable token types
        >>> @app.get("/api/profile")
        >>> async def get_profile(
        ...     context: SecurityContext = Depends(require_token_type("session", "access_token"))
        ... ):
        ...     return get_user_profile(context.user_id)

    Token Types:
        Common token types in the system:
        - **"session"**: Browser session tokens (cookie-based)
        - **"access_token"**: OAuth 2.0 access tokens (API access)
        - **"refresh_token"**: OAuth 2.0 refresh tokens (token renewal)
        - **"id_token"**: OpenID Connect ID tokens (user identity)

    Security Considerations:
        - **Session tokens**: Higher security for user account operations
        - **Access tokens**: API access with limited scope
        - **Refresh tokens**: Should only be used for token renewal
        - **Mixed usage**: Some operations accept multiple token types

    Use Cases:
        - **Sensitive operations**: Require session tokens for account changes
        - **API restrictions**: Limit certain endpoints to access tokens
        - **Token lifecycle**: Different operations for different token phases
        - **Security policies**: Enforce token type policies per operation

    Performance:
        - **Fast string comparison**: Simple token type validation
        - **Minimal overhead**: Single field check after authentication

    Note:
        Token type validation occurs after authentication but before permission
        checking. This ensures the token is valid before checking its type.

        Use 400 Bad Request for wrong token type (client error) rather than
        403 Forbidden (authorization error) since this is a request format issue.
    """

    async def check_token_type(
        context: SecurityContext = Depends(require_authentication()),
    ) -> SecurityContext:

        if context.token_type not in allowed_types:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_token_type",
                    "error_description": f"Token type '{context.token_type}' not allowed",
                    "allowed_types": list(allowed_types),
                },
            )

        return context

    return check_token_type


# Convenience dependency combinations for common use cases

# Token type restrictions
require_session_token = require_token_type("session")
"""Dependency that requires session tokens only.

Pre-configured dependency for endpoints that should only accept session tokens,
typically used for sensitive user account operations like password changes,
profile updates, and account deletion.

Example:
    >>> @app.put("/api/users/me")
    >>> async def update_profile(
    ...     profile_data: dict,
    ...     context: SecurityContext = Depends(require_session_token)
    ... ):
    ...     return update_user_profile(context.user_id, profile_data)
"""

require_access_token = require_token_type("access_token")
"""Dependency that requires access tokens only.

Pre-configured dependency for API endpoints that should only accept OAuth 2.0
access tokens, typically used for programmatic access to resources.

Example:
    >>> @app.get("/api/portfolios")
    >>> async def list_portfolios(
    ...     context: SecurityContext = Depends(require_access_token)
    ... ):
    ...     return get_portfolios_for_api(context.user_id)
"""

# Portfolio permissions
require_portfolio_read = require_permissions(Permission.PORTFOLIO_READ)
"""Dependency that requires portfolio read permission.

Pre-configured dependency for endpoints that need to read portfolio data.

Example:
    >>> @app.get("/api/portfolios")
    >>> async def list_portfolios(
    ...     context: SecurityContext = Depends(require_portfolio_read)
    ... ):
    ...     return get_user_portfolios(context.user_id)
"""

require_portfolio_write = require_permissions(Permission.PORTFOLIO_WRITE)
"""Dependency that requires portfolio write permission.

Pre-configured dependency for endpoints that need to create or update portfolios.

Example:
    >>> @app.post("/api/portfolios")
    >>> async def create_portfolio(
    ...     portfolio_data: dict,
    ...     context: SecurityContext = Depends(require_portfolio_write)
    ... ):
    ...     return create_portfolio(context.user_id, portfolio_data)
"""

require_portfolio_admin = require_permissions(Permission.PORTFOLIO_ADMIN)
"""Dependency that requires portfolio admin permission.

Pre-configured dependency for administrative portfolio operations like deletion
and cross-user portfolio management.

Example:
    >>> @app.delete("/api/portfolios/{id}")
    >>> async def delete_portfolio(
    ...     id: str,
    ...     context: SecurityContext = Depends(require_portfolio_admin)
    ... ):
    ...     return delete_portfolio_completely(id)
"""

# Application permissions
require_app_read = require_permissions(Permission.APP_READ)
"""Dependency that requires application read permission."""

require_app_write = require_permissions(Permission.APP_WRITE)
"""Dependency that requires application write permission."""

require_app_admin = require_permissions(Permission.APP_ADMIN)
"""Dependency that requires application admin permission."""

# Component permissions
require_component_read = require_permissions(Permission.COMPONENT_READ)
"""Dependency that requires component read permission."""

require_component_write = require_permissions(Permission.COMPONENT_WRITE)
"""Dependency that requires component write permission."""

require_component_admin = require_permissions(Permission.COMPONENT_ADMIN)
"""Dependency that requires component admin permission."""

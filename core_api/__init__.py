"""Simple Cloud Kit Core API Package.

The core_api package provides a comprehensive API layer for the Simple Cloud Kit (SCK)
ecosystem, offering both FastAPI development interfaces and AWS Lambda serverless
deployment capabilities. This package bridges the gap between local development and
cloud-native production deployments.

Key Components:
    - **API Layer**: FastAPI routers for development and testing
    - **Lambda Handlers**: AWS API Gateway compatible proxy handlers
    - **OAuth Server**: Complete OAuth 2.0 authorization server implementation
    - **Request/Response Models**: Standardized data models for API interactions
    - **Proxy Integration**: Seamless development-to-production parity

Architecture:
    The package follows a dual-deployment pattern:
    
    **Development Mode**:
        FastAPI server → OAuth endpoints → Business logic
        FastAPI server → Proxy handlers → Lambda functions (local simulation)
    
    **Production Mode**:
        AWS API Gateway → Lambda functions → Business logic
        AWS API Gateway → OAuth Lambda → OAuth logic

Modules:
    - **api/**: FastAPI application and routing infrastructure
        - fast_api.py: Main FastAPI application configuration
        - router.py: API route definitions and handlers  
        - apis.py: Lambda proxy integration for development
        - handler.py: AWS API Gateway response processing
    
    - **oauth/**: Complete OAuth 2.0 authorization server
        - handler.py: AWS Lambda entry point for OAuth endpoints
        - auth_oauth.py: Core OAuth 2.0 protocol implementation
        - auth_github.py: GitHub OAuth provider integration
        - auth_client.py: OAuth client management endpoints
        - auth_direct.py: Direct authentication endpoints
        - tools.py: JWT, PKCE, and authentication utilities
    
    - **request.py**: Request models and validation
    - **response.py**: Response models and AWS API Gateway integration
    - **proxy.py**: AWS API Gateway proxy event/response models

Features:
    - **OAuth 2.0 Complete**: Authorization code, refresh token, PKCE support
    - **GitHub Integration**: Seamless GitHub OAuth provider support
    - **JWT Security**: Secure token generation and validation
    - **AWS Native**: Full AWS API Gateway and Lambda compatibility
    - **Development Parity**: Identical behavior in dev and production
    - **Cookie Management**: FastAPI-compatible session handling
    - **Error Handling**: Comprehensive exception management
    - **Type Safety**: Full Pydantic model validation

Usage Examples:
    
    **Development Server**:
    
    .. code-block:: python
    
        # Start FastAPI development server
        import uvicorn
        from core_api.api.fast_api import app
        
        uvicorn.run(app, host="0.0.0.0", port=8000, workers=1)
    
    **AWS Lambda Deployment**:
    
    .. code-block:: python
    
        # OAuth server Lambda handler
        from core_api.auth.handler import handler
        
        def lambda_handler(event, context):
            return handler(event, context)
    
    **OAuth Flow**:
    
    .. code-block:: text
    
        OAuth authorization endpoint:
        GET /auth/v1/authorize?client_id=app&response_type=code&redirect_uri=...
        
        OAuth token exchange:
        POST /auth/v1/token
        {
            "grant_type": "authorization_code",
            "code": "auth_code_123",
            "redirect_uri": "https://app.example.com/callback"
        }

Dependencies:
    - fastapi: Web framework and API development
    - pydantic: Data validation and serialization
    - python-jose[cryptography]: JWT token handling
    - boto3: AWS service integration
    - sck-core-db: Database operations and models
    - sck-core-framework: Shared utilities and constants

Version Information:
    This package follows semantic versioning with pre-release and build metadata
    support. The version format is: MAJOR.MINOR.PATCH[-pre.N][+build]
    
    Example: "0.0.11-pre.5+f304d65"
    - Major: 0 (pre-1.0 development)
    - Minor: 0 (feature additions)
    - Patch: 11 (bug fixes)
    - Pre-release: pre.5 (5th pre-release)
    - Build: f304d65 (git commit hash)

API Endpoints:
    
    **OAuth Server** (/auth/\\*):
    - GET /auth/v1/authorize: OAuth authorization endpoint
    - POST /auth/v1/token: OAuth token exchange endpoint
    - GET /auth/github/login: GitHub OAuth initiation
    - GET /auth/github/callback: GitHub OAuth callback
    - POST /auth/v1/login: Direct user authentication
    - PUT /auth/v1/users/me: User profile management
    
    **Registry API** (/api/\\*):
    - Portfolio management endpoints
    - Application lifecycle endpoints
    - Component configuration endpoints
    - Build and deployment endpoints

Deployment:
    
    **Local Development**:
    
    .. code-block:: bash
    
        # Install package
        pip install -e .
        
        # Start development server
        uvicorn core_api.api.fast_api:app --reload --workers 1
    
    **AWS Lambda**:
    
    .. code-block:: bash
    
        # Package for Lambda
        pip install . -t lambda_package/
        
        # Deploy to AWS
        aws lambda create-function --function-name oauth-server \\
            --runtime python3.9 --handler core_api.auth.handler.handler

Note:
    This package is part of the Simple Cloud Kit ecosystem and requires
    proper configuration of AWS credentials, database connections, and
    OAuth client registrations for full functionality.

Author: Simple Cloud Kit Development Team
License: MIT
Repository: https://github.com/simple-cloud-kit/sck-core-api
"""

__version__ = "0.1.2-pre.38+34c33a3"

__all__ = ["__version__"]

from fastapi.middleware.cors import CORSMiddleware
from starlette.types import ASGIApp, Scope, Receive, Send


class SimpleProxyHeadersMiddleware:
    """Minimal X-Forwarded-* processor. Use uvicorn --proxy-headers if possible."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope.get("type") == "http":
            # Normalize headers to dict[bytes, bytes]
            hdrs = {k.lower(): v for k, v in scope.get("headers", [])}
            xf_proto = hdrs.get(b"x-forwarded-proto")
            xf_host = hdrs.get(b"x-forwarded-host")
            xf_for = hdrs.get(b"x-forwarded-for")

            # Scheme
            if xf_proto:
                scope["scheme"] = xf_proto.decode().split(",")[0].strip()

            # Host/port
            if xf_host:
                host = xf_host.decode().split(",")[0].strip()
                if ":" in host:
                    h, p = host.rsplit(":", 1)
                    try:
                        scope["server"] = (h, int(p))
                    except ValueError:
                        scope["server"] = (host, 443 if scope.get("scheme") == "https" else 80)
                else:
                    scope["server"] = (host, 443 if scope.get("scheme") == "https" else 80)

            # Client IP
            if xf_for:
                ip = xf_for.decode().split(",")[0].strip()
                scope["client"] = (ip, 0)

        await self.app(scope, receive, send)

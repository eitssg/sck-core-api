"""Dev-only Prometheus metrics wiring.

This module is optional and imported only in development. It keeps any
prometheus-client coupling out of the base application code.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, JSONResponse
from core_helper.aws import store


def add_dev_metrics_endpoint(app: FastAPI) -> None:
    """Attach a Prometheus /metrics endpoint with useful process/thread/GC metrics.

    Safe for dev use; uses dynamic imports and raises no exceptions to callers.
    """
    try:
        import importlib
        import time
        import threading
        import tracemalloc

        prom = importlib.import_module("prometheus_client")
        CollectorRegistry = prom.CollectorRegistry
        CONTENT_TYPE_LATEST = prom.CONTENT_TYPE_LATEST
        generate_latest = prom.generate_latest
        PROCESS_COLLECTOR = prom.PROCESS_COLLECTOR
        PLATFORM_COLLECTOR = prom.PLATFORM_COLLECTOR
        GC_COLLECTOR = prom.GC_COLLECTOR
        Counter = prom.Counter
        Histogram = prom.Histogram
        Gauge = prom.Gauge

        # Start tracemalloc to track memory allocations (helps surface leaks)
        if not tracemalloc.is_tracing():
            tracemalloc.start()

        registry = CollectorRegistry()
        # Default useful collectors
        registry.register(PROCESS_COLLECTOR)
        registry.register(PLATFORM_COLLECTOR)
        registry.register(GC_COLLECTOR)

        # Custom metrics
        req_count = Counter(
            "fastapi_requests_total",
            "Total HTTP requests",
            ["method", "path", "status"],
            registry=registry,
        )
        req_latency = Histogram(
            "fastapi_request_duration_seconds",
            "Request latency in seconds",
            ["method", "path"],
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
            registry=registry,
        )
        threads_gauge = Gauge(
            "process_threads",
            "Number of active threads",
            registry=registry,
        )
        heap_gauge = Gauge(
            "python_tracemalloc_heap_current_bytes",
            "Current Python heap size (tracemalloc current) in bytes",
            registry=registry,
        )
        cache_size_gauge = Gauge(
            "sck_cache_objects",
            "Number of objects in core_helper.aws.store",
            registry=registry,
        )
        # Metric for listing keys: export as an info metric with key labels
        cache_key_info = Gauge(
            "sck_cache_key_info",
            "Info metric to emit a time series per cache key (value is always 1).",
            ["key"],
            registry=registry,
        )

        # Middleware to record metrics per request
        @app.middleware("http")
        async def metrics_middleware(request: Request, call_next):  # type: ignore
            start = time.perf_counter()
            method = request.method
            # Reduce high-cardinality: use route path template if available
            path_template = None
            try:
                route = request.scope.get("route")
                if route and getattr(route, "path", None):
                    path_template = route.path
            except Exception:
                path_template = None
            path = path_template or request.url.path

            response = await call_next(request)

            dur = time.perf_counter() - start
            req_latency.labels(method=method, path=path).observe(dur)
            req_count.labels(method=method, path=path, status=str(response.status_code)).inc()

            # Update basic gauges
            threads_gauge.set(threading.active_count())
            try:
                current, _peak = tracemalloc.get_traced_memory()
                heap_gauge.set(current)
            except Exception:
                pass

            # Update cache metrics (guarded in case store changes)
            try:
                size = store.size() if hasattr(store, "size") else 0
                cache_size_gauge.set(size)
                # Reset all key infos first by setting observed keys to 1; old keys naturally disappear if not updated
                if hasattr(store, "keys"):
                    for k in store.keys():
                        cache_key_info.labels(key=str(k)).set(1)
            except Exception:
                pass
            return response

        @app.get("/metrics")
        def metrics_endpoint():  # type: ignore
            data = generate_latest(registry)
            return PlainTextResponse(data, media_type=CONTENT_TYPE_LATEST)

        @app.get("/metrics/cache_keys")
        def cache_keys_endpoint():  # type: ignore
            try:
                keys = store.keys() if hasattr(store, "keys") else []
            except Exception:
                keys = []
            return JSONResponse({"keys": keys})

    except Exception:
        # Silent no-op in dev if prometheus_client is missing or any error occurs
        # Caller gated this feature behind an env flag.
        return

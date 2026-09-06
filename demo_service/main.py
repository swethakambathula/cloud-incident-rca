"""
Cloud Run Production Demo Service (Checkout Service).
Implements structured JSON application logging and realistic incident simulation endpoints:
  - /health: Normal service health check
  - /simulate/error: Generates HTTP 500 and DATABASE_CONNECTION_TIMEOUT
  - /simulate/latency: Adds controlled high latency
  - /simulate/pool-exhaustion: Generates DATABASE_CONNECTION_POOL_EXHAUSTED
  - /simulate/dependency-failure: Simulates failure of downstream orders-service
  - /simulate/cpu: Creates controlled CPU pressure
  - /simulate/config-error: Produces endpoint-specific configuration failure
"""
import os
import time
import json
import uuid
import logging
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.responses import JSONResponse
import requests

SERVICE_NAME = os.getenv("K_SERVICE", "checkout-service")
REVISION_NAME = os.getenv("K_REVISION", "checkout-service-00004-v1")
ORDERS_SERVICE_URL = os.getenv("ORDERS_SERVICE_URL", "http://127.0.0.1:8081")

app = FastAPI(title="Checkout Service - Cloud Run Incident Demo")


def emit_structured_log(
    severity: str,
    message: str,
    incident_type: Optional[str] = None,
    error_code: Optional[str] = None,
    dependency: Optional[str] = None,
    request_id: Optional[str] = None,
    trace_id: Optional[str] = None,
    extra_fields: Optional[dict] = None
):
    """Emits machine-readable structured JSON logs compliant with Google Cloud Logging."""
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity": severity,
        "service": SERVICE_NAME,
        "revision": REVISION_NAME,
        "incident_type": incident_type or "none",
        "error_code": error_code or "none",
        "dependency": dependency or "none",
        "request_id": request_id or str(uuid.uuid4()),
        "trace_id": trace_id or "none",
        "message": message
    }
    if extra_fields:
        log_entry.update(extra_fields)

    print(json.dumps(log_entry), flush=True)


@app.get("/health")
def health():
    """Returns normal service health."""
    emit_structured_log("INFO", "Service health check passed.")
    return {
        "status": "healthy",
        "service": SERVICE_NAME,
        "revision": REVISION_NAME,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get("/simulate/error")
def simulate_error(request: Request, x_cloud_trace_context: Optional[str] = Header(None)):
    """Generates HTTP 500 and DATABASE_CONNECTION_TIMEOUT."""
    trace_id = x_cloud_trace_context.split("/")[0] if x_cloud_trace_context else str(uuid.uuid4())
    req_id = str(uuid.uuid4())

    emit_structured_log(
        severity="ERROR",
        message="DATABASE_CONNECTION_TIMEOUT: Connection to orders-db failed after 5000ms deadline exceeded",
        incident_type="database_connectivity_failure",
        error_code="DATABASE_CONNECTION_TIMEOUT",
        dependency="orders-db.internal",
        request_id=req_id,
        trace_id=trace_id,
        extra_fields={
            "db_host": "orders-db.internal:5432",
            "timeout_ms": 5000,
            "path": "/simulate/error"
        }
    )
    raise HTTPException(
        status_code=500,
        detail="DATABASE_CONNECTION_TIMEOUT: could not establish connection to database"
    )


@app.get("/simulate/latency")
def simulate_latency(duration_seconds: float = 3.5, x_cloud_trace_context: Optional[str] = Header(None)):
    """Adds controlled high latency."""
    trace_id = x_cloud_trace_context.split("/")[0] if x_cloud_trace_context else str(uuid.uuid4())
    time.sleep(duration_seconds)
    emit_structured_log(
        severity="WARNING",
        message=f"Request took {duration_seconds * 1000:.0f}ms exceeding SLA threshold",
        incident_type="high_latency_degradation",
        error_code="SLOW_QUERY_LATENCY",
        trace_id=trace_id,
        extra_fields={"duration_ms": duration_seconds * 1000}
    )
    return {
        "status": "degraded",
        "incident": "high_latency",
        "duration_seconds": duration_seconds
    }


@app.get("/simulate/pool-exhaustion")
def simulate_pool_exhaustion(x_cloud_trace_context: Optional[str] = Header(None)):
    """Generates DATABASE_CONNECTION_POOL_EXHAUSTED."""
    trace_id = x_cloud_trace_context.split("/")[0] if x_cloud_trace_context else str(uuid.uuid4())
    emit_structured_log(
        severity="ERROR",
        message="DATABASE_CONNECTION_POOL_EXHAUSTED: Pool max limit 50 reached. 45 threads waiting to acquire connection.",
        incident_type="connection_pool_exhaustion",
        error_code="DATABASE_CONNECTION_POOL_EXHAUSTED",
        dependency="orders-db",
        trace_id=trace_id,
        extra_fields={
            "pool_active": 50,
            "pool_max": 50,
            "pending_threads": 45,
            "wait_time_ms": 4800
        }
    )
    raise HTTPException(
        status_code=500,
        detail="DATABASE_CONNECTION_POOL_EXHAUSTED: timeout waiting for connection from pool"
    )


@app.get("/simulate/dependency-failure")
def simulate_dependency_failure(x_cloud_trace_context: Optional[str] = Header(None)):
    """Simulates failure of downstream orders-service."""
    trace_id = x_cloud_trace_context.split("/")[0] if x_cloud_trace_context else str(uuid.uuid4())
    target_url = f"{ORDERS_SERVICE_URL}/orders"

    try:
        resp = requests.get(target_url, timeout=2.0)
        if resp.status_code >= 400:
            emit_structured_log(
                severity="ERROR",
                message=f"DOWNSTREAM_DEPENDENCY_FAILURE: orders-service responded with HTTP {resp.status_code}",
                incident_type="dependency_failure",
                error_code="DOWNSTREAM_DEPENDENCY_FAILURE",
                dependency="orders-service",
                trace_id=trace_id,
                extra_fields={"downstream_status": resp.status_code, "url": target_url}
            )
            raise HTTPException(status_code=502, detail=f"Bad Gateway: orders-service returned {resp.status_code}")
        return {"status": "success", "orders": resp.json()}
    except Exception as e:
        emit_structured_log(
            severity="ERROR",
            message=f"DOWNSTREAM_DEPENDENCY_FAILURE: Failed calling downstream orders-service: {str(e)}",
            incident_type="dependency_failure",
            error_code="DOWNSTREAM_DEPENDENCY_FAILURE",
            dependency="orders-service",
            trace_id=trace_id,
            extra_fields={"error": str(e), "url": target_url}
        )
        raise HTTPException(
            status_code=502,
            detail=f"Bad Gateway: Downstream orders-service is unavailable ({str(e)})"
        )


@app.get("/simulate/cpu")
def simulate_cpu(intensity: int = 5000000):
    """Creates controlled CPU pressure."""
    start = time.time()
    total = 0
    for i in range(intensity):
        total += (i * i) % 12345
    elapsed_ms = (time.time() - start) * 1000

    emit_structured_log(
        severity="WARNING",
        message=f"CPU burn routine executed ({intensity} iterations in {elapsed_ms:.1f}ms)",
        incident_type="cpu_spike",
        error_code="CPU_UTILIZATION_HIGH",
        extra_fields={"elapsed_ms": elapsed_ms, "iterations": intensity}
    )
    return {"status": "completed", "elapsed_ms": elapsed_ms}


@app.get("/simulate/config-error")
def simulate_config_error(x_cloud_trace_context: Optional[str] = Header(None)):
    """Produces endpoint-specific configuration failure."""
    trace_id = x_cloud_trace_context.split("/")[0] if x_cloud_trace_context else str(uuid.uuid4())
    api_key = os.getenv("PAYMENT_GATEWAY_API_KEY")
    if not api_key:
        emit_structured_log(
            severity="ERROR",
            message="CONFIGURATION_REGRESSION: Required environment variable 'PAYMENT_GATEWAY_API_KEY' is missing or empty",
            incident_type="configuration_regression",
            error_code="CONFIGURATION_REGRESSION",
            trace_id=trace_id,
            extra_fields={"missing_env_var": "PAYMENT_GATEWAY_API_KEY"}
        )
        raise HTTPException(
            status_code=500,
            detail="CONFIGURATION_REGRESSION: missing required environment variable 'PAYMENT_GATEWAY_API_KEY'"
        )
    return {"status": "configured", "api_key_set": True}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)

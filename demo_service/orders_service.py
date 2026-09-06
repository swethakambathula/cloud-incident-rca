"""
Orders Service - Downstream dependency service for Cloud Run incident simulation.
Provides:
  - /health: Normal service health
  - /orders: List of customer orders (can fail when failure mode is toggled)
  - /fail: Toggle or trigger deliberate failure in orders-service
"""
import os
import json
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException

SERVICE_NAME = os.getenv("K_SERVICE", "orders-service")
REVISION_NAME = os.getenv("K_REVISION", "orders-service-00001-prod")

app = FastAPI(title="Orders Service - Downstream Dependency")

# State for failure simulation
FAILURE_MODE = False


@app.get("/health")
def health():
    return {
        "service": SERVICE_NAME,
        "revision": REVISION_NAME,
        "status": "healthy",
        "failure_mode": FAILURE_MODE
    }


@app.get("/orders")
def get_orders():
    if FAILURE_MODE:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": "CRITICAL",
            "service": SERVICE_NAME,
            "revision": REVISION_NAME,
            "message": "INTERNAL_FAILURE: Database connection lost. Unable to fetch orders."
        }
        print(json.dumps(log_entry), flush=True)
        raise HTTPException(
            status_code=503,
            detail="Service Unavailable: orders-service internal database failure"
        )

    return {
        "service": SERVICE_NAME,
        "orders": [
            {"order_id": "ord-1001", "total": 49.99, "status": "COMPLETED"},
            {"order_id": "ord-1002", "total": 129.50, "status": "PENDING"}
        ]
    }


@app.post("/fail/enable")
def enable_failure():
    global FAILURE_MODE
    FAILURE_MODE = True
    return {"failure_mode": FAILURE_MODE, "message": "orders-service will now return HTTP 503"}


@app.post("/fail/disable")
def disable_failure():
    global FAILURE_MODE
    FAILURE_MODE = False
    return {"failure_mode": FAILURE_MODE, "message": "orders-service healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8081)

import logging
import random
import time

from fastapi import FastAPI, HTTPException

app = FastAPI()
logger = logging.getLogger("incident-demo")
logging.basicConfig(level=logging.INFO)


@app.get("/")
def home():
    logger.info("Normal request completed")
    return {"status": "healthy"}


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/simulate/latency")
def simulate_latency():
    logger.warning("Simulating high latency incident")

    time.sleep(5)

    return {
        "status": "degraded",
        "incident": "high_latency"
    }

import logging

from fastapi import FastAPI, HTTPException

app = FastAPI()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("incident-demo")


@app.get("/")
def root():
    return {"status": "ok"}


@app.get("/simulate/error")
def simulate_error():

    logger.error(
        "DATABASE_CONNECTION_TIMEOUT "
        "service=demo-service dependency=orders-db"
    )

    raise HTTPException(
        status_code=500,
        detail="Database connection timeout"
    )

@app.get("/simulate/intermittent")
def intermittent():
    if random.random() < 0.7:
        logger.error(
            "DATABASE_CONNECTION_POOL_EXHAUSTED "
            "pool_usage=100"
        )

        raise HTTPException(
            status_code=500,
            detail="Connection pool exhausted"
        )

    return {"status": "success"}
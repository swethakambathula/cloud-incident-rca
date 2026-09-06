# Architecture: checkout-service

## Overview
Primary user-facing service handling cart checkout. Runs on Cloud Run, us-central1, scales 0-20 instances, concurrency 80. Written in Python Flask.

## Dependencies
- **orders-service** (downstream HTTP): called on `POST /checkout` to create order; critical path.
- **orders-db** (PostgreSQL via VPC connector): accessed through connection pool (max 50).
- **payment-service** (optional external, not in demo): called after order creation.

## Endpoints
- `/checkout` (POST) - triggers orders-service call + DB write
- `/simulate/error` - synthetic DB timeout injection
- `/simulate/pool-exhaustion` - pool saturation
- `/simulate/dependency-failure` - downstream outage simulation
- `/simulate/cpu`, `/simulate/latency`, `/simulate/config-error` - resource simulations
- `/health` - readiness probe (does not require DB)

## Scaling & Configuration
- Env vars: `DATABASE_URL`, `ORDERS_SERVICE_URL`, `POOL_MAX_SIZE`
- VPC connector: `projects/.../connectors/serverless-connector`
- Connection pool: Hikari-like pool max 50, idle timeout 30s

## Failure Modes
- DB unreachable → `DATABASE_CONNECTION_TIMEOUT`
- Pool exhausted → `DATABASE_CONNECTION_POOL_EXHAUSTED`
- orders-service down → `DOWNSTREAM_DEPENDENCY_FAILURE`
- Bad revision → `NULL_POINTER_EXCEPTION` in PaymentProcessor

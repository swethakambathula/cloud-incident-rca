# Architecture: orders-service

## Overview
Downstream service owned by orders team. Handles `POST /orders` and `GET /orders/{id}`. Stateless, backed by same PostgreSQL cluster as checkout-service but separate schema.

## Dependencies
- **orders-db** (PostgreSQL)
- No downstream calls of its own (leaf service)

## Failure Modes
- DB outage propagates as 503 to checkout-service
- CPU saturation under overload returns 429/503
- Version mismatch can cause contract breakage (checkout expects 201, receives 500)

## Observability
- Logs: `orders-service` Cloud Run revision logs
- Metrics: `run.googleapis.com/request_count` filtered by service_name=orders-service
- Traces: span name `orders-service.create_order`

## Blast Radius Relationship
- checkout-service depends on orders-service; failure cascades upward.
- Failure in orders-service should be classified as dependency failure, not caller bug.

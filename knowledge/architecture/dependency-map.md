# Architecture: Dependency Map

```
Client (Browser / API Gateway)
  |
  v
checkout-service (Cloud Run, us-central1)
  |--[HTTP Sync]--> orders-service (Cloud Run, us-central1)
  |                    |
  |                    v
  |                orders-db (Cloud SQL PostgreSQL, us-central1)
  |
  |--[DB Pool]--> orders-db (direct pooled connections)
  |
  v (optional)
payment-service (external, not instrumented)
```

## Edge Criticality
- checkout -> orders-service : HARD dependency; checkout cannot succeed without order creation.
- checkout -> orders-db : HARD dependency for checkout history write.
- orders-service -> orders-db : HARD.

## Failure Propagation
- orders-db unreachable → both services return 500 (checkout logs `DATABASE_CONNECTION_TIMEOUT`, orders-service also fails).
- orders-service unavailable → checkout returns 502/503 with `DOWNSTREAM_DEPENDENCY_FAILURE`; DB metrics remain healthy.
- Client-side pool exhaustion → checkout latency spike; DB healthy; orders-service healthy.

## Regional Scope
- All demo services in us-central1 single region. Multi-region not deployed. Blast radius `REGIONAL` would require cross-region replication which is not configured.

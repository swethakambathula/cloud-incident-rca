# Runbook: Connection Pool Exhaustion

## Description
Application connection pool saturation where active connections reach configured maximum, causing pending acquire queue buildup and worker thread starvation. Database server itself remains healthy.

## Symptoms
- Log Code: `DATABASE_CONNECTION_POOL_EXHAUSTED`
- Pool metrics: `active == max` (e.g., 50/50), `pending_acquire` > 0, `waiting_threads` elevated
- P95 latency surge due to queue wait, not DB query time
- HTTP 500 on endpoints requiring DB access
- Database CPU remains normal (<30%)

## Diagnostic Checks
1. Check pool metrics: active, idle, pending, wait queue length.
2. Inspect trace spans: queue_wait_ms >> db_query_ms confirms client-side bottleneck.
3. Review transaction scopes for unclosed connections or leaked connections.
4. Verify max pool size vs database max_connections.
5. Check for recent traffic increase or long-running transactions holding connections.

## Known Failure Patterns
- Leak: connections not returned after request completes.
- Undersized pool: legitimate traffic growth exceeds pool capacity.
- Long transaction: single slow query holds connection blocking others.

## Approved Remediation Guidance
- Increase max pool size cautiously after verifying DB can handle more connections.
- Fix connection leaks: ensure `try/finally` close or context manager usage.
- Reduce transaction scope: fetch only required rows, avoid holding connection during external calls.
- Do not restart database; bottleneck is client-side.

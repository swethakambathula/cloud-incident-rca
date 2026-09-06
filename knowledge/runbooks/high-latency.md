# Runbook: High Latency Degradation

## Description
Occurs when p95 or p99 service response latency exceeds defined SLA thresholds (> 1000ms).

## Symptoms
- Elevated latency metrics in Cloud Monitoring
- Client timeouts or slow page renders
- Increased worker concurrency in Cloud Run instances

## Diagnostic Checks
1. Identify whether latency is internal (CPU/thread starvation) or external (slow database query / third-party API).
2. Check trace spans to isolate the longest duration child span.
3. Review database query logs for table scans or missing indexes.

## Approved Remediation Guidance
- If external dependency is slow, enable aggressive caching or fallback defaults.
- Optimize slow queries or adjust connection pool timeouts.

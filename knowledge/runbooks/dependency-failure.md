# Runbook: Downstream Dependency Failure

## Description
Checkout-service (or other caller) fails because a downstream dependency (orders-service, payments-service, inventory-service) became unavailable, propagating 502/503 errors upstream.

## Symptoms
- Log Code: `DOWNSTREAM_DEPENDENCY_FAILURE`
- Only endpoints calling downstream service fail; independent endpoints remain healthy
- Trace path shows `client -> caller-service -> failing-dependency -> error/timeout`
- Caller CPU/memory remains normal
- Dependency status UNREACHABLE or UNAVAILABLE
- HTTP 502/503 upstream, not 500 from caller logic

## Diagnostic Checks
1. Inspect dependency health: Cloud Run logs and metrics of downstream service.
2. Check traces: identify failing downstream span and its latency/error code.
3. Verify if failure is origin (downstream is truly down) vs caller misconfiguration (wrong URL, stale service discovery).
4. Check circuit breaker / retry policy: should isolate failure.

## Approved Remediation Guidance
- Investigate downstream service first; do not roll back caller unless caller config caused it.
- Enable fallback or cached response if downstream has graceful degradation.
- Review dependency timeout settings: too-short timeout can mimic outage.

# Historical Incident INC-003: Downstream Dependency Failure

- **Date**: 2026-08-02T13:45:00Z
- **Service**: checkout-service (origin: orders-service)
- **Failure Pattern**: dependency_failure
- **Title**: orders-service Outage Cascaded to checkout-service 502/503
- **Symptoms**: DOWNSTREAM_DEPENDENCY_FAILURE targeting orders-service, status UNAVAILABLE, checkout CPU normal, dependency cascade in traces
- **Root Cause**: orders-service OOMKilled after traffic spike, restarted with insufficient memory limit.
- **Resolution**: Scale orders-service memory and instances; add circuit breaker in checkout-service.
- **Similarity Key**: DOWNSTREAM_DEPENDENCY_FAILURE + healthy caller metrics + dependency status UNAVAILABLE + trace spans show downstream error
- **Diagnostic Checks Recommended**: Check downstream service logs/metrics, inspect trace dependency path, verify circuit breaker config.

# Runbook: Traffic Overload / Capacity Exhaustion

## Description
Incoming request volume surges beyond provisioned Cloud Run capacity, saturating CPU and causing request queue throttling. Errors span all endpoints uniformly.

## Symptoms
- Log Code: `REQUEST_QUEUE_FULL_THROTTLED` or `RATE_LIMITED`
- Request volume +200% vs baseline or sustained high RPM
- CPU utilization CRITICAL (>=85%), memory may also spike
- Instance count at max ceiling, concurrency saturated
- Latency elevated due to queuing, but uniform across endpoints
- No recent deployment or error code pointing to bug

## Diagnostic Checks
1. Compare baseline vs incident request volume percentage change.
2. Check CPU utilization: must be CRITICAL to support overload hypothesis. Normal CPU contradicts overload.
3. Check instance count vs max-instances config; verify autoscaling hit ceiling.
4. Inspect IP distribution for botnet or DDoS signature.
5. Verify no code regression causing infinite loop (would show CPU spike without traffic surge).

## Approved Remediation Guidance
- Increase max-instances or CPU allocation.
- Enable Cloud Armor rate limiting or throttle abusive IPs.
- Do not roll back recent deployment unless deployment reduced concurrency.
- Contradictory evidence: if CPU normal, do not diagnose as traffic overload.

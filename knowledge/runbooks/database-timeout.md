# Runbook: Database Connection Timeout

## Description
Occurs when the application container fails to establish a TCP or TLS connection with the target database host within the configured socket connect timeout (default 5000ms).

## Symptoms
- Log Code: `DATABASE_CONNECTION_TIMEOUT`
- HTTP 500 status on database-dependent API endpoints
- Spikes in response latency due to connection retry backoff
- Database server CPU / memory may remain completely normal

## Diagnostic Checks
1. Verify Serverless VPC Access connector health and egress routing in Cloud Run.
2. Check Cloud SQL or PostgreSQL database instance status (ensure not in MAINTENANCE or STOPPED state).
3. Inspect VPC firewall rules for dropped egress traffic on port 5432 / 3306.
4. Verify database user credentials and host IP resolution.

## Approved Remediation Guidance
- If VPC connector is degraded, restart or scale connector instances.
- If database instance is restarting, await healthy status and verify failover replica.
- Do not blindly roll back application revisions unless connection string configuration changed.

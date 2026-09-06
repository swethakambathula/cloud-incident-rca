# Historical Incident INC-001: Database Timeout

- **Date**: 2026-07-12T14:10:00Z
- **Service**: checkout-service
- **Failure Pattern**: database_connectivity
- **Title**: VPC Connector Degradation Caused orders-db Unreachable
- **Symptoms**: DATABASE_CONNECTION_TIMEOUT count=148, 5xx 24%, p95 5020ms, CPU normal 24%
- **Root Cause**: Serverless VPC connector egress route misconfigured after maintenance, blocking port 5432 to Cloud SQL.
- **Resolution**: Restart VPC connector; verify firewall egress rule.
- **Similarity Key**: DATABASE_CONNECTION_TIMEOUT + normal CPU/memory + UNREACHABLE DB status
- **Diagnostic Checks Recommended**: Check VPC connector health, Cloud SQL instance status, firewall port 5432.

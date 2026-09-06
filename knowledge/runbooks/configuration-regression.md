# Runbook: Configuration Regression

## Description
Required environment variable or secret missing or misconfigured in new revision, causing endpoint-specific failures while container and health checks remain OK.

## Symptoms
- Log Code: `CONFIGURATION_REGRESSION`
- Error message mentioning missing env var or secret (e.g., `Missing required env var DATABASE_URL`)
- Failure isolated to endpoints needing the missing config; `/health` succeeds
- CPU/memory normal; DB healthy; no traffic surge

## Diagnostic Checks
1. Compare env vars between previous and current revision (added/removed/modified).
2. Check Secret Manager IAM for runtime service account.
3. Verify Cloud Build deployment correctly injected secrets.

## Approved Remediation Guidance
- Restore missing env var in Cloud Run service spec and redeploy.

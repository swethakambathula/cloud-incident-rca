# Runbook: Bad Deployment / Faulty Revision

## Description
Faulty Cloud Run revision deployed with code regression, missing dependency, or configuration error causing runtime exceptions on new revision only. Previous revision was healthy.

## Symptoms
- New revision deployed minutes before incident (check `creation_time` vs incident start)
- Traffic 100% migrated to new revision immediately before error spike
- Log Code: `NULL_POINTER_EXCEPTION`, `UNHANDLED_RUNTIME_EXCEPTION`, or similar application stack traces containing new revision name
- Error rate surge isolated to new revision; rollback immediately restores health
- CPU/memory remain normal; dependencies healthy

## Diagnostic Checks
1. Compare `creation_time` of latest revision with incident start timestamp. Proximity < 15min increases suspicion but is not proof.
2. Check traffic allocation: confirm 100% traffic on suspected revision.
3. Compare revision configs: image SHA, env vars, secrets between previous and current revision.
4. Check git diff between revisions for recent code changes.
5. Validate that only new revision emits stack traces.

## Approved Remediation Guidance
- Roll back traffic to previous healthy revision (human approval required).
- Do not scale or restart database; issue is application code.
- Add regression test covering failing code path.

## Historical Precedent
- INC-002-bad-deployment: NullPointerException in PaymentProcessor.java after refactoring, 2min after deploy.

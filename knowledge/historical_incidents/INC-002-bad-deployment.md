# Historical Incident INC-002: Bad Deployment

- **Date**: 2026-07-20T14:58:00Z
- **Service**: checkout-service
- **Failure Pattern**: faulty_revision
- **Title**: Faulty Revision checkout-00042 NullPointerException After 2-Minute Deploy
- **Symptoms**: New revision checkout-00042 deployed at 14:58, errors from 15:00, NULL_POINTER_EXCEPTION 310, error rate 34%, revision 100% traffic
- **Root Cause**: Refactor of PaymentProcessor.java left null branch unhandled (line 84).
- **Resolution**: Rollback to checkout-00004-v1.
- **Similarity Key**: NULL_POINTER_EXCEPTION + deployment within minutes + previous revision healthy + no DB/dependency issues
- **Diagnostic Checks Recommended**: Compare creation_time vs incident start, inspect git diff, verify traffic split, check that only new revision emits stack traces.

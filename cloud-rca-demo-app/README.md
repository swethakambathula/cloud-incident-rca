# cloud-rca-demo-app

Intentionally faulty demo services for the Cloud RCA Agent end-to-end
“Incident → RCA → Code Fix → PR” workflow.

## Layout

- `services/checkout/` — checkout API (database pool, config, downstream calls)
- `services/orders/` — downstream orders dependency
- `services/payments/` — payments gateway client
- `scenarios/` — 12 incident definitions with ground-truth RCA metadata
- `tests/` — pytest suite (incident-scenario tests fail on faulty code, pass after patch)

## Publish as its own repository

```bash
cd cloud-rca-demo-app
git init -b main
git add -A && git commit -m "feat: faulty demo services with ground-truth scenarios"
gh repo create swethakambathula/cloud-rca-demo-app --public --source=. --push
```

## Run tests

```bash
pytest -q
```

## Fault catalogue

| Scenario | Fault location | Fix |
|---|---|---|
| pool_exhaustion | `services/checkout/database.py` POOL_SIZE=2/TIMEOUT=1 | 20/10 |
| bad_deployment | `services/checkout/config.py` FEATURE_FLAG_NEW_BILLING=True | False |
| config_regression | `services/checkout/config.py` host/key | routable host + key |
| dependency_failure | `services/checkout/dependencies.py` timeout=1/retries=0 | 5s + 2 retries |
| others (db_timeout, traffic, …) | infra/client-side | **no code fix** |

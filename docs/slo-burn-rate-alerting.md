# ALB error-budget burn-rate alerting

The existing absolute target-5xx alarm is useful for a simple failure count, but five errors have very different meaning at 50 requests and five million requests. `infra/slo.tf` adds request-normalized availability alerts for a 99.9% target SLO.

For each window, CloudWatch metric math evaluates:

```text
error rate (%) = 100 × target 5xx count / request count
```

The expression returns zero below a declared request floor so low-volume ratios do not create noisy alerts. Four window alarms feed two composite signals:

| Signal | Short window | Long window | Burn rate | Error-rate threshold |
| --- | ---: | ---: | ---: | ---: |
| Page | 5 minutes | 1 hour | 14.4× | 1.44% |
| Ticket | 30 minutes | 6 hours | 6× | 0.60% |

Both windows in a pair must be in `ALARM`. The short window reacts quickly; the long window prevents a brief isolated spike from paging or ticketing by itself. Alert actions are intentionally not embedded because SNS/PagerDuty routing, ownership and escalation policy belong to the deployment environment.

## Credential-free validation

`infra/tests/slo_burn_rate.tftest.hcl` uses Terraform's mocked AWS provider. It plans the complete module without credentials and asserts:

- all four burn windows remain present;
- thresholds continue to match the 99.9% error budget and declared burn rates;
- each window retains request and target-5xx metrics plus one returned expression;
- missing-data and evaluation semantics remain explicit;
- composite rules require both their short and long windows.

Run locally with Terraform 1.9.8:

```bash
terraform -chdir=infra init -backend=false -input=false
terraform -chdir=infra test -test-directory=tests
```

## Operational boundary

These alarms measure ALB target 5xx responses, not total user-perceived availability. They omit client errors, load-balancer-generated failures, timeouts that surface through other metrics and correctness failures returning HTTP 2xx. The request floors also intentionally suppress low-volume windows; production should separately monitor traffic disappearance and tune floors from observed volume.

The next step is to add latency SLO burn alerts, route composite alarm ARNs through environment-owned notification policy and rehearse alarm transitions with synthetic CloudWatch metric injection in an isolated AWS account.

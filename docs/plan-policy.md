# Terraform plan policy gate

`tools/aws_plan_policy.py` evaluates `terraform show -json` output before deployment. It blocks
resource deletion/replacement, public security-group ingress, incomplete S3 public-access
controls, disabled versioning, non-KMS bucket encryption, weak object ownership, disabled KMS
rotation, and wildcard IAM grants. Required control resource types must remain in the plan.

```bash
terraform -chdir=infra show -json tfplan > plan.json
python tools/aws_plan_policy.py plan.json
```

The JSON report is deterministic and the CLI exits `1` for policy violations or `2` for malformed
evidence. Fixture tests run without AWS credentials.

## Boundaries

This structural gate is deliberately narrow. It does not evaluate effective IAM across attached
managed policies, organization SCPs, bucket policies, live-state drift, provider-computed unknown
values, or application-layer authorization. Production deployment should combine it with a real
plan from an isolated AWS account, state locking, policy review, and cloud-native detection.

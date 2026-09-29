# ECR inference image boundary

The platform already routes private workloads to the ECR API and Docker endpoints. This module adds
the repository-side controls that make that path usable without treating a mutable tag as a release
identity.

## Enforced controls

- Tags are immutable, so a published `release-*` name cannot be moved to different bytes.
- Images are encrypted with the platform KMS key rather than the service-default key.
- Basic ECR vulnerability scanning starts on every push.
- Terraform refuses to delete a non-empty repository through `force_delete`.
- The newest 30 `release-*` images remain available for rollback.
- Untagged intermediate images expire after seven days to bound abandoned build storage.

`infra/tests/ecr_security.tftest.hcl` evaluates these properties in an isolated Terraform test with
a mocked AWS provider. It needs no cloud credentials, creates no AWS resources and catches a
weakened configuration before a real apply.

## Deployment contract

Tag immutability prevents overwriting a tag; it does not make the tag the strongest deployment
identity. Build automation should resolve the pushed manifest digest and update the external ECS task
definition with an image reference such as:

```text
123456789012.dkr.ecr.eu-central-1.amazonaws.com/ml-inference@sha256:<manifest-digest>
```

The external ECS execution role—not the application task role in this repository—must receive only
the ECR authorization and pull permissions it needs. The task role intentionally remains limited to
model artifacts, the application secret and KMS decryption.

## Limitations and next control

Basic scanning is asynchronous and does not block deployment. A clean scan is also not proof of
source provenance, reproducibility or absence of unknown vulnerabilities. Lifecycle rules are
retention policy, not a backup, and image expiry is asynchronous.

The next control is a deployment gate that verifies a keyless signature and SBOM/provenance
attestations for the exact manifest digest, then records that digest in the ECS task definition and
release evidence. Production accounts should also enable account-level enhanced scanning and route
findings through their governed vulnerability-response workflow.

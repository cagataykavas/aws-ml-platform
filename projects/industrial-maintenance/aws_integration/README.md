# SageMaker SDK boundary demo (offline only)

**Implemented and tested:** Python request builder, installed botocore schema
validation, and a real boto3 client behind `botocore.stub.Stubber`.
**Not performed:** S3 upload, AWS job creation, cloud training, deployment, IAM
configuration, live cost measurement, or inference against an AWS endpoint.
There is intentionally no submit function or cloud-enabled CLI flag.

## Run from the repository root

```sh
python -m venv .venv
.venv/bin/pip install -r requirements-sdk.txt
.venv/bin/python -m pytest -q aws_integration
.venv/bin/python -m aws_integration.request
```

The final command prints JSON using placeholder resources; it sends nothing.
The checked-in `example_request.json` is the same generated payload.

## Design and official reference

The [official CreateAutoMLJobV2 SDK reference](https://docs.aws.amazon.com/boto3/latest/reference/services/sagemaker/client/create_auto_ml_job_v2.html)
was checked on 2026-11-08. The payload selects tabular binary classification,
F1, and XGBoost in hyperparameter-tuning mode. Separate training and validation
channels use CSV headers. The target column defaults to `Machine failure`; override it
if the prepared CSV uses a different name. Both channels need identical headers.
No `DataSplitConfig` is supplied. `ModelDeployConfig` is omitted, so no automatic
deployment is requested. Setting its `AutoGenerateEndpointName` field to false
is not an alternative deployment-disable switch: that configuration expects a
named endpoint. Completion criteria constrain candidate count and runtime.

## Guardrails and evidence boundaries

- Local policy caps: two candidates, 600 seconds per candidate, 1,800 seconds
  total. These are conservative project choices, **not a guaranteed dollar cap**.
- Input/output prefixes cannot overlap. This catches obvious mistakes but does
  not inspect S3 or prove that datasets contain different rows.
- Preserve the local split when preparing cloud inputs: no held-out test rows,
  IDs, future information, or post-failure labels among predictors. A successful
  request-shape test cannot detect data leakage.
- Tests replace network connections with failures, isolate AWS profile paths,
  disable metadata lookup, and pass dummy credentials explicitly.
- Stubber returns a programmed ARN. It does not prove AWS accepted the request,
  the role exists, S3 is readable, region/quota availability, model quality, or
  that an endpoint works. Botocore validation checks modeled shapes, not every
  service-side semantic constraint (including all enum/range rules).
- Before any future cloud run: obtain separate approval for the precise AWS
  account/region, data upload, resource scope, and a reviewed spending limit;
  establish least-privilege roles and data controls. This project has no such
  permission and contains no credential setup workflow.
- If later authorized, review current pricing and quotas; set budget alerts and
  a teardown checklist. Alerts and runtime limits are not hard spending caps.
  Inventory training/processing jobs, S3 artifacts and any separately created
  endpoints, stop active compute, and remove resources only under an approved
  cleanup plan. Do not assume a successful experiment cleans up everything.

## Honest interview description

“I built an offline SageMaker Autopilot request path and tested its SDK contract
with boto3 and Stubber. I verified the API schema and isolated train/validation
inputs. I have not run or deployed this experiment in AWS.”

## Dataset semantics and split mapping

This example uses the official UCI AI4I 2020 synthetic benchmark. These are
synthetic records, not field sensor measurements. `Machine failure` is a same-row
fault classification target, not a future-failure horizon or remaining-useful-life
target. Do not present its results as prospective predictive maintenance.

For a separately approved future upload, map `reports/autopilot_train.csv` to
the training channel and `reports/autopilot_selection.csv` to the validation
channel. Keep the final test partition excluded from both channels and all
model/threshold selection. No upload is implemented or performed here.

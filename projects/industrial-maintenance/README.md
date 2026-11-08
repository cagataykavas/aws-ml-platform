# Industrial Maintenance ML: reproducible fault classification + SageMaker AutoML request tests

A portfolio project built to demonstrate industrial data-science and AWS integration concepts, with deliberately explicit evidence boundaries.

## What is actually demonstrated?

- A local, reproducible benchmark on the public UCI AI4I 2020 dataset (10,000 observations).
- Explicit exclusion of failure-mode labels and identifiers from model inputs.
- Three-model automated local comparison, separate threshold-calibration set, untouched final test evaluation.
- A trained preprocessing/model artifact, JSON/CSV inference handlers, schema checks and quality monitoring.
- A **real boto3 SageMaker CreateAutoMLJobV2 request builder**, validated with botocore and Stubber tests without contacting AWS.
- **Not** a completed SageMaker cloud job, endpoint deployment, AWS certification, production maintenance system or independently acquired candidate experience.

The local three-model search is a simple automated comparison. It is **not** SageMaker Autopilot execution. The SageMaker request tests separately demonstrate SDK integration correctness at the local contract boundary. They cannot prove account permissions, regional availability, actual training success or deployment.

## Dataset and task honesty

Source: [UCI AI4I 2020](https://archive.ics.uci.edu/dataset/601/ai4i), DOI [10.24432/C5HS5C](https://doi.org/10.24432/C5HS5C). Author: Stephan Matzka. License: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

The data is **synthetic**, designed to resemble industrial maintenance observations. It is not measured PaneraTech furnace data. The target is whether a failure occurs in the **current observation**, not whether a machine fails in 24 hours or its remaining useful life. There are no verified per-machine timestamps permitting claims about real-world warning lead time or new-asset generalization.

We retain the provided UDI order for a block-wise robustness benchmark. UDI is an observation identifier, **not a timestamp or asset ID**. No claim of rigorous chronological or unseen-machine validation is made. Feature distributions and rare failure counts can differ across blocks. Strong field conclusions require real time/asset provenance, multiple evaluations and uncertainty estimates.

Inputs: Type, air temperature, process temperature, rotational speed, torque, tool wear. Excluded: UDI, Product ID, TWF/HDF/PWF/OSF/RNF failure-mode labels, and Machine failure itself.

Data CSV SHA-256: `dc6630cd9b1f0f853922fad78a1b6436570d3f1ec863f1dd5c4340ac56bc8a8e`

## Run locally

Python 3.12 recommended. Package versions are pinned.

```bash
python -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
export OMP_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2 MKL_NUM_THREADS=2 LOKY_MAX_CPU_COUNT=2
.venv/bin/python -m maintenance.train --data data/ai4i2020.csv --output reports
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m pytest -q aws_integration
```

On Windows use `.venv\Scripts\python.exe`; set environment variables using your shell. No AWS credentials are needed. Training, tests and request generation do not launch cloud services.

## Architecture

```text
Public CSV
  → SensorValidator + strict feature whitelist
  → UDI-ordered partitions
      train 6000 → fit preprocessors + 3 candidate models
      selection 1500 → choose highest average precision
      calibration 1000 → choose threshold (illustrative FN:FP cost 10:1)
      test 1500 → one final evaluation; no tuning here
  → model.joblib + metrics.json + predictions.csv + reference.json
  → local JSON/CSV inference + batch sensor-quality checks

Optional, not executed:
  approved S3 train/selection exports
  → validated CreateAutoMLJobV2 request
  → SageMaker Autopilot HPO with runtime/candidate limits
  → separate external final evaluation before any deployment decision
```

The SDK builder creates a request only. It has no submit function. See [SDK details](aws_integration/README.md). Any actual cloud run would need user-approved cost scope, authorized S3 locations/role and current account/region checks.

## Measured results

Model selection average precision: logistic regression 0.409, random forest 0.554, histogram gradient boosting 0.672. The last model wins **on selection data**, not on final test.

Final held-out block (1,500 rows, only 29 positive observations):

| Metric | Result |
|---|---:|
| Average precision | 0.6804 |
| No-skill positive prevalence | 0.0193 |
| Precision | 0.2857 |
| Recall | 0.8276 |
| F1 | 0.4248 |
| True positives / false negatives | 24 / 5 |
| False positives / true negatives | 60 / 1411 |
| Threshold selected on calibration | 0.01698 |
| Example cost (FN=10, FP=1) | 110 |
| All-negative example cost | 290 |

This is a recall-oriented operating point with **many false alarms**. Do not market it as production-ready or “high-accuracy predictive maintenance.” The 10:1 cost assumption is illustrative, not verified industrial economics. Model probabilities are not independently calibrated; the calibration split calibrates the **decision threshold**, not probability reliability. Only 29 test failures limits certainty. The exact report and dependency versions are in reports/metrics.json.

Quality checks detect invalid values and large distribution shifts, but neither proves a physical fault or performance decay. They request human review; no automatic retraining or operational shutdown occurs.

## Test coverage

ML/core tests cover feature exclusion, partition ordering/disjointness, schema violations, invalid labels, cost arithmetic, artifact-to-JSON inference roundtrip and a monitoring shift. SDK tests cover request boundaries, local parameter validation, split-prefix overlap, cost limits, deployment omission and a stubbed SDK invocation. These are local tests, not a cloud integration test or an industrial safety validation.

Use only trusted model artifacts: joblib/pickle loading can execute code.

## How to discuss this in an interview

TR: “Açık UCI AI4I verisinde veri doğrulama, sızıntı önleme, model karşılaştırma, ayrı eşik kalibrasyonu ve final değerlendirmeyi içeren bir portföy projesi hazırladım. Boto3 üzerinden SageMaker Autopilot istek şemasını gerçek SDK ile yerelde test ettim. AWS'de eğitim/deployment henüz çalıştırmadım. Veri sentetik ve hedef aynı gözlemde arıza sınıflandırması; bunu erken arıza tahmini olarak sunmuyorum.”

Only use first-person statements after personally running, reviewing and understanding the project. This package was prepared with AI assistance. Do not imply sole authorship or past professional deployment. Be able to explain the target, excluded failure flags, split limitations, false-alarm tradeoff, SDK mock boundary and what remains before production.

## Practical next steps

1. Run all tests, then explain each failed-input scenario without reading the code.
2. Choose different illustrative costs using only the calibration set; explain why test data cannot choose your preferred threshold.
3. Add uncertainty estimation and repeated order-aware evaluations without reusing the current test for tuning.
4. Obtain authorized run-to-failure data with machine/time identifiers for a genuine future-horizon/RUL study.
5. For an approved AWS experiment, upload only permitted data, use least-privilege IAM, record job metadata and costs, compare Autopilot against the frozen local baseline, and clean up explicitly authorized resources. Runtime/candidate caps are not a monetary spending cap. No auto-deployment is configured.
6. Add container packaging and test against the selected SageMaker serving container before claiming serving compatibility in AWS.

## Source code map

- maintenance/data.py: OOP validator, feature whitelist and partitions.
- maintenance/train.py: model comparison, threshold, metrics and reproducible exports.
- maintenance/inference.py: local SageMaker-style handler functions.
- maintenance/monitor.py: transparent sensor-quality checks.
- tests/test_core.py: core tests.
- aws_integration/: actual AWS SDK request builder and offline contract tests.
- reports/: observed metrics, execution evidence and local outputs.

## AWS reference notes

[Autopilot documentation](https://docs.aws.amazon.com/sagemaker/latest/dg/autopilot-automate-model-development.html)
[CreateAutoMLJobV2](https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_CreateAutoMLJobV2.html)
[SageMaker AI overview](https://docs.aws.amazon.com/sagemaker/latest/dg/)
[Model Monitor availability](https://docs.aws.amazon.com/sagemaker/latest/dg/model-monitor.html): new-customer availability changed; do not blindly follow older tutorials.

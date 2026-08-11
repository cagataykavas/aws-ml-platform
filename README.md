# AWS ML Platform

Reference architecture for taking an ML workload from training data to production inference on AWS.

```mermaid
flowchart LR
    S3[(S3 Data Lake)] --> GLUE[Glue Catalog / ETL]
    GLUE --> ATH[Athena]
    S3 --> SM[SageMaker Training]
    SM --> REG[Model Registry]
    REG --> ECR[ECR Image]
    ECR --> ECS[ECS / EKS Inference]
    ECS --> ALB[ALB / API Gateway]
    ECS --> REDIS[(ElastiCache)]
    ECS --> RDS[(RDS PostgreSQL)]
    ECS --> CW[CloudWatch]
    SEC[Secrets Manager + KMS + IAM] --> ECS
```

## Coverage

- S3 data lake patterns
- Glue/Athena analytics
- SageMaker-style training and model registry concepts
- ECR container registry
- ECS/EKS deployment patterns
- API Gateway / ALB serving
- RDS, DynamoDB and ElastiCache design choices
- IAM least privilege
- KMS encryption and Secrets Manager
- CloudWatch observability
- Terraform infrastructure as code

The repository uses synthetic/public examples only.

# SentinelPay — Architectural Notes (from the previous engineering lead)

> These notes were written by Femi (former Head of Platform) before his
> departure in Q1 2026. They describe the *intended* architecture, not what
> currently runs in production. Treat this as background reading.

## Intended target state

We always knew we'd need to formalise security before the Series A audit. The
intended target state — which we never delivered — looked roughly like this:

### Network
- A dedicated VPC per environment (dev, staging, prod) with three private
  subnets and two public subnets across two AZs.
- Application services in private subnets, ALB in public subnets, RDS and
  Redis in dedicated isolated subnets with no internet route at all.
- VPC flow logs to a centralised S3 bucket with Athena indexing.
- A single NAT gateway per AZ for egress, restricted by VPC endpoints for
  S3, ECR, Secrets Manager, KMS, and CloudWatch.

### Compute
- ECS Fargate for `payments-api` and `kyc-api`, with separate task roles
  scoped to the specific resources each service consumes.
- Auto-scaling on CPU and request count.
- No SSH, no Session Manager into tasks except via an explicit emergency
  IAM role with break-glass approval.

### Data
- RDS PostgreSQL in Multi-AZ, encrypted at rest with a customer-managed KMS
  key. Master credentials rotated by a Secrets Manager rotation lambda.
- ElastiCache Redis with encryption in transit and at rest, AUTH token in
  Secrets Manager.
- S3 buckets for KYC documents: default SSE-KMS encryption, versioning,
  MFA Delete, server access logging, Object Lock in Governance Mode for
  audit logs.

### Identity
- IAM Identity Center for human access, MFA mandatory, sessions capped at
  four hours.
- OIDC federation between GitHub Actions and AWS — no long-lived
  deployment keys anywhere.
- Service-to-service auth via short-lived signed JWTs, signing key in
  Secrets Manager with automatic rotation.

### Detection
- GuardDuty enabled in all active regions, EKS/S3/RDS protection plans
  switched on (we don't run EKS yet but the plan accommodates it).
- CloudTrail organisation trail with log file validation, KMS encryption,
  and Object Lock on the destination bucket.
- Security Hub with AWS Foundational Security Best Practices and the CIS
  AWS Foundations Benchmark standards both enabled.
- EventBridge rules routing high-severity GuardDuty findings to a Lambda
  function that disables compromised IAM users and quarantines affected
  ECS tasks.
- A honeytoken IAM access key embedded somewhere boring, alarmed on use.

### Pipeline
- GitHub Actions as the *only* path to production. Manual changes blocked
  by SCP.
- Pre-commit secret scanning, SAST in CI, SCA in CI, IaC scanning in CI,
  container scanning in CI, image signing with Cosign keyless, ephemeral
  DAST per PR.
- SBOM generation in CycloneDX format, attached to every signed image.
- Branch protection on `main`: required reviewers, required status checks,
  no direct push, no force push.

## What we actually shipped

Almost none of the above. We shipped:

- One VPC, one subnet, one security group that allows 0.0.0.0/0 on
  everything because "we'll lock it down when we have time."
- ECS Fargate, but with one task role that has `*` on `*`.
- RDS in the same single subnet, publicly addressable.
- S3 buckets created from the console with default settings.
- Long-lived AWS keys in the GitHub Actions environment.
- No GuardDuty, no Security Hub, no Config.
- The CI workflow in `.github/workflows/ci.yml` — which doesn't even fail
  on a failing test.

The gap between intent and reality is the engagement.

— Femi (last edited 2026-02-14)

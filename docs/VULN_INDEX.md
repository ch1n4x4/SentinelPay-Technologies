# Vulnerability Index — Discovery Hints

> ⚠️ Do not consult this file until your pod has produced its own initial
> vulnerability inventory from scratch. The point of Week 1 is for you to
> find these yourselves. This file exists so the lead can verify completeness
> at the Day 7 review.

## Application Layer

| ID         | Title                          | File                                                  | Notes |
| ---------- | ------------------------------ | ----------------------------------------------------- | ----- |
| V-APP-01   | SQL Injection                  | `services/payments-api/app/routes/transactions.py`    | Also `services/kyc-api/app/routes/verify.py` |
| V-APP-02   | Broken JWT Validation          | `services/payments-api/app/auth.py`                   | Replicated in `services/kyc-api/app/auth.py` |
| V-APP-03   | IDOR                           | `services/payments-api/app/routes/accounts.py`        | Also `services/kyc-api/app/routes/documents.py` |
| V-APP-04   | SSRF                           | `services/payments-api/app/routes/webhooks.py`        | Variant in `services/kyc-api/app/routes/verify.py` (BVN provider URL) |
| V-APP-05   | Wallet Race Condition          | `services/payments-api/app/routes/wallets.py`         | `debit_wallet` |
| V-APP-06   | Weak Password Hashing          | `services/payments-api/app/auth.py`                   | `hash_password` (MD5) |
| V-APP-07   | Mass Assignment                | `services/payments-api/app/routes/accounts.py`        | `update_profile` |
| V-APP-08   | Missing Rate Limiting          | `services/payments-api/app/routes/auth.py`            | login, register, otp |
| V-APP-09   | Verbose Error Responses        | `services/payments-api/app/main.py`                   | Global error handler |
| V-APP-10   | Insecure Deserialisation       | `services/payments-api/app/routes/admin.py`           | `restore_session` (pickle) |
| V-APP-11   | Missing Audit Logging          | `services/payments-api/app/routes/wallets.py`         | And every other money-moving path |

## Cloud Layer

These cannot be found in the codebase — they apply to the infrastructure you
will design in Week 2. Your Terraform must avoid them:

| ID       | Title                       |
| -------- | --------------------------- |
| V-CLD-01 | Public RDS Instance         |
| V-CLD-02 | Unencrypted S3 KYC Bucket   |
| V-CLD-03 | Public ACL on Demo Bucket   |
| V-CLD-04 | Hardcoded AWS Access Keys   |
| V-CLD-05 | Overbroad IAM Role          |
| V-CLD-06 | Missing CloudTrail Integrity |
| V-CLD-07 | GuardDuty Disabled          |
| V-CLD-08 | No Flow Logs                |

Note that V-CLD-04 is partially observable in the existing codebase — see
`scripts/legacy_deploy.sh`, `.env.example`, and `docker-compose.yml`, plus
whatever else `git log -p` and Gitleaks turn up.

## Pipeline & Supply Chain

| ID       | Title                       | File                                |
| -------- | --------------------------- | ----------------------------------- |
| V-PIP-01 | Unsigned Container Images   | `.github/workflows/ci.yml`          |
| V-PIP-02 | No SBOM Generation          | `.github/workflows/ci.yml`          |
| V-PIP-03 | Pipeline Has Admin          | `.github/workflows/ci.yml`          |
| V-PIP-04 | No Branch Protection        | (repository settings — invisible from source) |

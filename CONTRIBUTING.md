# Contributing to SentinelPay

Thank you for contributing to SentinelPay. This repository is a security-sensitive payments application. Every change must preserve application security, authentication and authorization controls, data integrity, service isolation, and reproducible security checks.

## Before You Push

Run the application tests and all security scanners locally before pushing a branch.

Requirements:
    - Python 3.9+
    - gitleaks available on PATH
    - semgrep available on PATH
    - bandit available on PATH
    - openpyxl installed via pip (python3 pip install openpyxl OR python3 -m pip install openpyxl --break-system-packages)

From the repository root:

```bash
git checkout <your_branch>
git pull --ff-only origin <your_branch>

python3 scripts/security_scan.py
```

Do not push code with unresolved real security findings.

## Security Scanner

security_scan.py uses:

- **Gitleaks** — secret and credential detection
- **Semgrep** — static application-security analysis
- **Bandit** — Python security analysis

security_scan.py outputs:

- **Gitleaks.json** — secret and credential detection report
- **Semgrep.json** — static application-security analysis report
- **Bandit.json** — Python security analysis report
- **merged_findings.json** — merged json report
- **security_scan_report.xlsx** — workbook summary of findings
- **unified_inventory.csv** — merged human readable csv report 

The scanner must be run against the complete repository before pushing to remote.

#### Gitleaks triage

For every finding:

1. Open the referenced file and line.
2. Determine whether the value is a real credential or a false positive.
3. Rotate and remove real credentials.
4. Only suppress a confirmed false positive.
5. Re-run Gitleaks after the change.

Do not suppress real secrets.

For a confirmed false positive, use a line-level suppression with a reason:

```text
# False positive: fixed non-secret test fixture used only by the unit test.
TEST_TOKEN = "not-a-real-secret"  # gitleaks:allow
```

Do not use repository-wide or blanket secret ignores to silence findings.


#### Semgrep triage

For every result:

1. Read the rule description.
2. Inspect the actual source context.
3. Determine whether the finding is exploitable.
4. Fix real vulnerabilities.
5. Re-run Semgrep.
6. Suppress only confirmed false positives.

Use a rule-specific inline suppression:

```python
# False positive: value is a compile-time constant and never contains user input.
value = TRUSTED_CONSTANT  # nosemgrep: <rule-id>
```

Use the exact rule ID reported by Semgrep.

Do not disable an entire rule or scanner simply because one finding is inconvenient.


#### Bandit triage

For every finding:

1. Identify the Bandit test ID.
2. Inspect the surrounding code.
3. Fix genuine security problems.
4. Only suppress a demonstrable false positive.
5. Scope the suppression to the specific Bandit rule.

Example:

```python
# False positive: MD5 is used only to generate a deterministic test fixture ID;
# it is never used for authentication, integrity, or secrecy.
fixture_id = hashlib.md5(data).hexdigest()  # nosec B324
```

Do not use an unqualified `# nosec` when a specific Bandit test ID can be named.


## PR Severity Threshold

The SentinelPay policy is:

| Severity | PR status | Required action |
|---|---|---|
| **Critical** | Blocks PR | Fix before merge |
| **High** | Blocks PR | Fix before merge |
| **Medium** | Does not automatically block | Review, document, and assign |
| **Low** | Review | Fix when practical or document |
| **Info** | Does not block | Review as appropriate |

A Medium or Low finding must still block the PR when manual review determines that it is exploitable or violates a mandatory security requirement.

A scanner result must never be downgraded merely to get a PR through.

False-positive suppressions are not a substitute for remediation.

Every suppression must be:

- inline;
- tied to the specific finding/rule;
- accompanied by a one-line explanation;
- justified by the actual code context.

## Pull Request Requirements

Before opening a PR:

```bash
git status
git diff --check

python3 scripts/security_scan.py
```

Then inspect:

```bash
cat security-reports/summary.json
```

A PR description should include:

```markdown
## Security checks

- [x] Gitleaks
- [x] Semgrep
- [x] Bandit

## Security findings

- Critical: 0
- High: 0
- Medium: 0
- Low: 0

## Suppressions

None.
```

If suppressions exist, list them explicitly with the rule ID and reason.

## If a Scanner Finds a Real Vulnerability

Do not simply add a suppression.

Instead:

1. Reproduce or validate the finding.
2. Determine the affected data flow.
3. Fix the vulnerable code.
4. Add or update a regression test.
5. Run the relevant unit/integration tests.
6. Re-run all three scanners.
7. Confirm the original finding is gone.
8. Mention the finding and remediation in the PR.

Where applicable, reference the repository's vulnerability identifier, such as `V-APP-01`, `V-APP-02`, etc.

## App Bugs and Security-Sensitive Bugs

Application bugs should be directed to the AppSec team when they could affect:

- authentication or authorization;
- payment balances or transactions;
- customer or personal data;
- secrets or credentials;
- KYC data or documents;
- external service access;
- input validation or trust boundaries;
- security controls or rate limiting.

Use the repository's `appsec_intake.md` as the intake template.

When submitting an AppSec issue, include:

- concise title;
- affected service/file/endpoint;
- description and impact;
- reproduction steps;
- expected vs. actual behavior;
- relevant request/response examples with secrets and customer data removed;
- severity assessment;
- whether exploitation is confirmed or suspected;
- suggested remediation, if known.

Do not put real credentials, private keys, customer personal data, production tokens, or other sensitive secrets into issue comments.

## Customer-Reported Security Finding

Customer security reports must be treated as confidential security matters until triage determines otherwise.

### Immediate handling

1. Do not discuss the report publicly.
2. Do not ask the customer to post exploit details in a public issue.
3. Preserve the original report and available evidence.
4. Record the date/time, affected product/service, reporter contact, affected account/resource, and reported impact.
5. Acknowledge receipt without prematurely confirming exploitability.
6. Route the report to the AppSec/security incident owner.

### Triage

Determine:

- whether the report is reproducible;
- affected versions/branches;
- affected customers/data;
- whether exploitation is ongoing;
- severity and business impact;
- whether credentials, tokens, personal data, or funds may be exposed.

Do not expose customer data while reproducing the issue.

### If the finding is confirmed

Use this process:

```text
customer report
      ↓
security triage
      ↓
confirm exploitability
      ↓
contain / mitigate
      ↓
create tracked security issue
      ↓
implement fix
      ↓
security review
      ↓
run full scanner suite
      ↓
deploy fix
      ↓
verify remediation
      ↓
notify affected parties as appropriate
```

For a critical issue involving authentication, authorization, credentials, payment balances, private keys, or customer data, prioritize containment and credential/token rotation ahead of normal release scheduling.

### Customer communication

Provide:

- confirmation that the report was received;
- a secure channel for additional evidence;
- a status update after triage;
- remediation information after resolution, where appropriate.

Do not disclose internal exploit details, secrets, customer information, or other customers' data.

### Security issues are never closed by suppression

A customer-reported vulnerability must not be closed simply because Gitleaks, Semgrep, or Bandit no longer reports it.

The security team must verify that the underlying vulnerability has actually been eliminated.

## Security Review Checklist

Before merging a security-sensitive change:

```text
[ ] Tests pass
[ ] Gitleaks passes
[ ] Semgrep passes
[ ] Bandit passes
[ ] No Critical findings
[ ] No High findings
[ ] Medium findings reviewed
[ ] Low findings reviewed
[ ] Every suppression is inline and justified
[ ] No real secrets committed
[ ] Authentication/authorization behavior reviewed
[ ] Data-flow impact reviewed
[ ] Database changes reviewed
[ ] PR references the relevant security finding
[ ] AppSec intake used where appropriate
```

## Never Do This

Do not:

```text
[ ] Disable the scanner globally
[ ] Add a blanket ignore for a rule
[ ] Suppress a real secret
[ ] Downgrade a severity without evidence
[ ] Merge with an unresolved Critical/High finding
[ ] Push directly to main
[ ] Publish a customer vulnerability report publicly
[ ] Include customer secrets or production data in test fixtures
```

The goal is not merely to make the scanners green. The goal is to make SentinelPay difficult to attack while keeping every security decision traceable and reviewable.

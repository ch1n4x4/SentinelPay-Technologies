name: Appsec Bug Report
description: File a bug report.
title: "[Bug]: "
labels: ["bug", "triage"]
projects: ["octo-org/1", "octo-org/44"]
assignees:
  ---
type: bug
body:
  - type: markdown
    attributes:
      value: |
        Thanks for taking the time to fill out this bug report!
  - type: input
    id: Security Finding
    attributes:
      label: Scanner
      description: Which tool detected the issue? 
      placeholder: (e.g., Semgrep, bandit, None)
    validations:
      required: false
  - type: textarea
    id: what-happened
    attributes:
      label: What happened?
      description: Provide a brief explanation of the finding or link directly to the PR comment/artifact.
      placeholder: Tell us what you see!
      value: "A bug happened!"
    validations:
      required: true
  - type: dropdown
    id: service
    attributes:
      label: Service
      description: What service of our software was the bug found?
      options:
        - Payments 
        - KYC
        - Both
      default: 0
    validations:
      required: true
  - type: textarea
    id: location
    attributes:
      label: Exact locations
      description: Please pinpoint the exact endpoint where the bug exixts. Identify the exact line if possible.
      placeholder: e.g /payments-api/main: line 2
    validations:
      required: True
  - type: upload
    id: screenshots
    attributes:
      label: Upload screenshots
      description: If applicable, add screenshots to help explain your problem.
    validations:
      required: false

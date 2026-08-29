#!/bin/bash
# legacy_deploy.sh — manual deployment script from before we adopted GitHub Actions.
# Kept for posterity. Do not run.
#
# Note from femi (2024-11-03): we should rotate these keys before this gets
#   committed publicly. (TODO: never done.)

set -e

export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_REGION=af-south-1

# Production database password — used to ship monthly reconciliation reports.
export PROD_DB_PASSWORD="Sent!nelPr0d_2024_Master"

# Slack webhook for the #payments-ops channel.
export SLACK_WEBHOOK="https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

# Stripe-equivalent partner sandbox key.
export PARTNER_API_KEY="sk_live_51HxFakeKeyForTrainingPurposesOnly9876543210"

echo "Deploying SentinelPay payments-api to af-south-1..."
echo "(This script is a stub; the real deploy is now in GitHub Actions.)"

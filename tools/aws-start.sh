#!/usr/bin/env bash
# Starts the sentinel-app EC2 instance and the database-2 RDS instance back
# up. Safe to run even if one or both are already running/starting.
set -euo pipefail

REGION="ap-south-1"
EC2_INSTANCE_ID="i-0c8385adc8355dea6"
RDS_INSTANCE_ID="database-2"

echo "==> Starting RDS instance $RDS_INSTANCE_ID..."
aws rds start-db-instance --region "$REGION" --db-instance-identifier "$RDS_INSTANCE_ID" >/dev/null 2>&1 \
  || echo "    (already available/starting — check with aws-status.sh)"

echo "==> Starting EC2 instance $EC2_INSTANCE_ID..."
aws ec2 start-instances --region "$REGION" --instance-ids "$EC2_INSTANCE_ID" >/dev/null

echo "==> Done. RDS takes a few minutes to become available before the app can reach it."
echo "    Run tools/aws-status.sh to check."

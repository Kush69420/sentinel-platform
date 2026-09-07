#!/usr/bin/env bash
# Stops the sentinel-app EC2 instance and the database-2 RDS instance, so
# neither keeps billing by the hour overnight. Safe to run even if one or
# both are already stopped/stopping.
#
# Note: RDS auto-restarts a stopped instance after ~7 days (AWS limitation),
# so this alone doesn't cover long absences — re-run it, or just expect the
# occasional 7-day auto wake-up.
set -euo pipefail

REGION="ap-south-1"
EC2_INSTANCE_ID="i-0c8385adc8355dea6"
RDS_INSTANCE_ID="database-2"

echo "==> Stopping EC2 instance $EC2_INSTANCE_ID..."
aws ec2 stop-instances --region "$REGION" --instance-ids "$EC2_INSTANCE_ID" >/dev/null

echo "==> Stopping RDS instance $RDS_INSTANCE_ID..."
aws rds stop-db-instance --region "$REGION" --db-instance-identifier "$RDS_INSTANCE_ID" >/dev/null 2>&1 \
  || echo "    (already stopped/stopping, or a snapshot is in progress — check with aws-status.sh)"

echo "==> Done. States may take a minute to settle; run tools/aws-status.sh to check."

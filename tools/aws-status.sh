#!/usr/bin/env bash
# Prints current state of the sentinel-app EC2 instance and database-2 RDS instance.
set -euo pipefail

REGION="ap-south-1"
EC2_INSTANCE_ID="i-0c8385adc8355dea6"
RDS_INSTANCE_ID="database-2"

EC2_STATE=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$EC2_INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].State.Name' --output text)
RDS_STATE=$(aws rds describe-db-instances --region "$REGION" --db-instance-identifier "$RDS_INSTANCE_ID" \
  --query 'DBInstances[0].DBInstanceStatus' --output text)

echo "EC2 ($EC2_INSTANCE_ID): $EC2_STATE"
echo "RDS ($RDS_INSTANCE_ID): $RDS_STATE"

#!/bin/bash
# One-time bootstrap for continuous deployment on the NAS.
#
# Run this ONCE, by hand, from the stack directory. After it completes, every further
# change to the deployment — app code, compose file, nginx config, the deploy script
# itself, its systemd units, even /etc/docker/daemon.json — ships by pushing to the
# tracked branch. There should be no further reason to SSH in and edit anything.
#
#   cd <stack>/deploy && ./install-cd.sh
#
# Idempotent: safe to re-run.
set -euo pipefail

STACK_DIR=$(cd "$(dirname "$0")/.." && pwd)
BRANCH=$(git -C "$STACK_DIR" rev-parse --abbrev-ref HEAD)

[ "$(id -u)" -eq 0 ] || { echo "must run as root"; exit 1; }

echo "==> stack:  $STACK_DIR"
echo "==> branch: $BRANCH"

# The deploy script reads these; keeping them in /etc rather than baking them into the
# unit means the stack can move without editing anything tracked in git.
cat > /etc/sentinel-deploy.conf <<CONF
SENTINEL_STACK_DIR=$STACK_DIR
SENTINEL_BRANCH=$BRANCH
SENTINEL_HEALTH_TIMEOUT=180
CONF
chmod 0644 /etc/sentinel-deploy.conf

install -m 0755 "$STACK_DIR/deploy/sentinel-deploy.sh" /usr/local/bin/sentinel-deploy.sh
install -m 0644 "$STACK_DIR/deploy/systemd/sentinel-deploy.service" /etc/systemd/system/
install -m 0644 "$STACK_DIR/deploy/systemd/sentinel-deploy.timer"   /etc/systemd/system/

touch /var/log/sentinel-deploy.log && chmod 0640 /var/log/sentinel-deploy.log

# git runs as root against a tree owned by another user, and the source drive is mounted
# 777 so every file otherwise looks mode-modified. Both make git refuse to work or report
# a permanently dirty tree, which would block --ff-only pulls forever.
git config --global --add safe.directory "$STACK_DIR" 2>/dev/null || true
git -C "$STACK_DIR" config core.fileMode false

cat > /etc/logrotate.d/sentinel-deploy <<'ROTATE'
/var/log/sentinel-deploy.log {
    weekly
    rotate 8
    compress
    missingok
    notifempty
    copytruncate
}
ROTATE

systemctl daemon-reload
systemctl enable --now sentinel-deploy.timer

echo
echo "==> done. Continuous deployment is live."
systemctl list-timers sentinel-deploy.timer --no-pager | head -3
echo
echo "From here on, deploying means: git push. To watch a deploy:"
echo "  tail -f /var/log/sentinel-deploy.log"
echo "To force one immediately:"
echo "  systemctl start sentinel-deploy.service"

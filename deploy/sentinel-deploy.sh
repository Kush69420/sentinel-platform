#!/bin/bash
# Continuous deployment for the SENTINEL stack.
#
# Polls the tracked branch, and when it moves, pulls and rebuilds. Driven by
# sentinel-deploy.timer; safe to run by hand at any time.
#
# Polling rather than a GitHub webhook is deliberate: the deployment currently sits
# behind a Cloudflare *quick* tunnel whose hostname changes on every cloudflared
# restart, so there is no stable URL to point a webhook at. Polling also needs no
# inbound exposure, which matters on a campus network that NATs and filters.
#
# Runs as root from /usr/local/bin (NOT from the repo) so that pulling a new version
# of this file cannot change the script out from under a run in progress.
set -uo pipefail

STACK_DIR="${SENTINEL_STACK_DIR:?set SENTINEL_STACK_DIR in /etc/sentinel-deploy.conf}"
BRANCH="${SENTINEL_BRANCH:-main}"
LOG=/var/log/sentinel-deploy.log
HEALTH_TIMEOUT="${SENTINEL_HEALTH_TIMEOUT:-180}"

log() { printf '%s %s\n' "$(date -Is)" "$*" >> "$LOG"; }

# One deploy at a time. -n so a tick that lands mid-build exits immediately instead of
# queueing up behind it; the next tick will catch the change anyway.
exec 9>/var/lock/sentinel-deploy.lock
flock -n 9 || { log "SKIP another deploy is already running"; exit 0; }

cd "$STACK_DIR" || { log "ERROR stack dir $STACK_DIR missing"; exit 1; }

# Deploying tracks whatever branch the checkout is actually on, so a mismatch between
# that and $BRANCH would fast-forward the wrong branch to $BRANCH's tip and leave the
# box on a misleadingly-named branch. Fail loudly rather than switching automatically:
# a switch here could quietly discard work done directly on the box.
CURRENT=$(git rev-parse --abbrev-ref HEAD)
if [ "$CURRENT" != "$BRANCH" ]; then
    log "ERROR checkout is on '$CURRENT' but deploying '$BRANCH'."
    log "      Switch it once with: cd $STACK_DIR && git checkout $BRANCH"
    exit 1
fi

# A failed fetch is almost always the campus network session having lapsed rather than
# anything wrong with the deploy. Exit quietly and let the next tick retry — thrashing
# here would just fill the log.
if ! git fetch -q origin "$BRANCH" 2>>"$LOG"; then
    log "SKIP git fetch failed (network session lapsed? try: systemctl restart caa)"
    exit 0
fi

LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse "origin/$BRANCH")
[ "$LOCAL" = "$REMOTE" ] && exit 0

log "DEPLOY $BRANCH ${LOCAL:0:8} -> ${REMOTE:0:8}"

# --ff-only so that anything edited directly on the box surfaces as a failed deploy
# instead of being silently discarded by a reset.
if ! git pull -q --ff-only origin "$BRANCH" 2>>"$LOG"; then
    log "ERROR git pull --ff-only failed — the working tree has diverged from origin."
    log "      Inspect with: cd $STACK_DIR && git status"
    exit 1
fi

# Warn when an example env file grows a key the live env lacks. New settings arrive as
# additions to the examples, and a missing one usually shows up as a confusing runtime
# error rather than a startup failure. Warn only — never edit the real env files, they
# hold secrets and are deliberately gitignored.
check_env_drift() {
    local example="$1" actual="$2"
    [ -f "$example" ] && [ -f "$actual" ] || return 0
    local missing
    missing=$(comm -23 \
        <(grep -oE '^[A-Z_][A-Z0-9_]*=' "$example" | tr -d '=' | sort -u) \
        <(grep -oE '^[A-Z_][A-Z0-9_]*=' "$actual"  | tr -d '=' | sort -u))
    [ -n "$missing" ] && log "WARN $actual is missing keys present in $example: $(echo "$missing" | tr '\n' ' ')"
    return 0
}
check_env_drift deploy/env.app.example     deploy/app.env
check_env_drift deploy/env.compose.example deploy/.env

# Keep the installed copy of this script in step with the repo.
if ! cmp -s deploy/sentinel-deploy.sh /usr/local/bin/sentinel-deploy.sh; then
    install -m 0755 deploy/sentinel-deploy.sh /usr/local/bin/sentinel-deploy.sh
    log "INFO deploy script itself updated; next run uses the new version"
fi

# The captive-portal renewal script, alongside the units below. Not restarted here —
# it is a oneshot driven by its own timer, so the next tick picks up the new version.
if [ -f deploy/caa-renew.sh ] && ! cmp -s deploy/caa-renew.sh /usr/local/bin/caa-renew.sh; then
    install -m 0755 deploy/caa-renew.sh /usr/local/bin/caa-renew.sh
    log "INFO updated /usr/local/bin/caa-renew.sh"
fi

# The cloudflared readiness watchdog, same pattern as caa-renew.sh above — a oneshot
# driven by its own timer, so the next tick picks up a changed version on its own.
if [ -f deploy/sentinel-cloudflared-watchdog.sh ] && ! cmp -s deploy/sentinel-cloudflared-watchdog.sh /usr/local/bin/sentinel-cloudflared-watchdog.sh; then
    install -m 0755 deploy/sentinel-cloudflared-watchdog.sh /usr/local/bin/sentinel-cloudflared-watchdog.sh
    log "INFO updated /usr/local/bin/sentinel-cloudflared-watchdog.sh"
fi

# Host-level config lives in the repo too, so that changing it is a `git push` rather
# than an SSH session. Anything synced here must be idempotent and safe to re-apply.
#
# caa.service is here because the network session this whole box depends on is host
# state that was previously only ever edited over SSH — losing it loses internet, and
# the stale-pidfile guard in it is the difference between a restart working and the
# box sitting offline. Syncing it does NOT restart caa: that would drop the link
# mid-deploy. A changed caa.service takes effect at the next caa-renew tick.
reload_systemd=0
for unit in sentinel-deploy.service sentinel-deploy.timer \
            caa.service caa-renew.service caa-renew.timer \
            sentinel-cloudflared-watchdog.service sentinel-cloudflared-watchdog.timer; do
    [ -f "deploy/systemd/$unit" ] || continue
    if ! cmp -s "deploy/systemd/$unit" "/etc/systemd/system/$unit"; then
        install -m 0644 "deploy/systemd/$unit" "/etc/systemd/system/$unit"
        log "INFO updated /etc/systemd/system/$unit"
        reload_systemd=1
    fi
done
if [ "$reload_systemd" -eq 1 ]; then
    systemctl daemon-reload
    systemctl enable --now sentinel-deploy.timer >/dev/null 2>&1
    systemctl enable --now caa-renew.timer >/dev/null 2>&1
    # Enable only, not --now: caa-renew.service is now also boot-activated
    # (multi-user.target), but starting it here mid-deploy would re-auth and
    # drop the link out from under this very run.
    systemctl enable caa-renew.service >/dev/null 2>&1
    # --now is safe here (unlike caa-renew.service above): a probe run mid-deploy just
    # takes the deploy lock non-blocking and skips (see sentinel-cloudflared-watchdog.sh),
    # it does not touch the network or anything deploy-sensitive.
    systemctl enable --now sentinel-cloudflared-watchdog.timer >/dev/null 2>&1
fi

# Docker daemon settings — notably the explicit DNS servers, without which BuildKit
# cannot resolve anything even though the host itself resolves fine (containers inherit
# the LAN router as resolver and it does not answer reliably from NAT'd source ports).
# Restarting dockerd bounces every container on the box, so only do it on real change.
if [ -f deploy/docker-daemon.json ] && ! cmp -s deploy/docker-daemon.json /etc/docker/daemon.json; then
    install -m 0644 deploy/docker-daemon.json /etc/docker/daemon.json
    log "INFO /etc/docker/daemon.json changed — restarting dockerd (all containers bounce)"
    systemctl restart docker

    # Wait for dockerd to actually answer, rather than sleeping a guessed interval.
    # This used to be a blind `sleep 15` and it silently swallowed a whole deploy on
    # 2026-08-23: the log ended at the INFO line above, `docker compose up -d` never
    # ran, yet systemd still recorded status=0/SUCCESS. Containers came back on their
    # *stored* config — dockerd restores what it had, it does not re-read compose — so
    # the tree was at the new commit while the running containers were still the old
    # ones. A deploy that cannot prove it reached `compose up` must not look successful.
    dockerd_deadline=$(( $(date +%s) + 120 ))
    until docker info >/dev/null 2>&1; do
        if [ "$(date +%s)" -ge "$dockerd_deadline" ]; then
            log "ERROR dockerd did not come back within 120s after restart — aborting deploy"
            exit 1
        fi
        sleep 2
    done
    log "INFO dockerd back up; continuing deploy"
fi

# Decide whether this deploy actually needs `docker compose --build`. The Dockerfile
# does `COPY . .` from the repo root, so the honest default is "assume everything
# rebuilds a real image layer" — this only skips --build for paths verified to be
# genuinely inert: excluded from the build context entirely by .dockerignore
# (deploy/, .gitignore), or copied in but never read at runtime (*.md, plans/, a
# hypothetical docs/ or .github/). A compose-only or systemd-only commit lands
# entirely under deploy/, so it hits this and skips the rebuild machinery outright.
# Bias hard toward rebuilding: stale code in prod is far worse than a wasted build,
# so a missing local image, a failed/empty diff, or any path outside the inert set
# all force a rebuild.
build_irrelevant_path() {
    case "$1" in
        deploy/*|.github/*|docs/*|plans/*|*.md|.gitignore) return 0 ;;
        *) return 1 ;;
    esac
}

DO_BUILD=1
BUILD_REASON="default (bias toward rebuild)"

if ! docker image inspect sentinel-app:local >/dev/null 2>&1; then
    BUILD_REASON="no local sentinel-app:local image present (first deploy?)"
elif CHANGED=$(git diff --name-only "$LOCAL" "$REMOTE" 2>>"$LOG"); then
    if [ -z "$CHANGED" ]; then
        BUILD_REASON="git diff ${LOCAL:0:8}..${REMOTE:0:8} returned no paths (ambiguous)"
    else
        DO_BUILD=0
        TRIGGERS=""
        while IFS= read -r changed_file; do
            [ -n "$changed_file" ] || continue
            if build_irrelevant_path "$changed_file"; then
                continue
            fi
            DO_BUILD=1
            TRIGGERS="$TRIGGERS $changed_file"
        done <<<"$CHANGED"
        if [ "$DO_BUILD" -eq 1 ]; then
            BUILD_REASON="paths outside the known-inert set changed:$TRIGGERS"
        else
            # Intentional word-splitting: $CHANGED is one path per line, folded into
            # a single space-separated log line.
            # shellcheck disable=SC2086
            BUILD_REASON="only known-inert paths changed:$(printf ' %s' $CHANGED)"
        fi
    fi
else
    BUILD_REASON="git diff ${LOCAL:0:8}..${REMOTE:0:8} failed (shallow clone? force-push? unrelated history?) — forcing rebuild"
fi

BUILD_FLAGS=()
if [ "$DO_BUILD" -eq 1 ]; then
    log "REBUILD ${BUILD_REASON}"
    BUILD_FLAGS=(--build)
else
    log "NO-BUILD ${BUILD_REASON}"
fi

# CPU/IO niceness: 4 cores and spinning rust, and this can run under load from
# whatever else the box is doing. Degrade to nice-only if ionice isn't installed.
if command -v ionice >/dev/null 2>&1; then
    NICE_PREFIX=(nice -n 19 ionice -c 3)
else
    log "WARN ionice not found on this host; running compose up with nice only"
    NICE_PREFIX=(nice -n 19)
fi

cd "$STACK_DIR/deploy" || exit 1
if ! "${NICE_PREFIX[@]}" docker compose up -d "${BUILD_FLAGS[@]}" >>"$LOG" 2>&1; then
    log "ERROR build/up failed — rolling back to ${LOCAL:0:8}"
    cd "$STACK_DIR" && git reset -q --hard "$LOCAL"
    cd "$STACK_DIR/deploy" && "${NICE_PREFIX[@]}" docker compose up -d --build >>"$LOG" 2>&1
    log "ROLLBACK complete at ${LOCAL:0:8}"
    exit 1
fi

# Health gate. Rolling back code is safe here because the schema only ever applies on a
# first-boot empty datadir, so a redeploy of an older image cannot leave the database
# ahead of the code. That stops being true the day a real migration runner lands.
deadline=$(( $(date +%s) + HEALTH_TIMEOUT ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    unhealthy=$(docker compose ps --format '{{.Name}} {{.Status}}' | grep -c -E 'unhealthy|starting|Exit|Restarting')
    if [ "$unhealthy" -eq 0 ]; then
        log "OK deployed ${REMOTE:0:8} — all services healthy"
        docker image prune -f >/dev/null 2>&1
        exit 0
    fi
    sleep 10
done

log "ERROR services did not become healthy within ${HEALTH_TIMEOUT}s — rolling back to ${LOCAL:0:8}"
docker compose ps --format '{{.Name}} {{.Status}}' >> "$LOG"
cd "$STACK_DIR" && git reset -q --hard "$LOCAL"
cd "$STACK_DIR/deploy" && "${NICE_PREFIX[@]}" docker compose up -d --build >>"$LOG" 2>&1
log "ROLLBACK complete at ${LOCAL:0:8}"
exit 1

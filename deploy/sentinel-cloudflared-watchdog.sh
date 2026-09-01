#!/bin/bash
# Restart sentinel-cloudflared after SUSTAINED readiness failure.
#
# Driven by sentinel-cloudflared-watchdog.timer every 45s; safe to run by hand.
#
# Why this exists: cloudflared never exits on its own, even when every edge connection
# is down — it retries internally forever. That means `restart: unless-stopped` in
# docker-compose.yml has nothing to react to (no exit code is ever produced), and Docker
# does not restart a container just because its HEALTHCHECK reports unhealthy — that
# field is observability only. Something has to actually run `docker restart`, and it
# has to do so on its own schedule rather than depending on cloudflared to ever exit or
# on the compose healthcheck subsystem to do more than it does. Hence a host-level timer
# with its own independent probe, not a docker.sock-mounted sidecar reacting to the
# compose healthcheck (see docker-compose.yml's cloudflared healthcheck comment, and
# DOCKER_DEPLOY.md, for why that tradeoff was rejected: it would need root-equivalent
# docker.sock access inside a container on a box that also serves public traffic).
#
# Why 3 consecutive failures spanning ~90s, not the first failure: during the
# 2026-08-23 incident, all 4 edge connections dropped when caa.service's 2-hourly
# captive-portal renewal bounced the container's NAT'd network path, and they
# re-registered on their own ~20s later — no restart involved. A `docker restart` costs
# roughly 10s of guaranteed downtime (the old process actually goes away) plus a fresh
# edge registration handshake on top, i.e. more total downtime than the self-heal caused
# by itself. Restarting on the first failed probe would therefore make things worse, and
# risks oscillating with the self-heal (restart mid-reconnect, drop the fresh
# connections, repeat). Requiring 3 consecutive failures AND >=90s between the first and
# the deciding one — comfortably past the observed ~20s self-heal window — filters that
# out. DO NOT lower FAILURE_THRESHOLD or MIN_FAILURE_SPAN "to be more responsive"
# without re-reading this paragraph; that was tried in effect (a naive first-failure
# trigger) and is exactly the failure mode this script exists to avoid.
set -uo pipefail

CONTAINER=sentinel-cloudflared
METRICS_ADDR=127.0.0.1:20241
STATE_FILE=/run/sentinel-cloudflared-watchdog.state
RESTART_FILE=/run/sentinel-cloudflared-watchdog.last-restart
LOG=/var/log/sentinel-cloudflared-watchdog.log
FAILURE_THRESHOLD=3     # consecutive failed probes required before a restart
MIN_FAILURE_SPAN=90     # seconds between the first and the deciding failed probe
RESTART_COOLDOWN=600    # seconds to withhold a further restart after issuing one

# RESTART_COOLDOWN exists because the threshold above only filters the ~20s self-heal
# case (see the incident writeup at the top of this file); it does nothing for an
# outage that a restart cannot fix at all, e.g. the box's WAN link itself being down.
# Without a cooldown, every ~135s (one more 3-over-90s cycle) would issue another
# `docker restart` for the entire duration of an outage that has nothing to do with
# this container — pure churn, each one costing the ~10s stop/start plus a fresh edge
# handshake, for zero benefit. The probe still runs and failures still get logged every
# tick during the cooldown, so a real recovery is still noticed immediately (the first
# successful probe clears $STATE_FILE as before); only the *action* of restarting is
# withheld until RESTART_COOLDOWN has elapsed since the last one.

log() { printf '%s %s\n' "$(date -Is)" "$*" >> "$LOG"; }

# Don't fight a deploy: `docker compose up -d --build` can recreate this very container
# (e.g. if docker-compose.yml or cloudflared.sentinel.yml changed), and a `docker
# restart` landing mid-recreation would race it. sentinel-deploy.sh's own health gate
# already covers cloudflared's compose healthcheck during a deploy, so it's safe for the
# watchdog to just sit this cycle out. Non-blocking, like caa-renew.sh's guard on the
# same lock, and held for the rest of the script (not just probed) so a deploy also
# cannot start mid-probe/restart. State (the failure count below) is left untouched, not
# reset, on SKIP — a real ongoing outage that happens to overlap a deploy tick keeps
# counting once the deploy finishes rather than losing progress toward the threshold.
exec 7>/var/lock/sentinel-deploy.lock
if ! flock -n 7; then
    log "SKIP a deploy is in progress; leaving failure count as-is"
    exit 0
fi

count=0
first_ts=0
if [ -f "$STATE_FILE" ]; then
    read -r count first_ts < "$STATE_FILE" 2>/dev/null || { count=0; first_ts=0; }
    case "$count$first_ts" in *[!0-9]*|'') count=0; first_ts=0 ;; esac
fi

if timeout 10 docker exec "$CONTAINER" cloudflared tunnel --metrics "$METRICS_ADDR" ready >/dev/null 2>&1; then
    [ "$count" -gt 0 ] && log "OK probe succeeded, clearing failure count (was $count)"
    rm -f "$STATE_FILE"
    exit 0
fi

now=$(date +%s)
[ "$count" -eq 0 ] && first_ts=$now
count=$((count + 1))
printf '%s %s\n' "$count" "$first_ts" > "$STATE_FILE"
span=$((now - first_ts))
log "WARN probe failed (consecutive=$count span=${span}s, need >=${FAILURE_THRESHOLD} over >=${MIN_FAILURE_SPAN}s)"

if [ "$count" -ge "$FAILURE_THRESHOLD" ] && [ "$span" -ge "$MIN_FAILURE_SPAN" ]; then
    last_restart=0
    if [ -f "$RESTART_FILE" ]; then
        read -r last_restart < "$RESTART_FILE" 2>/dev/null || last_restart=0
        case "$last_restart" in *[!0-9]*|'') last_restart=0 ;; esac
    fi
    since_restart=$((now - last_restart))

    if [ "$last_restart" -gt 0 ] && [ "$since_restart" -lt "$RESTART_COOLDOWN" ]; then
        # Still failing, but we already tried a restart within the cooldown window and
        # it didn't help — restarting again right now would just be more of the same
        # churn (see RESTART_COOLDOWN comment above). Leave $STATE_FILE as-is: the
        # failure count keeps growing for visibility in the log, and the moment the
        # cooldown expires the next tick acts on it immediately without waiting for a
        # fresh 3-over-90s run.
        log "WARN sustained failure but restarted ${since_restart}s ago (< ${RESTART_COOLDOWN}s cooldown) — withholding another restart"
    else
        log "ACTION restarting $CONTAINER after $count consecutive failures over ${span}s"
        if docker restart "$CONTAINER" >>"$LOG" 2>&1; then
            log "OK restart issued"
        else
            log "ERROR docker restart $CONTAINER failed"
        fi
        printf '%s\n' "$now" > "$RESTART_FILE"
        rm -f "$STATE_FILE"
    fi
fi

#!/bin/bash
# Re-authenticate the campus captive-portal session (Sophos/Cyberoam client).
#
# Driven by caa-renew.timer every 2h, and safe to run by hand. The portal expires the
# session on its own schedule; when it lapses the box still answers HTTP 200 but every
# body is the ~727-byte portal page, so a bare status check is not enough to notice —
# re-authenticating on a cycle is simpler and cheaper than detecting the lapse.
set -uo pipefail

LOG=/var/log/caa-renew.log
log() { printf '%s %s\n' "$(date -Is)" "$*" >> "$LOG"; }

# Restarting caa drops the network for a few seconds, and a deploy in flight is pulling
# from GitHub and rebuilding images over that link — so defer rather than break it. The
# lock is held for the rest of the script, not just probed, so a deploy tick also cannot
# start inside the window where the link is down. sentinel-deploy.sh takes this same
# lock with -n and skips, retrying on its own 3-minute cycle; the session outlives that.
exec 8>/var/lock/sentinel-deploy.lock
if ! flock -n 8; then
    log "SKIP a deploy is in progress; deferring re-auth to the next tick"
    exit 0
fi

systemctl restart caa || { log "ERROR systemctl restart caa failed"; exit 1; }

# caa needs a moment to complete the handshake before traffic flows again.
for _ in $(seq 1 12); do
    sleep 5
    # Byte count, not status code: the captive portal answers 200 with its own page.
    # curl still prints its write-out when it exits non-zero (a timeout reports 0
    # bytes), so strip to digits rather than appending a fallback value — "0" from
    # curl plus "0" from an `|| echo 0` would make the comparison below a syntax error.
    bytes=$(curl -s -o /dev/null -w '%{size_download}' -m 10 https://github.com/ 2>/dev/null)
    bytes=${bytes//[^0-9]/}
    if [ "${bytes:-0}" -gt 10000 ]; then
        log "OK session renewed (github fetched ${bytes} bytes)"
        exit 0
    fi
done

log "ERROR still no real internet 60s after restarting caa — check /var/log/caa.log"
exit 1

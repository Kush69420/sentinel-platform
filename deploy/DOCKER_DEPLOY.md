# SENTINEL — Docker Compose deploy (OMV homelab, staging)

Containerised replacement for `deploy/sentinel.service` + `deploy/nginx.conf`, which
remain as the native-install reference for the eventual move to paid compute.

**This is a staging environment.** It is not the final production target — see
`CLAUDE.md` for the deferred items it still carries.

---

## Topology

```
Internet ──HTTPS──▶ Cloudflare edge ──outbound tunnel──▶ [cloudflared]
                                                              │  private compose network
                                                              ▼
                                                          [nginx :80]
                                                              │
                                                              ▼
                                                    [app: gunicorn :8000]
                                                              │
                                                              ▼
                                                       [mysql :3306]
```

Nothing is published to the LAN. `nginx` binds `127.0.0.1:8080` on the NAS for
shell-level debugging only; host `:80` belongs to OMV's own web UI and must stay free.

---

## Host facts this deploy is shaped around

Surveyed 2026-08-18. Re-check before assuming any of it still holds.

| | |
|---|---|
| CPU / RAM | 4 cores, 7.7 GiB **shared with jellyfin and navidrome** |
| Disks | **all spinning HDDs, no SSD** |
| `blue` | ext4, sdc1, 1.7 TB free → **MySQL datadir** |
| `reed` | btrfs RAID1, sda+sdb, 1.82 TiB free → **uploads + backups** |
| OS disk | 28 GiB, 22 GiB free, and **`/var/lib/docker` lives here** |

Two consequences worth internalising:

1. **Every service caps its logs** (`max-size: 10m`, `max-file: 3`) and **all state is
   bind-mounted onto the big pools.** If either rule is broken, the 28 GiB root
   filesystem fills and takes the whole NAS down, not just Sentinel.
2. **Every service has a `mem_limit`.** Without them, MySQL's buffer pool growth would
   evict jellyfin.

### Why the datadir is on ext4 and not the RAID1 pool

btrfs copy-on-write fragments InnoDB badly, and RAID1 doubles every write — worst
exactly during the bulk import. So the datadir goes on the single ext4 disk for speed,
and redundancy is bought back by `backup.sh` dumping to the RAID1 pool. That trade is
only acceptable because the bulk lookup table is **reconstructible from the source
xlsx**, while the gov-ID uploads and the accounts/audit tables are not — which is why
those live on the mirror directly.

If you ever do point `SENTINEL_MYSQL_DIR` at the btrfs pool, run
`chattr +C <dir>` **while it is still empty**; it has no effect on existing files.
`prepare-host.sh` warns about this.

---

## Before anything: check the captive portal

The NAS sits behind an IIIT-NR Cyberoam/Sophos gateway that SSL-bumps **all** outbound
HTTPS and authorises per source IP. When its session lapses, every HTTPS host — Docker
Hub, PyPI, `api.trycloudflare.com`, even `debian.org` — returns an identical ~727-byte
portal login page **under HTTP 200**, not a redirect and not a 407.

This one condition masquerades as three unrelated failures: `docker pull` reporting
`x509: certificate signed by unknown authority`, `pip install` failing inside
`docker build`, and `cloudflared` timing out on `POST https://api.trycloudflare.com/tunnel`.
Check it first, before debugging anything else:

```bash
curl -s -o /tmp/x -w '%{http_code} %{size_download}\n' https://www.debian.org/
# 200 with ~727 bytes  -> portal session lapsed, nothing else will work
# 200 with ~100KB      -> fine
```

Re-authenticate from the NAS's **own IP** — the portal authorises per source address,
so logging in from a laptop does not help the NAS. Sessions expire, so a long-running
deploy wants either a keepalive or a MAC/IP exemption from campus IT. Note that
trusting the Sophos CA does *not* fix this; it only makes the portal page verify
cleanly instead of erroring.

Two knock-on effects on this deploy:
- Every lapse drops the tunnel, and the quick tunnel comes back on a **different**
  hostname.
- Outbound **TCP 7844 is blocked** on this network, which is cloudflared's default
  QUIC edge transport. `docker-compose.yml` therefore pins `--protocol http2` (TCP 443).
  Do not remove that flag here.

## First-time bring-up

```bash
git clone <repo> /srv/dev-disk-by-uuid-4ffa.../blue/sentinel/stack
cd /srv/dev-disk-by-uuid-4ffa.../blue/sentinel/stack/deploy

cp env.compose.example .env      # bind-mount paths + MySQL passwords
cp env.app.example    app.env    # SECRET_KEY, ENCRYPTION_KEY, app config
chmod 600 .env app.env
```

Generate the three secrets **on the NAS**:

```bash
openssl rand -base64 30                                              # MYSQL_ROOT_PASSWORD
openssl rand -base64 30                                              # SENTINEL_DB_PASSWORD / DB_PASSWORD (same value, both files)
python3 -c "import secrets; print(secrets.token_urlsafe(48))"        # SECRET_KEY
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"   # ENCRYPTION_KEY
```

> **Back up `ENCRYPTION_KEY` off this box before first use.** It encrypts gov-ID
> uploads, 2FA secrets and stored API keys. If it is lost or regenerated, every
> encrypted value is permanently unrecoverable — and `backup.sh` deliberately does not
> contain it, so the dumps alone will not save you.

Then:

```bash
sudo ./prepare-host.sh          # creates + chowns the bind-mount dirs
docker compose up -d --build
docker compose logs -f mysql    # first boot applies the schema; wait for healthy
```

On first boot only, MySQL initialises an empty datadir and
`db-init/00-apply-schema.sh` applies the four schema files **in the dependency order
`CLAUDE.md` specifies** (the order is not alphabetical, which is why it is a script and
not four mounted `.sql` files), plus `migration_coming_soon.sql`. There is still no
migration runner and no version tracking — a `schema_migrations` table remains a Day-4
item, and this only handles the from-empty case.

### Get the public URL

```bash
docker compose logs cloudflared | grep -o 'https://.*trycloudflare.com'
```

**This URL changes every time the `cloudflared` container restarts.** That is inherent
to quick tunnels; it goes away when a domain is bought and a named tunnel replaces it.

### Immediately after first bring-up: the admin seed

`db_setup.sql` seeds `admin` / `admin123`. RBAC (`role_required`) is modelled but not
enforced, and both are deliberately deferred to the planned OAuth2 pass — see the
Decision note in `CLAUDE.md`. A quick tunnel is public and **Cloudflare Access cannot
be applied to it**, so there is no auth layer in front of this.

Set a strong password on that account as the first thing you do after the stack is up.
This is a stopgap for a staging box, not a fix, and it does not change `db_setup.sql`.

---

## Deploying: push to the branch

The NAS runs continuous deployment. **`git push` is the deploy** — you should not need
to SSH in to ship a change.

`sentinel-deploy.timer` fires every 3 minutes and runs `sentinel-deploy.sh`, which
pulls the tracked branch when it moves, rebuilds, and waits for every service to come
back healthy. If the build fails or the stack does not go healthy within
`SENTINEL_HEALTH_TIMEOUT` (default 180s), it resets to the previous commit and rebuilds
that instead, so a bad push self-heals rather than leaving the site down.

Host config is deployed the same way. The systemd unit and timer (`deploy/systemd/`),
the deploy script itself, and `/etc/docker/daemon.json` (`deploy/docker-daemon.json`)
are all re-applied from the repo when they change — so editing them means committing,
not SSHing. `dockerd` is only restarted when its config genuinely changes, because that
bounces every container on the box, including Jellyfin and Navidrome.

```bash
tail -f /var/log/sentinel-deploy.log      # watch a deploy
systemctl start sentinel-deploy.service   # force one now, don't wait for the timer
systemctl list-timers sentinel-deploy.timer
```

One-time bootstrap on a fresh box (the only step that must be run by hand):

```bash
cd <stack>/deploy && sudo ./install-cd.sh
```

Things that will legitimately stop a deploy, and what they mean in the log:
- `SKIP git fetch failed` — the campus network session lapsed, not a deploy problem.
  `systemctl restart caa`; the next tick recovers on its own.
- `ERROR git pull --ff-only failed` — someone edited files directly on the box and the
  tree diverged. This is deliberate: a `reset --hard` here would silently destroy that
  work. Resolve it by hand, then deploys resume.
- `WARN <file> is missing keys present in <example>` — a new setting was added to an
  `env.*.example` but not to the live env file on the box. The env files hold secrets,
  are gitignored, and are never edited automatically; add the key yourself.

## Day-to-day

```bash
docker compose ps
docker compose logs -f app
docker compose restart app
docker compose down                  # stop; data survives in the bind mounts
docker compose up -d --build         # manual deploy; normally the timer does this
```

### Backups

`backup.sh` writes a `--single-transaction` dump plus a tar of `uploads/` to the RAID1
pool and prunes past `SENTINEL_BACKUP_KEEP_DAYS` (default 14). Schedule it nightly via
OMV → System → Scheduled Tasks, or cron:

```
30 3 * * *  /srv/.../blue/sentinel/stack/deploy/backup.sh >> /var/log/sentinel-backup.log 2>&1
```

Restore drill (do this at least once — an untested backup is not a backup):

```bash
gunzip -c sentinel_db-<stamp>.sql.gz | docker exec -i sentinel-mysql \
    mysql -u root -p"$MYSQL_ROOT_PASSWORD" sentinel_db
```

---

## Verification

Adapted from the Phase B list (`sentinel-phase-b-packaging.md`), with systemd steps
replaced by their Docker equivalents.

1. **Test suite green inside the real image**
   `docker compose exec app python -m unittest discover -s tests -v`
2. **Fail-fast secrets still hold**
   Blank `SECRET_KEY` in `app.env`, `docker compose up app` → must exit with a
   `RuntimeError` naming `SECRET_KEY`. Restore it afterwards.
3. **Headers**
   `curl -sSI https://<tunnel-url>/` → 200/302 carrying `Content-Security-Policy`,
   `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`.
4. **DB connectivity through the compose network**
   `curl -sS https://<tunnel-url>/api/api-status` → valid JSON.
5. **SSE end-to-end** (the one thing unit tests cannot exercise)
   `curl -N -sS --max-time 15 -H "Cookie: session=<real cookie>" https://<tunnel-url>/api/events`
   → `data:` lines roughly every 5s for the full window. **One burst at the end means
   buffering is wrong somewhere** — check `proxy_buffering off` survived. Run three
   concurrently and confirm a simultaneous `/api/api-status` still returns instantly
   (proves the 8-thread pool has headroom).
6. **Rate limiter correct at `workers 1`**
   Fire N+1 rapid wrong-password `POST /api/user/login` → the (N+1)th returns 429.
   Do **not** raise `--workers`: `_rate_limiter` is per-process with no shared store,
   so the effective limit would silently become `limit x workers`.
7. **`TRUSTED_PROXY_COUNT` end-to-end**
   Trigger a failed login through the tunnel and confirm `activity_log` records your
   real client IP, not a `172.28.x.x` container address. If it shows a container IP,
   `realip.cloudflare.conf` is not doing its job.
8. **Supervision**
   `docker compose restart` → all healthy. `docker compose stop mysql` → app stays up
   and `/api/admin/health` reports `database.status: red` rather than crashing.
   Reboot the NAS → stack returns unattended (`restart: unless-stopped`).
9. **Restore drill** — see Backups above.

---

## Known constraints

- **`--workers 1` is load-bearing.** `_rate_limiter` in `app.py` is an in-process
  sliding window with no shared store. Raising the worker count multiplies every
  configured rate limit by the worker count. Fixing that means moving the limiter to
  Redis or the DB behind the same `rate_limit()` interface — its own piece of work.
- **The buffer pool caches well under 1% of the projected ~400 GB dataset**, on
  spinning disks. Every query must stay an index-driven point lookup. Table scans,
  aggregate reporting and leading-wildcard `LIKE` will not perform acceptably here.
- **Do not import the ~200 GB of xlsx through `/api/admin/import/modules`.** On 4 cores
  with openpyxl and HDD writes that is plausibly days. Convert xlsx → CSV offline and
  use `LOAD DATA INFILE`.
- **Quick tunnel limits**: random hostname per restart, ~200 concurrent in-flight
  requests before 429s, no Cloudflare Access. Replace with a named tunnel once a
  domain exists.
- **The campus gateway is the single most likely cause of any outage here.** See the
  portal section at the top before suspecting the stack.

# Request: delegate `sentinel.gatiwavetechnologies.com` to Cloudflare

**For:** whoever administers DNS for `gatiwavetechnologies.com`
**Asks for:** two `NS` records on one subdomain label. Nothing else.

## What is being asked

Delegate the single label `sentinel` to Cloudflare, so that Cloudflare — and only
Cloudflare — answers DNS for `sentinel.gatiwavetechnologies.com`.

This is standard NS delegation, the same mechanism used to hand a subdomain to any
third-party service.

## What this does NOT touch

Stated explicitly, because this is a live production zone:

- **The apex `gatiwavetechnologies.com` is unchanged.** It currently resolves to
  `52.74.6.109` and `13.215.239.219` and will continue to.
- **The zone's nameservers are unchanged.** They stay on NS1
  (`dns1.p08.nsone.net` … `dns4.p08.nsone.net`). The zone is *not* migrating to
  Cloudflare.
- **Every other record — `www`, mail, MX, SPF/DKIM/DMARC, any other subdomain — is
  untouched.** Delegation is scoped to the `sentinel` label only.
- **`sentinel.gatiwavetechnologies.com` has no DNS record today** (verified: `NXDOMAIN`
  / empty answer), so nothing currently in service is being taken over or replaced.

**Reversible at any time:** deleting the two `NS` records ends the delegation
immediately. No account access, no registrar change, no transfer.

## Why it is needed

The host being published sits behind NAT on a network with no inbound connectivity, so it
cannot be reached by pointing an `A` record at an IP. It is exposed via a **Cloudflare
Tunnel** — an outbound-only connection from the host to Cloudflare's edge.

Cloudflare Tunnel routes traffic by managing a DNS record *inside a zone Cloudflare
controls*. A `CNAME` from NS1 to the tunnel's `<uuid>.cfargotunnel.com` address does not
work, because that hostname is resolvable only through Cloudflare's own edge. Hence
delegation rather than a simple record.

## Steps

### 1. (Our side) Add the subdomain as a zone in Cloudflare
We add `sentinel.gatiwavetechnologies.com` to a Cloudflare account. Cloudflare then issues
two assigned nameservers, e.g.:

```
xxxx.ns.cloudflare.com
yyyy.ns.cloudflare.com
```

The actual pair is assigned per zone — **we will send you the exact two names**; do not
copy the placeholders above.

### 2. (Your side) Add the delegation in the NS1 zone
In the `gatiwavetechnologies.com` zone, create:

| Name | Type | Value | TTL |
|---|---|---|---|
| `sentinel` | `NS` | `xxxx.ns.cloudflare.com` | 3600 |
| `sentinel` | `NS` | `yyyy.ns.cloudflare.com` | 3600 |

Two records, same name, different values. **Do not** add an `A`, `CNAME`, or `ALIAS` for
`sentinel` — a delegated label must carry `NS` records only, or resolution breaks.

### 3. Verify

```
dig NS sentinel.gatiwavetechnologies.com +trace
```

Should return the two Cloudflare nameservers. Propagation is usually minutes.

## Known caveat — please check this first

Cloudflare calls this **"subdomain setup"** (also "partial setup"). Historically it has
been limited to **Business and Enterprise plans**, and we have **not** confirmed whether
it is available on the plan in question. If the Cloudflare dashboard refuses to add
`sentinel.gatiwavetechnologies.com` as a zone, this approach is unavailable and there is
no point making the NS change.

**So the order is:** confirm Cloudflare accepts the subdomain as a zone → only then add
the `NS` records.

If it is not available, we will use a separate domain instead and this request can be
dropped entirely — nothing else depends on it.

## What we need back

1. Confirmation that subdomain setup is available on the Cloudflare plan being used.
2. Confirmation that the two `NS` records have been added.

We will supply the exact nameserver pair at step 1.

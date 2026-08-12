# Day 1 — Self-serve signup, LEA clearance gate, credits & payments

Implements the model agreed before this session:

> Anyone can sign up → the account can log in but every lookup returns 403 →
> unlocking lookups requires **both** approved LEA verification **and** credits.
> **Money buys credits; the gov-ID review buys access.**

Everything below is in the working tree. **Nothing has been committed** — review first.

---

## Scope note: this checkout is behind the plan

`plans/5dayplan.md` cites line numbers from the PR-#1 branch, which is not in this
clone (`git log` shows one commit, `70f9987 Initial commit`). Two things the plan
assumed already existed were **not present here** and had to be built rather than fixed:

- `run_tool_generic()` charged **no credits at all** and wrote **no `search_logs`** rows.
  The plan's "surface HTTP 402 properly — the backend returns `credits_required`"
  describes code that did not exist. The billing and audit path is new.
- The `credits_required` / `credits_available` response fields did not exist either.

Worth reconciling against the branch before merging.

---

## What changed

### 1. The account-takeover chain is closed

| Before | After |
|---|---|
| `approve_lea_application()` inserted `bot_users` rows with no `password_hash` | Approval only **grants clearance** to an account that already exists. It can no longer create one — if no account matches, it returns 409. |
| Login treated an empty hash as "accept `dev123`" | `password_ok = bool(stored_hash) and check_password_hash(...)`. No fallback. `DEV_USER_PASSWORD` is gone from `app.py` and `.env`. |
| Admin "Reset Password" returned success and did nothing | Issues a real single-use, 24h, hashed-at-rest token. Shown to the admin **once**, handed over out of band. |
| `/api/user/password-reset/request` was a stub claiming success | Files a request into the admin queue. Response is identical whether or not the account exists, so it cannot enumerate officers. |
| Recovery codes were generated but never verified | Accepted at login and burned on use (`consume_recovery_code`), shared with the admin login path. |
| Session was not regenerated on login | `session.clear()` before establishing identity — closes session fixation. |

New: `POST /api/user/signup`, `POST /api/user/password-reset/confirm`, `/reset-password` page.
Password policy: ≥10 chars, letters **and** digits (`password_problem()`).

### 2. Account state vs. data clearance are now separate columns

- `bot_users.status` — can this account sign in (`pending`/`approved`/`blocked`/`rejected`/`inactive`)
- `bot_users.verification_status` — **new**: `unverified`/`pending`/`approved`/`rejected`

A rejected application no longer destroys the account: the operator keeps their login
and can correct and resubmit. `@verified_required` gates data routes and returns a
machine-readable `reason` so the dashboard renders the right call to action.

### 3. `subscriber_lookup` free-data bypass is dead

Every gate was `if service and ...`, so a code with no `services` row skipped all of
them and ran uncharged. Now **fail-closed**: `if not service: return 404`. This protects
every future tool code, not just this one. `subscriber_lookup` was a duplicate of
`mobile_lookup` and has been removed from all branch sets.

### 4. Mobile lookup now bills and audits

- Affordability checked **up front** → HTTP 402 with `credits_required` / `credits_available`.
- Debit happens **only on a hit** — a miss is never billed (verified end-to-end).
- Debit is `UPDATE ... WHERE credits >= %s` with a `rowcount` check, so concurrent
  lookups cannot drive a balance negative.
- Every hit writes `search_logs` **and** `credit_transactions`.
- The `master_data_records` fallback was `data_json LIKE '%query%'` — a substring match
  that could bill for, and print a PDF from, an unrelated record. Now exact `record_key`.

### 5. Spoofable client IP fixed

`_client_ip()` returned `X-Forwarded-For` unconditionally, defeating the login rate
limit, the lockout counter and the IP in `activity_log`. Now reads `request.remote_addr`,
with `ProxyFix` wired from `TRUSTED_PROXY_COUNT` (**default 0 = header ignored**).

> ⚠️ **Set `TRUSTED_PROXY_COUNT=1` when you put nginx/Caddy in front**, or every client
> will appear to come from the proxy and the rate limit will apply to everyone at once.

### 6. XSS sweep — every render path, not just the known one

`loadUsers()` (`admin.html`) interpolated `u.name`/`u.phone`/`u.department`/`u.status`
raw — fed straight from the registration form. Swept **all** `innerHTML` sites across
`admin.html`, `dashboard.html`, `workspace.html`: ~90 user-controlled interpolations now
escaped, including CSV headers, search queries, case titles, uploaded filenames and
activity-log descriptions.

`dashboard.html` had no `esc()` at all — its `escapeHtml()` did a bare `s.replace()`
that throws on a number or null. Replaced with a null-safe `esc()`.

`tests/test_access_control.py` contains a **generic** guard that scans every render
function for the whole class of bug, so a third instance cannot land quietly.

### 7. Public registration surface eliminated

`/api/lea/register` was unauthenticated, unrated, and wrote two files to `uploads/` per
request. It is now `@user_required` + rate-limited (5/hour), and identity fields come
from the signed-in account rather than the form — an applicant cannot claim to be a
different officer. **This closes the Day-2 "harden public registration / add CAPTCHA"
item outright.** `/register` is now account signup; verification moved into the dashboard.

### 8. Plans, credits and payments

Admin owns everything (Admin → **Plans & Payments**):
plan CRUD (credits, price, description, ordering, featured, retire),
signup and LEA-approval free-credit defaults, per-service `credits_per_use`,
manual per-user credit adjustment (already existed), and a **Payment Orders** queue.

Crediting happens in exactly one place — `credit_payment_order()` — and is idempotent:
an order already `paid` returns False. Verified: a replayed "Mark Paid" returns 409.

**The payment gateway seam.** `PaymentProvider` has two implementations:
- `ManualProvider` (live) — order filed `pending`, admin confirms the transfer.
- `RazorpayProvider` — **complete, inert.** Order creation via the Orders API and
  webhook signature verification with `hmac.compare_digest` are both implemented. It
  deliberately uses `urllib` rather than the razorpay SDK so `requirements.txt` does not
  change before the account exists.

**To go live, once KYC clears — no code changes:**
1. `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET`, `RAZORPAY_WEBHOOK_SECRET` in `.env`
2. `PAYMENTS_PROVIDER=razorpay`
3. Point the dashboard webhook at `POST /api/payments/webhook/razorpay`, event `payment.captured`
4. In `pricing.html`, the `if(d.checkout)` branch is where the Razorpay SDK handoff goes
   (currently shows a redirect message) — that is the **only** frontend work left.

If keys are missing the app **falls back to manual** rather than taking checkout offline.

### 9. Frontend

- `/pricing` — new, public, matches the existing dark-cyberpunk tokens.
- Homepage nav gained Pricing; "Apply" → "Sign Up".
- Dashboard: `creditBalance` was a hardcoded `248` that nothing ever assigned to. It now
  reads live from `/api/user/session` and refreshes after each search and every 60s.
- Dashboard gate banner reflecting `unverified` / `pending` / `rejected` / no-credits.
- LEA verification form moved into the dashboard.
- The raw `<pre>` JSON dump is now a formatted result card; 402 renders required vs.
  available with a Buy Credits action.

---

## Verification performed

**74/74 unit tests pass** (`.venv/bin/python -m unittest discover -s tests`) — 28 new.
There is no pytest in the venv, so use `unittest`.

**Migration chain applied cleanly from empty** against real MySQL 8 (throwaway Docker
container, since no local MySQL is installed):
`db_setup.sql` → `migration_admin_customization.sql` → `migration_fix_import_errors.sql`
→ `migration_selfserve_auth.sql`. Re-running the new migration is a no-op (idempotent).

> Note: `migration_coming_soon.sql`, referenced in the 5-day plan, **does not exist in
> this checkout**. Presumably on the PR-#1 branch.

**End-to-end, 17/17 against real MySQL** — signup → weak password rejected → duplicate
rejected → lookup blocked while unverified → `subscriber_lookup` bypass dead → verification
submitted → still blocked while pending → admin approves → **`dev123` login rejected (401)**
→ real password works → hit charges 2 credits → **miss charges nothing** → 402 when short
→ `search_logs` + `credit_transactions` correct → order placed → marked paid credits 50 →
replay blocked → reset token works, reuse blocked, new password logs in.

An XSS payload (`<img src=x onerror=alert(1)>`) submitted as the signup name is stored
verbatim and rendered escaped.

---

## Not done / next

- **Day 2 remains**: `admin`/`admin123` seed, `role_required` across admin routes, CSRF
  tokens, `SESSION_COOKIE_SECURE`/`SAMESITE`, security headers, `/api/admin/login` rate
  limit, `/uploads/<filename>` path traversal guard, `/api/events` unauthenticated SSE,
  PDF injection, fail-fast on missing `SECRET_KEY`/`ENCRYPTION_KEY`.
- **Day 5 packaging** untouched: no `wsgi.py`, no gunicorn, `app.run(debug=True)` still at
  the bottom of `app.py` (the interactive debugger is RCE — do not expose this as-is).
- The in-process rate limiter still multiplies by gunicorn worker count.
- Other tool codes (`vehicle_lookup`, `tower_bts_lookup`, `ip_lookup`, Aadhaar validator)
  are now behind the clearance gate and fail-closed service check, but do **not** yet
  charge credits or write `search_logs` — only `mobile_lookup` does, per the agreed scope.

## Apply on your instance — NOT YET DONE

**Status: pending.** There is no MySQL instance yet, so none of this has been applied to a
real database. Everything above was verified against a throwaway MySQL 8 Docker container.

The full ordered checklist lives in **`CLAUDE.md`** under "⚠️ Pending — must be done before
deployment" so it is not lost. In short: apply the four SQL files in dependency order, copy
the new keys from `.env.example` into `.env`, set `TRUSTED_PROXY_COUNT=1` once a reverse
proxy is in front, and back up `ENCRYPTION_KEY`.

`DEV_USER_PASSWORD` has been removed from `.env` — it is no longer read by anything.

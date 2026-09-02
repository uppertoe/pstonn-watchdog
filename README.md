# pstonn-watchdog

An **independent** dead-man's switch for [p.stonn](../pstonn), in Go (standard
library only — no dependencies). It runs on GitHub Actions, deliberately **off**
the p.stonn VPS, so the same outage that takes p.stonn down can't also silence
the alert.

Every ~10 minutes it polls p.stonn's `/status` endpoint:

- **Healthy** → refresh a cached, encrypted copy of the notify roster (email +
  ntfy per user), so a copy is on hand for when p.stonn is unreachable.
- **Unreachable, or the scheduler is stalled**, for long enough → email + push
  the affected users (from the cached roster) telling them to set their permit
  directly with the council, and ping the operator sooner.

A short outage rarely matters (an un-applied permit still gets the council's
default ~1 hour, and an already-set plate stays on the council record even while
p.stonn is down), so users are only alarmed after a **sustained** outage.

## Where state lives

Split by sensitivity:

- **`state/state.json` — committed to the repo** (by the workflow, only when it
  changes). It holds the outage/probe timers and notified flags — no PII — and
  committing it means the escalation clock survives an Actions cache miss.
- **`state/roster.enc` and `state/notified.enc` — Actions cache only**, never
  committed (both gitignored). They hold user emails/topics — the roster, and
  who has been told about the current outage — **AES-256-GCM encrypted** with
  `ROSTER_KEY` as defence in depth on top of the cache not being publicly
  downloadable. Losing the cache mid-outage re-notifies at worst; never the
  reverse.

A healthy stretch produces no state commits, so a monthly `keepalive` workflow
makes one trivial commit regardless, keeping GitHub from auto-disabling the
schedule after 60 idle days.

## How it decides

| Signal | Meaning |
|---|---|
| `/status` reachable + `scheduler.stale = false` | healthy — refresh roster, clear any outage |
| unreachable / non-2xx / `scheduler.stale = true` | count from first failure |
| down ≥ `OPERATOR_ALERT_MIN` (default **10 min**) | alert the operator (once) |
| down ≥ `DOWN_THRESHOLD_MIN` (default **45 min**) | begin **targeted** user alerts (see below) |
| down ≥ `BACKSTOP_ALERT_MIN` (default **12 h**) | alert every household still untold (QR codes are dead at the door by then) |
| healthy again after alerting | send an all-clear to exactly those who were told |
| `council.state` alertable for ≥ `CONNECTOR_ALERT_MIN` (default **20 min**) | alert the operator (once): the app is fine but its council operations aren't |

Timed from the **first failure timestamp** (not a tick count), so GitHub's
best-effort cron jitter can't cause false alarms.

### The front door

`/status` says whether the app is up; it says nothing about whether a *new
visitor* can get in. On 2026-08-28 an edge routing change made the landing
page's Sign in button loop back to the landing page for two days while every
health signal stayed green — nobody deploying noticed, because they were already
signed in. So on every healthy poll the watchdog also acts as an anonymous
visitor: it loads `/`, finds the Sign in button, follows it **once** without
following redirects, and requires the first hop to be the login prompt on
`SIGNIN_AUTH_HOST` (and the same for `/signin` directly). Broken for
`SIGNIN_ALERT_MIN` (default 10) → the operator is told once, with what the probe
saw; a recovery notice follows when it passes again. Users are never alerted
by this probe — scheduled permit changes keep running on the stored council
session, and there is nothing they could do. Leave `SIGNIN_AUTH_HOST` unset to
disable the probe.

### The council side

"Scheduler is alive" and "the scheduler's dependency is usable" are different
facts: if the council added a CAPTCHA to its login tomorrow, or blocked
p.stonn's IP, `/status` would stay green while every permit write failed. So
the app derives a connector state from the **real council operations it
performs** (keep-warm refreshes, plate reads and writes, logins — production
traffic is the probe; the watchdog never holds council credentials) and
publishes it as `council.state` on `/status`. Every healthy poll reads it.

Three states alert, each already breadth- or structure-gated app-side so one
household's typo'd password or one glitched response can never raise them:

| `council.state` | Meaning |
|---|---|
| `auth_failed` | logins rejected across **distinct** households — the portal, not a password |
| `upstream_changed` | the sign-in page stopped parsing, or repeated responses stopped making sense — the CAPTCHA/portal-upgrade signature |
| `blocked` | the app's fleet breaker confirmed a shared-edge/IP block |

The state must persist for `CONNECTOR_ALERT_MIN` (default 20 — two to three
polls) before the operator is told, once, with a recovery notice to follow;
`healthy` / `idle` / `degraded` / `rate_limited` never alert. Users are never
alerted by this check — the app's own notifier already tells affected
households per permit.

### Who gets told

The roster p.stonn serves covers only accounts that **manage a live permit**,
and each entry carries `next_change_at` — when that household's schedule next
requires a permit write, stamped by the app while healthy. During an outage,
each run alerts only the households whose stamped change has fallen inside the
outage window (plus a `NOTIFY_LEAD_MIN` lead, default 60 min): a short outage
bothers exactly whom it hurt, a long one reaches each household roughly as it
becomes affected. Households with nothing scheduled hear nothing until the
backstop. Each household is told **once per outage** (tracked in the encrypted
`notified.enc`, cache-only like the roster), and the all-clear goes only to
those who were told.

## Setup

1. **Create a public repo** and push this directory:
   ```sh
   gh repo create pstonn-watchdog --public --source=. --push
   ```

2. **On p.stonn**, set `STATUS_TOKEN` to a long random secret and redeploy, so
   `GET https://p.<domain>/status` returns JSON with `Authorization: Bearer <token>`.

3. **Set the repo secrets** (Settings → Secrets and variables → Actions):
   ```sh
   gh secret set STATUS_URL       --body 'https://p.example.org/status'
   gh secret set STATUS_TOKEN     --body '<same token as p.stonn>'
   gh secret set ROSTER_KEY       --body "$(openssl rand -hex 32)"   # keep a copy!
   gh secret set SES_HOST         --body 'email-smtp.ap-southeast-2.amazonaws.com'
   gh secret set SES_PORT         --body '587'
   gh secret set SES_USER         --body '<SES SMTP username>'
   gh secret set SES_PASS         --body '<SES SMTP password>'
   gh secret set MAIL_FROM        --body 'p.stonn <no-reply@yourdomain>'
   gh secret set NTFY_BASE        --body 'https://ntfy.yourdomain'   # optional
   gh secret set NTFY_TOKEN       --body '<ntfy token>'              # optional
   gh secret set ADMIN_EMAIL      --body 'you@yourdomain'           # operator alerts
   gh secret set ADMIN_NTFY_TOPIC --body 'pstonn-admin-<random>'    # operator alerts
   ```
   Optional thresholds (repo *variables*, not secrets):
   ```sh
   gh variable set DOWN_THRESHOLD_MIN --body '45'
   gh variable set OPERATOR_ALERT_MIN --body '10'
   gh variable set NOTIFY_LEAD_MIN    --body '60'   # warn this far ahead of a due change
   gh variable set BACKSTOP_ALERT_MIN --body '720'  # tell everyone at this age (< the app's 48h stamp horizon)
   gh variable set SIGNIN_AUTH_HOST   --body 'auth.example.org'  # enables the sign-in probe
   gh variable set SIGNIN_ALERT_MIN   --body '10'
   gh variable set CONNECTOR_ALERT_MIN --body '20' # council-connector persistence before alerting
   ```

4. **SES must be out of the sandbox** to email real users (verify your domain and
   request production access in the SES console). `MAIL_FROM` must be verified.

5. **Test it** with the manual trigger:
   ```sh
   gh workflow run watch.yml
   ```
   With p.stonn healthy it logs `healthy` and caches the encrypted roster. To
   rehearse an outage without a real one, point `STATUS_URL` at a bad path.

## Run locally

```sh
STATUS_URL=https://p.example.org/status STATUS_TOKEN=... \
ROSTER_KEY=$(openssl rand -hex 32) go run .
```

## Notes / caveats

- **GitHub cron is best-effort** — runs can be delayed 10–30+ min under load. Fine
  here (generous threshold); not for tight SLAs.
- Keep a copy of `ROSTER_KEY`. Rotating it just means the next healthy poll
  re-encrypts a fresh roster (the old cache becomes unreadable, which is fine).
- Actions caches are best-effort; refreshed every healthy run, so effectively
  always warm. If a cache were ever cold during an outage, the operator alert
  (which needs no roster) still fires.

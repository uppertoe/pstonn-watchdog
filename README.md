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

**Not in the repo.** The outage flags and the roster cache live in the **GitHub
Actions cache** (restored/saved by the workflow), so user emails are never
committed to a public repo, and the cache isn't publicly downloadable. The roster
is additionally **AES-256-GCM encrypted** with `ROSTER_KEY` as defence in depth.

Because nothing is committed, a monthly `keepalive` workflow makes one trivial
commit so GitHub doesn't auto-disable the schedule after 60 idle days.

## How it decides

| Signal | Meaning |
|---|---|
| `/status` reachable + `scheduler.stale = false` | healthy — refresh roster, clear any outage |
| unreachable / non-2xx / `scheduler.stale = true` | count from first failure |
| down ≥ `OPERATOR_ALERT_MIN` (default **10 min**) | alert the operator (once) |
| down ≥ `DOWN_THRESHOLD_MIN` (default **45 min**) | begin **targeted** user alerts (see below) |
| down ≥ `BACKSTOP_ALERT_MIN` (default **12 h**) | alert every household still untold (QR codes are dead at the door by then) |
| healthy again after alerting | send an all-clear to exactly those who were told |

Timed from the **first failure timestamp** (not a tick count), so GitHub's
best-effort cron jitter can't cause false alarms.

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

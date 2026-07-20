# pstonn-watchdog

An **independent** dead-man's switch for [p.stonn](../pstonn). It runs on GitHub
Actions — deliberately **off** the p.stonn VPS, so the same outage that takes
p.stonn down can't also silence the alert.

Every ~10 minutes it polls p.stonn's `/status` endpoint:

- **Healthy** → refresh a cached, encrypted copy of the notify roster (email +
  ntfy per user), so a copy is on hand for when p.stonn is unreachable.
- **Unreachable, or the scheduler is stalled**, for long enough → email + push
  the affected users (from the cached roster) telling them to set their permit
  directly with the council, and ping the operator sooner.

Because a short outage rarely matters (an un-applied permit still gets the
council's default ~1 hour, and an already-set plate stays on the council record
even while p.stonn is down), users are only alarmed after a **sustained** outage.

## How it decides

| Signal | Meaning |
|---|---|
| `/status` reachable + `scheduler.stale = false` | healthy — refresh roster, clear any outage |
| unreachable / non-2xx / `scheduler.stale = true` | count from first failure |
| down ≥ `OPERATOR_ALERT_MIN` (default **10 min**) | alert the operator (once) |
| down ≥ `DOWN_THRESHOLD_MIN` (default **45 min**) | alert users (once), with the council portal link |
| healthy again after alerting | send an all-clear |

State (outage flags + the encrypted roster) is committed back to the repo, so it
survives between runs. The roster is **AES-256-GCM encrypted** with `ROSTER_KEY`
— never stored in the clear (this repo is public).

## Setup

1. **Create a public repo** and push this directory:
   ```sh
   gh repo create pstonn-watchdog --public --source=. --push
   ```

2. **On p.stonn**, set `STATUS_TOKEN` to a long random secret and redeploy, so
   `GET https://p.<domain>/status` returns JSON with `Authorization: Bearer <token>`.

3. **Set the repo secrets** (Settings → Secrets and variables → Actions), e.g.:
   ```sh
   gh secret set STATUS_URL      --body 'https://p.example.org/status'
   gh secret set STATUS_TOKEN    --body '<same token as p.stonn>'
   gh secret set ROSTER_KEY      --body "$(openssl rand -hex 32)"   # keep a copy!
   gh secret set SES_HOST        --body 'email-smtp.ap-southeast-2.amazonaws.com'
   gh secret set SES_PORT        --body '587'
   gh secret set SES_USER        --body '<SES SMTP username>'
   gh secret set SES_PASS        --body '<SES SMTP password>'
   gh secret set MAIL_FROM       --body 'p.stonn <no-reply@yourdomain>'
   gh secret set NTFY_BASE       --body 'https://ntfy.yourdomain'   # optional
   gh secret set NTFY_TOKEN      --body '<ntfy token>'              # optional
   gh secret set ADMIN_EMAIL     --body 'you@yourdomain'           # operator alerts
   gh secret set ADMIN_NTFY_TOPIC --body 'pstonn-admin-<random>'   # operator alerts
   ```
   Optional thresholds (repo *variables*, not secrets):
   ```sh
   gh variable set DOWN_THRESHOLD_MIN --body '45'
   gh variable set OPERATOR_ALERT_MIN --body '10'
   ```

4. **SES must be out of the sandbox** to email real users (verify your domain and
   request production access in the SES console). `MAIL_FROM` must be a verified
   sender.

5. **Test it** with the manual trigger:
   ```sh
   gh workflow run watch.yml
   ```
   With p.stonn healthy it should log `healthy` and (first time) commit the
   encrypted roster. To rehearse an outage without a real one, point `STATUS_URL`
   at a bad path for a run.

## Notes / caveats

- **GitHub cron is best-effort** — runs can be delayed 10–30+ min under load. Fine
  here because the user threshold is generous; not suitable for tight SLAs.
- Uses the timestamp of first failure (not a tick count), so cron jitter doesn't
  cause false alarms.
- Keep a copy of `ROSTER_KEY`. Rotating it just means the next healthy poll
  re-encrypts a fresh roster (the old cache becomes unreadable, which is fine).
- Only `nodemailer` is pulled in; everything else uses the Node standard library.

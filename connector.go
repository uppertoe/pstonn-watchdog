package main

import (
	"fmt"
	"log"
	"time"
)

// The council-connector check.
//
// "Scheduler is alive" and "the scheduler's dependency is usable" are different
// facts. If the council changed its login flow tomorrow — added a CAPTCHA,
// rotated its auth shape, blocked p.stonn's egress IP — /status would stay
// green, the scheduler would keep ticking, and the first person to notice would
// be a household whose plate change silently failed. So the app derives a
// connector state from the REAL council operations it performs (keep-warm
// refreshes, plate reads and writes, logins — production traffic is the probe;
// this watchdog never holds council credentials) and publishes it on /status as
// `council.state`; every healthy poll reads it here.
//
// Two layers keep this from crying wolf. App-side, every alertable state
// already requires breadth or structure: `auth_failed` means logins rejected
// across DISTINCT households (one wrong password can never raise it),
// `upstream_changed` means the sign-in page itself stopped parsing or repeated
// responses stopped making sense, and `blocked` means the app's fleet breaker
// confirmed a shared-edge block. Watchdog-side, the state must then PERSIST for
// CONNECTOR_ALERT_MIN across polls before the operator is told — a blip that
// heals between polls is never mailed. The informational states (healthy, idle,
// degraded, rate_limited) never alert: the app's own backoff machinery owns
// those, and mailing them would train the operator to ignore this alarm.
//
// Operator only, like the sign-in probe: users are never alerted by this check.
// Their permit writes may indeed be failing, but the app's own notifier already
// tells affected households with wording specific to their permit — a watchdog
// blast on top would be a second, vaguer alarm for the same event.

// connectorStatus is the slice of /status `council` this check reasons on. An
// app too old to send it decodes to the zero value, whose empty State is not
// alertable — the two sides can be deployed apart in either order.
type connectorStatus struct {
	State               string `json:"state"`
	ConsecutiveFailures int    `json:"consecutive_failures"`
	LastAttemptAt       string `json:"last_attempt_at"`
	LastSuccessAt       string `json:"last_success_at"`
	BreakerOpen         bool   `json:"breaker_open"`
}

// alertableConnectorStates are the states worth operator email: each one names
// a cause outside the app that will not fix itself. Everything else — including
// an unknown word from a newer app — is informational.
var alertableConnectorStates = map[string]bool{
	"auth_failed":      true,
	"upstream_changed": true,
	"blocked":          true,
}

// checkConnector drives the operator alert/recovery state for the connector.
// Called only on a healthy /status poll: during an app outage the connector is
// unreadable for a bigger reason the outage alert already covers.
func (cfg config) checkConnector(st *state, cs connectorStatus, now time.Time) {
	if !alertableConnectorStates[cs.State] {
		if st.ConnectorBrokenSince != 0 {
			brokenMin := sinceMin(st.ConnectorBrokenSince, now)
			if st.ConnectorNotified {
				if cfg.notifyOperator("Council connector recovered",
					fmt.Sprintf("p.stonn's council operations are working again (state %q) after about %.0f minutes in %q. Scheduled changes the app deferred during the incident retry on their own.", orWord(cs.State, "healthy"), brokenMin, st.ConnectorState)) {
					st.ConnectorNotified = false
				}
			}
			// Keep the incident on the books until the recovery notice actually
			// delivered, so a failed send retries next run instead of vanishing.
			if !st.ConnectorNotified {
				st.ConnectorBrokenSince, st.ConnectorState = 0, ""
			}
		}
		return
	}

	if st.ConnectorBrokenSince == 0 {
		st.ConnectorBrokenSince = now.UnixMilli()
	}
	// An incident may move between alertable states (auth_failed hardening into
	// blocked); it is one incident — record the latest word, keep the clock.
	st.ConnectorState = cs.State
	brokenMin := sinceMin(st.ConnectorBrokenSince, now)
	log.Printf("connector state %q for %.1f min (consecutive failures: %d)", cs.State, brokenMin, cs.ConsecutiveFailures)
	if !st.ConnectorNotified && brokenMin >= cfg.connectorAlertMin {
		subject, body := connectorAlertText(cs, brokenMin)
		if cfg.notifyOperator(subject, body) {
			st.ConnectorNotified = true
		}
	}
}

// connectorAlertText names what the state means and what to look at first. The
// body carries the success clock so the operator can see at a glance how long
// real operations have been failing, without opening /status themselves.
func connectorAlertText(cs connectorStatus, brokenMin float64) (subject, body string) {
	var what, look string
	switch cs.State {
	case "auth_failed":
		subject = "Council portal is rejecting p.stonn's logins"
		what = "The council portal is rejecting logins across multiple households at once — that is the portal, not anyone's password."
		look = "Likeliest causes: the council changed its sign-in flow (a CAPTCHA/Turnstile on the login form arrives EXACTLY like this or as upstream_changed), or a portal-wide account problem. Try a manual login to the council portal in a browser and compare what it serves."
	case "upstream_changed":
		subject = "Council portal no longer looks like the portal"
		what = "The council portal is answering in shapes p.stonn does not recognise — an unparseable sign-in page, or repeated responses that no longer match the captured API."
		look = "Likeliest causes: a portal upgrade (Orikan version drift), a new challenge/interstitial page, or a changed login form. Open the council portal in a browser and look at its sign-in page first."
	case "blocked":
		subject = "p.stonn appears blocked at the council edge"
		what = "Several distinct households were refused in quick succession and the app's fleet breaker has opened — the signature of an edge/IP block on p.stonn's shared egress address, not of any one account."
		look = "The app has already paused all council traffic and will probe its way back on its own. If this persists, the /status council block carries the edge's own correlation id (last_pushback_ref) to quote to the council."
	}
	clock := fmt.Sprintf("Consecutive failed operations: %d.", cs.ConsecutiveFailures)
	if cs.LastSuccessAt != "" {
		clock += " Last successful council operation: " + cs.LastSuccessAt + "."
	}
	body = fmt.Sprintf("%s\n\nThe app and scheduler are otherwise healthy (/status is green) — this is specifically the council side failing, for about %.0f minutes.\n\n%s\n\n%s\n\nUsers have NOT been alerted by the watchdog: the app's own notifier tells affected households per permit, with wording specific to their schedule.", what, brokenMin, clock, look)
	return subject, body
}

// orWord returns s, or fallback when s is empty (an older app sends no state).
func orWord(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

package main

import (
	"strings"
	"testing"
	"time"
)

// The connector check emails a human, so its false-positive contract is what
// these tests pin: informational states never alert, an alertable state must
// persist across polls before it alerts, one incident is one email, a blip that
// heals between polls sends nothing at all, and recovery notices retry until
// they actually deliver. Users are never part of this path by construction —
// the check has no roster and only notifyOperator to speak through.

// connRig returns a config whose operator channel records every subject, and
// whose deliveries succeed unless *fail is true.
func connRig(t *testing.T, fail *bool) (config, *[]string) {
	t.Helper()
	var sent []string
	cfg := config{
		connectorAlertMin: 20,
		operatorHook: func(subject string) bool {
			if fail != nil && *fail {
				return false
			}
			sent = append(sent, subject)
			return true
		},
	}
	return cfg, &sent
}

func TestConnectorInformationalStatesNeverAlert(t *testing.T) {
	now := time.Date(2026, 9, 2, 9, 0, 0, 0, time.UTC)
	// "" is an app too old to send the council block; an unknown word is an app
	// NEWER than this watchdog. Both must stay silent, not crash or mail.
	for _, s := range []string{"", "healthy", "idle", "degraded", "rate_limited", "brand_new_state"} {
		cfg, sent := connRig(t, nil)
		st := state{}
		for i := 0; i < 10; i++ { // however long it persists
			cfg.checkConnector(&st, connectorStatus{State: s, ConsecutiveFailures: 99}, now.Add(time.Duration(i)*10*time.Minute))
		}
		if len(*sent) != 0 {
			t.Errorf("state %q alerted: %v", s, *sent)
		}
		if st.ConnectorBrokenSince != 0 || st.ConnectorNotified {
			t.Errorf("state %q started an incident: %+v", s, st)
		}
	}
}

func TestConnectorAlertNeedsPersistence(t *testing.T) {
	now := time.Date(2026, 9, 2, 9, 0, 0, 0, time.UTC)
	cfg, sent := connRig(t, nil)
	st := state{}

	cs := connectorStatus{State: "auth_failed", ConsecutiveFailures: 5, LastSuccessAt: "2026-09-02T08:00:00Z"}
	cfg.checkConnector(&st, cs, now) // first sighting: clock starts, no mail
	cfg.checkConnector(&st, cs, now.Add(10*time.Minute))
	if len(*sent) != 0 {
		t.Fatalf("alerted before the persistence threshold: %v", *sent)
	}
	if st.ConnectorBrokenSince == 0 || st.ConnectorState != "auth_failed" {
		t.Fatalf("incident clock not started: %+v", st)
	}

	cfg.checkConnector(&st, cs, now.Add(25*time.Minute)) // past 20 min: alert once
	if len(*sent) != 1 || !strings.Contains((*sent)[0], "rejecting p.stonn's logins") {
		t.Fatalf("sent = %v, want one auth-failed alert", *sent)
	}
	if !st.ConnectorNotified {
		t.Fatal("delivered alert not recorded")
	}

	// Still broken, even hardened into a different alertable state: SAME incident,
	// no second email, latest word recorded.
	cfg.checkConnector(&st, connectorStatus{State: "blocked"}, now.Add(40*time.Minute))
	cfg.checkConnector(&st, connectorStatus{State: "blocked"}, now.Add(60*time.Minute))
	if len(*sent) != 1 {
		t.Fatalf("one incident produced %d emails: %v", len(*sent), *sent)
	}
	if st.ConnectorState != "blocked" {
		t.Fatalf("latest state not recorded: %+v", st)
	}

	// Recovery: one notice to the operator, then a clean slate.
	cfg.checkConnector(&st, connectorStatus{State: "healthy"}, now.Add(70*time.Minute))
	if len(*sent) != 2 || !strings.Contains((*sent)[1], "recovered") {
		t.Fatalf("sent = %v, want a recovery notice", *sent)
	}
	if st.ConnectorBrokenSince != 0 || st.ConnectorNotified || st.ConnectorState != "" {
		t.Fatalf("state not reset after recovery: %+v", st)
	}
	cfg.checkConnector(&st, connectorStatus{State: "healthy"}, now.Add(80*time.Minute))
	if len(*sent) != 2 {
		t.Fatalf("healthy polls keep mailing: %v", *sent)
	}
}

func TestConnectorBlipNeverMails(t *testing.T) {
	now := time.Date(2026, 9, 2, 9, 0, 0, 0, time.UTC)
	cfg, sent := connRig(t, nil)
	st := state{}
	// One poll sees upstream_changed; the next sees it healed. Nothing — not an
	// alert, not a recovery notice — should reach the operator.
	cfg.checkConnector(&st, connectorStatus{State: "upstream_changed"}, now)
	cfg.checkConnector(&st, connectorStatus{State: "healthy"}, now.Add(10*time.Minute))
	if len(*sent) != 0 {
		t.Fatalf("a self-healing blip mailed the operator: %v", *sent)
	}
	if st.ConnectorBrokenSince != 0 || st.ConnectorState != "" {
		t.Fatalf("blip left incident state behind: %+v", st)
	}
}

func TestConnectorRecoveryNoticeRetriesUntilDelivered(t *testing.T) {
	now := time.Date(2026, 9, 2, 9, 0, 0, 0, time.UTC)
	fail := false
	cfg, sent := connRig(t, &fail)
	st := state{}
	cs := connectorStatus{State: "blocked"}
	cfg.checkConnector(&st, cs, now)
	cfg.checkConnector(&st, cs, now.Add(25*time.Minute)) // alert delivered
	if len(*sent) != 1 {
		t.Fatalf("setup: want the alert out, got %v", *sent)
	}

	fail = true // recovery notice cannot be delivered this run
	cfg.checkConnector(&st, connectorStatus{State: "healthy"}, now.Add(35*time.Minute))
	if st.ConnectorBrokenSince == 0 || !st.ConnectorNotified {
		t.Fatalf("undelivered recovery notice was forgotten: %+v", st)
	}

	fail = false // next run delivers it, then resets
	cfg.checkConnector(&st, connectorStatus{State: "healthy"}, now.Add(45*time.Minute))
	if len(*sent) != 2 || !strings.Contains((*sent)[1], "recovered") {
		t.Fatalf("sent = %v, want the retried recovery notice", *sent)
	}
	if st.ConnectorBrokenSince != 0 || st.ConnectorNotified || st.ConnectorState != "" {
		t.Fatalf("state not reset once delivered: %+v", st)
	}
}

// TestConnectorAlertText pins each alertable state to wording that tells the
// operator what happened and what to look at, and pins the invariant every
// variant must carry: the watchdog did not alarm users.
func TestConnectorAlertText(t *testing.T) {
	cases := []struct {
		state       string
		wantSubject string
		wantBody    string
	}{
		{"auth_failed", "rejecting p.stonn's logins", "not anyone's password"},
		{"upstream_changed", "no longer looks like the portal", "sign-in page"},
		{"blocked", "blocked at the council edge", "fleet breaker"},
	}
	for _, tc := range cases {
		subject, body := connectorAlertText(connectorStatus{
			State: tc.state, ConsecutiveFailures: 7, LastSuccessAt: "2026-09-02T08:00:00Z",
		}, 30)
		if !strings.Contains(subject, tc.wantSubject) {
			t.Errorf("%s subject = %q, want it to contain %q", tc.state, subject, tc.wantSubject)
		}
		if !strings.Contains(body, tc.wantBody) {
			t.Errorf("%s body missing %q:\n%s", tc.state, tc.wantBody, body)
		}
		for _, invariant := range []string{"NOT been alerted", "7", "2026-09-02T08:00:00Z"} {
			if !strings.Contains(body, invariant) {
				t.Errorf("%s body missing %q:\n%s", tc.state, invariant, body)
			}
		}
	}
}

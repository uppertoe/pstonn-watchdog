package main

import (
	"strings"
	"testing"
	"time"
)

// TestPickTargets pins the whole notification policy to its reason for
// existing: during an outage, warn exactly the households whose scheduled
// change the outage has cost (or is about to cost), nobody else — until the
// backstop age, when dead QR codes make it everyone's problem.
func TestPickTargets(t *testing.T) {
	downStart := time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)
	now := downStart.Add(50 * time.Minute) // past a 45-min user threshold
	lead := time.Hour

	stamp := func(at time.Time) string { return at.UTC().Format(time.RFC3339) }
	roster := []rosterEntry{
		// Change fell INSIDE the outage: their write was missed. Must be told.
		{Email: "missed@example.com", NextChangeAt: stamp(downStart.Add(20 * time.Minute))},
		// Change due within the lead: about to be missed. Must be told.
		{Email: "imminent@example.com", NextChangeAt: stamp(now.Add(30 * time.Minute))},
		// Change happened BEFORE the outage began: it was applied while healthy.
		{Email: "already-done@example.com", NextChangeAt: stamp(downStart.Add(-time.Hour))},
		// Change well beyond the lead: nothing is wrong for them yet.
		{Email: "later@example.com", NextChangeAt: stamp(now.Add(6 * time.Hour))},
		// Nothing scheduled at all: a static plate loses nothing in a short outage.
		{Email: "static@example.com"},
		// A stamp we cannot read: fail toward warning, never toward silence.
		{Email: "garbled@example.com", NextChangeAt: "not-a-time"},
	}

	got := pickTargets(roster, nil, downStart, now, lead, false)
	want := map[string]bool{"missed@example.com": true, "imminent@example.com": true, "garbled@example.com": true}
	if len(got) != len(want) {
		t.Fatalf("targets = %+v, want exactly %v", got, want)
	}
	for _, r := range got {
		if !want[r.Email] {
			t.Errorf("unexpected target %s", r.Email)
		}
	}

	// Once told, never re-told within the outage — however many runs follow.
	got = pickTargets(roster, got, downStart, now.Add(10*time.Minute), lead, false)
	if len(got) != 0 {
		t.Fatalf("second run re-targeted already-told households: %+v", got)
	}

	// The backstop sweeps in everyone still untold — static plates included,
	// because by then their guest QR codes are dead at the kerb.
	told := []rosterEntry{{Email: "missed@example.com"}, {Email: "imminent@example.com"}, {Email: "garbled@example.com"}}
	got = pickTargets(roster, told, downStart, downStart.Add(13*time.Hour), lead, true)
	rest := map[string]bool{"already-done@example.com": true, "later@example.com": true, "static@example.com": true}
	if len(got) != len(rest) {
		t.Fatalf("backstop targets = %+v, want %v", got, rest)
	}
	for _, r := range got {
		if !rest[r.Email] {
			t.Errorf("unexpected backstop target %s", r.Email)
		}
	}
}

// TestOutageMessageShapes: the targeted notice must name the missed change (in
// Melbourne time — the reader's clock) and carry the manual council remedy; the
// backstop notice must be the one that warns about QR codes. Getting these
// crossed either buries the actionable detail or scares a static household
// with talk of a "missed change" they never scheduled.
func TestOutageMessageShapes(t *testing.T) {
	// 2026-08-23 14:00 UTC = midnight 2026-08-24 in Melbourne (AEST, +10).
	r := rosterEntry{Email: "x@example.com", NextChangeAt: "2026-08-23T14:00:00Z"}
	subject, body := outageMessage(r, 50, false)
	if !strings.Contains(subject, "your scheduled permit change") {
		t.Fatalf("targeted subject = %q", subject)
	}
	for _, wantPart := range []string{"Mon 24 Aug, 12:00am", "has NOT been made", councilPortal} {
		if !strings.Contains(body, wantPart) {
			t.Errorf("targeted body missing %q:\n%s", wantPart, body)
		}
	}
	if strings.Contains(body, "QR") {
		t.Error("targeted notice talks about QR codes; that's the backstop's job")
	}

	// Backstop, and any entry with no readable stamp, gets the general notice.
	subject, body = outageMessage(rosterEntry{Email: "y@example.com"}, 780, true)
	if strings.Contains(subject, "your scheduled") {
		t.Fatalf("general subject claims a specific change: %q", subject)
	}
	for _, wantPart := range []string{"QR codes", councilPortal, "for some time"} {
		if !strings.Contains(body, wantPart) {
			t.Errorf("general body missing %q:\n%s", wantPart, body)
		}
	}
	// The duration stays UNSPECIFIED past two hours (operator preference):
	// "about 13 hours" reads as a catastrophe announcement.
	if strings.Contains(body, "hours") {
		t.Errorf("long-outage body states a duration:\n%s", body)
	}
}

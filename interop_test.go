package main

import (
	"encoding/hex"
	"testing"
)

// TestOpenSealedRosterInterop pins the wire format against a payload produced by
// the APP's own sealing code (internal/secretbox), not by this program. If either
// side ever changes construction — nonce placement, encoding, key derivation —
// this fails here, rather than silently blinding the watchdog to new users and
// leaving it to notify a stale roster during the outage it exists for.
func TestOpenSealedRosterInterop(t *testing.T) {
	key, err := hex.DecodeString("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	const sealedByApp = "jDMZfyH3PRsqKrc/tzyP+o5j1mKSqPxpS/PFz/DhDh1jx4rudjAbt45Ei1A+6apdr5YvDTXf7cBbfjG2I7OYMO8JZ7F07z/EFBm+E6wyrrmcXZeCf1C2EQVcA0lEE7kun4g69HzfF/PHcKEQ"

	cfg := config{rosterKey: key}
	got, err := cfg.openSealedRoster(sealedByApp)
	if err != nil {
		t.Fatalf("could not open the app's sealed roster: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(got), got)
	}
	if got[0].Email != "a@example.com" || got[1].Email != "b@example.com" {
		t.Fatalf("wrong emails: %+v", got)
	}

	// A wrong key must fail closed, not yield garbage.
	bad := config{rosterKey: make([]byte, 32)}
	if _, err := bad.openSealedRoster(sealedByApp); err == nil {
		t.Fatal("decryption succeeded under the wrong key")
	}
}

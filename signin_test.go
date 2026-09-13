package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// A stand-in for the app behind its edge. landingHref is what the Sign in
// button links to; routes maps a path to (status, Location).
func fakeEdge(t *testing.T, landingHref string, routes map[string][2]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != signinUserAgent {
			t.Errorf("probe did not identify itself: UA %q", r.Header.Get("User-Agent"))
		}
		if r.Header.Get("Cookie") != "" {
			t.Errorf("probe sent cookies: %q", r.Header.Get("Cookie"))
		}
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<!doctype html><section class="lhero"><h1>Schedule your permit.</h1>
<a href="` + landingHref + `" hx-boost="false" class="btnlike cta">Sign in <svg></svg></a></section>`))
			return
		}
		if rt, ok := routes[r.URL.Path]; ok {
			if rt[1] != "" {
				w.Header().Set("Location", rt[1])
			}
			code := 200
			switch rt[0] {
			case "302":
				code = 302
			case "404":
				code = 404
			case "500":
				code = 500
			}
			w.WriteHeader(code)
			return
		}
		http.NotFound(w, r)
	}))
}

func probe(t *testing.T, srv *httptest.Server) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return probeSignin(ctx, noRedirectClient(5*time.Second), srv.URL, "auth.example.org")
}

const login = "https://auth.example.org/login?rd=x"

func healthyRoutes() map[string][2]string {
	// /signin and /tenant/link redirect to the login prompt; /vehicles (a @pages
	// route) redirects to the landing page — both are "gated".
	return map[string][2]string{
		"/signin":      {"302", login},
		"/tenant/link": {"302", login},
		"/vehicles":    {"302", "/"},
	}
}

func TestSigninProbePassesOnAHealthyFrontDoor(t *testing.T) {
	srv := fakeEdge(t, "/signin", healthyRoutes())
	defer srv.Close()
	if err := probe(t, srv); err != nil {
		t.Fatalf("healthy front door failed: %v", err)
	}
}

// The Aug 2026 bug: a protected route renamed in the app but not in the proxy's
// forward-auth list falls to the catch-all and the app 401s it. The probe must
// catch that even while /signin itself is fine.
func TestSigninProbeCatchesAProtectedRouteFallingThrough(t *testing.T) {
	r := healthyRoutes()
	r["/tenant/link"] = [2]string{"401", ""} // fell to catch-all: app 401, not gated
	srv := fakeEdge(t, "/signin", r)
	defer srv.Close()
	err := probe(t, srv)
	if err == nil || !strings.Contains(err.Error(), "/tenant/link") {
		t.Fatalf("protected-route fall-through not caught: %v", err)
	}
}

// The 2026-08-28 incident, exactly: the button links to /schedule and the edge
// bounces anonymous /schedule to the landing page.
func TestSigninProbeCatchesTheLandingPageLoop(t *testing.T) {
	rt := healthyRoutes()
	rt["/schedule"] = [2]string{"302", "/"}
	srv := fakeEdge(t, "/schedule", rt)
	defer srv.Close()
	err := probe(t, srv)
	if err == nil || !strings.Contains(err.Error(), `redirects to "/"`) {
		t.Fatalf("loop not caught: %v", err)
	}
}

func TestSigninProbeChecksTheDedicatedPathToo(t *testing.T) {
	// Button is fine (points at a path that logs in), but /signin itself is dead.
	srv := fakeEdge(t, "/schedule", map[string][2]string{
		"/schedule": {"302", login},
		"/signin":   {"404", ""},
	})
	defer srv.Close()
	err := probe(t, srv)
	if err == nil || !strings.HasPrefix(err.Error(), "/signin:") {
		t.Fatalf("dead /signin not caught: %v", err)
	}
}

func TestSigninProbeFailsWhenTheButtonIsMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<!doctype html><h1>Nothing to see</h1>`))
	}))
	defer srv.Close()
	err := probe(t, srv)
	if err == nil || !strings.Contains(err.Error(), "no Sign in button") {
		t.Fatalf("missing button not caught: %v", err)
	}
}

func TestSigninProbeRejectsRedirectToTheWrongHost(t *testing.T) {
	srv := fakeEdge(t, "/signin", map[string][2]string{"/signin": {"302", "https://evil.example.net/login"}})
	defer srv.Close()
	err := probe(t, srv)
	if err == nil || !strings.Contains(err.Error(), "want the login prompt on auth.example.org") {
		t.Fatalf("wrong host not caught: %v", err)
	}
}

func TestSigninProbeFailsOnServerError(t *testing.T) {
	srv := fakeEdge(t, "/signin", map[string][2]string{"/signin": {"500", ""}})
	defer srv.Close()
	if err := probe(t, srv); err == nil {
		t.Fatal("500 on /signin passed")
	}
}

// checkSignin: the operator is told once after the alert window, and told again
// when it recovers; the clock starts at the first failure, not the first alert.
func TestCheckSigninAlertsOnceThenRecovers(t *testing.T) {
	brokenRoutes := healthyRoutes()
	brokenRoutes["/schedule"] = [2]string{"302", "/"}
	broken := fakeEdge(t, "/schedule", brokenRoutes)
	defer broken.Close()
	healthy := fakeEdge(t, "/signin", healthyRoutes())
	defer healthy.Close()

	var sent []string
	cfg := config{signinAuthHost: "auth.example.org", signinAlertMin: 10, ntfyBase: "http://127.0.0.1:1"}
	// Route operator notifications to a capture instead of a real channel.
	notify := func(subject string) bool { sent = append(sent, subject); return true }
	cfg.operatorHook = notify

	st := state{}
	t0 := time.Now()
	cfg.signinBase = broken.URL
	cfg.checkSignin(&st, t0)
	if st.SigninBrokenSince == 0 || st.SigninNotified || len(sent) != 0 {
		t.Fatalf("first failure should start the clock and NOT alert: %+v sent=%v", st, sent)
	}
	cfg.checkSignin(&st, t0.Add(11*time.Minute))
	if !st.SigninNotified || len(sent) != 1 || !strings.Contains(sent[0], "BROKEN") {
		t.Fatalf("second failure past the window should alert once: %+v sent=%v", st, sent)
	}
	cfg.checkSignin(&st, t0.Add(21*time.Minute))
	if len(sent) != 1 {
		t.Fatalf("still broken: must not re-alert; sent=%v", sent)
	}
	cfg.signinBase = healthy.URL
	cfg.checkSignin(&st, t0.Add(31*time.Minute))
	if st.SigninNotified || st.SigninBrokenSince != 0 || len(sent) != 2 || !strings.Contains(sent[1], "works again") {
		t.Fatalf("recovery should notify and clear: %+v sent=%v", st, sent)
	}
}

func TestCheckSigninIsSkippedWhenUnconfigured(t *testing.T) {
	cfg := config{}
	st := state{SigninBrokenSince: 5}
	cfg.checkSignin(&st, time.Now())
	if st.SigninBrokenSince != 5 {
		t.Fatal("unconfigured probe must not touch state")
	}
}

// TestLiveSigninProbe runs the real probe against a real deployment. Opt-in:
//
//	SIGNIN_LIVE_BASE=https://p.stonn.org SIGNIN_LIVE_AUTH_HOST=auth.stonn.org go test -run TestLiveSigninProbe -v
func TestLiveSigninProbe(t *testing.T) {
	base, host := os.Getenv("SIGNIN_LIVE_BASE"), os.Getenv("SIGNIN_LIVE_AUTH_HOST")
	if base == "" || host == "" {
		t.Skip("set SIGNIN_LIVE_BASE and SIGNIN_LIVE_AUTH_HOST to probe a live deployment")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := probeSignin(ctx, noRedirectClient(20*time.Second), base, host); err != nil {
		t.Fatalf("live front door: %v", err)
	}
	t.Logf("live front door ok: %s -> login prompt on %s", base, host)
}

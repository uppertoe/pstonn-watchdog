package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// The sign-in probe.
//
// On 2026-08-28 an edge (Caddy) change made anonymous requests to the app's
// home path bounce to the public landing page — and the landing page's own
// "Sign in" button linked to that very path. Every new sign-up and every
// logged-out sign-in silently looped back to the landing page for two days.
// Nobody deploying noticed, because everyone deploying was already signed in;
// /status stayed green throughout, because the app itself was healthy.
//
// This probe behaves like a brand-new visitor every run: load the landing page
// with no cookies, find the Sign in button, follow it ONCE without following
// redirects, and insist that the next hop is the identity provider's login
// prompt. It also checks the dedicated /signin path directly. Anything else —
// a bounce back to the landing page, a 200, a 404, a 5xx — is a broken
// front door, and the operator hears about it within one alert window. Users
// are never alarmed by this probe: there is nothing they can do, and their
// scheduled permit changes keep running on the stored council session.

// signinUserAgent identifies the probe in the app's access log so it can be
// filtered out of visitor counts.
const signinUserAgent = "pstonn-watchdog/1 (+https://github.com/uppertoe/pstonn-watchdog)"

// signinButtonRe finds the landing page's Sign in control: an anchor whose
// button text is "Sign in". Deliberately narrow — the probe should fail when
// the button disappears, not silently probe something else.
var signinButtonRe = regexp.MustCompile(`(?is)<a\s+href="([^"]+)"[^>]*>\s*<button[^>]*>\s*Sign in\b`)

// probeSignin checks the anonymous sign-in path of the app at base (scheme +
// host, no trailing slash). authHost is the identity provider's hostname that
// a correct first hop must redirect to. It returns nil when the front door
// works, or an error naming the first thing that is wrong.
func probeSignin(ctx context.Context, client *http.Client, base, authHost string) error {
	base = strings.TrimRight(base, "/")

	// 1. The landing page, as an anonymous visitor.
	body, status, _, err := fetch(ctx, client, base+"/")
	if err != nil {
		return fmt.Errorf("landing page: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("landing page: status %d", status)
	}
	m := signinButtonRe.FindSubmatch(body)
	if m == nil {
		return errors.New("landing page has no Sign in button")
	}
	href := string(m[1])

	// 2. Follow the button once. The first hop must be the login prompt.
	if err := expectAuthRedirect(ctx, client, base, href, authHost); err != nil {
		return fmt.Errorf("Sign in button (%s): %w", href, err)
	}
	// 3. And the dedicated path, in case the button is ever pointed elsewhere.
	if href != "/signin" {
		if err := expectAuthRedirect(ctx, client, base, "/signin", authHost); err != nil {
			return fmt.Errorf("/signin: %w", err)
		}
	}
	// 4. Representative signed-in-only routes must redirect an anonymous request
	// to the login prompt too — NOT serve a 200 and not return the app's own
	// 401 page. The latter is the exact 2026-08 failure: a route renamed in the
	// app (/council/link -> /tenant/link) but not in the proxy's forward-auth
	// list fell to the catch-all, got no identity, and 401'd every new user's
	// council-linking step for days while /signin itself still looked fine. One
	// route per surface (the link step, an app page) is enough to catch a whole
	// class of "the proxy route list drifted from the app" bugs.
	for _, pth := range protectedProbePaths {
		if err := expectGated(ctx, client, base, pth); err != nil {
			return fmt.Errorf("protected route %s: %w", pth, err)
		}
	}
	return nil
}

// protectedProbePaths are signed-in-only routes an anonymous request must never
// be served. /tenant/link is the council-link step that broke in Aug 2026 (it
// redirects an anon request to the login prompt); /vehicles is an ordinary app
// page (it redirects an anon request to the landing page — the shared-link
// hygiene behaviour). Both are "gated"; the bug returns the app's own 401
// sign-in page or 200 content instead.
var protectedProbePaths = []string{"/tenant/link", "/vehicles"}

// expectGated requires an anonymous request to a signed-in-only route to be
// redirected AWAY (3xx) — whether to the login prompt (@app routes) or to the
// landing page (@pages routes). The failure this guards against is the route
// falling through the proxy's forward-auth list to the catch-all: the app then
// receives no identity and answers 200 (content leak) or, as in Aug 2026, 401
// with its "sign-in isn't available" page. Any non-redirect fails.
func expectGated(ctx context.Context, client *http.Client, base, path string) error {
	_, status, location, err := fetch(ctx, client, base+path)
	if err != nil {
		return err
	}
	if status == 200 {
		return fmt.Errorf("served 200 to an anonymous request (content leak or no auth)")
	}
	if status < 300 || status > 399 {
		return fmt.Errorf("status %d (a gated route must redirect an anonymous request away; 401 here means it fell through the proxy's forward-auth list)", status)
	}
	if location == "" {
		return fmt.Errorf("status %d with no Location", status)
	}
	return nil
}

// expectAuthRedirect requests base+path without following redirects and
// requires a 3xx whose Location is on authHost.
func expectAuthRedirect(ctx context.Context, client *http.Client, base, path, authHost string) error {
	target := path
	if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		target = base + path
	}
	_, status, location, err := fetch(ctx, client, target)
	if err != nil {
		return err
	}
	if status < 300 || status > 399 {
		return fmt.Errorf("status %d, want a redirect to the login prompt", status)
	}
	if location == "" {
		return fmt.Errorf("status %d with no Location header", status)
	}
	loc, perr := url.Parse(location)
	if perr != nil {
		return fmt.Errorf("unparseable Location %q", location)
	}
	// A relative Location ("/") is the exact shape of the 2026-08-28 loop.
	if loc.Host == "" || !strings.EqualFold(loc.Host, authHost) {
		return fmt.Errorf("redirects to %q, want the login prompt on %s", location, authHost)
	}
	return nil
}

// fetch performs one anonymous GET (no cookies, redirects NOT followed) and
// returns the body (capped), status and Location header.
func fetch(ctx context.Context, client *http.Client, u string) (body []byte, status int, location string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, "", err
	}
	req.Header.Set("User-Agent", signinUserAgent)
	req.Header.Set("Accept", "text/html")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, "", err
	}
	defer resp.Body.Close()
	body, _ = io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	return body, resp.StatusCode, resp.Header.Get("Location"), nil
}

// noRedirectClient never follows redirects: the probe judges the FIRST hop.
func noRedirectClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// checkSignin runs the probe and drives the operator alert/recovery state.
// Called only on a healthy /status poll: during an outage the front door is
// down for a bigger reason, and that alert already covers it.
func (cfg config) checkSignin(st *state, now time.Time) {
	if cfg.signinAuthHost == "" {
		return // probe not configured for this deployment
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := probeSignin(ctx, noRedirectClient(20*time.Second), cfg.signinBase, cfg.signinAuthHost)

	if err == nil {
		if st.SigninBrokenSince != 0 {
			brokenMin := sinceMin(st.SigninBrokenSince, now)
			if st.SigninNotified {
				if cfg.notifyOperator("Sign-in works again",
					fmt.Sprintf("The anonymous sign-in probe passes again after about %.0f minutes: the landing page's Sign in button reaches the login prompt on %s.", brokenMin, cfg.signinAuthHost)) {
					st.SigninNotified = false
				}
			}
			// Keep BrokenSince until the recovery notice has actually gone out, so
			// a failed send retries next run rather than being forgotten.
			if !st.SigninNotified {
				st.SigninBrokenSince = 0
			}
		}
		log.Print("sign-in probe ok")
		return
	}

	if st.SigninBrokenSince == 0 {
		st.SigninBrokenSince = now.UnixMilli()
	}
	brokenMin := sinceMin(st.SigninBrokenSince, now)
	log.Printf("sign-in probe FAILED for %.1f min: %v", brokenMin, err)
	if !st.SigninNotified && brokenMin >= cfg.signinAlertMin {
		if cfg.notifyOperator("Sign-in is BROKEN for new visitors",
			fmt.Sprintf("For about %.0f minutes an anonymous visitor pressing Sign in on %s has NOT reached the login prompt on %s.\n\nWhat the probe saw: %v\n\n/status is healthy, so scheduled permit changes are still running — but nobody can sign up or sign in. Check the edge (Caddy) routing and the landing page's Sign in link. Users have not been alerted (there is nothing they can do).", brokenMin, cfg.signinBase, cfg.signinAuthHost, err)) {
			st.SigninNotified = true
		}
	}
}

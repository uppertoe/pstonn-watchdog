// Command pstonn-watchdog is an independent dead-man's switch for p.stonn.
//
// Every run polls p.stonn's /status endpoint. A poll that returns a roster
// refreshes a cached (encrypted) copy of it. If p.stonn is unreachable or its
// work loop is stalled for long enough, this tells the affected users — from the
// cached roster, since p.stonn itself is the thing that's down — to set their
// permit directly with the council, and pings the operator sooner.
//
// It runs on GitHub Actions (off the p.stonn VPS on purpose) and keeps its state
// between runs. Standard library only; no secrets live in the code — everything
// comes from the workflow env (GitHub Secrets).
//
// Key invariant: an outage is only recorded as "handled" once a message actually
// DELIVERED. A failed send is retried next run rather than silently dropped, so a
// delivery/config fault can't turn a real outage into a silent missed alarm.
package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata" // Melbourne zone data on a bare Actions runner
)

// councilPortal is where users are sent to sort their permit out themselves.
const councilPortal = "https://parkingpermits.stonnington.vic.gov.au/"

// State: state.json (outage flags + timer — no PII) is committed to the repo so
// the escalation clock survives a cache miss; roster.enc (the user emails) and
// notified.enc (who has been told about the CURRENT outage) live ONLY in the
// Actions cache, gitignored, and are AES-256-GCM encrypted at rest. Losing the
// cache mid-outage therefore re-notifies at worst — a duplicate email — never
// the reverse.
const (
	stateDir     = "state"
	stateFile    = "state/state.json"
	rosterFile   = "state/roster.enc"
	notifiedFile = "state/notified.enc"
)

type rosterEntry struct {
	Email string `json:"email"`
	Ntfy  string `json:"ntfy,omitempty"`
	// NextChangeAt (RFC3339 UTC, may be empty) is when this household's schedule
	// next requires a permit write, stamped by the app while healthy. It is what
	// lets an outage warn exactly the households whose change it has actually
	// cost: an entry with no stamp has nothing due, and hears only from the
	// long-outage backstop.
	NextChangeAt string `json:"next_change_at,omitempty"`
}

type statusResp struct {
	Scheduler struct {
		Stale bool `json:"stale"`
	} `json:"scheduler"`
	Roster []rosterEntry `json:"roster"`
	// RosterSealed is the roster encrypted under ROSTER_KEY — the same AES-GCM
	// construction this program already uses for its own on-disk cache. The app
	// sends this instead of Roster once ROSTER_KEY is configured there, so a
	// leaked STATUS_TOKEN no longer hands over every user's email and push topic.
	// Both shapes are accepted so the app and this watchdog can be updated apart.
	RosterSealed string `json:"roster_sealed"`
}

// state persists across runs. DownSince is unix millis of the first failure
// (0 when healthy). The *Notified flags are set ONLY once a message delivered.
// WHO has been told lives in notified.enc (it is PII and this file is public);
// RecoverDownMin carries the outage's length across all-clear retry runs, when
// DownSince has already been zeroed. (The pre-targeting `notified` bool is gone;
// an old state.json's copy of it is simply ignored on parse.)
type state struct {
	DownSince           int64   `json:"down_since"`
	OperatorNotified    bool    `json:"operator_notified"`
	ConfigErrorNotified bool    `json:"config_error_notified"`
	RecoverDownMin      float64 `json:"recover_down_min,omitempty"`
}

// pollResult classifies a poll so a self-inflicted config fault (a 401 from a
// rotated token, a 404 from a path change) can't be mistaken for an outage and
// blasted to users.
type pollResult int

const (
	pollHealthy     pollResult = iota // reachable, 200, valid JSON, scheduler running
	pollOutage                        // unreachable / 5xx / scheduler stalled — a real outage
	pollConfigError                   // 4xx / unparseable — we can't read status; likely our config
)

type config struct {
	statusURL, statusToken string
	rosterKey              []byte
	userThresholdMin       float64
	operatorThresholdMin   float64
	// notifyLeadMin: how far AHEAD of a household's due change to warn them,
	// once the outage is past userThresholdMin. An hour mirrors the app's own
	// rollover window — the natural slack a scheduled change already has.
	notifyLeadMin float64
	// backstopThresholdMin: when the outage is this old, every household on the
	// roster is told regardless of schedule — a static-plate household loses
	// nothing in a short outage, but in a day-long one their guest QR codes are
	// dead at the kerb and they deserve to hear it. Must stay well inside the
	// app's 48h NextChangeAt horizon so no missed write can escape both nets.
	backstopThresholdMin   float64
	ntfyBase, ntfyToken    string
	adminEmail, adminTopic string
	// SES SMTP
	sesHost, sesPort, sesUser, sesPass, mailFrom string
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return err
	}
	st := readState()
	now := time.Now()

	result, roster := poll(cfg)
	if len(roster) > 0 { // W9: never overwrite a good cache with an empty roster
		cfg.refreshRoster(roster)
	}

	switch result {
	case pollHealthy:
		downMin := sinceMin(st.DownSince, now)
		st.DownSince = 0
		st.ConfigErrorNotified = false
		// All-clear goes ONLY to those actually told about the outage (notified.enc),
		// and each is dropped from the file only once their all-clear DELIVERED —
		// the leftovers retry next run. RecoverDownMin keeps the outage's length
		// for those retries, when DownSince is already zero.
		if told, err := cfg.readNotified(); err == nil && len(told) > 0 {
			if st.RecoverDownMin == 0 {
				st.RecoverDownMin = downMin
			}
			msg := fmt.Sprintf("p.stonn is updating permits again after about %.0f minutes. You don't need to do anything — your schedule has resumed and QR codes are working.", st.RecoverDownMin)
			var remaining []rosterEntry
			for _, r := range told {
				if !cfg.sendToEntry(r, "p.stonn is back to normal", msg, "default") {
					remaining = append(remaining, r)
				}
			}
			if werr := cfg.writeNotified(remaining); werr != nil {
				log.Printf("write notified: %v", werr)
			}
			if len(remaining) == 0 {
				st.RecoverDownMin = 0
			}
			log.Printf("all-clear delivered to %d/%d", len(told)-len(remaining), len(told))
		} else if err == nil {
			st.RecoverDownMin = 0
		}
		if st.OperatorNotified {
			if cfg.notifyOperator("Recovered", fmt.Sprintf("p.stonn is back after about %.0f minutes.", downMin)) {
				st.OperatorNotified = false
			}
		}
		writeState(st)
		log.Print("healthy")
		return nil

	case pollConfigError:
		// We can't READ /status — probably STATUS_TOKEN/URL drift, not an outage.
		// Alert the operator once; do NOT alarm users or start the outage clock.
		log.Print("config error reading /status — not alarming users")
		if !st.ConfigErrorNotified {
			if cfg.notifyOperator("Can't read p.stonn /status — check the watchdog config",
				"The watchdog got a 4xx or unparseable response from /status. This usually means STATUS_TOKEN or STATUS_URL drifted after a p.stonn redeploy — NOT necessarily an outage. Users were NOT alarmed. Please check the watchdog secrets.") {
				st.ConfigErrorNotified = true
			}
		}
		writeState(st)
		return nil
	}

	// pollOutage: unreachable, 5xx, or the scheduler is stalled.
	if st.DownSince == 0 {
		st.DownSince = now.UnixMilli()
	}
	st.RecoverDownMin = 0 // a fresh outage invalidates any half-delivered all-clear
	downMin := sinceMin(st.DownSince, now)
	log.Printf("outage for %.1f min", downMin)

	if !st.OperatorNotified && downMin >= cfg.operatorThresholdMin {
		if cfg.notifyOperator("p.stonn appears down",
			fmt.Sprintf("p.stonn's /status has been unreachable or stalled for about %.0f minutes. From %.0f min, households are alerted as their scheduled changes fall due; everyone is alerted at %.0f min.", downMin, cfg.userThresholdMin, cfg.backstopThresholdMin)) {
			st.OperatorNotified = true
		}
	}
	if downMin >= cfg.userThresholdMin {
		// Targeted, progressive alerting: each run notifies the households whose
		// scheduled change has fallen inside the outage (plus a lead), so a short
		// outage bothers only whom it actually hurt, while a long one reaches each
		// household roughly as it becomes affected. Past the backstop threshold,
		// everyone still untold is told (QR codes are dead at the door by then).
		// Delivery-or-retry per household: an entry joins notified.enc only once a
		// channel accepted, so failures retry next run.
		cached := roster
		if len(cached) == 0 { // roster may be cache-only during the outage
			if r, e := cfg.readRoster(); e == nil {
				cached = r
			}
		}
		told, err := cfg.readNotified()
		if err != nil {
			log.Printf("read notified: %v (treating as none told)", err)
		}
		backstop := downMin >= cfg.backstopThresholdMin
		targets := pickTargets(cached, told, time.UnixMilli(st.DownSince), now,
			time.Duration(cfg.notifyLeadMin)*time.Minute, backstop)
		if len(targets) > 0 {
			reached := 0
			for _, tg := range targets {
				subject, body := outageMessage(tg, downMin, backstop)
				if cfg.sendToEntry(tg, subject, body, "high") {
					told = append(told, tg)
					reached++
				}
			}
			if werr := cfg.writeNotified(told); werr != nil {
				log.Printf("write notified: %v", werr)
			}
			if reached > 0 {
				cfg.notifyOperator("Users alerted", fmt.Sprintf("Outage notice delivered to %d of %d newly affected household(s); %d told in total.", reached, len(targets), len(told)))
			} else {
				// Affected households exist and none could be reached — the user
				// alarm itself is failing, which the operator must know.
				cfg.notifyOperator("COULD NOT ALERT USERS",
					fmt.Sprintf("Tried to alert %d affected household(s) but reached none (delivery failing). Will retry.", len(targets)))
			}
		}
	}
	writeState(st)
	return nil
}

// pickTargets selects who to tell about the outage THIS run: roster entries not
// yet told whose stamped next change falls inside [downStart, now+lead] — their
// write has been missed or is about to be — or, once backstop is set, everyone
// still untold. An unparseable stamp counts as affected (fail toward warning);
// an EMPTY stamp does not (the app healthily reported nothing due), until the
// backstop sweeps it in.
func pickTargets(roster, told []rosterEntry, downStart, now time.Time, lead time.Duration, backstop bool) []rosterEntry {
	toldSet := make(map[string]bool, len(told))
	for _, r := range told {
		toldSet[r.Email] = true
	}
	var out []rosterEntry
	for _, r := range roster {
		if toldSet[r.Email] {
			continue
		}
		include := backstop
		if !include && r.NextChangeAt != "" {
			tc, err := time.Parse(time.RFC3339, r.NextChangeAt)
			if err != nil {
				include = true
			} else {
				include = !tc.Before(downStart) && !tc.After(now.Add(lead))
			}
		}
		if include {
			out = append(out, r)
		}
	}
	return out
}

func sinceMin(unixMillis int64, now time.Time) float64 {
	if unixMillis == 0 {
		return 0
	}
	return float64(now.UnixMilli()-unixMillis) / 60000
}

// poll fetches /status and classifies the outcome.
func poll(cfg config) (pollResult, []rosterEntry) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// Ask for the roster explicitly: once the app has a ROSTER_KEY it omits the
	// roster entirely unless requested, so that its frequent health polls carry
	// nothing sensitive. Older app versions ignore the parameter and include the
	// roster regardless, so this is safe to deploy first.
	pollURL := cfg.statusURL
	if u, perr := url.Parse(pollURL); perr == nil {
		q := u.Query()
		q.Set("roster", "1")
		u.RawQuery = q.Encode()
		pollURL = u.String()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pollURL, nil)
	if err != nil {
		log.Printf("build request: %v", err)
		return pollConfigError, nil
	}
	req.Header.Set("Authorization", "Bearer "+cfg.statusToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("poll unreachable: %v", err)
		return pollOutage, nil // network/timeout = genuine outage
	}
	defer func() { io.Copy(io.Discard, res.Body); res.Body.Close() }()

	switch {
	case res.StatusCode == http.StatusOK:
		// fall through to decode
	case res.StatusCode >= 500:
		log.Printf("status %d — outage", res.StatusCode)
		return pollOutage, nil
	default: // 4xx / 3xx — WE can't read it; treat as our config problem, not an outage
		log.Printf("status %d — config error", res.StatusCode)
		return pollConfigError, nil
	}
	var sr statusResp
	if err := json.NewDecoder(res.Body).Decode(&sr); err != nil {
		log.Printf("decode status: %v — config error", err) // 200 but not our JSON (maintenance/proxy page)
		return pollConfigError, nil
	}
	roster := sr.Roster
	if sr.RosterSealed != "" {
		dec, derr := cfg.openSealedRoster(sr.RosterSealed)
		if derr != nil {
			// Keep polling on the health signal, but say so loudly: we are now blind
			// to new users, and would fall back to a stale cache in an outage.
			log.Printf("decrypt roster: %v — check ROSTER_KEY matches the app's", derr)
		} else {
			roster = dec
		}
	}
	if sr.Scheduler.Stale {
		return pollOutage, roster // reachable but the work loop is wedged
	}
	return pollHealthy, roster
}

// outageMessage composes the per-household outage notice. A household selected
// for its stamped change gets that change named — the specific, actionable
// version ("your midnight change was missed; here's the manual fix") that a
// generic outage blast can't be. The backstop tier (or an unparseable stamp)
// gets the general version, which is the one that must mention QR codes: by
// backstop age, dead activation pages at the kerb are the live risk.
func outageMessage(r rosterEntry, downMin float64, backstop bool) (subject, body string) {
	// Duration stays vague past two hours (operator preference, 2026-08-23):
	// "about 13 hours" reads as a catastrophe announcement, and the reader's
	// action is the same regardless of the number.
	dur := "some time"
	if downMin < 120 {
		dur = fmt.Sprintf("about %.0f minutes", downMin)
	}
	if tc, err := time.Parse(time.RFC3339, r.NextChangeAt); err == nil && !backstop {
		subject = "p.stonn could not make your scheduled permit change"
		body = strings.Join([]string{
			"p.stonn has been unable to update visitor parking permits for " + dur + ".",
			"",
			"Your schedule had a plate change due around " + tc.In(melbourne()).Format("Mon 2 Jan, 3:04pm") + " — that change has NOT been made, so the permit may still show the previous car.",
			"",
			// Sentence ends with a full stop, not a colon: the HTML alternative
			// renders the URL block below as an "Open the council portal" button,
			// and a trailing colon above a button reads as a typo.
			"To be safe, set the vehicle on your permit directly with the City of Stonnington.",
			"",
			councilPortal,
			"",
			"We'll email you when p.stonn is back to normal. Sorry for the trouble.",
		}, "\n")
		return subject, body
	}
	subject = "p.stonn is not updating parking permits right now"
	body = strings.Join([]string{
		"p.stonn has been unable to update visitor parking permits for " + dur + ", so scheduled plate changes and guest QR codes are not working.",
		"",
		"If a visitor is parked (or expected), set the vehicle on your permit directly with the City of Stonnington.",
		"",
		councilPortal,
		"",
		"Printed or shared QR codes won't work until this is resolved — a guest may need you to set their plate at the council site instead.",
		"",
		"We'll email you when p.stonn is back to normal. Sorry for the trouble.",
	}, "\n")
	return subject, body
}

// melbourne is the timezone rosters are written in; change times are shown to
// users in it, never in UTC. The tzdata import keeps this working on a bare
// Actions runner even without system zone files.
func melbourne() *time.Location {
	loc, err := time.LoadLocation("Australia/Melbourne")
	if err != nil {
		return time.UTC // degraded but never wrong by more than the label
	}
	return loc
}

// ---- state ----

func readState() state {
	var s state
	b, err := os.ReadFile(stateFile)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("read state: %v (starting from empty)", err)
		}
		return state{}
	}
	if err := json.Unmarshal(b, &s); err != nil {
		log.Printf("parse state: %v (starting from empty)", err)
		return state{}
	}
	return s
}

func writeState(s state) {
	b, _ := json.MarshalIndent(s, "", "  ")
	if err := os.WriteFile(stateFile, append(b, '\n'), 0o644); err != nil {
		log.Printf("write state: %v", err)
	}
}

// ---- encrypted roster cache ----

func (cfg config) refreshRoster(roster []rosterEntry) {
	if len(roster) == 0 {
		return // guard: don't clobber a good cache with nothing
	}
	// Only rewrite when the content changed: the random nonce makes every
	// encryption differ, which would otherwise churn the cache each run.
	if cur, err := cfg.readRoster(); err == nil && sameRoster(cur, roster) {
		return
	}
	if err := cfg.writeRoster(roster); err != nil {
		log.Printf("write roster: %v", err)
	}
}

func (cfg config) writeRoster(roster []rosterEntry) error {
	return cfg.writeSealedJSON(rosterFile, roster)
}

func (cfg config) readRoster() ([]rosterEntry, error) {
	var roster []rosterEntry
	err := cfg.readSealedJSON(rosterFile, &roster)
	return roster, err
}

// readNotified returns who has been told about the current outage. A missing
// file is simply "no one yet" — the normal healthy state — not an error; so is
// the empty placeholder the workflow's cache-save `touch` leaves behind.
func (cfg config) readNotified() ([]rosterEntry, error) {
	b, err := os.ReadFile(notifiedFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if strings.TrimSpace(string(b)) == "" {
		return nil, nil
	}
	var told []rosterEntry
	err = cfg.readSealedJSON(notifiedFile, &told)
	return told, err
}

// writeNotified records who has been told (full entries, not just emails: the
// all-clear needs their ntfy topics too). An empty list is written as such —
// the file's continued presence is harmless and keeps the cache step simple.
func (cfg config) writeNotified(told []rosterEntry) error {
	if told == nil {
		told = []rosterEntry{}
	}
	return cfg.writeSealedJSON(notifiedFile, told)
}

// writeSealedJSON / readSealedJSON are the at-rest encryption for everything
// this program persists that carries PII: AES-256-GCM under ROSTER_KEY,
// base64(nonce || ciphertext || tag), one line per file.
func (cfg config) writeSealedJSON(path string, v any) error {
	pt, err := json.Marshal(v)
	if err != nil {
		return err
	}
	gcm, err := cfg.gcm()
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	sealed := gcm.Seal(nonce, nonce, pt, nil)
	return os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(sealed)+"\n"), 0o644)
}

func (cfg config) readSealedJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return err
	}
	gcm, err := cfg.gcm()
	if err != nil {
		return err
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return fmt.Errorf("%s: sealed file too short", path)
	}
	pt, err := gcm.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return err
	}
	return json.Unmarshal(pt, v)
}

// openSealedRoster decrypts the roster the app sent over the wire. Same format as
// the on-disk cache below: base64(nonce || ciphertext || tag) under ROSTER_KEY.
func (cfg config) openSealedRoster(sealed string) ([]rosterEntry, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sealed))
	if err != nil {
		return nil, err
	}
	gcm, err := cfg.gcm()
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return nil, fmt.Errorf("sealed roster too short")
	}
	pt, err := gcm.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return nil, err
	}
	var out []rosterEntry
	if err := json.Unmarshal(pt, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (cfg config) gcm() (cipher.AEAD, error) {
	block, err := aes.NewCipher(cfg.rosterKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func sameRoster(a, b []rosterEntry) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

// ---- delivery ----

// sendToEntry delivers one message to one household on every channel they have,
// reporting whether at least one channel accepted — the bar for counting them
// as told (or, on recovery, as given the all-clear).
func (cfg config) sendToEntry(r rosterEntry, subject, body, priority string) bool {
	ok := false
	if r.Email != "" {
		if e := cfg.sendEmail(r.Email, subject, body); e != nil {
			log.Printf("email %s: %v", r.Email, e)
		} else {
			ok = true
		}
	}
	if r.Ntfy != "" {
		if e := cfg.sendNtfy(r.Ntfy, subject, body, priority); e != nil {
			log.Printf("ntfy %s: %v", r.Ntfy, e)
		} else {
			ok = true
		}
	}
	return ok
}

// notifyOperator returns true if at least one operator channel accepted.
func (cfg config) notifyOperator(subject, body string) bool {
	subject = "[p.stonn watchdog] " + subject
	ok := false
	if cfg.adminEmail != "" {
		if e := cfg.sendEmail(cfg.adminEmail, subject, body); e != nil {
			log.Printf("operator email: %v", e)
		} else {
			ok = true
		}
	}
	if cfg.adminTopic != "" {
		if e := cfg.sendNtfy(cfg.adminTopic, subject, body, "high"); e != nil {
			log.Printf("operator ntfy: %v", e)
		} else {
			ok = true
		}
	}
	return ok
}

// headerValue strips CR/LF so a value can't inject extra email headers.
func headerValue(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

func (cfg config) sendEmail(to, subject, body string) error {
	if cfg.sesHost == "" {
		return errors.New("email channel not configured") // NOT a silent success
	}
	// multipart/alternative: the plain text (always shown by text-only clients)
	// plus a branded HTML part matching the app. Both base64-encoded so long
	// inline-styled HTML lines can't trip the SMTP line-length limit.
	var b strings.Builder
	b.WriteString(strings.Join([]string{
		"From: " + headerValue(cfg.mailFrom),
		"To: " + headerValue(to),
		"Subject: " + headerValue(subject),
		"MIME-Version: 1.0",
		`Content-Type: multipart/alternative; boundary="` + emailBoundary + `"`,
	}, "\r\n"))
	b.WriteString("\r\n\r\n")
	b.WriteString("--" + emailBoundary + "\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
	b.WriteString(b64Wrap(body) + "\r\n")
	b.WriteString("--" + emailBoundary + "\r\n")
	b.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
	b.WriteString(b64Wrap(htmlDocument(subject, body)) + "\r\n")
	b.WriteString("--" + emailBoundary + "--\r\n")
	msg := b.String()
	addr := cfg.sesHost + ":" + cfg.sesPort
	auth := smtp.PlainAuth("", cfg.sesUser, cfg.sesPass, cfg.sesHost)
	from := senderAddress(cfg.mailFrom)
	if cfg.sesPort == "465" { // implicit TLS — smtp.SendMail only does STARTTLS
		return sendImplicitTLS(addr, cfg.sesHost, auth, from, to, []byte(msg))
	}
	return smtp.SendMail(addr, auth, from, []string{to}, []byte(msg))
}

// sendImplicitTLS handles SMTPS (port 465), which net/smtp.SendMail does not.
func sendImplicitTLS(addr, host string, auth smtp.Auth, from, to string, msg []byte) error {
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: host})
	if err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Auth(auth); err != nil {
		return err
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// senderAddress extracts the bare address from "Name <a@b>".
func senderAddress(from string) string {
	if i := strings.LastIndex(from, "<"); i >= 0 {
		if j := strings.Index(from[i:], ">"); j >= 0 {
			return strings.TrimSpace(from[i+1 : i+j])
		}
	}
	return strings.TrimSpace(from)
}

func (cfg config) sendNtfy(topic, title, body, priority string) error {
	if cfg.ntfyBase == "" || topic == "" {
		return errors.New("ntfy channel not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.ntfyBase+"/"+topic, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Title", headerValue(title))
	req.Header.Set("Priority", priority)
	if cfg.ntfyToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.ntfyToken)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { io.Copy(io.Discard, res.Body); res.Body.Close() }()
	if res.StatusCode >= 300 {
		return fmt.Errorf("ntfy %s: %d", topic, res.StatusCode)
	}
	return nil
}

// ---- config ----

func loadConfig() (config, error) {
	must := func(k string) (string, error) {
		v := strings.TrimSpace(os.Getenv(k))
		if v == "" {
			return "", fmt.Errorf("missing required env %s", k)
		}
		return v, nil
	}
	var cfg config
	var err error
	if cfg.statusURL, err = must("STATUS_URL"); err != nil {
		return cfg, err
	}
	if cfg.statusToken, err = must("STATUS_TOKEN"); err != nil {
		return cfg, err
	}
	keyHex, err := must("ROSTER_KEY")
	if err != nil {
		return cfg, err
	}
	if cfg.rosterKey, err = hex.DecodeString(keyHex); err != nil {
		return cfg, fmt.Errorf("ROSTER_KEY: %w", err)
	}
	if len(cfg.rosterKey) != 32 {
		return cfg, fmt.Errorf("ROSTER_KEY must be 32 bytes (64 hex chars)")
	}
	cfg.userThresholdMin = envFloat("DOWN_THRESHOLD_MIN", 45)
	cfg.operatorThresholdMin = envFloat("OPERATOR_ALERT_MIN", 10)
	cfg.notifyLeadMin = envFloat("NOTIFY_LEAD_MIN", 60)
	cfg.backstopThresholdMin = envFloat("BACKSTOP_ALERT_MIN", 720)
	if cfg.backstopThresholdMin < cfg.userThresholdMin {
		// The backstop is the OUTER net; letting it undercut the targeted tier
		// would turn every blip into a full-roster blast again.
		cfg.backstopThresholdMin = cfg.userThresholdMin
	}
	cfg.ntfyBase = strings.TrimRight(os.Getenv("NTFY_BASE"), "/")
	cfg.ntfyToken = os.Getenv("NTFY_TOKEN")
	cfg.adminEmail = strings.TrimSpace(os.Getenv("ADMIN_EMAIL"))
	cfg.adminTopic = strings.TrimSpace(os.Getenv("ADMIN_NTFY_TOPIC"))
	cfg.sesHost = strings.TrimSpace(os.Getenv("SES_HOST"))
	cfg.sesPort = envDefault("SES_PORT", "587")
	cfg.sesUser = os.Getenv("SES_USER")
	cfg.sesPass = os.Getenv("SES_PASS")
	cfg.mailFrom = strings.TrimSpace(os.Getenv("MAIL_FROM"))

	// A watchdog that can't deliver is worse than none — fail loudly rather than
	// silently marking outages "handled" while telling no one.
	if cfg.sesHost == "" && cfg.ntfyBase == "" {
		return cfg, errors.New("no delivery channel configured: set SES_HOST (+ creds) and/or NTFY_BASE")
	}
	if cfg.sesHost != "" && (cfg.sesUser == "" || cfg.sesPass == "" || cfg.mailFrom == "") {
		return cfg, errors.New("SES_HOST set but SES_USER/SES_PASS/MAIL_FROM missing")
	}
	if cfg.adminEmail == "" && cfg.adminTopic == "" {
		log.Print("warning: no operator alert channel (ADMIN_EMAIL / ADMIN_NTFY_TOPIC) — you won't be told if user delivery fails")
	}
	return cfg, nil
}

func envDefault(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func envFloat(k string, def float64) float64 {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

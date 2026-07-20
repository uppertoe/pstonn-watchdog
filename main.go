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
	"os"
	"strconv"
	"strings"
	"time"
)

// councilPortal is where users are sent to sort their permit out themselves.
const councilPortal = "https://parkingpermits.stonnington.vic.gov.au/"

// State: state.json (outage flags + timer — no PII) is committed to the repo so
// the escalation clock survives a cache miss; roster.enc (the user emails) lives
// ONLY in the Actions cache, gitignored, and is AES-256-GCM encrypted at rest.
const (
	stateDir   = "state"
	stateFile  = "state/state.json"
	rosterFile = "state/roster.enc"
)

type rosterEntry struct {
	Email string `json:"email"`
	Ntfy  string `json:"ntfy,omitempty"`
}

type statusResp struct {
	Scheduler struct {
		Stale bool `json:"stale"`
	} `json:"scheduler"`
	Roster []rosterEntry `json:"roster"`
}

// state persists across runs. DownSince is unix millis of the first failure
// (0 when healthy). The *Notified flags are set ONLY once a message delivered.
type state struct {
	DownSince           int64 `json:"down_since"`
	Notified            bool  `json:"notified"`
	OperatorNotified    bool  `json:"operator_notified"`
	ConfigErrorNotified bool  `json:"config_error_notified"`
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
		if st.Notified { // all-clear to users; only clear the flag once it delivered
			msg := fmt.Sprintf("p.stonn is updating permits again after about %.0f minutes. You don't need to do anything — your schedule has resumed.", downMin)
			if cfg.broadcastToUsers("p.stonn is back to normal", msg, "default") > 0 || len(roster) == 0 {
				st.Notified = false
			}
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
	downMin := sinceMin(st.DownSince, now)
	log.Printf("outage for %.1f min", downMin)

	if !st.OperatorNotified && downMin >= cfg.operatorThresholdMin {
		if cfg.notifyOperator("p.stonn appears down",
			fmt.Sprintf("p.stonn's /status has been unreachable or stalled for about %.0f minutes. Users will be alerted at %.0f min.", downMin, cfg.userThresholdMin)) {
			st.OperatorNotified = true
		}
	}
	if !st.Notified && downMin >= cfg.userThresholdMin {
		reached := cfg.broadcastToUsers("p.stonn may not be updating your parking permit", outageBody(downMin), "high")
		total := len(roster)
		if total == 0 { // roster may be cache-only; count what's actually cached
			if r, e := cfg.readRoster(); e == nil {
				total = len(r)
			}
		}
		if reached > 0 || total == 0 {
			st.Notified = true // delivered to at least one, or nobody to reach — done
			cfg.notifyOperator("Users alerted", fmt.Sprintf("Outage notice delivered to %d of %d users.", reached, total))
		} else {
			// Reached no one though users exist — keep retrying next run, and make
			// sure the operator knows the user alarm is not getting through.
			cfg.notifyOperator("COULD NOT ALERT USERS",
				fmt.Sprintf("Tried to send the outage notice to %d users but reached none (delivery failing). Will retry.", total))
		}
	}
	writeState(st)
	return nil
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.statusURL, nil)
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
	if sr.Scheduler.Stale {
		return pollOutage, sr.Roster // reachable but the work loop is wedged
	}
	return pollHealthy, sr.Roster
}

func outageBody(downMin float64) string {
	return strings.Join([]string{
		fmt.Sprintf("p.stonn has been unable to update visitor parking permits for about %.0f minutes.", downMin),
		"",
		"Your permit may not show the vehicle you scheduled. To be safe, set the vehicle on your permit directly with the City of Stonnington:",
		"",
		councilPortal,
		"",
		"We'll let you know when p.stonn is back to normal. Sorry for the trouble.",
	}, "\n")
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
	pt, err := json.Marshal(roster)
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
	sealed := gcm.Seal(nonce, nonce, pt, nil) // nonce || ciphertext || tag
	return os.WriteFile(rosterFile, []byte(base64.StdEncoding.EncodeToString(sealed)+"\n"), 0o644)
}

func (cfg config) readRoster() ([]rosterEntry, error) {
	b, err := os.ReadFile(rosterFile)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, err
	}
	gcm, err := cfg.gcm()
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return nil, fmt.Errorf("roster cache too short")
	}
	pt, err := gcm.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return nil, err
	}
	var roster []rosterEntry
	return roster, json.Unmarshal(pt, &roster)
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

// broadcastToUsers sends to every roster entry and returns how many were REACHED
// (at least one channel accepted). A reached count of 0 with a non-empty roster
// means nothing got through — the caller must not mark the outage handled.
func (cfg config) broadcastToUsers(subject, body, priority string) int {
	roster, err := cfg.readRoster()
	if err != nil {
		log.Printf("read roster: %v", err)
	}
	reached := 0
	for _, r := range roster {
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
		if ok {
			reached++
		}
	}
	log.Printf("reached %d/%d users", reached, len(roster))
	return reached
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

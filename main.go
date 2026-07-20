// Command pstonn-watchdog is an independent dead-man's switch for p.stonn.
//
// Every run polls p.stonn's /status endpoint. A healthy poll refreshes a cached
// (encrypted) copy of the notify roster. If p.stonn is unreachable or its work
// loop is stalled for long enough, this tells the affected users — from the
// cached roster, since p.stonn itself is the thing that's down — to set their
// permit directly with the council, and pings the operator sooner.
//
// It runs on GitHub Actions (off the p.stonn VPS on purpose) and keeps its state
// in the repo between runs. Standard library only; no secrets live in the code —
// everything comes from the workflow env (GitHub Secrets).
package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

// State lives in the GitHub Actions cache (restored/saved by the workflow), NOT in
// the repo — so the roster (user emails) is never committed to a public repo. It is
// also AES-256-GCM encrypted at rest as defence in depth.
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

// state persists across runs (committed to the repo by the workflow). DownSince
// is unix millis of the first failure, 0 when healthy.
type state struct {
	DownSince        int64 `json:"down_since"`
	Notified         bool  `json:"notified"`
	OperatorNotified bool  `json:"operator_notified"`
}

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

	healthy, roster := poll(cfg)

	if healthy {
		if roster != nil {
			cfg.refreshRoster(roster)
		}
		if st.Notified || st.OperatorNotified {
			downMin := 0.0
			if st.DownSince != 0 {
				downMin = float64(now.UnixMilli()-st.DownSince) / 60000
			}
			msg := fmt.Sprintf("p.stonn is updating permits again after about %.0f minutes. You don't need to do anything — your schedule has resumed.", downMin)
			if st.Notified {
				cfg.broadcastToUsers("p.stonn is back to normal", msg, "default")
			}
			if st.OperatorNotified {
				cfg.notifyOperator("Recovered", msg)
			}
		}
		writeState(state{})
		log.Print("healthy")
		return nil
	}

	// Unhealthy: unreachable, non-2xx, or the scheduler is stalled.
	if st.DownSince == 0 {
		st.DownSince = now.UnixMilli()
	}
	downMin := float64(now.UnixMilli()-st.DownSince) / 60000
	log.Printf("unhealthy for %.1f min", downMin)

	if !st.OperatorNotified && downMin >= cfg.operatorThresholdMin {
		cfg.notifyOperator("p.stonn appears down",
			fmt.Sprintf("p.stonn's /status has been unreachable or stalled for about %.0f minutes. Users will be alerted at %.0f min.", downMin, cfg.userThresholdMin))
		st.OperatorNotified = true
	}
	if !st.Notified && downMin >= cfg.userThresholdMin {
		n := cfg.broadcastToUsers("p.stonn may not be updating your parking permit", outageBody(downMin), "high")
		cfg.notifyOperator("Users alerted", fmt.Sprintf("Sent the outage notice to %d users.", n))
		st.Notified = true
	}
	writeState(st)
	return nil
}

// poll fetches /status and reports whether p.stonn is healthy (reachable AND the
// work loop is running) plus the roster it returned.
func poll(cfg config) (healthy bool, roster []rosterEntry) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.statusURL, nil)
	if err != nil {
		log.Printf("build request: %v", err)
		return false, nil
	}
	req.Header.Set("Authorization", "Bearer "+cfg.statusToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("poll failed: %v", err)
		return false, nil
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		log.Printf("status %d", res.StatusCode)
		return false, nil
	}
	var sr statusResp
	if err := json.NewDecoder(res.Body).Decode(&sr); err != nil {
		log.Printf("decode status: %v", err)
		return false, nil
	}
	return !sr.Scheduler.Stale, sr.Roster
}

func outageBody(downMin float64) string {
	return strings.Join([]string{
		fmt.Sprintf("p.stonn has been unable to update visitor parking permits for about %.0f minutes.", downMin),
		"",
		"Your permit may not show the vehicle you scheduled. To be safe, set the vehicle on your",
		"permit directly with the City of Stonnington:",
		"",
		"  " + councilPortal,
		"",
		"We'll let you know when p.stonn is back to normal. Sorry for the trouble.",
	}, "\n")
}

// ---- state ----

func readState() state {
	var s state
	b, err := os.ReadFile(stateFile)
	if err != nil {
		return state{}
	}
	_ = json.Unmarshal(b, &s)
	return s
}

func writeState(s state) {
	b, _ := json.MarshalIndent(s, "", "  ")
	_ = os.WriteFile(stateFile, append(b, '\n'), 0o644)
}

// ---- encrypted roster cache (repo is public, so it must be encrypted) ----

func (cfg config) refreshRoster(roster []rosterEntry) {
	// Only rewrite when the content changed: the random nonce makes every
	// encryption differ, which would otherwise commit on every run.
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
	block, err := aes.NewCipher(cfg.rosterKey)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
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
	block, err := aes.NewCipher(cfg.rosterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
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

func sameRoster(a, b []rosterEntry) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

// ---- delivery ----

func (cfg config) broadcastToUsers(subject, body, priority string) int {
	roster, err := cfg.readRoster()
	if err != nil {
		log.Printf("read roster: %v", err)
	}
	for _, r := range roster {
		if r.Email != "" {
			if err := cfg.sendEmail(r.Email, subject, body); err != nil {
				log.Printf("email %s: %v", r.Email, err)
			}
		}
		if r.Ntfy != "" {
			if err := cfg.sendNtfy(r.Ntfy, subject, body, priority); err != nil {
				log.Printf("ntfy %s: %v", r.Ntfy, err)
			}
		}
	}
	log.Printf("notified %d users", len(roster))
	return len(roster)
}

func (cfg config) notifyOperator(subject, body string) {
	subject = "[p.stonn watchdog] " + subject
	if cfg.adminEmail != "" {
		if err := cfg.sendEmail(cfg.adminEmail, subject, body); err != nil {
			log.Printf("operator email: %v", err)
		}
	}
	if cfg.adminTopic != "" {
		if err := cfg.sendNtfy(cfg.adminTopic, subject, body, "high"); err != nil {
			log.Printf("operator ntfy: %v", err)
		}
	}
}

// headerValue strips CR/LF so a value can't inject extra email headers.
func headerValue(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

func (cfg config) sendEmail(to, subject, body string) error {
	if cfg.sesHost == "" {
		return nil // email not configured
	}
	msg := strings.Join([]string{
		"From: " + headerValue(cfg.mailFrom),
		"To: " + headerValue(to),
		"Subject: " + headerValue(subject),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		body,
	}, "\r\n")
	addr := cfg.sesHost + ":" + cfg.sesPort
	auth := smtp.PlainAuth("", cfg.sesUser, cfg.sesPass, cfg.sesHost)
	return smtp.SendMail(addr, auth, senderAddress(cfg.mailFrom), []string{to}, []byte(msg))
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
		return nil
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

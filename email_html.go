package main

import (
	"encoding/base64"
	"html"
	"regexp"
	"strings"
)

// Branded HTML alternative for the watchdog's outage/restore emails, matching the
// p.stonn app: a white card on slate, teal wordmark + accent rule, a button for a
// standalone URL (the council portal), and an unofficial-tool footer. Stdlib only,
// so the watchdog keeps its zero-dependency guarantee. Email-safe: table layout,
// inline styles, system fonts, no remote assets.

const (
	colBg      = "#eceff5"
	colCard    = "#ffffff"
	colLine    = "#e4e8f0"
	colInk     = "#0f1729"
	colMuted   = "#5b6675"
	colPrimary = "#0d9488"
	colOnPrim  = "#ffffff"
	emailFont  = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif"
	// emailBoundary separates the plain and HTML MIME parts. Fixed token is fine:
	// both parts are base64-encoded, so it can never appear inside a body.
	emailBoundary = "==_pstonn_alt_b19c7f42a8=="
)

var (
	standaloneURL = regexp.MustCompile(`^https?://\S+$`)
	inlineURL     = regexp.MustCompile(`https?://[^\s<>()]+`)
	blankLine     = regexp.MustCompile(`\n[ \t]*\n`)
)

func htmlDocument(subject, body string) string {
	var b strings.Builder
	b.WriteString(`<!doctype html><html><head><meta charset="utf-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width,initial-scale=1">`)
	b.WriteString(`<title>` + html.EscapeString(subject) + `</title></head>`)
	b.WriteString(`<body style="margin:0;padding:0;background:` + colBg + `;">`)
	b.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:` + colBg + `;"><tr><td align="center" style="padding:24px 12px;">`)
	b.WriteString(`<table role="presentation" width="560" cellpadding="0" cellspacing="0" style="width:100%;max-width:560px;">`)
	b.WriteString(`<tr><td style="background:` + colCard + `;border:1px solid ` + colLine + `;border-radius:14px;padding:28px 30px;font-family:` + emailFont + `;">`)
	b.WriteString(`<div style="font-size:21px;font-weight:700;letter-spacing:-0.02em;color:` + colInk + `;">p<span style="color:` + colPrimary + `;">.</span>stonn</div>`)
	b.WriteString(`<div style="height:3px;width:46px;background:` + colPrimary + `;border-radius:2px;margin:14px 0 22px;"></div>`)
	b.WriteString(bodyToHTML(body))
	b.WriteString(`</td></tr>`)
	b.WriteString(`<tr><td style="padding:18px 30px;text-align:center;font-family:` + emailFont + `;font-size:12px;line-height:1.5;color:` + colMuted + `;">`)
	b.WriteString(`p<span style="color:` + colPrimary + `;">.</span>stonn — a free, unofficial tool. Not affiliated with the City of Stonnington.`)
	b.WriteString(`</td></tr></table></td></tr></table></body></html>`)
	return b.String()
}

func bodyToHTML(body string) string {
	body = strings.ReplaceAll(body, "\r\n", "\n")
	var out strings.Builder
	for _, blk := range blankLine.Split(strings.TrimSpace(body), -1) {
		blk = strings.TrimSpace(blk)
		if blk == "" {
			continue
		}
		lines := strings.Split(blk, "\n")
		last := strings.TrimSpace(lines[len(lines)-1])
		if !standaloneURL.MatchString(last) {
			out.WriteString(paragraph(blk))
			continue
		}
		lead := strings.TrimSpace(strings.Join(lines[:len(lines)-1], "\n"))
		label := urlLabel(last)
		if strings.HasSuffix(lead, ":") {
			leadLines := strings.Split(lead, "\n")
			label = strings.TrimRight(strings.TrimSpace(leadLines[len(leadLines)-1]), ":")
			lead = strings.TrimSpace(strings.Join(leadLines[:len(leadLines)-1], "\n"))
		}
		if lead != "" {
			out.WriteString(paragraph(lead))
		}
		out.WriteString(button(last, label))
	}
	return out.String()
}

func urlLabel(u string) string {
	switch {
	case strings.Contains(u, "stonn.org"):
		return "Open p.stonn"
	case strings.Contains(u, "stonnington"):
		return "Open the council portal"
	default:
		return "Open link"
	}
}

func paragraph(s string) string {
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		lines[i] = linkify(ln)
	}
	return `<p style="margin:0 0 14px;font-size:15px;line-height:1.6;color:` + colInk + `;">` +
		strings.Join(lines, "<br>") + `</p>`
}

func linkify(line string) string {
	var b strings.Builder
	last := 0
	for _, loc := range inlineURL.FindAllStringIndex(line, -1) {
		b.WriteString(html.EscapeString(line[last:loc[0]]))
		u := line[loc[0]:loc[1]]
		b.WriteString(`<a href="` + html.EscapeString(u) + `" style="color:` + colPrimary + `;text-decoration:underline;word-break:break-all;">` + html.EscapeString(u) + `</a>`)
		last = loc[1]
	}
	b.WriteString(html.EscapeString(line[last:]))
	return b.String()
}

func button(url, label string) string {
	return `<table role="presentation" cellpadding="0" cellspacing="0" style="margin:4px 0 18px;"><tr>` +
		`<td style="border-radius:9px;background:` + colPrimary + `;">` +
		`<a href="` + html.EscapeString(url) + `" style="display:inline-block;padding:12px 22px;color:` + colOnPrim + `;font-size:15px;font-weight:600;text-decoration:none;border-radius:9px;">` +
		html.EscapeString(label) + `</a></td></tr></table>`
}

func b64Wrap(s string) string {
	enc := base64.StdEncoding.EncodeToString([]byte(s))
	var out strings.Builder
	for len(enc) > 76 {
		out.WriteString(enc[:76])
		out.WriteString("\r\n")
		enc = enc[76:]
	}
	out.WriteString(enc)
	return out.String()
}

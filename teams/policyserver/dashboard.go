// SPDX-License-Identifier: Apache-2.0

package policyserver

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"sylenix-guard-poc/teams/auditevent"
)

const (
	sessionCookieName = "sylenix_teams_session"
	sessionTTL        = 12 * time.Hour
	displayTime       = "2006-01-02 15:04 UTC"
)

func newSessionKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("cannot create dashboard session key: %w", err)
	}
	return key, nil
}

type dashboardMetric struct {
	Blocks    int
	Approvals int
	Prompts   int
}

type dashboardWindow struct {
	Key              string
	Label            string
	Blocks           int
	Approvals        int
	Prompts          int
	BlocksPerHour    string
	ApprovalsPerHour string
	PromptsPerHour   string
}

type dashboardDeveloper struct {
	Developer string
	LastSeen  string
	Ago       string
	Day       dashboardMetric
	Week      dashboardMetric
}

type dashboardTool struct {
	Tool string
	Day  int
	Week int
}

type dashboardStale struct {
	Developer string
	LastSeen  string
	Ago       string
}

type dashboardPage struct {
	Team        string
	GeneratedAt string
	Windows     []dashboardWindow
	Developers  []dashboardDeveloper
	Tools       []dashboardTool
	Stale       []dashboardStale
}

type developerAggregate struct {
	last time.Time
	day  dashboardMetric
	week dashboardMetric
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	setDashboardHeaders(w)
	switch r.Method {
	case http.MethodGet:
		team, ok := s.sessionTeam(r)
		if !ok {
			s.renderLogin(w, r, "", http.StatusOK)
			return
		}
		s.renderDashboard(w, team)
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil {
			s.renderLogin(w, r, "Could not read the login form.", http.StatusBadRequest)
			return
		}
		team, ok := s.teamForToken(r.PostFormValue("token"))
		if !ok {
			s.renderLogin(w, r, "Invalid team token.", http.StatusUnauthorized)
			return
		}
		s.setSession(w, team)
		http.Redirect(w, r, DashboardAPI, http.StatusSeeOther)
	default:
		w.Header().Set("Allow", "GET, POST")
		s.fail(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use GET or POST")
	}
}

func setDashboardHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func (s *Server) setSession(w http.ResponseWriter, team string) {
	expires := time.Now().Add(sessionTTL)
	payload := team + "|" + strconv.FormatInt(expires.Unix(), 10)
	mac := hmac.New(sha256.New, s.sessionKey)
	_, _ = mac.Write([]byte(payload))
	value := base64.RawURLEncoding.EncodeToString([]byte(payload + "|" + hex.EncodeToString(mac.Sum(nil))))
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) sessionTeam(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return "", false
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 3 {
		return "", false
	}
	team := parts[0]
	expiry, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().After(time.Unix(expiry, 0)) {
		return "", false
	}
	gotMAC, err := hex.DecodeString(parts[2])
	if err != nil {
		return "", false
	}
	mac := hmac.New(sha256.New, s.sessionKey)
	_, _ = mac.Write([]byte(team + "|" + parts[1]))
	if !hmac.Equal(gotMAC, mac.Sum(nil)) {
		return "", false
	}
	if _, ok := s.tokens[team]; !ok {
		return "", false
	}
	return team, true
}

func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, message string, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = loginTemplate.Execute(w, map[string]string{
		"Error": message,
		"Next":  DashboardAPI,
	})
}

func (s *Server) renderDashboard(w http.ResponseWriter, team string) {
	events, err := s.ReadEvents(team)
	if err != nil {
		s.logger.Printf("dashboard rejected team=%s reason=storage", team)
		s.fail(w, http.StatusInternalServerError, "EVENT_READ_FAILED", "cannot read stored events")
		return
	}
	page := buildDashboard(team, events, time.Now().UTC())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := dashboardTemplate.Execute(w, page); err != nil {
		s.logger.Printf("dashboard render failed team=%s", team)
	}
}

func buildDashboard(team string, events []auditevent.Event, now time.Time) dashboardPage {
	dayStart := now.Add(-24 * time.Hour)
	weekStart := now.Add(-7 * 24 * time.Hour)
	page := dashboardPage{
		Team:        team,
		GeneratedAt: now.Format(displayTime),
	}
	dayMetric := dashboardMetric{}
	weekMetric := dashboardMetric{}
	developers := map[string]*developerAggregate{}
	dayTools := map[string]int{}
	weekTools := map[string]int{}

	for _, ev := range events {
		ts, err := time.Parse(time.RFC3339Nano, ev.Timestamp)
		if err != nil {
			continue
		}
		if ts.After(now.Add(5 * time.Minute)) {
			continue
		}
		dev := developers[ev.DeveloperID]
		if dev == nil {
			dev = &developerAggregate{}
			developers[ev.DeveloperID] = dev
		}
		if ts.After(dev.last) {
			dev.last = ts
		}
		blocked := ev.Decision == "block"
		prompt := ev.ReasonCode == "APPROVAL_GRANTED" || ev.ReasonCode == "APPROVAL_DENIED"
		approved := ev.ReasonCode == "APPROVAL_GRANTED"
		inDay := !ts.Before(dayStart)
		inWeek := !ts.Before(weekStart)
		if inWeek {
			if blocked {
				weekMetric.Blocks++
				dev.week.Blocks++
				if ev.Tool != "" {
					weekTools[ev.Tool]++
				}
			}
			if approved {
				weekMetric.Approvals++
				dev.week.Approvals++
			}
			if prompt {
				weekMetric.Prompts++
				dev.week.Prompts++
			}
		}
		if inDay {
			if blocked {
				dayMetric.Blocks++
				dev.day.Blocks++
				if ev.Tool != "" {
					dayTools[ev.Tool]++
				}
			}
			if approved {
				dayMetric.Approvals++
				dev.day.Approvals++
			}
			if prompt {
				dayMetric.Prompts++
				dev.day.Prompts++
			}
		}
	}

	page.Windows = []dashboardWindow{
		makeWindow("24h", "Last 24 hours", dayMetric, 24),
		makeWindow("7d", "Last 7 days", weekMetric, 7*24),
	}

	devNames := make([]string, 0, len(developers))
	for name := range developers {
		devNames = append(devNames, name)
	}
	sort.Slice(devNames, func(i, j int) bool {
		a, b := developers[devNames[i]], developers[devNames[j]]
		if a.week.Blocks != b.week.Blocks {
			return a.week.Blocks > b.week.Blocks
		}
		if a.day.Blocks != b.day.Blocks {
			return a.day.Blocks > b.day.Blocks
		}
		return devNames[i] < devNames[j]
	})
	staleCutoff := now.Add(-24 * time.Hour)
	for _, name := range devNames {
		agg := developers[name]
		row := dashboardDeveloper{
			Developer: name,
			LastSeen:  formatEventTime(agg.last),
			Ago:       ago(now, agg.last),
			Day:       agg.day,
			Week:      agg.week,
		}
		page.Developers = append(page.Developers, row)
		if agg.last.Before(staleCutoff) {
			page.Stale = append(page.Stale, dashboardStale{
				Developer: name,
				LastSeen:  row.LastSeen,
				Ago:       row.Ago,
			})
		}
	}

	toolNames := map[string]bool{}
	for name := range dayTools {
		toolNames[name] = true
	}
	for name := range weekTools {
		toolNames[name] = true
	}
	toolList := make([]string, 0, len(toolNames))
	for name := range toolNames {
		toolList = append(toolList, name)
	}
	sort.Slice(toolList, func(i, j int) bool {
		ai, aj := weekTools[toolList[i]], weekTools[toolList[j]]
		if ai != aj {
			return ai > aj
		}
		di, dj := dayTools[toolList[i]], dayTools[toolList[j]]
		if di != dj {
			return di > dj
		}
		return toolList[i] < toolList[j]
	})
	if len(toolList) > 10 {
		toolList = toolList[:10]
	}
	for _, name := range toolList {
		page.Tools = append(page.Tools, dashboardTool{Tool: name, Day: dayTools[name], Week: weekTools[name]})
	}
	return page
}

func makeWindow(key, label string, m dashboardMetric, hours float64) dashboardWindow {
	return dashboardWindow{
		Key:              key,
		Label:            label,
		Blocks:           m.Blocks,
		Approvals:        m.Approvals,
		Prompts:          m.Prompts,
		BlocksPerHour:    fmt.Sprintf("%.2f", float64(m.Blocks)/hours),
		ApprovalsPerHour: fmt.Sprintf("%.2f", float64(m.Approvals)/hours),
		PromptsPerHour:   fmt.Sprintf("%.2f", float64(m.Prompts)/hours),
	}
}

func formatEventTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format(displayTime)
}

func ago(now, then time.Time) string {
	if then.IsZero() {
		return "never"
	}
	d := now.Sub(then)
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

const loginHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in · Sylenix Teams</title>
<style>
:root { color-scheme: light dark; --bg:#f6f7f9; --panel:#fff; --text:#14181f; --muted:#5f6b7a; --line:#d9dee6; --accent:#0b6bcb; --bad:#b42318; }
@media (prefers-color-scheme: dark) { :root { --bg:#10141a; --panel:#171d25; --text:#e8edf4; --muted:#9aa7b6; --line:#2c3541; --accent:#6fb3ff; --bad:#ff8a80; } }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }
main { max-width:26rem; margin:12vh auto; padding:2rem; background:var(--panel); border:1px solid var(--line); border-radius:12px; }
h1 { margin:0 0 .35rem; font-size:1.35rem; }
p { margin:0 0 1.25rem; color:var(--muted); }
label { display:block; font-weight:600; margin-bottom:.4rem; }
input { width:100%; padding:.7rem .8rem; border:1px solid var(--line); border-radius:8px; background:var(--bg); color:var(--text); font:inherit; }
button { margin-top:1rem; width:100%; padding:.75rem; border:0; border-radius:8px; background:var(--accent); color:#fff; font:inherit; font-weight:700; cursor:pointer; }
.error { color:var(--bad); font-weight:600; margin:0 0 1rem; }
</style>
</head>
<body>
<main>
<h1>Sylenix Teams</h1>
<p>Sign in with the team API token to view the audit dashboard.</p>
{{if .Error}}<p class="error">{{.Error}}</p>{{end}}
<form method="post" action="{{.Next}}">
<label for="token">Team token</label>
<input id="token" name="token" type="password" autocomplete="current-password" required autofocus>
<button type="submit">Sign in</button>
</form>
</main>
</body>
</html>`

const dashboardHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Audit dashboard · {{.Team}}</title>
<style>
:root { color-scheme: light dark; --bg:#f6f7f9; --panel:#fff; --text:#14181f; --muted:#5f6b7a; --line:#d9dee6; --accent:#0b6bcb; --warn:#9a3412; }
@media (prefers-color-scheme: dark) { :root { --bg:#10141a; --panel:#171d25; --text:#e8edf4; --muted:#9aa7b6; --line:#2c3541; --accent:#6fb3ff; --warn:#ffb27a; } }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:15px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }
header { padding:1.2rem 1.5rem; border-bottom:1px solid var(--line); background:var(--panel); }
header h1 { margin:0; font-size:1.35rem; }
header p { margin:.25rem 0 0; color:var(--muted); }
main { max-width:74rem; margin:0 auto; padding:1.5rem; display:grid; gap:1.5rem; }
section { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:1.1rem; overflow:auto; }
h2 { margin:0 0 .8rem; font-size:1.05rem; }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(20rem,1fr)); gap:1.5rem; padding:0; border:0; background:transparent; overflow:visible; }
.card { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:1.1rem; }
.metrics { display:grid; grid-template-columns:repeat(3,1fr); gap:.7rem; }
.metric { border:1px solid var(--line); border-radius:8px; padding:.7rem; }
.metric span { display:block; color:var(--muted); font-size:.8rem; text-transform:uppercase; letter-spacing:.04em; }
.metric strong { display:block; font-size:1.5rem; }
.metric small { color:var(--muted); }
table { width:100%; border-collapse:collapse; font-variant-numeric:tabular-nums; }
th, td { text-align:left; padding:.45rem .55rem; border-bottom:1px solid var(--line); white-space:nowrap; }
th { color:var(--muted); font-size:.78rem; text-transform:uppercase; letter-spacing:.04em; }
td.num, th.num { text-align:right; }
.muted { color:var(--muted); }
.stale { color:var(--warn); font-weight:600; }
footer { color:var(--muted); font-size:.85rem; text-align:center; padding:0 1.5rem 2rem; }
</style>
</head>
<body>
<header>
<h1>Audit dashboard</h1>
<p>Team {{.Team}} · generated {{.GeneratedAt}} · last 24 hours and last 7 days</p>
</header>
<main>
<section class="cards">
{{range .Windows}}
<article class="card">
<h2>{{.Label}}</h2>
<div class="metrics">
<div class="metric" data-window="{{.Key}}" data-metric="blocks" data-value="{{.Blocks}}"><span>Blocks</span><strong>{{.Blocks}}</strong><small>{{.BlocksPerHour}}/h</small></div>
<div class="metric" data-window="{{.Key}}" data-metric="approvals" data-value="{{.Approvals}}"><span>Approvals</span><strong>{{.Approvals}}</strong><small>{{.ApprovalsPerHour}}/h</small></div>
<div class="metric" data-window="{{.Key}}" data-metric="prompts" data-value="{{.Prompts}}"><span>Prompts</span><strong>{{.Prompts}}</strong><small>{{.PromptsPerHour}}/h</small></div>
</div>
</article>
{{end}}
</section>

<section>
<h2>Per developer</h2>
<table>
<thead><tr><th>Developer / machine</th><th>Last event</th><th class="num">24h blocks</th><th class="num">24h approvals</th><th class="num">24h prompts</th><th class="num">7d blocks</th><th class="num">7d approvals</th><th class="num">7d prompts</th></tr></thead>
<tbody>
{{range .Developers}}
<tr data-developer="{{.Developer}}"><td>{{.Developer}}</td><td>{{.LastSeen}} <span class="muted">({{.Ago}})</span></td><td class="num">{{.Day.Blocks}}</td><td class="num">{{.Day.Approvals}}</td><td class="num">{{.Day.Prompts}}</td><td class="num">{{.Week.Blocks}}</td><td class="num">{{.Week.Approvals}}</td><td class="num">{{.Week.Prompts}}</td></tr>
{{else}}
<tr><td colspan="8" class="muted">No events stored for this team.</td></tr>
{{end}}
</tbody>
</table>
</section>

<section>
<h2>Top blocked tools</h2>
<table>
<thead><tr><th>Tool</th><th class="num">24h blocks</th><th class="num">7d blocks</th></tr></thead>
<tbody>
{{range .Tools}}
<tr data-tool="{{.Tool}}"><td>{{.Tool}}</td><td class="num">{{.Day}}</td><td class="num">{{.Week}}</td></tr>
{{else}}
<tr><td colspan="3" class="muted">No blocked tool calls in the last 7 days.</td></tr>
{{end}}
</tbody>
</table>
</section>

<section>
<h2>Machines not reporting in 24h</h2>
{{if .Stale}}
<table>
<thead><tr><th>Developer / machine</th><th>Last event</th><th>Last seen</th></tr></thead>
<tbody>
{{range .Stale}}
<tr data-stale="{{.Developer}}"><td class="stale">{{.Developer}}</td><td>{{.LastSeen}}</td><td>{{.Ago}}</td></tr>
{{end}}
</tbody>
</table>
{{else}}
<p class="muted">All known machines reported in the last 24 hours.</p>
{{end}}
</section>
</main>
<footer>Only sanitized event fields are shown. Argument values, content, URLs and tool output are never stored or rendered.</footer>
</body>
</html>`

var (
	loginTemplate     = template.Must(template.New("login").Parse(loginHTML))
	dashboardTemplate = template.Must(template.New("dashboard").Parse(dashboardHTML))
)

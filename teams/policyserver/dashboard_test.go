// SPDX-License-Identifier: Apache-2.0

package policyserver_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"sylenix-guard-poc/teams/auditevent"
	"sylenix-guard-poc/teams/policyserver"
)

func dashboardEvent(ts time.Time, developer, tool, decision, reason, taint string) auditevent.Event {
	return auditevent.Event{
		Timestamp:   ts.UTC().Format(time.RFC3339Nano),
		DeveloperID: developer,
		Server:      "demo",
		Tool:        tool,
		Decision:    decision,
		ReasonCode:  reason,
		TaintState:  taint,
	}
}

func TestDashboardRendersFromTestDataWithTokenLogin(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := policyserver.New(policyserver.Config{
		DataDir:   t.TempDir(),
		PublicKey: pub,
		Tokens:    map[string]string{"acme": policyserver.HashToken("correct-token")},
		Logger:    log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	events := []auditevent.Event{
		dashboardEvent(now.Add(-1*time.Hour), "machine-a", "write_file", "block", "TAINT_SINK", "tainted"),
		dashboardEvent(now.Add(-2*time.Hour), "machine-a", "write_file", "allow", "APPROVAL_GRANTED", "tainted"),
		dashboardEvent(now.Add(-3*time.Hour), "machine-a", "http_post", "block", "EGRESS_TARGET", "tainted"),
		dashboardEvent(now.Add(-4*time.Hour), "machine-a", "write_file", "deny", "APPROVAL_DENIED", "tainted"),
		dashboardEvent(now.Add(-30*time.Hour), "machine-a", "old_tool", "block", "TAINT_SINK", "tainted"),
		dashboardEvent(now.Add(-48*time.Hour), "machine-b", "old_tool", "block", "TAINT_SINK", "tainted"),
		dashboardEvent(now.Add(-10*time.Minute), "machine-c", "read_ticket", "allow", "ALLOW", "clean"),
		dashboardEvent(now.Add(-5*time.Hour), `<script>alert(1)</script>`, `<i>tool</i>`, "block", "SENSITIVE_TARGET", "tainted"),
	}
	if err := srv.AppendEvents("acme", events); err != nil {
		t.Fatal(err)
	}
	httpSrv := httptest.NewTLSServer(srv)
	defer httpSrv.Close()
	client := &http.Client{
		Transport: httpSrv.Client().Transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	dashboardURL := httpSrv.URL + policyserver.DashboardAPI

	// No session: the page is a login form, not data.
	resp, err := client.Get(dashboardURL)
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `name="token"`) || !strings.Contains(body, `type="password"`) {
		t.Fatalf("login page: code=%d body=%s", resp.StatusCode, body)
	}
	if strings.Contains(body, `data-tool=`) {
		t.Fatal("login page rendered dashboard data without authentication")
	}

	// Wrong token is rejected without a session cookie.
	resp, err = client.PostForm(dashboardURL, url.Values{"token": {"wrong-token"}})
	if err != nil {
		t.Fatal(err)
	}
	body = readBody(t, resp)
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(body, "Invalid team token") || len(resp.Cookies()) != 0 {
		t.Fatalf("wrong-token login: code=%d cookies=%v body=%s", resp.StatusCode, resp.Cookies(), body)
	}

	// Correct token sets an HttpOnly, Secure, SameSite=Strict session cookie.
	resp, err = client.PostForm(dashboardURL, url.Values{"token": {"correct-token"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != policyserver.DashboardAPI {
		t.Fatalf("login redirect: code=%d location=%q", resp.StatusCode, resp.Header.Get("Location"))
	}
	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("login cookies: %v", cookies)
	}
	cookie := cookies[0]
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode || cookie.Value == "" {
		t.Fatalf("session cookie flags: %+v", cookie)
	}

	req, err := http.NewRequest(http.MethodGet, dashboardURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body = readBody(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("dashboard: code=%d content-type=%q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("dashboard CSP missing: %q", resp.Header.Get("Content-Security-Policy"))
	}
	for _, want := range []string{
		`data-window="24h" data-metric="blocks" data-value="3"`,
		`data-window="24h" data-metric="approvals" data-value="1"`,
		`data-window="24h" data-metric="prompts" data-value="2"`,
		`data-window="7d" data-metric="blocks" data-value="5"`,
		`data-window="7d" data-metric="approvals" data-value="1"`,
		`data-window="7d" data-metric="prompts" data-value="2"`,
		`data-developer="machine-a"`,
		`data-developer="machine-b"`,
		`data-developer="machine-c"`,
		`data-tool="old_tool"`,
		`data-stale="machine-b"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard missing %q", want)
		}
	}
	if strings.Contains(body, `data-stale="machine-a"`) || strings.Contains(body, `data-stale="machine-c"`) {
		t.Fatal("active machine listed as stale")
	}
	if strings.Contains(body, `<script>`) || strings.Contains(body, `<i>tool</i>`) {
		t.Fatal("dashboard did not escape developer/tool text")
	}
	if !strings.Contains(body, `&lt;script&gt;alert(1)&lt;/script&gt;`) || !strings.Contains(body, `&lt;i&gt;tool&lt;/i&gt;`) {
		t.Fatal("dashboard did not render escaped developer/tool text")
	}
	if strings.Contains(body, "<script") || strings.Contains(body, "<link") || strings.Contains(body, "http://") || strings.Contains(body, "https://") || strings.Contains(body, "cdn.") {
		t.Fatal("dashboard references an external script, stylesheet or CDN")
	}
	const argumentMarker = "SECRET-ARGUMENT-VALUE"
	if strings.Contains(body, argumentMarker) {
		t.Fatal("dashboard leaked an argument value")
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

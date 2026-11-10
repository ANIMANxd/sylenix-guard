// SPDX-License-Identifier: Apache-2.0

package policyserver_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/csv"
	"fmt"
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

func TestExportCSVAndPDFMatchDashboard(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
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
	}
	if err := srv.AppendEvents("acme", events); err != nil {
		t.Fatal(err)
	}
	policy1 := []byte("version: 1\nservers:\n  demo:\n    tools:\n      write_file:\n        class: read\n")
	policy2 := []byte("version: 1\nservers:\n  demo:\n    tools:\n      write_file:\n        class: exec\n")
	if err := srv.WriteStored("acme", policy1, ed25519.Sign(priv, policy1)); err != nil {
		t.Fatal(err)
	}
	if err := srv.WriteStored("acme", policy2, ed25519.Sign(priv, policy2)); err != nil {
		t.Fatal(err)
	}
	history, err := srv.ReadPolicyHistory("acme")
	if err != nil || len(history) != 2 {
		t.Fatalf("policy history: %v %+v", err, history)
	}

	httpSrv := httptest.NewTLSServer(srv)
	defer httpSrv.Close()
	client := httpSrv.Client()
	from := now.Add(-24 * time.Hour).Format(time.RFC3339)
	to := now.Add(time.Minute).Format(time.RFC3339)
	query := url.Values{"from": {from}, "to": {to}}.Encode()
	get := func(path string, token string) (*http.Response, []byte) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, httpSrv.URL+path+"?"+query, nil)
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp, body
	}

	resp, _ := get(policyserver.CSVExportAPI, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("CSV without token: %d", resp.StatusCode)
	}
	resp, csvBody := get(policyserver.CSVExportAPI, "correct-token")
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/csv") {
		t.Fatalf("CSV export: code=%d content-type=%q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	rows, err := csv.NewReader(bytes.NewReader(csvBody)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 6 { // header + five events in the 24h range
		t.Fatalf("CSV rows: got %d, want 6: %s", len(rows), csvBody)
	}
	wantHeader := []string{"timestamp", "developer_id", "server", "tool", "decision", "reason_code", "taint_state"}
	for i := range wantHeader {
		if rows[0][i] != wantHeader[i] {
			t.Fatalf("CSV header: %v", rows[0])
		}
	}
	const argumentMarker = "EXPORT-SECRET-ARGUMENT-VALUE"
	if strings.Contains(string(csvBody), argumentMarker) || strings.Contains(string(csvBody), ",arguments") || strings.Contains(string(csvBody), ",content") {
		t.Fatalf("CSV export contains argument-like content: %s", csvBody)
	}

	resp, pdfBody := get(policyserver.PDFExportAPI, "correct-token")
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/pdf" {
		t.Fatalf("PDF export: code=%d content-type=%q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if !bytes.HasPrefix(pdfBody, []byte("%PDF-1.4")) || !bytes.Contains(pdfBody, []byte("%%EOF")) {
		t.Fatalf("PDF is not a PDF: %q", pdfBody[:min(len(pdfBody), 80)])
	}
	for _, want := range []string{
		"Sylenix Guard Audit Evidence Summary",
		"Events: 5",
		"Blocks: 2",
		"Approvals: 1",
		"Prompts: 2",
		"Machines covered: 2",
		"Blocks by reason",
		"TAINT_SINK",
		"Policy version history",
		"Mapping to DPDP security safeguards",
		"to be reviewed by counsel",
		"safeguards",
		"compliance",
		history[1].SHA256[:16],
	} {
		if !bytes.Contains(pdfBody, []byte(want)) {
			t.Fatalf("PDF missing %q", want)
		}
	}
	if bytes.Contains(pdfBody, []byte(argumentMarker)) {
		t.Fatal("PDF export leaked an argument value")
	}

	// The dashboard's 24h cards must agree with the export summary.
	dashboardClient := &http.Client{
		Transport: client.Transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	loginResp, err := dashboardClient.PostForm(httpSrv.URL+policyserver.DashboardAPI, url.Values{"token": {"correct-token"}})
	if err != nil {
		t.Fatal(err)
	}
	loginResp.Body.Close()
	if len(loginResp.Cookies()) != 1 {
		t.Fatal("dashboard login did not issue a session")
	}
	dashReq, _ := http.NewRequest(http.MethodGet, httpSrv.URL+policyserver.DashboardAPI, nil)
	dashReq.AddCookie(loginResp.Cookies()[0])
	dashResp, err := dashboardClient.Do(dashReq)
	if err != nil {
		t.Fatal(err)
	}
	pageBody, _ := io.ReadAll(dashResp.Body)
	dashResp.Body.Close()
	page := string(pageBody)
	for metric, value := range map[string]string{"blocks": "2", "approvals": "1", "prompts": "2"} {
		attr := fmt.Sprintf(`data-window="24h" data-metric="%s" data-value="%s"`, metric, value)
		if !strings.Contains(page, attr) {
			t.Fatalf("dashboard does not match export: missing %q", attr)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

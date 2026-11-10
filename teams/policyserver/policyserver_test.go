// SPDX-License-Identifier: Apache-2.0

package policyserver_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sylenix-guard-poc/teams/auditevent"
	"sylenix-guard-poc/teams/policyserver"
)

func TestTokenFileStoresHashesOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens")
	token := "high-entropy-token"
	hash := policyserver.HashToken(token)
	if err := os.WriteFile(path, []byte("# comment\n\nacme:"+hash+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tokens, err := policyserver.LoadTokenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if tokens["acme"] != hash {
		t.Fatalf("hash mismatch: %v", tokens)
	}
	if strings.Contains(hash, token) {
		t.Fatal("token hash must not contain the plaintext token")
	}

	for name, body := range map[string]string{
		"plaintext": "acme:" + token + "\n",
		"duplicate": "acme:" + hash + "\nacme:" + hash + "\n",
		"badhex":    "acme:not-a-hash\n",
		"notoken":   "acme:\n",
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := policyserver.LoadTokenFile(path); err == nil {
				t.Fatalf("accepted invalid token file %q", body)
			}
		})
	}
}

func TestServerAuthenticatesAndVerifiesSignatures(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	srv, err := policyserver.New(policyserver.Config{
		DataDir:   dir,
		PublicKey: pub,
		Tokens:    map[string]string{"acme": policyserver.HashToken("correct-token")},
		Logger:    log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	httpSrv := httptest.NewTLSServer(srv)
	defer httpSrv.Close()
	endpoint := httpSrv.URL + policyserver.APIPath

	policy := []byte("version: 1\napproval: deny\n")
	sig := ed25519.Sign(priv, policy)
	body, err := policyserver.EncodeEnvelope(policy, sig)
	if err != nil {
		t.Fatal(err)
	}

	do := func(method, token string, body []byte) *http.Response {
		t.Helper()
		req, err := http.NewRequest(method, endpoint, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := httpSrv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	resp := do(http.MethodGet, "", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET without token: %d", resp.StatusCode)
	}
	resp = do(http.MethodPut, "wrong-token", body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("PUT with wrong token: %d", resp.StatusCode)
	}

	tampered := append([]byte(nil), policy...)
	tampered[0] ^= 1
	resp = do(http.MethodPut, "correct-token", mustEnvelope(t, tampered, sig))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("PUT tampered policy: %d", resp.StatusCode)
	}

	resp = do(http.MethodPut, "correct-token", body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT valid policy: %d", resp.StatusCode)
	}

	resp = do(http.MethodGet, "correct-token", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET valid policy: %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	gotPolicy, gotSig, err := policyserver.DecodeEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPolicy, policy) || !bytes.Equal(gotSig, sig) {
		t.Fatal("server returned different policy or signature")
	}

	// A byte changed on disk but a valid signature file left behind must not be
	// served as valid policy.
	stored := filepath.Join(dir, "policy-acme.yaml")
	disk, err := os.ReadFile(stored)
	if err != nil {
		t.Fatal(err)
	}
	disk[0] ^= 1
	if err := os.WriteFile(stored, disk, 0o600); err != nil {
		t.Fatal(err)
	}
	resp = do(http.MethodGet, "correct-token", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("GET tampered stored policy: %d", resp.StatusCode)
	}
}

func mustEnvelope(t *testing.T, policy, sig []byte) []byte {
	t.Helper()
	body, err := policyserver.EncodeEnvelope(policy, sig)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestCollectorStoresExportsAndRejectsArguments(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	srv, err := policyserver.New(policyserver.Config{
		DataDir:   dir,
		PublicKey: pub,
		Tokens:    map[string]string{"acme": policyserver.HashToken("correct-token")},
		Logger:    log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	httpSrv := httptest.NewTLSServer(srv)
	defer httpSrv.Close()
	endpoint := httpSrv.URL + policyserver.EventsAPI
	syslogEndpoint := httpSrv.URL + policyserver.SyslogAPI

	ev := auditevent.Event{
		Timestamp:   time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
		DeveloperID: "dev-01",
		Server:      "demo",
		Tool:        "write_file",
		Decision:    "block",
		ReasonCode:  "TAINT_SINK",
		TaintState:  "tainted",
	}
	body, err := json.Marshal([]auditevent.Event{ev})
	if err != nil {
		t.Fatal(err)
	}
	post := func(payload []byte, token string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := httpSrv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	resp := post(body, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("event POST without token: %d", resp.StatusCode)
	}
	resp = post(body, "correct-token")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("event POST: %d", resp.StatusCode)
	}

	secret := "SECRET-ARGUMENT-MUST-NOT-APPEAR"
	bad := []byte(`[{"timestamp":"2026-11-10T12:00:00Z","developer_id":"dev-01","server":"demo","tool":"write_file","decision":"block","reason_code":"TAINT_SINK","taint_state":"tainted","arguments":{"content":"` + secret + `"}}]`)
	resp = post(bad, "correct-token")
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("event batch with arguments: %d", resp.StatusCode)
	}

	get := func(url string) (int, string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer correct-token")
		resp, err := httpSrv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(raw)
	}
	code, exported := get(endpoint)
	if code != http.StatusOK || !strings.Contains(exported, `"reason_code":"TAINT_SINK"`) {
		t.Fatalf("JSON export: code=%d body=%s", code, exported)
	}
	if strings.Contains(exported, secret) {
		t.Fatalf("JSON export leaked an argument value: %s", exported)
	}
	var events []auditevent.Event
	if err := json.Unmarshal([]byte(exported), &events); err != nil || len(events) != 1 {
		t.Fatalf("JSON export did not contain exactly one event: %v %s", err, exported)
	}
	code, syslog := get(syslogEndpoint)
	if code != http.StatusOK || !strings.HasPrefix(syslog, "<132>1 ") {
		t.Fatalf("syslog export: code=%d body=%s", code, syslog)
	}
	if !strings.Contains(syslog, `developer_id="dev-01"`) || !strings.Contains(syslog, `reason_code="TAINT_SINK"`) {
		t.Fatalf("syslog export missing fields: %s", syslog)
	}
	if strings.Contains(syslog, secret) {
		t.Fatalf("syslog export leaked an argument value: %s", syslog)
	}
	stored, err := os.ReadFile(filepath.Join(dir, "events-acme.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored), secret) {
		t.Fatalf("stored events leaked an argument value: %s", stored)
	}
}

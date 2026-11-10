// SPDX-License-Identifier: Apache-2.0

package policyserver_test

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sylenix-guard-poc/teams/auditevent"
	"sylenix-guard-poc/teams/policyserver"
)

const (
	teamName = "team"
	token    = "test-team-token-0123456789"
	interval = 150 * time.Millisecond
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type toggleHandler struct {
	next    http.Handler
	offline atomic.Bool
}

func (h *toggleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.offline.Load() {
		http.Error(w, "offline", http.StatusServiceUnavailable)
		return
	}
	h.next.ServeHTTP(w, r)
}

type guardProc struct {
	t      *testing.T
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	lines  chan []byte
	stderr *syncBuffer
	nextID int
}

func startGuard(t *testing.T, args ...string) *guardProc {
	t.Helper()
	binary := guardBinary(t)
	cmd := exec.Command(binary, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := &syncBuffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &guardProc{t: t, cmd: cmd, stdin: stdin, lines: make(chan []byte, 32), stderr: stderr, nextID: 1}
	go func() {
		r := bufio.NewReader(stdout)
		for {
			line, err := r.ReadBytes('\n')
			if len(line) > 0 {
				p.lines <- line
			}
			if err != nil {
				close(p.lines)
				return
			}
		}
	}()
	t.Cleanup(func() { p.close() })
	return p
}

func (p *guardProc) send(obj any) {
	p.t.Helper()
	data, err := json.Marshal(obj)
	if err != nil {
		p.t.Fatal(err)
	}
	if _, err := p.stdin.Write(append(data, '\n')); err != nil {
		p.t.Fatalf("write to guard: %v\nstderr: %s", err, p.stderr.String())
	}
}

func (p *guardProc) recv(timeout time.Duration) map[string]any {
	p.t.Helper()
	select {
	case line, ok := <-p.lines:
		if !ok {
			p.t.Fatalf("guard closed stdout\nstderr: %s", p.stderr.String())
		}
		var obj map[string]any
		if err := json.Unmarshal(line, &obj); err != nil {
			p.t.Fatalf("guard emitted non-JSON %q: %v", strings.TrimSpace(string(line)), err)
		}
		return obj
	case <-time.After(timeout):
		p.t.Fatalf("timed out waiting for guard reply\nstderr: %s", p.stderr.String())
		return nil
	}
}

func (p *guardProc) request(method string, params any) map[string]any {
	p.t.Helper()
	id := p.nextID
	p.nextID++
	msg := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		msg["params"] = params
	}
	p.send(msg)
	return p.recv(10 * time.Second)
}

func (p *guardProc) initialize() {
	p.t.Helper()
	reply := p.request("initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "team-integration", "version": "0"},
	})
	if reply["result"] == nil {
		p.t.Fatalf("initialize failed: %v\nstderr: %s", reply, p.stderr.String())
	}
	p.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	reply = p.request("tools/list", nil)
	if reply["result"] == nil {
		p.t.Fatalf("tools/list failed: %v\nstderr: %s", reply, p.stderr.String())
	}
}

func (p *guardProc) call(name string, args map[string]any) map[string]any {
	p.t.Helper()
	return p.request("tools/call", map[string]any{"name": name, "arguments": args})
}

func (p *guardProc) close() {
	if p.cmd == nil || p.cmd.Process == nil {
		return
	}
	_ = p.stdin.Close()
	done := make(chan struct{})
	go func() {
		_ = p.cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = p.cmd.Process.Kill()
		<-done
	}
	p.cmd = nil
}

func rule(reply map[string]any) string {
	errObj, _ := reply["error"].(map[string]any)
	data, _ := errObj["data"].(map[string]any)
	rule, _ := data["rule"].(string)
	return rule
}

func guardBinary(t *testing.T) string {
	t.Helper()
	if path := os.Getenv("SYLENIX_GUARD"); path != "" {
		return path
	}
	root := repoRoot(t)
	name := "sylenix-guard"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(root, "bin", name)
	if _, err := os.Stat(path); err == nil {
		return path
	}
	cmd := exec.Command("go", "build", "-o", path, "./cmd/sylenix-guard")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build guard: %v\n%s", err, out)
	}
	return path
}

func teamsBinary(t *testing.T) string {
	t.Helper()
	if path := os.Getenv("SYLENIX_TEAMS"); path != "" {
		return path
	}
	root := repoRoot(t)
	name := "sylenix-teams"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(root, "bin", name)
	if _, err := os.Stat(path); err == nil {
		return path
	}
	cmd := exec.Command("go", "build", "-o", path, "./teams/cmd/sylenix-teams")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build teams binary: %v\n%s", err, out)
	}
	return path
}

func runWithInput(t *testing.T, input string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			t.Fatalf("run %v: %v\n%s", args, err, out)
		}
	}
	code := 0
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	return string(out), code
}

func pythonExe(t *testing.T) string {
	t.Helper()
	if path := os.Getenv("SYLENIX_PYTHON"); path != "" {
		return path
	}
	for _, name := range []string{"python3", "python"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	t.Fatal("python3 or python is required for the integration test")
	return ""
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate repository root")
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(file)))
}

func writeFile(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func policyYAML(writeClass string) string {
	return fmt.Sprintf(`version: 1
approval: deny
servers:
  demo:
    tools:
      read_ticket:
        class: read
      write_file:
        class: %s
      noisy:
        class: write
`, writeClass)
}

func localOverlay(escape string) string {
	return fmt.Sprintf(`version: 1
approval: dialog
spotlight: false
egress:
  allow_hosts:
    - "evil.example.com"
servers:
  demo:
    tools:
      read_ticket:
        class: read
        trust: true
      write_file:
        class: read
      noisy:
        class: write
        allow_paths:
          - %q
`, escape)
}

func signPolicy(t *testing.T, priv ed25519.PrivateKey, policy string) ([]byte, []byte) {
	t.Helper()
	raw := []byte(policy)
	return raw, ed25519.Sign(priv, raw)
}

func putPolicy(t *testing.T, client *http.Client, endpoint string, token string, policy, sig []byte) int {
	t.Helper()
	body, err := policyserver.EncodeEnvelope(policy, sig)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func auditText(t *testing.T, state string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(state, "audit-demo.jsonl"))
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func waitFor(t *testing.T, timeout time.Duration, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestTeamPolicyIntegration(t *testing.T) {
	root := repoRoot(t)
	fake := filepath.Join(root, "demo", "fake_server.py")
	py := pythonExe(t)
	tmp := t.TempDir()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(tmp, "team.pub")
	writeFile(t, pubPath, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})))
	tokenPath := filepath.Join(tmp, "team.token")
	writeFile(t, tokenPath, token+"\n")
	if out, code := runWithInput(t, token, teamsBinary(t), "token", "hash", "--team", teamName); code != 0 ||
		strings.TrimSpace(out) != teamName+":"+policyserver.HashToken(token) {
		t.Fatalf("token hash CLI: code=%d out=%q", code, out)
	}
	localPath := filepath.Join(tmp, "local.yaml")
	writeFile(t, localPath, localOverlay(filepath.Join(tmp, "escape")))

	dataDir := filepath.Join(tmp, "server-data")
	srv, err := policyserver.New(policyserver.Config{
		DataDir:   dataDir,
		PublicKey: pub,
		Tokens:    map[string]string{teamName: policyserver.HashToken(token)},
		Logger:    log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	httpsSrv := httptest.NewTLSServer(srv)
	defer httpsSrv.Close()
	endpoint := httpsSrv.URL + policyserver.APIPath
	caPath := filepath.Join(tmp, "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: httpsSrv.Certificate().Raw})
	writeFile(t, caPath, string(caPEM))

	// Authentication and signed publication happen before any Guard starts.
	noToken, err := httpsSrv.Client().Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	noToken.Body.Close()
	if noToken.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET without token: got %d, want 401", noToken.StatusCode)
	}
	v1Policy, v1Sig := signPolicy(t, priv, policyYAML("read"))
	if code := putPolicy(t, httpsSrv.Client(), endpoint, "wrong-token", v1Policy, v1Sig); code != http.StatusUnauthorized {
		t.Fatalf("PUT with wrong token: got %d, want 401", code)
	}
	tampered := append([]byte(nil), v1Policy...)
	tampered[0] ^= 1
	if code := putPolicy(t, httpsSrv.Client(), endpoint, token, tampered, v1Sig); code != http.StatusBadRequest {
		t.Fatalf("PUT with tampered policy: got %d, want 400", code)
	}
	if code := putPolicy(t, httpsSrv.Client(), endpoint, token, v1Policy, v1Sig); code != http.StatusOK {
		t.Fatalf("PUT v1: got %d, want 200", code)
	}

	var guards []*guardProc
	states := []string{}
	for i := 0; i < 3; i++ {
		state := filepath.Join(tmp, fmt.Sprintf("guard-%d", i))
		states = append(states, state)
		g := startGuard(t,
			"--name", "demo",
			"--state-dir", state,
			"--team-url", endpoint,
			"--team-token-file", tokenPath,
			"--team-pubkey", pubPath,
			"--team-ca", caPath,
			"--team-interval", interval.String(),
			"--policy", localPath,
			"--readonly", "write_file,read_ticket",
			"--trust", "read_ticket",
			"--no-spotlight",
			"--grant", "write_file=15m",
			"--", py, fake,
		)
		guards = append(guards, g)
		g.initialize()
		waitFor(t, 2*time.Second, "team_policy_loaded", func() bool {
			return strings.Contains(auditText(t, state), `"event":"team_policy_loaded"`)
		})
	}

	// v1 makes write_file read-only, so a tainted call is forwarded.
	for i, g := range guards {
		read := g.call("read_ticket", map[string]any{"ticket_id": 7})
		if read["result"] == nil {
			t.Fatalf("guard %d read_ticket failed: %v", i, read)
		}
		write := g.call("write_file", map[string]any{"path": "note.txt", "content": "x"})
		if write["result"] == nil {
			t.Fatalf("guard %d write_file under v1 was not allowed: %v\n%s", i, write, auditText(t, states[i]))
		}
	}

	// Publish a stricter policy and require every Guard to apply it within one
	// pull interval (with a small scheduling allowance).
	v2Policy, v2Sig := signPolicy(t, priv, policyYAML("exec"))
	v2Path := filepath.Join(tmp, "v2.yaml")
	writeFile(t, v2Path, string(v2Policy))
	writeFile(t, v2Path+".sig", string(v2Sig))
	if out, code := runWithInput(t, "",
		teamsBinary(t), "publish",
		"--url", endpoint,
		"--policy", v2Path,
		"--token-file", tokenPath,
		"--ca", caPath,
		"--pubkey", pubPath,
	); code != 0 {
		t.Fatalf("publish v2 via CLI: code=%d out=%s", code, out)
	}
	start := time.Now()
	for i, g := range guards {
		guardIndex := i
		waitFor(t, 3*interval+500*time.Millisecond, fmt.Sprintf("guard %d to apply v2", i), func() bool {
			reply := g.call("write_file", map[string]any{"path": "note.txt", "content": "x"})
			if rule(reply) == "TAINT_SINK" {
				return true
			}
			if reply["result"] == nil {
				t.Fatalf("guard %d unexpected reply while waiting for v2: %v", guardIndex, reply)
			}
			return false
		})
	}
	if elapsed := time.Since(start); elapsed > 3*interval+time.Second {
		t.Fatalf("policy change took %s, more than one pull plus allowance", elapsed)
	}
	for i, state := range states {
		text := auditText(t, state)
		if !strings.Contains(text, `"event":"team_policy_reloaded"`) {
			t.Fatalf("guard %d did not record team_policy_reloaded: %s", i, text)
		}
		if !strings.Contains(text, `"event":"team_policy_loosen_ignored"`) {
			t.Fatalf("guard %d did not record ignored local loosening: %s", i, text)
		}
		for _, field := range []string{"approval", "spotlight", "egress.allow_hosts", "servers.demo.tools.write_file.class", "servers.demo.tools.noisy.allow_paths", "servers.demo.tools.read_ticket.trust"} {
			if !strings.Contains(text, field) {
				t.Fatalf("guard %d ignored-event missing %q: %s", i, field, text)
			}
		}
	}

	// A tampered policy on the server is rejected and the last good policy
	// remains in force.
	stored := filepath.Join(dataDir, "policy-team.yaml")
	original, err := os.ReadFile(stored)
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), original...)
	bad[len(bad)/2] ^= 1
	if err := os.WriteFile(stored, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	before := make([]int, len(states))
	for i, state := range states {
		before[i] = strings.Count(auditText(t, state), `"event":"team_policy_rejected"`)
	}
	for i, state := range states {
		guardIndex := i
		waitFor(t, 3*interval+500*time.Millisecond, fmt.Sprintf("guard %d to reject tampered policy", i), func() bool {
			return strings.Count(auditText(t, state), `"event":"team_policy_rejected"`) > before[guardIndex]
		})
	}
	for i, g := range guards {
		reply := g.call("write_file", map[string]any{"path": "note.txt", "content": "x"})
		if rule(reply) != "TAINT_SINK" {
			t.Fatalf("guard %d lost the last good policy after tamper: %v", i, reply)
		}
	}

	// Restore the signed pair, then close the running Guards before taking the
	// service offline.
	if code := putPolicy(t, httpsSrv.Client(), endpoint, token, v2Policy, v2Sig); code != http.StatusOK {
		t.Fatalf("restore v2: got %d, want 200", code)
	}
	for _, g := range guards {
		g.close()
	}

	// Cache: with the service offline, a Guard with a verified cache starts and
	// keeps the cached policy. With no cache, or a tampered cache, it refuses.
	httpsSrv.Close()
	cacheState := states[0]
	cached := startGuard(t,
		"--name", "demo",
		"--state-dir", cacheState,
		"--team-url", endpoint,
		"--team-token-file", tokenPath,
		"--team-pubkey", pubPath,
		"--team-ca", caPath,
		"--team-interval", interval.String(),
		"--policy", localPath,
		"--readonly", "write_file,read_ticket",
		"--trust", "read_ticket",
		"--no-spotlight",
		"--grant", "write_file=15m",
		"--", py, fake,
	)
	cached.initialize()
	waitFor(t, 2*time.Second, "cache source", func() bool {
		return strings.Contains(auditText(t, cacheState), `"source":"cache"`)
	})
	read := cached.call("read_ticket", map[string]any{"ticket_id": 7})
	if read["result"] == nil {
		t.Fatalf("cached Guard read_ticket failed: %v", read)
	}
	write := cached.call("write_file", map[string]any{"path": "note.txt", "content": "x"})
	if rule(write) != "TAINT_SINK" {
		t.Fatalf("cached Guard did not keep v2: %v", write)
	}
	cached.close()

	noCacheState := filepath.Join(tmp, "no-cache")
	out, code := runGuardOnce(t, 10*time.Second,
		"--name", "demo",
		"--state-dir", noCacheState,
		"--team-url", endpoint,
		"--team-token-file", tokenPath,
		"--team-pubkey", pubPath,
		"--team-ca", caPath,
		"--team-interval", interval.String(),
		"--", py, fake,
	)
	if code != 2 || !strings.Contains(strings.ToLower(out), "cached") {
		t.Fatalf("no-cache Guard: code=%d out=%s", code, out)
	}

	cacheFile := filepath.Join(cacheState, "team-policy-demo.yaml")
	cacheBytes, err := os.ReadFile(cacheFile)
	if err != nil {
		t.Fatal(err)
	}
	cacheBytes[0] ^= 1
	if err := os.WriteFile(cacheFile, cacheBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	out, code = runGuardOnce(t, 10*time.Second,
		"--name", "demo",
		"--state-dir", cacheState,
		"--team-url", endpoint,
		"--team-token-file", tokenPath,
		"--team-pubkey", pubPath,
		"--team-ca", caPath,
		"--team-interval", interval.String(),
		"--policy", localPath,
		"--", py, fake,
	)
	if code != 2 || !strings.Contains(strings.ToLower(out), "cached") {
		t.Fatalf("tampered-cache Guard: code=%d out=%s", code, out)
	}

	// Plain HTTP is refused before any request is made.
	out, code = runGuardOnce(t, 10*time.Second,
		"--name", "demo",
		"--state-dir", filepath.Join(tmp, "http-refused"),
		"--team-url", "http://127.0.0.1:1/v1/policy",
		"--team-token-file", tokenPath,
		"--team-pubkey", pubPath,
		"--", py, fake,
	)
	if code != 2 || !strings.Contains(strings.ToLower(out), "https") {
		t.Fatalf("plain-HTTP Guard: code=%d out=%s", code, out)
	}
}

func TestAuditEventsFromThreeGuardsAndOfflineBuffer(t *testing.T) {
	root := repoRoot(t)
	fake := filepath.Join(root, "demo", "fake_server.py")
	py := pythonExe(t)
	tmp := t.TempDir()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(tmp, "team.token")
	writeFile(t, tokenPath, token+"\n")
	policyPath := filepath.Join(tmp, "policy.yaml")
	writeFile(t, policyPath, policyYAML("exec"))

	dataDir := filepath.Join(tmp, "collector-data")
	srv, err := policyserver.New(policyserver.Config{
		DataDir:   dataDir,
		PublicKey: pub,
		Tokens:    map[string]string{teamName: policyserver.HashToken(token)},
		Logger:    log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	toggle := &toggleHandler{next: srv}
	httpsSrv := httptest.NewTLSServer(toggle)
	defer httpsSrv.Close()
	caPath := filepath.Join(tmp, "ca.pem")
	writeFile(t, caPath, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: httpsSrv.Certificate().Raw})))
	eventsEndpoint := httpsSrv.URL + policyserver.EventsAPI
	syslogEndpoint := httpsSrv.URL + policyserver.SyslogAPI

	fetchExport := func() string {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, eventsEndpoint, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := httpsSrv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("event export: %d %s", resp.StatusCode, raw)
		}
		return string(raw)
	}
	parseExport := func(raw string) []auditevent.Event {
		t.Helper()
		var events []auditevent.Event
		if err := json.Unmarshal([]byte(raw), &events); err != nil {
			t.Fatalf("event export is not JSON: %v %s", err, raw)
		}
		return events
	}
	countBlocks := func(events []auditevent.Event, developer, tool string) int {
		n := 0
		for _, ev := range events {
			if ev.DeveloperID == developer && ev.Tool == tool && ev.Decision == "block" && ev.ReasonCode == "TAINT_SINK" {
				n++
			}
		}
		return n
	}
	countStoredBlocks := func(developer, tool string) int {
		t.Helper()
		stored, err := srv.ReadEvents(teamName)
		if err != nil {
			t.Fatal(err)
		}
		return countBlocks(stored, developer, tool)
	}

	var guards []*guardProc
	states := []string{}
	marker := "AUDIT-SECRET-ARGUMENT-" + fmt.Sprint(time.Now().UnixNano())
	for i := 0; i < 3; i++ {
		state := filepath.Join(tmp, fmt.Sprintf("audit-guard-%d", i))
		states = append(states, state)
		g := startGuard(t,
			"--name", "demo",
			"--state-dir", state,
			"--audit-url", eventsEndpoint,
			"--audit-token-file", tokenPath,
			"--audit-ca", caPath,
			"--audit-id", fmt.Sprintf("guard-%d", i),
			"--audit-interval", "100ms",
			"--audit-batch", "50",
			"--policy", policyPath,
			"--", py, fake,
		)
		guards = append(guards, g)
		g.initialize()
		if read := g.call("read_ticket", map[string]any{"ticket_id": 7}); read["result"] == nil {
			t.Fatalf("guard %d read_ticket failed: %v", i, read)
		}
		if write := g.call("write_file", map[string]any{"path": "note.txt", "content": marker}); rule(write) != "TAINT_SINK" {
			t.Fatalf("guard %d write_file was not blocked: %v", i, write)
		}
	}

	waitFor(t, 5*time.Second, "three Guards' block events", func() bool {
		events := parseExport(fetchExport())
		for i := 0; i < 3; i++ {
			if countBlocks(events, fmt.Sprintf("guard-%d", i), "write_file") < 1 {
				return false
			}
		}
		return true
	})
	exported := fetchExport()
	events := parseExport(exported)
	for i := 0; i < 3; i++ {
		developer := fmt.Sprintf("guard-%d", i)
		found := false
		for _, ev := range events {
			if ev.DeveloperID == developer && ev.Tool == "write_file" && ev.Decision == "block" {
				found = true
				if ev.Server != "demo" || ev.ReasonCode != "TAINT_SINK" || ev.TaintState != "tainted" {
					t.Fatalf("guard %d event has wrong fields: %+v", i, ev)
				}
			}
		}
		if !found {
			t.Fatalf("guard %d event missing from export", i)
		}
	}
	if strings.Contains(exported, marker) {
		t.Fatalf("event export leaked an argument value: %s", exported)
	}
	req, _ := http.NewRequest(http.MethodGet, syslogEndpoint, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := httpsSrv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	syslogRaw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(syslogRaw), "<132>1 ") || !strings.Contains(string(syslogRaw), `reason_code="TAINT_SINK"`) {
		t.Fatalf("syslog export: %d %s", resp.StatusCode, syslogRaw)
	}
	if strings.Contains(string(syslogRaw), marker) {
		t.Fatalf("syslog export leaked an argument value: %s", syslogRaw)
	}
	for i, state := range states {
		raw, err := os.ReadFile(filepath.Join(state, "audit-outbox-demo.jsonl"))
		if err != nil {
			t.Fatalf("guard %d outbox: %v", i, err)
		}
		if strings.Contains(string(raw), marker) {
			t.Fatalf("guard %d outbox leaked an argument value: %s", i, raw)
		}
	}

	// Offline: the collector returns 503, the Guard must keep the event on disk
	// and then deliver it after the collector returns.
	waitFor(t, 2*time.Second, "guard-0 outbox to drain", func() bool {
		raw, err := os.ReadFile(filepath.Join(states[0], "audit-outbox-demo.jsonl"))
		return err == nil && len(bytes.TrimSpace(raw)) == 0
	})
	time.Sleep(150 * time.Millisecond) // let any acknowledged batch settle
	before := countStoredBlocks("guard-0", "noisy")
	toggle.offline.Store(true)
	time.Sleep(250 * time.Millisecond)
	offlineMarker := marker + "-OFFLINE"
	if write := guards[0].call("noisy", map[string]any{"path": "offline.txt", "content": offlineMarker}); rule(write) != "TAINT_SINK" {
		t.Fatalf("offline noisy call was not blocked: %v", write)
	}
	waitFor(t, 2*time.Second, "offline event in outbox", func() bool {
		raw, err := os.ReadFile(filepath.Join(states[0], "audit-outbox-demo.jsonl"))
		return err == nil && strings.Contains(string(raw), `"reason_code":"TAINT_SINK"`) && strings.Contains(string(raw), `"tool":"noisy"`)
	})
	offlineRaw, err := os.ReadFile(filepath.Join(states[0], "audit-outbox-demo.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(offlineRaw), offlineMarker) {
		t.Fatalf("offline outbox leaked an argument value: %s", offlineRaw)
	}
	if got := countStoredBlocks("guard-0", "noisy"); got != before {
		t.Fatalf("offline event reached the collector: before=%d after=%d", before, got)
	}
	toggle.offline.Store(false)
	waitFor(t, 5*time.Second, "buffered event after collector returns", func() bool {
		return countStoredBlocks("guard-0", "noisy") > before
	})
	for _, g := range guards {
		g.close()
	}
}

func runGuardOnce(t *testing.T, timeout time.Duration, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(guardBinary(t), args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("guard did not exit within %s: %s", timeout, buf.String())
	}
	code := 0
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	return buf.String(), code
}

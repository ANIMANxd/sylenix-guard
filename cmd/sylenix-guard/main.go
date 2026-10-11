// Sylenix Guard POC: a transparent stdio wrapper for one MCP server.
//
//	sylenix-guard [flags] -- <server command> [args...]
//
// What it does: pins tool definitions (trust on first use), latches session
// taint when untrusted content comes back from a tool, blocks every tool that
// is not on the read-only list once the session is tainted, and can ask a human
// through an OS dialog instead of blocking. Standard library only.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
)

const maxFrame = 10 << 20 // 10 MB per JSON-RPC line

type frame map[string]json.RawMessage

type pendingReq struct {
	method string
	tool   string
}

type Guard struct {
	name      string
	stateDir  string
	readonly  map[string]bool // tools allowed even when the session is tainted
	trust     map[string]bool // tools whose results do not taint the session
	approve   string          // "deny" or "dialog"
	spotlight bool

	mu          sync.Mutex
	tainted     bool
	taintOrigin string
	pending     map[string]pendingReq
	pins        map[string]string
	quarantined map[string]string

	outMu sync.Mutex // serializes every write to the host's stdout
	out   io.Writer

	logMu sync.Mutex
	log   *os.File
}

func main() {
	name := flag.String("name", "", "label for this server; names the pin and log files (default: command name)")
	stateDir := flag.String("state-dir", "", "directory for pins and the audit log (default ~/.sylenix-poc)")
	readonly := flag.String("readonly", "", "comma-separated tools that stay allowed when the session is tainted")
	trust := flag.String("trust", "", "comma-separated tools whose results do NOT taint the session")
	approve := flag.String("approve", "deny", "what to do with a blocked call: deny | dialog")
	noSpot := flag.Bool("no-spotlight", false, "do not datamark untrusted tool results")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: sylenix-guard [flags] -- <server command> [args...]")
		os.Exit(2)
	}
	if *approve != "deny" && *approve != "dialog" {
		fmt.Fprintln(os.Stderr, "sylenix-guard: --approve must be deny or dialog")
		os.Exit(2)
	}
	if *name == "" {
		*name = filepath.Base(args[0])
	}
	if *stateDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, "sylenix-guard: cannot find home directory; pass --state-dir")
			os.Exit(2)
		}
		*stateDir = filepath.Join(home, ".sylenix-poc")
	}
	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard:", err)
		os.Exit(2)
	}
	logf, err := os.OpenFile(filepath.Join(*stateDir, "audit-"+*name+".jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard:", err)
		os.Exit(2)
	}

	g := &Guard{
		name:        *name,
		stateDir:    *stateDir,
		readonly:    toSet(*readonly),
		trust:       toSet(*trust),
		approve:     *approve,
		spotlight:   !*noSpot,
		pending:     map[string]pendingReq{},
		pins:        map[string]string{},
		quarantined: map[string]string{},
		out:         os.Stdout,
		log:         logf,
	}
	g.loadPins()

	cmd := exec.Command(args[0], args[1:]...)
	childIn, err := cmd.StdinPipe()
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard:", err)
		os.Exit(1)
	}
	childOut, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard:", err)
		os.Exit(1)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard: cannot start server:", err)
		os.Exit(1)
	}
	g.event("start", map[string]any{"command": args[0], "readonly": sortedKeys(g.readonly), "trust": sortedKeys(g.trust), "approve": g.approve})

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		_ = cmd.Process.Kill()
		os.Exit(1)
	}()

	// Host -> server. Every tools/call is checked before it is forwarded.
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 64*1024), maxFrame)
		for sc.Scan() {
			line := append([]byte(nil), sc.Bytes()...)
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			forward, reply := g.fromHost(line)
			if reply != nil {
				g.write(reply)
			}
			if forward {
				_, _ = childIn.Write(append(line, '\n'))
			}
		}
		if err := sc.Err(); err != nil {
			g.event("host_read_error", map[string]any{"error": err.Error()})
		}
		// Host closed stdin: let the server finish, then make sure it exits.
		_ = childIn.Close()
		time.AfterFunc(5*time.Second, func() { _ = cmd.Process.Kill() })
	}()

	// Server -> host. Results are inspected, taint is latched, then forwarded.
	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(childOut)
		sc.Buffer(make([]byte, 64*1024), maxFrame)
		for sc.Scan() {
			line := append([]byte(nil), sc.Bytes()...)
			g.write(g.fromServer(line))
		}
		if err := sc.Err(); err != nil {
			g.event("server_read_error", map[string]any{"error": err.Error()})
		}
	}()

	<-done
	code := 0
	if err := cmd.Wait(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = 1
		}
	}
	g.event("exit", map[string]any{"code": code})
	os.Exit(code)
}

// ---------------------------------------------------------------- host -> server

func (g *Guard) fromHost(line []byte) (forward bool, reply []byte) {
	trim := bytes.TrimSpace(line)
	if len(trim) > 0 && trim[0] == '[' {
		g.event("batch_dropped", nil)
		return false, errorFrame(nil, -32600, "Batch frames are not supported", "BATCH_UNSUPPORTED")
	}
	var f frame
	if err := json.Unmarshal(trim, &f); err != nil {
		g.event("unparseable_host_frame", map[string]any{"bytes": len(line)})
		return false, errorFrame(nil, -32700, "Parse error", "UNPARSEABLE")
	}
	if hasDuplicateKeys(trim) {
		g.event("block", map[string]any{"rule": "DUPLICATE_KEYS"})
		return false, errorFrame(nil, -32600, "Invalid request", "DUPLICATE_KEYS")
	}
	var method string
	_ = json.Unmarshal(f["method"], &method)
	id := f["id"]
	if method == "" {
		return true, nil // a response from the host to a server request
	}
	if method != "tools/call" {
		g.track(id, method, "")
		return true, nil
	}

	var p struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(f["params"], &p); err != nil || p.Name == "" {
		g.event("block", map[string]any{"rule": "UNPARSEABLE_CALL"})
		return false, replyIfRequest(id, -32000, "Blocked by Sylenix Guard", "UNPARSEABLE_CALL")
	}

	g.mu.Lock()
	reason, quarantined := g.quarantined[p.Name]
	tainted, origin := g.tainted, g.taintOrigin
	g.mu.Unlock()

	if quarantined {
		g.event("block", map[string]any{"tool": p.Name, "rule": "MANIFEST_QUARANTINE", "detail": reason})
		alert("tool %q blocked: %s", p.Name, reason)
		return false, replyIfRequest(id, -32001, "Blocked by Sylenix Guard", "MANIFEST_QUARANTINE")
	}
	if !tainted || g.readonly[p.Name] {
		g.event("allow", map[string]any{"tool": p.Name, "tainted": tainted, "arg_keys": argKeys(p.Arguments)})
		g.track(id, method, p.Name)
		return true, nil
	}

	// Tainted session, tool is not read-only: this is a sink. Default deny.
	if g.approve == "dialog" {
		granted, note := askHuman(p.Name, p.Arguments, origin)
		g.event("approval", map[string]any{"tool": p.Name, "granted": granted, "note": note, "arg_keys": argKeys(p.Arguments)})
		if granted {
			g.track(id, method, p.Name)
			return true, nil
		}
		return false, replyIfRequest(id, -32002, "Authorization denied", "APPROVAL_DENIED")
	}
	g.event("block", map[string]any{"tool": p.Name, "rule": "TAINT_SINK", "origin": origin, "arg_keys": argKeys(p.Arguments)})
	alert("tool %q blocked: session tainted by %q", p.Name, origin)
	return false, replyIfRequest(id, -32000, "Blocked by Sylenix Guard", "TAINT_SINK")
}

// ---------------------------------------------------------------- server -> host

func (g *Guard) fromServer(line []byte) []byte {
	trim := bytes.TrimSpace(line)
	if len(trim) == 0 {
		return nil
	}
	var f frame
	if err := json.Unmarshal(trim, &f); err != nil {
		// Not JSON-RPC, so we cannot inspect it. Assume it carries untrusted content.
		g.latch("unparseable_server_output")
		g.event("unparseable_server_frame", map[string]any{"bytes": len(line)})
		return line
	}
	var method string
	_ = json.Unmarshal(f["method"], &method)
	if method != "" { // request or notification from the server
		if len(f["id"]) > 0 {
			g.event("server_request", map[string]any{"method": method})
		}
		return line
	}

	p, ok := g.take(f["id"])
	if !ok {
		g.latch("unmatched_response") // a response to nothing we tracked: assume untrusted
		g.event("unmatched_response", nil)
		return line
	}
	switch p.method {
	case "tools/list":
		g.inspectToolsList(f["result"])
		return line
	case "tools/call", "resources/read", "prompts/get":
		origin := p.tool
		if origin == "" {
			origin = p.method
		}
		if p.method == "tools/call" && g.trust[p.tool] {
			return line
		}
		g.latch(origin) // latch BEFORE the host can see the content
		if g.spotlight && p.method == "tools/call" {
			return g.datamark(f, origin, line)
		}
	}
	return line
}

func (g *Guard) latch(origin string) {
	g.mu.Lock()
	first := !g.tainted
	g.tainted = true
	if first {
		g.taintOrigin = origin
	}
	g.mu.Unlock()
	if first {
		g.event("taint_latched", map[string]any{"origin": origin})
		alert("session tainted by %q; non-read-only tools now need approval", origin)
	}
}

func (g *Guard) datamark(f frame, origin string, orig []byte) []byte {
	var res map[string]json.RawMessage
	if json.Unmarshal(f["result"], &res) != nil {
		return orig
	}
	var content []map[string]any
	if json.Unmarshal(res["content"], &content) != nil {
		return orig
	}
	for _, c := range content {
		if c["type"] != "text" {
			continue
		}
		s, ok := c["text"].(string)
		if !ok {
			continue
		}
		s = strings.ReplaceAll(stripInvisible(s), "</untrusted_tool_result", "</untrusted_tool_result_")
		c["text"] = fmt.Sprintf("<untrusted_tool_result origin=%q integrity=\"untrusted\">\n%s\n</untrusted_tool_result>", origin, s)
	}
	nc, err := json.Marshal(content)
	if err != nil {
		return orig
	}
	res["content"] = nc
	nr, err := json.Marshal(res)
	if err != nil {
		return orig
	}
	f["result"] = nr
	out, err := json.Marshal(f)
	if err != nil {
		return orig
	}
	return out
}

// ---------------------------------------------------------------- manifest pinning

func (g *Guard) inspectToolsList(raw json.RawMessage) {
	var res struct {
		Tools []map[string]any `json:"tools"`
	}
	if json.Unmarshal(raw, &res) != nil {
		return
	}
	changed := false
	g.mu.Lock()
	for _, t := range res.Tools {
		name, _ := t["name"].(string)
		if name == "" {
			continue
		}
		b, _ := json.Marshal(t) // map keys are sorted, so the encoding is stable
		sum := sha256.Sum256(b)
		h := hex.EncodeToString(sum[:])
		old, seen := g.pins[name]

		reason := ""
		switch {
		case hasInvisible(string(b)):
			reason = "hidden characters in tool definition"
		case seen && old != h:
			reason = "definition changed since it was pinned"
		}
		if reason != "" {
			if g.quarantined[name] != reason {
				g.event("tool_quarantined", map[string]any{"tool": name, "reason": reason})
				alert("tool %q quarantined: %s", name, reason)
			}
			g.quarantined[name] = reason
			continue
		}
		delete(g.quarantined, name)
		if !seen {
			g.pins[name] = h
			changed = true
			g.event("tool_pinned", map[string]any{"tool": name})
		}
	}
	g.mu.Unlock()
	if changed {
		g.savePins()
	}
}

func (g *Guard) pinsPath() string { return filepath.Join(g.stateDir, "pins-"+g.name+".json") }

func (g *Guard) loadPins() {
	b, err := os.ReadFile(g.pinsPath())
	if err != nil {
		return
	}
	if err := json.Unmarshal(b, &g.pins); err != nil {
		g.pins = map[string]string{}
		g.event("pins_unreadable", nil)
	}
}

func (g *Guard) savePins() {
	g.mu.Lock()
	b, _ := json.MarshalIndent(g.pins, "", "  ")
	g.mu.Unlock()
	tmp := g.pinsPath() + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, g.pinsPath())
	}
}

// ---------------------------------------------------------------- approval dialog

func askHuman(tool string, args map[string]any, origin string) (bool, string) {
	raw, _ := json.Marshal(args)
	msg := fmt.Sprintf("Sylenix Guard: the agent wants to run %s, but this session read untrusted content (%s). Arguments: %s. Allow this one call?",
		cleanForDialog(tool, 80), cleanForDialog(origin, 80), cleanForDialog(string(raw), 300))
	switch runtime.GOOS {
	case "darwin":
		script := fmt.Sprintf(`display dialog "%s" with title "Sylenix Guard" buttons {"Deny","Allow"} default button "Deny" with icon caution giving up after 60`, escapeAppleScript(msg))
		out, err := exec.Command("osascript", "-e", script).Output()
		if err != nil {
			return false, "dialog failed: " + err.Error()
		}
		return strings.Contains(string(out), "button returned:Allow"), "osascript"
	case "linux":
		err := exec.Command("zenity", "--question", "--no-markup", "--title=Sylenix Guard",
			"--ok-label=Allow", "--cancel-label=Deny", "--timeout=60", "--text="+msg).Run()
		if err == nil {
			return true, "zenity"
		}
		return false, "zenity: denied, timed out, or unavailable"
	}
	return false, "no dialog support on " + runtime.GOOS
}

func escapeAppleScript(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, `"`, `\"`)
}

// cleanForDialog makes attacker-influenced text safe to show: control and
// invisible characters become spaces or disappear, and the text is truncated.
func cleanForDialog(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case isInvisible(r):
			continue
		case unicode.IsControl(r):
			b.WriteRune(' ')
		default:
			b.WriteRune(r)
		}
	}
	out := []rune(b.String())
	if len(out) > max {
		return string(out[:max]) + "..."
	}
	return string(out)
}

// ---------------------------------------------------------------- helpers

func isInvisible(r rune) bool {
	switch {
	case r >= 0x200B && r <= 0x200F, // zero-width and direction marks
		r >= 0x202A && r <= 0x202E, // bidi embeddings and overrides
		r >= 0x2060 && r <= 0x2064,
		r >= 0x2066 && r <= 0x2069,
		r == 0xFEFF,
		r >= 0xE0000 && r <= 0xE007F: // Unicode tag characters
		return true
	}
	return false
}

// hasDuplicateKeys reports whether any JSON object inside b repeats a key.
// Parsers disagree about which duplicate wins, so the guard refuses such frames
// instead of guessing which value the server will act on.
func hasDuplicateKeys(b []byte) bool {
	type level struct {
		isObj     bool
		expectKey bool
		keys      map[string]bool
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	var stack []level
	valueDone := func() {
		if n := len(stack); n > 0 && stack[n-1].isObj {
			stack[n-1].expectKey = true
		}
	}
	for {
		tok, err := dec.Token()
		if err != nil {
			return false // io.EOF, or malformed input that json.Unmarshal already rejected
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				stack = append(stack, level{isObj: true, expectKey: true, keys: map[string]bool{}})
			case '[':
				stack = append(stack, level{})
			default: // '}' or ']'
				stack = stack[:len(stack)-1]
				valueDone()
			}
		default: // string, number, bool or null
			n := len(stack)
			if n == 0 || !stack[n-1].isObj {
				continue
			}
			if stack[n-1].expectKey {
				key, _ := t.(string)
				if stack[n-1].keys[key] {
					return true
				}
				stack[n-1].keys[key] = true
				stack[n-1].expectKey = false
			} else {
				stack[n-1].expectKey = true
			}
		}
	}
}

func hasInvisible(s string) bool {
	for _, r := range s {
		if isInvisible(r) {
			return true
		}
	}
	return false
}

func stripInvisible(s string) string {
	return strings.Map(func(r rune) rune {
		if isInvisible(r) {
			return -1
		}
		return r
	}, s)
}

func (g *Guard) track(id json.RawMessage, method, tool string) {
	if len(id) == 0 {
		return
	}
	g.mu.Lock()
	g.pending[string(bytes.TrimSpace(id))] = pendingReq{method, tool}
	g.mu.Unlock()
}

func (g *Guard) take(id json.RawMessage) (pendingReq, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	k := string(bytes.TrimSpace(id))
	p, ok := g.pending[k]
	delete(g.pending, k)
	return p, ok
}

func (g *Guard) write(b []byte) {
	if b == nil {
		return
	}
	buf := make([]byte, 0, len(b)+1)
	buf = append(append(buf, b...), '\n')
	g.outMu.Lock()
	defer g.outMu.Unlock()
	_, _ = g.out.Write(buf)
}

// event appends one JSON line to the audit log. It never records argument
// values, only their key names.
func (g *Guard) event(kind string, fields map[string]any) {
	rec := map[string]any{"ts": time.Now().UTC().Format(time.RFC3339Nano), "server": g.name, "event": kind}
	for k, v := range fields {
		rec[k] = v
	}
	b, _ := json.Marshal(rec)
	g.logMu.Lock()
	defer g.logMu.Unlock()
	_, _ = g.log.Write(append(b, '\n'))
}

func alert(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "[sylenix-guard] "+format+"\n", a...)
}

func errorFrame(id json.RawMessage, code int, msg, rule string) []byte {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	b, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": code, "message": msg, "data": map[string]string{"rule": rule}},
	})
	return b
}

// replyIfRequest answers only real requests; a notification has no id to answer.
func replyIfRequest(id json.RawMessage, code int, msg, rule string) []byte {
	if len(id) == 0 {
		return nil
	}
	return errorFrame(id, code, msg, rule)
}

func argKeys(args map[string]any) []string {
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func toSet(csv string) map[string]bool {
	m := map[string]bool{}
	for _, s := range strings.Split(csv, ",") {
		if s = strings.TrimSpace(s); s != "" {
			m[s] = true
		}
	}
	return m
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// SPDX-License-Identifier: Apache-2.0

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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"
)

const maxFrame = 10 << 20      // longest accepted JSON-RPC line: 10 MiB
const discardBudget = 64 << 20 // most bytes thrown away while skipping one oversize line

const grantTTL = 15 * time.Minute // how long a "Allow Tool for 15m" click stays valid

type frame map[string]json.RawMessage

type pendingReq struct {
	method string
	tool   string
}

// scratchRule is one --allow-write-under entry: tainted calls to tool (any tool
// when tool is empty) need no prompt while every path argument stays inside dir.
type scratchRule struct {
	tool string
	dir  string
}

// grant is a time-bounded approval: calls to tool need no prompt until expires,
// as long as every path argument stays inside dir (any path when dir is empty).
type grant struct {
	tool      string
	dir       string
	expires   time.Time
	human     bool // recorded by the dialog, not by --grant
	protected bool // the approved call was itself a protected target
}

// stringList collects a repeatable string flag.
type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ", ") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

type Guard struct {
	name      string
	stateDir  string
	readonly  map[string]bool // tools allowed even when the session is tainted
	trust     map[string]bool // tools whose results do not taint the session
	approve   string          // "deny" or "dialog"
	spotlight bool
	scratch   []scratchRule // --allow-write-under entries, fixed after startup

	mu          sync.Mutex
	tainted     bool
	taintOrigin string
	pending     map[string]pendingReq
	pins        map[string]string
	quarantined map[string]string
	grants      []grant // live time-bounded approvals

	serverGone atomic.Bool // set once the server's stdout has closed

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
	resetPins := flag.Bool("reset-pins", false, "discard existing pins and trust every tool as new on first sight")
	allowWriteUnder := stringList{}
	flag.Var(&allowWriteUnder, "allow-write-under", "tainted calls need no prompt while every path argument stays inside DIR, or TOOL=DIR to scope it to one tool; repeatable")
	grantSpecs := stringList{}
	flag.Var(&grantSpecs, "grant", "pre-approved sink calls: TOOL[:DIR]=DURATION (for example write_file=15m); repeatable")
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
	var scratch []scratchRule
	for _, spec := range allowWriteUnder {
		tool, dir := "", spec
		if i := strings.Index(spec, "="); i >= 0 {
			tool, dir = spec[:i], spec[i+1:]
		}
		if dir == "" || strings.ContainsAny(tool, `/\`) {
			fmt.Fprintln(os.Stderr, "sylenix-guard: --allow-write-under wants DIR or TOOL=DIR")
			os.Exit(2)
		}
		if real, ok := canonicalPath(dir); ok {
			dir = real
		}
		scratch = append(scratch, scratchRule{tool: tool, dir: dir})
	}
	var seeded []grant
	for _, spec := range grantSpecs {
		i := strings.LastIndex(spec, "=")
		if i <= 0 {
			fmt.Fprintln(os.Stderr, "sylenix-guard: --grant wants TOOL[:DIR]=DURATION, for example write_file=15m")
			os.Exit(2)
		}
		dur, err := time.ParseDuration(spec[i+1:])
		if err != nil || dur <= 0 {
			fmt.Fprintln(os.Stderr, "sylenix-guard: --grant duration must be positive, for example write_file=15m")
			os.Exit(2)
		}
		tool, dir := spec[:i], ""
		if j := strings.Index(tool, ":"); j >= 0 {
			tool, dir = tool[:j], tool[j+1:]
		}
		if tool == "" || strings.ContainsAny(tool, `/\`) {
			fmt.Fprintln(os.Stderr, "sylenix-guard: --grant wants TOOL[:DIR]=DURATION, for example write_file=15m")
			os.Exit(2)
		}
		if dir != "" {
			if real, ok := canonicalPath(dir); ok {
				dir = real
			}
		}
		seeded = append(seeded, grant{tool: tool, dir: dir, expires: time.Now().Add(dur)})
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
		scratch:     scratch,
		pending:     map[string]pendingReq{},
		pins:        map[string]string{},
		quarantined: map[string]string{},
		grants:      seeded,
		out:         os.Stdout,
		log:         logf,
	}
	if !g.loadPins(*resetPins) {
		fmt.Fprintf(os.Stderr, "[sylenix-guard] pin file %s exists but cannot be read; refusing to start. Inspect it, or restart with --reset-pins to trust every tool as new.\n", g.pinsPath())
		os.Exit(2)
	}

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
	g.event("start", map[string]any{"command": args[0], "readonly": sortedKeys(g.readonly), "trust": sortedKeys(g.trust), "approve": g.approve,
		"allow_write_under": []string(allowWriteUnder), "grants": []string(grantSpecs)})

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		_ = cmd.Process.Kill()
		os.Exit(1)
	}()

	// Closing the server's stdin asks it to exit; the kill timer makes sure it does.
	var shutdownOnce sync.Once
	shutdownServer := func() {
		shutdownOnce.Do(func() {
			_ = childIn.Close()
			time.AfterFunc(5*time.Second, func() { _ = cmd.Process.Kill() })
		})
	}

	// Host -> server. Every tools/call is checked before it is forwarded.
	go func() {
		rd := bufio.NewReaderSize(os.Stdin, 64*1024)
		for {
			line, tooLong, broken, err := readFrame(rd, maxFrame)
			if err != nil {
				if err != io.EOF {
					g.event("host_read_error", map[string]any{"error": err.Error()})
				}
				break
			}
			if tooLong {
				g.event("host_frame_too_large", map[string]any{"fatal": broken})
				g.write(errorFrame(nil, -32600, "Frame too large", "FRAME_TOO_LARGE"))
				if broken {
					break
				}
				continue
			}
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
		// Host closed stdin (or the stream can no longer be framed): let the server finish.
		shutdownServer()
	}()

	// Server -> host. Results are inspected, taint is latched, then forwarded.
	done := make(chan struct{})
	go func() {
		defer close(done)
		rd := bufio.NewReaderSize(childOut, 64*1024)
		for {
			line, tooLong, broken, err := readFrame(rd, maxFrame)
			if err != nil {
				if err != io.EOF {
					g.event("server_read_error", map[string]any{"error": err.Error()})
				}
				break
			}
			if tooLong {
				// We cannot inspect it and we cannot tell which request it answered.
				g.latch("oversize_server_frame")
				g.event("server_frame_too_large", map[string]any{"fatal": broken})
				g.failPending(-32000, "Server frame too large", "SERVER_FRAME_TOO_LARGE")
				if broken {
					break
				}
				continue
			}
			g.write(g.fromServer(line))
		}
		// The server's output is gone, so anything still pending will never be answered.
		g.serverGone.Store(true)
		g.event("server_stream_closed", nil)
		g.failPending(-32000, "Server stream closed", "SERVER_STREAM_CLOSED")
		shutdownServer()
	}()

	<-done
	code := 0
	if err := cmd.Wait(); err != nil {
		code = 1
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() >= 0 {
			code = ee.ExitCode() // -1 means the guard killed the server; report 1
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
	if g.serverGone.Load() {
		return false, replyIfRequest(id, -32000, "Server stream closed", "SERVER_STREAM_CLOSED")
	}
	if len(id) > 0 && g.isPending(id) {
		// A response must only ever carry the identity of the request it answers.
		// The reply uses id null so it cannot be mistaken for the answer to the first request.
		g.event("block", map[string]any{"rule": "DUPLICATE_ID", "method": method})
		return false, errorFrame(nil, -32600, "Invalid request", "DUPLICATE_ID")
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

	// Tainted session, tool is not read-only: this is a sink. Hard blocks go
	// first, then protected persistence targets, then grants/scratch, then the
	// dialog or default deny. A fast path can never reach a hard-blocked or
	// protected target.
	scan := scanArgs(p.Arguments)
	if scan.egress {
		g.event("block", map[string]any{"tool": p.Name, "rule": "EGRESS_TARGET", "origin": origin, "arg_keys": argKeys(p.Arguments)})
		alert("tool %q blocked: network target in a session tainted by %q", p.Name, origin)
		return false, replyIfRequest(id, -32000, "Blocked by Sylenix Guard", "EGRESS_TARGET")
	}
	if scan.sensitive {
		g.event("block", map[string]any{"tool": p.Name, "rule": "SENSITIVE_TARGET", "origin": origin, "arg_keys": argKeys(p.Arguments)})
		alert("tool %q blocked: sensitive path in a session tainted by %q", p.Name, origin)
		return false, replyIfRequest(id, -32000, "Blocked by Sylenix Guard", "SENSITIVE_TARGET")
	}
	if !scan.protected && g.protectedCall(p.Name, scan.paths) {
		scan.protected = true
	}
	if scan.protected && g.approve != "dialog" {
		g.event("block", map[string]any{"tool": p.Name, "rule": "SENSITIVE_TARGET", "origin": origin, "arg_keys": argKeys(p.Arguments)})
		alert("tool %q blocked: protected persistence path in a session tainted by %q", p.Name, origin)
		return false, replyIfRequest(id, -32000, "Blocked by Sylenix Guard", "SENSITIVE_TARGET")
	}
	// A grant or scratch rule may only short-cut a call whose path arguments
	// are all understood and inside the approved tree. Anything ambiguous,
	// and every protected target without a human dialog grant, falls through
	// to denial or a fresh human decision.
	if !scan.ambiguous && g.grantAllows(p.Name, scan.paths, scan.protected) {
		g.event("allow", map[string]any{"tool": p.Name, "tainted": true, "rule": "GRANT", "arg_keys": argKeys(p.Arguments)})
		g.track(id, method, p.Name)
		return true, nil
	}
	if !scan.protected && !scan.ambiguous && g.scratchAllows(p.Name, scan.paths) {
		g.event("allow", map[string]any{"tool": p.Name, "tainted": true, "rule": "SCRATCH", "arg_keys": argKeys(p.Arguments)})
		g.track(id, method, p.Name)
		return true, nil
	}
	if g.approve == "dialog" {
		scope := scopeDir(scan.paths)
		decision, note := askHuman(p.Name, p.Arguments, origin, grantScopeNote(p.Name, scope))
		g.event("approval", map[string]any{"tool": p.Name, "granted": decision != "deny", "decision": decision, "note": note, "arg_keys": argKeys(p.Arguments)})
		if decision == "grant" {
			g.addGrant(p.Name, scope, grantTTL, scan.protected)
			g.event("grant_recorded", map[string]any{"tool": p.Name, "scope": scopeKind(scope), "ttl_seconds": int(grantTTL.Seconds())})
		}
		if decision != "deny" {
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

// serverMessageHasContent reports whether a server-to-client request or
// notification carries text or resource content toward the model or user.
// Content is not logged: callers only record the method and reason code.
func serverMessageHasContent(method string, line []byte) bool {
	switch method {
	case "sampling/createMessage", "elicitation/create":
		return true
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return true // a method-bearing frame we cannot inspect: fail closed
	}
	return hasServerContent(v, "")
}

func hasServerContent(v any, key string) bool {
	if key != "" && serverContentKey(strings.ToLower(key)) {
		switch t := v.(type) {
		case nil:
			return false
		case string:
			return strings.TrimSpace(t) != ""
		case []any:
			return len(t) > 0
		case map[string]any:
			return len(t) > 0
		default:
			return true
		}
	}
	switch t := v.(type) {
	case []any:
		for _, x := range t {
			if hasServerContent(x, key) {
				return true
			}
		}
	case map[string]any:
		for k, x := range t {
			if hasServerContent(x, k) {
				return true
			}
		}
	}
	return false
}

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
		if serverMessageHasContent(method, line) {
			g.event("server_request_content", map[string]any{"method": method, "rule": "TAINT_SERVER_REQUEST"})
			g.latchReason("server_request", "TAINT_SERVER_REQUEST")
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
	g.latchReason(origin, "")
}

func (g *Guard) latchReason(origin, reason string) {
	g.mu.Lock()
	first := !g.tainted
	g.tainted = true
	if first {
		g.taintOrigin = origin
	}
	g.mu.Unlock()
	if first {
		fields := map[string]any{"origin": origin}
		if reason != "" {
			fields["reason"] = reason
		}
		g.event("taint_latched", fields)
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
	if raw, ok := res["structuredContent"]; ok {
		// Not wrapped (that would break schema validation); invisible characters are stripped.
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var v any
		if dec.Decode(&v) == nil {
			if nb, err := json.Marshal(stripAll(v)); err == nil {
				res["structuredContent"] = nb
			}
		}
	}
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
		case containsInvisible(t):
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

// loadPins returns false when a pin file exists but cannot be trusted. Trust on
// first use applies only to genuine first sight, never to a file that is damaged.
func (g *Guard) loadPins(reset bool) bool {
	if reset {
		_ = os.Remove(g.pinsPath())
		g.event("pins_reset", nil)
		return true
	}
	b, err := os.ReadFile(g.pinsPath())
	if os.IsNotExist(err) {
		return true
	}
	var pins map[string]string
	if err != nil || json.Unmarshal(b, &pins) != nil || pins == nil {
		g.event("pins_unreadable", nil)
		return false
	}
	// A null or malformed value unmarshals into an empty string without an
	// error and would brick that tool on the next tools/list. Refuse the whole
	// file instead: only a hex SHA-256 is a pin this build wrote.
	for name, h := range pins {
		if name == "" || len(h) != sha256.Size*2 {
			g.event("pins_unreadable", nil)
			return false
		}
		if _, err := hex.DecodeString(h); err != nil {
			g.event("pins_unreadable", nil)
			return false
		}
	}
	g.pins = pins
	return true
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

// ---------------------------------------------------------------- sink policy: grants, scratch paths, argument shapes

// Argument keys decide how a string value is read. Content keys are never
// treated as paths (a body of text is not a filename); URL keys always name a
// network target; path keys always name a file. For any other key the value
// itself decides. A call with no recognizable path at all gets no shortcuts.
var contentKeys = map[string]bool{
	"content": true, "body": true, "text": true, "message": true, "note": true, "notes": true,
	"summary": true, "description": true, "prompt": true, "data": true, "input": true,
	"comment": true, "comments": true, "instructions": true, "query": true, "code": true,
	"html": true, "markdown": true, "snippet": true, "diff": true, "patch": true,
	"title": true, "subject": true, "reason": true, "answer": true, "details": true,
	"oldtext": true, "newtext": true, "old_text": true, "new_text": true,
}

// serverContentKeys are additional content-bearing fields in server-to-client
// requests and notifications. They are checked together with contentKeys.
var serverContentKeys = map[string]bool{
	"messages": true, "contents": true, "resource": true, "resources": true,
	"blob": true, "image": true, "images": true, "audio": true,
	"structuredcontent": true, "systemprompt": true, "output": true, "outputs": true,
}

func serverContentKey(k string) bool {
	return keyMatches(contentKeys, k) || serverContentKeys[k] ||
		serverContentKeys[keyNormalizer.Replace(k)]
}

var pathKeys = map[string]bool{
	"path": true, "paths": true, "pathname": true, "file": true, "files": true, "filename": true,
	"filepath": true, "file_path": true, "file_name": true, "dir": true, "directory": true,
	"folder": true, "dest": true, "destination": true, "target": true, "source": true,
	"src": true, "location": true, "root": true, "workspace": true,
	"output": true, "output_path": true, "outputpath": true, "output_file": true,
	"outputfile": true, "input_path": true, "inputpath": true,
	"input_file": true, "inputfile": true, "from_file": true, "fromfile": true,
	"to_file": true, "tofile": true,
	"dest_path": true, "destpath": true, "dest_file": true, "destfile": true,
	"destination_path": true, "destinationpath": true,
	"destination_file": true, "destinationfile": true,
	"target_path": true, "targetpath": true, "target_file": true, "targetfile": true,
	"source_path": true, "sourcepath": true, "source_file": true, "sourcefile": true,
}

var urlKeys = map[string]bool{
	"url": true, "uri": true, "endpoint": true, "webhook": true, "href": true, "link": true,
}

// destinationKeys name a recipient or remote endpoint even when the value is a
// bare hostname rather than a URL. They are hard blocks once the session is
// tainted; a grant or scratch rule must never carry data to them.
var destinationKeys = map[string]bool{
	"host": true, "hostname": true, "server": true, "address": true, "addr": true,
	"to": true, "recipient": true, "recipients": true, "email": true,
	"remote": true, "callback": true, "redirect": true, "upload": true,
	"bucket": true, "queue": true, "topic": true,
	"sendto": true, "postto": true, "exfil": true, "exfiltrate": true, "egress": true,
	"endpointurl": true, "webhookurl": true, "callbackurl": true, "redirecturl": true,
	"uploadurl": true, "serverurl": true, "remoteurl": true, "destinationurl": true,
	"targeturl": true, "apiurl": true, "serviceurl": true, "posturl": true,
	"sendurl": true, "exfilurl": true, "hosturl": true, "emailto": true,
	"sendemail": true, "emailaddress": true, "serveraddress": true,
	"remoteaddress": true, "destinationhost": true, "targethost": true,
	"remotehost": true, "serverhost": true, "exfilhost": true,
	"servername": true, "remotename": true, "endpointname": true,
	"bucketname": true, "queuename": true, "topicname": true,
	"uploadto": true, "redirectto": true, "forwardto": true,
}

var egressSchemes = map[string]bool{
	"http": true, "https": true, "ftp": true, "ftps": true, "sftp": true,
	"ssh": true, "smb": true, "nfs": true, "ws": true, "wss": true,
	"mailto": true, "file": true,
}

// sensitiveNames are file names no tainted call may ever touch, at any depth.
var sensitiveNames = map[string]bool{
	"go.mod": true, "go.sum": true, "package.json": true, "package-lock.json": true,
	"makefile": true, "dockerfile": true, "docker-compose.yml": true, "docker-compose.yaml": true,
	"cargo.toml": true, "pyproject.toml": true, "requirements.txt": true,
	"tsconfig.json": true, "setup.py": true, "gemfile": true, "composer.json": true,
}

// protectedTargets is the single table of agent-instruction and persistence
// paths. Parts are consecutive path components matched from any depth.
// subtree means every path below the component sequence is protected too.
// A one-part, non-subtree rule matches that file name at any depth.
// Prompt 7 can replace this table from the policy file without changing the
// matcher or the decision order.
type protectedTarget struct {
	category string
	parts    []string
	subtree  bool
}

var protectedTargets = []protectedTarget{
	{category: "agent instructions", parts: []string{"AGENTS.md"}},
	{category: "agent instructions", parts: []string{"CLAUDE.md"}},
	{category: "agent instructions", parts: []string{"GEMINI.md"}},
	{category: "agent instructions", parts: []string{".cursorrules"}},
	{category: "agent instructions", parts: []string{".windsurfrules"}},
	{category: "agent instructions", parts: []string{".cursor", "rules"}, subtree: true},

	{category: "mcp and editor config", parts: []string{".mcp.json"}},
	{category: "mcp and editor config", parts: []string{"mcp.json"}},
	{category: "mcp and editor config", parts: []string{"claude_desktop_config.json"}},
	{category: "mcp and editor config", parts: []string{".vscode"}, subtree: true},
	{category: "mcp and editor config", parts: []string{".idea"}, subtree: true},

	{category: "ci and hooks", parts: []string{".github", "workflows"}, subtree: true},
	{category: "ci and hooks", parts: []string{".gitlab-ci.yml"}},
	{category: "ci and hooks", parts: []string{".git", "hooks"}, subtree: true},
	{category: "ci and hooks", parts: []string{".husky"}, subtree: true},

	{category: "shell startup", parts: []string{".bashrc"}},
	{category: "shell startup", parts: []string{".zshrc"}},
	{category: "shell startup", parts: []string{".profile"}},
	{category: "shell startup", parts: []string{".bash_profile"}},
	{category: "shell startup", parts: []string{"Microsoft.PowerShell_profile.ps1"}},
	{category: "shell startup", parts: []string{"Microsoft.PowerShellISE_profile.ps1"}},
	{category: "shell startup", parts: []string{"Microsoft.VSCode_profile.ps1"}},
	{category: "shell startup", parts: []string{"profile.ps1"}},

	{category: "cron", parts: []string{"crontab"}},
	{category: "cron", parts: []string{".crontab"}},
	{category: "cron", parts: []string{"anacrontab"}},
	{category: "cron", parts: []string{"cron"}, subtree: true},
	{category: "cron", parts: []string{"cron.d"}, subtree: true},
	{category: "cron", parts: []string{"cron.daily"}, subtree: true},
	{category: "cron", parts: []string{"cron.hourly"}, subtree: true},
	{category: "cron", parts: []string{"cron.weekly"}, subtree: true},
	{category: "cron", parts: []string{"cron.monthly"}, subtree: true},
	{category: "cron", parts: []string{"cron.yearly"}, subtree: true},
	{category: "cron", parts: []string{"spool", "cron"}, subtree: true},
	{category: "cron", parts: []string{"cron", "tabs"}, subtree: true},

	{category: "launchd", parts: []string{"LaunchAgents"}, subtree: true},
	{category: "launchd", parts: []string{"LaunchDaemons"}, subtree: true},
	{category: "launchd", parts: []string{"launchd"}, subtree: true},

	{category: "systemd user units", parts: []string{"systemd"}, subtree: true},
	{category: "systemd user units", parts: []string{"systemd", "user"}, subtree: true},

	{category: "windows startup", parts: []string{"Start Menu", "Programs", "Startup"}, subtree: true},
	{category: "windows startup", parts: []string{"Startup"}, subtree: true},
}

var keyNormalizer = strings.NewReplacer("_", "", "-", "")

func keyMatches(m map[string]bool, k string) bool {
	return m[k] || m[keyNormalizer.Replace(k)]
}

func pathComponents(p string) []string {
	return strings.FieldsFunc(filepath.ToSlash(p), func(r rune) bool { return r == '/' })
}

func componentEqual(a, b string, fold bool) bool {
	if fold {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func (t protectedTarget) matches(components []string, fold bool) bool {
	if len(t.parts) == 0 {
		return false
	}
	if !t.subtree && len(t.parts) == 1 {
		return len(components) > 0 && componentEqual(components[len(components)-1], t.parts[0], fold)
	}
	for i := 0; i+len(t.parts) <= len(components); i++ {
		match := true
		for j := range t.parts {
			if !componentEqual(components[i+j], t.parts[j], fold) {
				match = false
				break
			}
		}
		if match && (t.subtree || i+len(t.parts) == len(components)) {
			return true
		}
	}
	return false
}

// protectedCanonicalPath matches a path that has already been canonicalised.
func protectedCanonicalPath(p string) bool {
	components := pathComponents(p)
	if len(components) == 0 {
		return false
	}
	fold := caseInsensitiveFS(filepath.Dir(p))
	for _, target := range protectedTargets {
		if target.matches(components, fold) {
			return true
		}
	}
	return false
}

func protectedTargetPath(p string) bool {
	if canonical, ok := canonicalPath(p); ok {
		return protectedCanonicalPath(canonical)
	}
	// Even when a host would expand an environment variable or the path is
	// otherwise unresolvable, an obvious protected shape must not be missed.
	// The path itself is still refused by the normal canonicalisation rules.
	return protectedCanonicalPath(filepath.Clean(strings.ReplaceAll(p, `\`, "/")))
}

// protectedCall also checks relative names against the approved roots, so a
// symlink inside a scratch or grant directory cannot hide a protected target.
func (g *Guard) protectedCall(tool string, paths []string) bool {
	for _, p := range paths {
		if protectedTargetPath(p) {
			return true
		}
		if isExplicitlyRooted(p) {
			continue
		}
		for _, rule := range g.scratch {
			if rule.tool != "" && rule.tool != tool {
				continue
			}
			if canonical, ok := canonicalPath(rule.dir + string(os.PathSeparator) + p); ok && protectedCanonicalPath(canonical) {
				return true
			}
		}
		g.mu.Lock()
		grants := append([]grant(nil), g.grants...)
		g.mu.Unlock()
		for _, gr := range grants {
			if gr.tool != tool || gr.dir == "" {
				continue
			}
			if canonical, ok := canonicalPath(gr.dir + string(os.PathSeparator) + p); ok && protectedCanonicalPath(canonical) {
				return true
			}
		}
	}
	return false
}

// callScan is the classification of one tools/call's arguments. Only values
// under a known path key are paths. ambiguous means the call contains a
// non-content value that could be a path or destination but is not under a
// known path key; such a call must never take a grant or scratch shortcut.
type callScan struct {
	paths     []string
	egress    bool
	sensitive bool
	protected bool
	ambiguous bool
}

// scanArgs classifies every string inside a call's arguments. Paths are drawn
// only from known path keys: a filename-shaped value under an unknown key is
// not a path we can safely compare, so it disqualifies the fast paths instead.
func scanArgs(args map[string]any) callScan {
	var s callScan
	var walk func(key string, v any)
	walk = func(key string, v any) {
		switch t := v.(type) {
		case string:
			if t == "" {
				return
			}
			kl := strings.ToLower(key)
			switch {
			case keyMatches(contentKeys, kl):
				return // a body of text is neither a path nor a network target
			case keyMatches(urlKeys, kl) || keyMatches(destinationKeys, kl) ||
				isURLValue(t) || hasEgressScheme(t) || isIPAddress(t):
				s.egress = true
			case keyMatches(pathKeys, kl):
				// Keep the raw value: cleaning before symlink resolution can
				// turn "link/../x" into a path the server never opens.
				s.paths = append(s.paths, t)
				resolved, resolvedOK := canonicalPath(t)
				protected := resolvedOK && protectedCanonicalPath(resolved)
				if !protected {
					protected = protectedTargetPath(t)
				}
				if protected {
					// Agent-instruction and persistence targets are the one
					// sensitive class a human may approve with --approve dialog.
					s.protected = true
					if isSensitivePathWithoutGit(t) ||
						(resolvedOK && isSensitivePathWithoutGit(resolved)) {
						s.sensitive = true
					}
				} else if isSensitivePath(t) {
					s.sensitive = true
				} else if resolvedOK && isSensitivePath(resolved) {
					// A symlink inside the scratch root can hide a sensitive
					// target; treat its resolved name as the destination too.
					s.sensitive = true
				}
			case isHostPort(t):
				s.egress = true
			case protectedTargetPath(t):
				s.protected = true
				if isSensitivePathWithoutGit(t) {
					s.sensitive = true
				}
			case isSensitivePath(t):
				s.sensitive = true
			case looksLikePath(t) || hasPathSyntax(t):
				// Unknown destination: never let it ride a fast path.
				s.ambiguous = true
			}
		case []any:
			for _, x := range t {
				walk(key, x)
			}
		case map[string]any:
			for k, x := range t {
				walk(k, x)
			}
		}
	}
	for k, v := range args {
		walk(k, v)
	}
	return s
}

// isURLValue reports whether the whole value is a URL, so a URL mentioned in
// the middle of a sentence does not count as addressing a network target.
func isURLValue(s string) bool {
	i := strings.Index(s, "://")
	if i <= 0 || i > 16 {
		return false
	}
	for j := 0; j < i; j++ {
		c := s[j]
		ok := c == '+' || c == '-' || c == '.' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (j > 0 && c >= '0' && c <= '9')
		if !ok {
			return false
		}
	}
	return true
}

// hasEgressScheme catches URI forms that carry a destination without "://",
// such as mailto: or file:.
func hasEgressScheme(s string) bool {
	i := strings.IndexByte(s, ':')
	if i <= 0 || i > 16 {
		return false
	}
	for j := 0; j < i; j++ {
		c := s[j]
		ok := c == '+' || c == '-' || c == '.' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (j > 0 && c >= '0' && c <= '9')
		if !ok {
			return false
		}
	}
	return egressSchemes[strings.ToLower(s[:i])]
}

func isIPAddress(s string) bool {
	host := s
	if h, _, err := net.SplitHostPort(s); err == nil {
		host = h
	}
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	return net.ParseIP(host) != nil
}

func isHostPort(s string) bool {
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" || port == "" {
		return false
	}
	n := 0
	for _, c := range port {
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
		if n > 65535 {
			return false
		}
	}
	if n == 0 {
		return false
	}
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	if net.ParseIP(host) != nil {
		return true
	}
	hasName := false
	for _, c := range host {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			hasName = true
			continue
		}
		if (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' {
			continue
		}
		return false
	}
	return hasName
}

// looksLikePath reports whether a value has a filename shape. It is used only
// to refuse a fast path for values whose key does not identify them as paths.
func looksLikePath(s string) bool {
	if s == "" || len(s) > 400 || strings.ContainsAny(s, "\n\r\t") {
		return false
	}
	if strings.ContainsAny(s, `/\`) {
		return true
	}
	if strings.Contains(s, " ") {
		return false
	}
	i := strings.LastIndexByte(s, '.')
	return i > 0 && i < len(s)-1 && len(s)-i-1 <= 12
}

// hasPathSyntax catches destination shapes that do not need a normal filename
// extension: drive-relative paths, UNC/backslash names, home paths, bare dot
// directories and environment expansion.
func hasPathSyntax(s string) bool {
	if strings.ContainsRune(s, 0) || strings.ContainsAny(s, "\n\r\t") || hasInvisible(s) {
		return true
	}
	if s != strings.TrimSpace(s) {
		return true
	}
	if s == "." || s == ".." || strings.HasPrefix(s, ".") || strings.HasPrefix(s, "~") {
		return true
	}
	if strings.HasSuffix(s, " ") || strings.HasSuffix(s, ".") {
		return true // trailing spaces/dots are stripped by some filesystems
	}
	if strings.ContainsAny(s, `/\`) || isWindowsDrivePath(s) {
		return true
	}
	if strings.ContainsAny(s, "$%") {
		return true // environment/percent expansion is not resolved here
	}
	return false
}

func isWindowsDrivePath(s string) bool {
	if len(s) < 2 || s[1] != ':' {
		return false
	}
	c := s[0]
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isSensitivePath(p string) bool {
	return isSensitivePathParts(p, true)
}

// isSensitivePathWithoutGit keeps .env, key, certificate and config checks but
// lets a human approve .git/hooks targets without making every .git path
// dialog-approvable.
func isSensitivePathWithoutGit(p string) bool {
	return isSensitivePathParts(p, false)
}

func isSensitivePathParts(p string, checkGit bool) bool {
	// Invisible characters must not be able to hide a sensitive name.
	p = stripInvisible(p)
	// Treat both separators as path separators so Windows-shaped probes are
	// classified the same way on every platform.
	norm := strings.TrimRight(strings.ReplaceAll(p, `\`, "/"), "/")
	for _, c := range strings.Split(norm, "/") {
		lower := strings.ToLower(c)
		if (checkGit && lower == ".git") || strings.HasPrefix(lower, ".env") ||
			strings.HasPrefix(lower, "id_rsa") || strings.HasPrefix(lower, "id_ed25519") {
			return true
		}
	}
	base := strings.ToLower(norm)
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	if strings.HasPrefix(base, ".env") || strings.HasPrefix(base, "id_rsa") || strings.HasPrefix(base, "id_ed25519") {
		return true
	}
	switch filepath.Ext(base) {
	case ".pem", ".key", ".p12", ".pfx":
		return true
	}
	return sensitiveNames[base]
}

// expandHome expands a leading ~ or ~/ or ~\ to the user's home directory.
// ~user is not resolvable here, so it returns false and callers fail closed.
func expandHome(p string) (string, bool) {
	if p == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", false
		}
		return home, true
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", false
		}
		return home + p[1:], true
	}
	if strings.HasPrefix(p, "~") {
		return "", false
	}
	return p, true
}

func hasWindowsUnsafeSuffix(p string) bool {
	for _, part := range strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == "" || part == "." || part == ".." {
			continue
		}
		if strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return true
		}
	}
	return false
}

// absoluteNoClean makes p absolute without collapsing "." or "..", because
// those must be resolved after symlinks to match what the server opens.
func absoluteNoClean(p string) (string, bool) {
	p, ok := expandHome(p)
	if !ok || p == "" {
		return "", false
	}
	if strings.ContainsRune(p, 0) || strings.ContainsAny(p, "\n\r\t") || hasInvisible(p) {
		return "", false // control/invisible characters can change how a host or OS reads the name
	}
	if strings.TrimSpace(p) != p {
		return "", false // leading/trailing space changes meaning on some hosts
	}
	if strings.ContainsAny(p, "$%") {
		return "", false // environment/percent expansion is not resolved here
	}
	if runtime.GOOS == "windows" && hasWindowsUnsafeSuffix(p) {
		return "", false // Windows would strip a trailing dot/space and change the name
	}
	if isWindowsDrivePath(p) && !filepath.IsAbs(p) {
		return "", false // C:foo is drive-relative; its host meaning is unknown
	}
	if filepath.IsAbs(p) {
		return p, true
	}
	if len(p) > 0 && (p[0] == '/' || p[0] == '\\') {
		if runtime.GOOS != "windows" {
			return "", false // backslash-rooted / UNC shape on a non-Windows host
		}
		wd, err := os.Getwd()
		if err != nil {
			return "", false
		}
		vol := filepath.VolumeName(wd)
		if vol == "" {
			return "", false
		}
		return vol + p, true
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", false
	}
	return wd + string(os.PathSeparator) + p, true
}

// resolveExistingPrefix resolves symlinks on the longest existing prefix of
// abs, then appends the missing tail. It never cleans before resolving, so
// "link/../file" follows the link before applying "..", as the OS does.
func lastPathSeparator(s string) int {
	if runtime.GOOS == "windows" {
		return strings.LastIndexAny(s, `/\`)
	}
	return strings.LastIndexByte(s, '/')
}

func hasDotDotComponent(p string) bool {
	for _, part := range strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == ".." {
			return true
		}
	}
	return false
}

func resolveExistingPrefix(abs string) (string, bool) {
	real, err := filepath.EvalSymlinks(abs)
	if err == nil {
		return filepath.Clean(real), true
	}
	if !os.IsNotExist(err) {
		return "", false // permission error, symlink loop, or another unresolvable state
	}
	// A missing final target is only safe to append when the path itself is
	// not an existing symlink. A symlink to a missing target could be created
	// outside the scratch root by the write that follows this check.
	if !hasDotDotComponent(abs) {
		if _, lerr := os.Lstat(abs); lerr == nil || !os.IsNotExist(lerr) {
			return "", false
		}
	}
	pos := len(abs)
	for pos > 0 {
		i := lastPathSeparator(abs[:pos])
		if i < 0 {
			break
		}
		prefix, tail := abs[:i], abs[i:]
		if prefix == "" || (filepath.VolumeName(prefix) == prefix && i < len(abs) && os.IsPathSeparator(abs[i])) {
			prefix, tail = abs[:i+1], abs[i+1:]
		}
		if prefix != "" {
			real, err := filepath.EvalSymlinks(prefix)
			if err == nil {
				if tail == "" {
					return filepath.Clean(real), true
				}
				return filepath.Clean(real + string(os.PathSeparator) + tail), true
			}
			if !os.IsNotExist(err) {
				return "", false
			}
			if !hasDotDotComponent(prefix) {
				if _, lerr := os.Lstat(prefix); lerr == nil || !os.IsNotExist(lerr) {
					return "", false
				}
			}
		}
		pos = i
	}
	return "", false
}

// canonicalPath returns an absolute, symlink-resolved path. Failure means the
// path cannot be classified, and callers treat that as not inside anywhere.
func canonicalPath(p string) (string, bool) {
	abs, ok := absoluteNoClean(p)
	if !ok {
		return "", false
	}
	return resolveExistingPrefix(abs)
}

// normalizeDrive makes a Windows drive letter upper-case before comparison.
// The rest of the path is case-folded only when the filesystem is actually
// case-insensitive; see caseInsensitiveFS.
func normalizeDrive(p string) string {
	if len(p) >= 2 && p[1] == ':' {
		p = strings.ToUpper(p[:1]) + p[1:]
	}
	return p
}

func flipCase(p string) string {
	dir, base := filepath.Split(p)
	if base == "" || base == "." || base == ".." {
		return p
	}
	r := []rune(base)
	for i, c := range r {
		switch {
		case c >= 'a' && c <= 'z':
			r[i] = c - ('a' - 'A')
			return dir + string(r)
		case c >= 'A' && c <= 'Z':
			r[i] = c + ('a' - 'A')
			return dir + string(r)
		}
	}
	return p
}

// caseInsensitiveFS probes the nearest existing parent of root. If two names
// that differ only in case are the same file, comparisons fold case; a
// case-sensitive filesystem keeps exact comparison.
func caseInsensitiveFS(root string) bool {
	probe := root
	for {
		alt := flipCase(probe)
		if alt != probe {
			if fi, err := os.Stat(probe); err == nil {
				fi2, err2 := os.Stat(alt)
				return err2 == nil && os.SameFile(fi, fi2)
			}
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			break
		}
		probe = parent
	}
	return runtime.GOOS == "windows"
}

// insideDir reports whether the resolved target lies under root. Volume names
// are normalised, and case is folded only on a case-insensitive filesystem.
func insideDir(root, target string) bool {
	root = normalizeDrive(filepath.Clean(root))
	target = normalizeDrive(filepath.Clean(target))
	if caseInsensitiveFS(root) {
		root = strings.ToLower(root)
		target = strings.ToLower(target)
	}
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func isExplicitlyRooted(p string) bool {
	if strings.HasPrefix(p, "~") || strings.HasPrefix(p, "$") || strings.HasPrefix(p, "%") ||
		isWindowsDrivePath(p) || filepath.IsAbs(p) {
		return true
	}
	return len(p) > 0 && (p[0] == '/' || p[0] == '\\')
}

func samePath(a, b string) bool {
	return insideDir(a, b) && insideDir(b, a)
}

// inside reports whether one path argument stays inside root. Relative names
// are interpreted against root, which is how a workspace-rooted MCP server
// resolves them; symlinks and ".." are resolved in OS order before comparison.
func inside(root, target string) bool {
	r, ok := canonicalPath(root)
	if !ok || !samePath(r, root) {
		// The approved root itself changed identity since it was recorded.
		return false
	}
	if strings.ContainsAny(target, "$%") || strings.ContainsRune(target, 0) ||
		strings.ContainsAny(target, "\n\r\t") || hasInvisible(target) ||
		strings.TrimSpace(target) != target {
		return false
	}
	if runtime.GOOS == "windows" && hasWindowsUnsafeSuffix(target) {
		return false
	}
	var t string
	if isExplicitlyRooted(target) {
		t, ok = canonicalPath(target)
	} else {
		t, ok = resolveExistingPrefix(r + string(os.PathSeparator) + target)
	}
	if !ok || isSensitivePath(t) {
		return false
	}
	return insideDir(r, t)
}

func allInside(dir string, paths []string) bool {
	for _, p := range paths {
		if !inside(dir, p) {
			return false
		}
	}
	return true
}

// pathsResolvable is the tool-wide grant check: the grant covers any
// directory, but a path whose meaning cannot be resolved is still no shortcut.
func pathsResolvable(paths []string) bool {
	for _, p := range paths {
		resolved, ok := canonicalPath(p)
		if !ok || isSensitivePath(resolved) {
			return false
		}
	}
	return true
}

// scopeDir narrows a grant to the deepest directory that holds every path of
// the approved call. No paths, an unresolvable path, or a filesystem root all
// mean the grant covers the whole tool (which is what the button says).
func scopeDir(paths []string) string {
	var scope string
	for _, p := range paths {
		r, ok := canonicalPath(p)
		if !ok {
			return ""
		}
		d := filepath.Dir(r)
		if scope == "" {
			scope = d
			continue
		}
		for !insideDir(scope, d) {
			parent := filepath.Dir(scope)
			if parent == scope {
				return ""
			}
			scope = parent
		}
	}
	if scope == "" || scope == filepath.Dir(scope) {
		return ""
	}
	return scope
}

// addGrant records one time-bounded approval from the dialog or the --grant flag.
func (g *Guard) addGrant(tool, dir string, ttl time.Duration, protected bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.grants = append(g.grants, grant{tool: tool, dir: dir, expires: time.Now().Add(ttl), human: true, protected: protected})
}

// grantAllows reports whether a live grant covers this call. Expired grants are
// dropped along the way; a directory-scoped grant only covers calls whose every
// path argument stays inside that directory. Protected targets ignore --grant
// seeds and need a human grant recorded for a protected call.
func (g *Guard) grantAllows(tool string, paths []string, protected bool) bool {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	kept := g.grants[:0]
	allowed := false
	for _, gr := range g.grants {
		if !gr.expires.After(now) {
			continue
		}
		kept = append(kept, gr)
		if gr.tool != tool || (protected && (!gr.human || !gr.protected)) {
			continue
		}
		if gr.dir == "" {
			if pathsResolvable(paths) {
				allowed = true
			}
		} else if len(paths) > 0 && allInside(gr.dir, paths) {
			allowed = true
		}
	}
	g.grants = kept
	return allowed
}

// scratchAllows is the --allow-write-under fast path: no prompt while every
// path argument stays inside the configured directory. A call with no
// recognizable path argument never qualifies.
func (g *Guard) scratchAllows(tool string, paths []string) bool {
	if len(paths) == 0 {
		return false
	}
	for _, e := range g.scratch {
		if e.tool != "" && e.tool != tool {
			continue
		}
		if allInside(e.dir, paths) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- approval dialog

// askHuman shows one OS dialog with three outcomes: deny, allow this one call,
// or allow this tool (scoped to the call's directory when it has one) for 15m.
func askHuman(tool string, args map[string]any, origin, scopeNote string) (decision, note string) {
	raw, _ := json.Marshal(args)
	msg := fmt.Sprintf("Sylenix Guard: the agent wants to run %s, but this session read untrusted content (%s). Arguments: %s. Deny blocks the call. Allow Once permits this one call. Allow Tool for 15m permits %s",
		cleanForDialog(tool, 80), cleanForDialog(origin, 80), cleanForDialog(string(raw), 300), scopeNote)
	switch runtime.GOOS {
	case "darwin":
		script := fmt.Sprintf(`display dialog "%s" with title "Sylenix Guard" buttons {"Deny","Allow Once","Allow Tool for 15m"} default button "Deny" with icon caution giving up after 60`, escapeAppleScript(msg))
		out, err := exec.Command("osascript", "-e", script).Output()
		if err != nil {
			return "deny", "dialog failed: " + err.Error()
		}
		return appleScriptChoice(string(out)), "osascript"
	case "linux":
		// A list, because zenity --question can only offer two buttons.
		out, err := exec.Command("zenity", "--list", "--no-markup", "--hide-header",
			"--title=Sylenix Guard", "--width=520", "--height=240", "--timeout=60",
			"--text="+msg, "--column=Decision", "Deny", "Allow Once", "Allow Tool for 15m").Output()
		if err != nil {
			return "deny", "zenity: denied, timed out, or unavailable"
		}
		res := string(out)
		switch {
		case strings.Contains(res, "Allow Tool for 15m"):
			return "grant", "zenity"
		case strings.Contains(res, "Allow Once"):
			return "once", "zenity"
		}
		return "deny", "zenity"
	case "windows":
		// The message travels in an environment variable, never inside the script text,
		// so attacker-influenced characters cannot change what PowerShell runs. The
		// script itself is static: exit 0 allows once, exit 2 grants for 15m.
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", windowsDialogScript)
		cmd.Env = append(os.Environ(), "SYLENIX_MSG="+msg)
		err := cmd.Run()
		if err == nil {
			return "once", "powershell"
		}
		if ee, ok := err.(*exec.ExitError); ok {
			switch ee.ExitCode() {
			case 2:
				return "grant", "powershell"
			case 1:
				return "deny", "powershell"
			}
		}
		return "deny", "powershell: denied, timed out, or unavailable"
	}
	return "deny", "no dialog support on " + runtime.GOOS
}

func appleScriptChoice(out string) (decision string) {
	switch {
	case strings.Contains(out, "button returned:Allow Tool for 15m"):
		return "grant"
	case strings.Contains(out, "button returned:Allow Once"):
		return "once"
	}
	return "deny"
}

// windowsDialogScript is a three-button dialog. Deny is focused first and is
// also the escape key, so the safe answer is the easiest one; the timeout
// closes the dialog without a choice, which counts as deny.
const windowsDialogScript = `
Add-Type -AssemblyName System.Windows.Forms
$f = New-Object System.Windows.Forms.Form
$f.Text = 'Sylenix Guard'; $f.TopMost = $true; $f.StartPosition = 'CenterScreen'
$f.FormBorderStyle = 'FixedDialog'; $f.MinimizeBox = $false; $f.MaximizeBox = $false
$f.ClientSize = New-Object System.Drawing.Size(560, 250)
$l = New-Object System.Windows.Forms.Label
$l.Location = New-Object System.Drawing.Point(12, 12); $l.Size = New-Object System.Drawing.Size(536, 168)
$l.Text = $env:SYLENIX_MSG
$deny = New-Object System.Windows.Forms.Button
$deny.Text = 'Deny'; $deny.Location = New-Object System.Drawing.Point(12, 192); $deny.Size = New-Object System.Drawing.Size(172, 40)
$deny.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$once = New-Object System.Windows.Forms.Button
$once.Text = 'Allow Once'; $once.Location = New-Object System.Drawing.Point(194, 192); $once.Size = New-Object System.Drawing.Size(172, 40)
$once.DialogResult = [System.Windows.Forms.DialogResult]::OK
$grant = New-Object System.Windows.Forms.Button
$grant.Text = 'Allow Tool for 15m'; $grant.Location = New-Object System.Drawing.Point(376, 192); $grant.Size = New-Object System.Drawing.Size(172, 40)
$grant.DialogResult = [System.Windows.Forms.DialogResult]::Retry
$f.CancelButton = $deny
$f.Controls.AddRange(@($l, $deny, $once, $grant))
$f.Add_Shown({ $deny.Focus() })
$t = New-Object System.Windows.Forms.Timer; $t.Interval = 60000
$t.Add_Tick({ $f.Close() }); $t.Start()
$r = $f.ShowDialog()
if ($r -eq [System.Windows.Forms.DialogResult]::OK) { exit 0 }
if ($r -eq [System.Windows.Forms.DialogResult]::Retry) { exit 2 }
exit 1
`

// grantScopeNote tells the human exactly what the third button authorizes.
func grantScopeNote(tool, scope string) string {
	if scope == "" {
		return fmt.Sprintf("any call to %s for 15 minutes (this session only)", cleanForDialog(tool, 80))
	}
	return fmt.Sprintf("calls to %s whose paths stay in %s for 15 minutes (this session only)",
		cleanForDialog(tool, 80), cleanForDialog(scope, 120))
}

func scopeKind(scope string) string {
	if scope == "" {
		return "tool"
	}
	return "dir"
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

// isInvisible reports characters that render as nothing, or that reorder or
// hide text. Zero-width joiners and non-joiners are included, which means
// stripping them also breaks some emoji sequences and some Persian and Indic text.
func isInvisible(r rune) bool {
	switch {
	case r == 0x00AD, // soft hyphen
		r == 0x034F,                                        // combining grapheme joiner
		r == 0x061C,                                        // Arabic letter mark
		r == 0x115F, r == 0x1160, r == 0x3164, r == 0xFFA0, // Hangul fillers
		r == 0x17B4, r == 0x17B5, // Khmer inherent vowels
		r == 0x180E,                // Mongolian vowel separator
		r >= 0x200B && r <= 0x200F, // zero-width and direction marks
		r >= 0x2028 && r <= 0x202E, // line and paragraph separators, bidi embeddings and overrides
		r >= 0x2060 && r <= 0x206F, // word joiner, invisible operators, deprecated format controls
		r == 0xFEFF,
		r >= 0xFFF9 && r <= 0xFFFB,   // interlinear annotation
		r >= 0xE0000 && r <= 0xE007F, // Unicode tag characters
		r >= 0xE0100 && r <= 0xE01EF: // variation selectors supplement
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

// containsInvisible checks the decoded strings (keys and values) of a JSON value.
// Checking the re-encoded bytes would miss U+2028 and U+2029, which encoding/json
// writes as escape sequences.
func containsInvisible(v any) bool {
	switch t := v.(type) {
	case string:
		return hasInvisible(t)
	case []any:
		for _, x := range t {
			if containsInvisible(x) {
				return true
			}
		}
	case map[string]any:
		for k, x := range t {
			if hasInvisible(k) || containsInvisible(x) {
				return true
			}
		}
	}
	return false
}

func hasInvisible(s string) bool {
	for _, r := range s {
		if isInvisible(r) {
			return true
		}
	}
	return false
}

// stripAll removes invisible characters from every string inside a decoded JSON value.
func stripAll(v any) any {
	switch t := v.(type) {
	case string:
		return stripInvisible(t)
	case []any:
		for i := range t {
			t[i] = stripAll(t[i])
		}
		return t
	case map[string]any:
		for k, x := range t {
			t[k] = stripAll(x)
		}
		return t
	}
	return v
}

// readFrame reads one newline-terminated line of at most max bytes. A longer
// line is discarded up to its newline and reported as tooLong. If no newline
// turns up within discardBudget bytes, broken is also true: the stream can no
// longer be framed and the caller should stop reading it.
func readFrame(r *bufio.Reader, max int) (line []byte, tooLong, broken bool, err error) {
	var buf []byte
	skipped := 0
	for {
		chunk, isPrefix, e := r.ReadLine()
		if e != nil {
			return nil, tooLong, false, e
		}
		if !tooLong {
			if len(buf)+len(chunk) > max {
				tooLong, buf, skipped = true, nil, len(chunk)
			} else {
				buf = append(buf, chunk...)
			}
		} else {
			skipped += len(chunk)
			if skipped > discardBudget {
				return nil, true, true, nil
			}
		}
		if !isPrefix {
			return buf, tooLong, false, nil
		}
	}
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

func (g *Guard) isPending(id json.RawMessage) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	_, ok := g.pending[string(bytes.TrimSpace(id))]
	return ok
}

// failPending answers every request that is still waiting, so the host is never
// left waiting for a response that cannot arrive.
func (g *Guard) failPending(code int, msg, rule string) {
	g.mu.Lock()
	ids := make([]string, 0, len(g.pending))
	for k := range g.pending {
		ids = append(ids, k)
	}
	g.pending = map[string]pendingReq{}
	g.mu.Unlock()
	sort.Strings(ids)
	for _, k := range ids {
		g.write(errorFrame(json.RawMessage(k), code, msg, rule))
	}
	if len(ids) > 0 {
		g.event("pending_failed", map[string]any{"count": len(ids), "rule": rule})
	}
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

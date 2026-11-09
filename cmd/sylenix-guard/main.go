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
	"crypto/rand"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

const maxFrame = 10 << 20      // longest accepted JSON-RPC line: 10 MiB
const discardBudget = 64 << 20 // most bytes thrown away while skipping one oversize line

const grantTTL = 15 * time.Minute // how long a "Allow Tool for 15m" click stays valid

const guardMetaKey = "_sylenixGuard"
const guardMetaVersion = 1

const policyVersion = 1
const policyFileName = "policy.yaml"

const controlVersion = 1
const controlHeartbeatEvery = 2 * time.Second
const controlStaleAfter = 15 * time.Second
const clearRequestTTL = 2 * time.Minute
const clearRequestPoll = 200 * time.Millisecond
const clearWaitTimeout = 90 * time.Second
const clearFileLimit = 1 << 20 // control/request/result files are tiny

const auditGapLimit = 600  // gaps longer than this are idle time, not active time
const auditMinActive = 300 // below this, prompts/hour is not meaningful

// version is the Guard build version. Release builds set it with
// -ldflags "-X main.version=<tag>"; local builds keep this default.
var version = "0.1.0"

// policyFile is the on-disk policy schema. It is decoded strictly: any field
// this struct does not name is an error, never silently ignored.
type policyFile struct {
	Version           int                     `json:"version"`
	Profile           string                  `json:"profile"`
	Approval          string                  `json:"approval"`
	Spotlight         *bool                   `json:"spotlight"`
	SensitivePaths    []string                `json:"sensitive_paths"`
	Egress            *policyEgress           `json:"egress"`
	AllowlistEnforced *bool                   `json:"allowlist_enforced"`
	Allowlist         []policyAllowEntry      `json:"allowlist"`
	Servers           map[string]policyServer `json:"servers"`
}

// policyAllowEntry is one exact server command/args approval. Args is a
// pointer so a missing args key is a validation error rather than "any args".
type policyAllowEntry struct {
	Name     string    `json:"name"`
	Command  string    `json:"command"`
	Args     *[]string `json:"args"`
	SHA256   string    `json:"sha256"`
	Lockfile string    `json:"lockfile"`
}

type policyEgress struct {
	AllowHosts []string `json:"allow_hosts"`
	DenyHosts  []string `json:"deny_hosts"`
}

type policyServer struct {
	Tools map[string]policyTool `json:"tools"`
}

type policyTool struct {
	Class      string   `json:"class"`
	PathKeys   []string `json:"path_keys"`
	AllowPaths []string `json:"allow_paths"`
	Trust      bool     `json:"trust"`
}

// policyProfile is a built-in per-server tool classification. The policy file
// can override individual tools, or select a profile explicitly.
type policyProfile struct {
	name        string
	source      string
	identifiers []string
	tools       map[string]string
}

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

// configTarget is one known MCP client configuration file. serverPaths are
// tried in order and may hold several client-specific server maps.
type configTarget struct {
	client      string
	path        string
	serverPaths [][]string
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
	scratch   []scratchRule // --allow-write-under or policy allow_paths, fixed after startup

	classes           map[string]string          // policy class for non-read tools
	toolPathKeys      map[string]map[string]bool // per-tool extra path argument keys
	egressAllow       map[string]bool            // policy host allowlist
	egressDeny        map[string]bool            // policy host denylist (wins over allow)
	policySource      string
	policyVersion     int
	policyPath        string
	profileName       string
	profileSource     string
	allowlistEnforced bool
	allowlist         []policyAllowEntry
	readonlyOverride  bool // --readonly was set, so policy class: read entries are ignored

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
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			os.Exit(runConfigCommand("install", os.Args[2:]))
		case "uninstall":
			os.Exit(runConfigCommand("uninstall", os.Args[2:]))
		case "policy":
			os.Exit(runPolicyCommand(os.Args[2:]))
		case "allow":
			os.Exit(runAllowCommand(os.Args[2:]))
		case "doctor":
			os.Exit(runDoctorCommand(os.Args[2:]))
		case "clear-taint":
			os.Exit(runClearTaintCommand(os.Args[2:]))
		case "stats":
			os.Exit(runStatsCommand(os.Args[2:]))
		}
	}
	name := flag.String("name", "", "label for this server; names the pin and log files (default: command name)")
	stateDir := flag.String("state-dir", "", "directory for pins and the audit log (default ~/.sylenix-poc)")
	policyPath := flag.String("policy", "", "path to a versioned policy file (default: <state-dir>/policy.yaml, else built-in defaults)")
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

	visited := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { visited[f.Name] = true })

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: sylenix-guard [flags] -- <server command> [args...]")
		os.Exit(2)
	}
	if visited["approve"] && *approve != "deny" && *approve != "dialog" {
		fmt.Fprintln(os.Stderr, "sylenix-guard: --approve must be deny or dialog")
		os.Exit(2)
	}
	var flagScratch []scratchRule
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
		flagScratch = append(flagScratch, scratchRule{tool: tool, dir: dir})
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
	nameExplicit := visited["name"] && *name != ""
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
		approve:     "deny",
		spotlight:   true,
		pending:     map[string]pendingReq{},
		pins:        map[string]string{},
		quarantined: map[string]string{},
		grants:      seeded,
		out:         os.Stdout,
		log:         logf,
	}
	pf, source, resolvedPath, err := loadPolicyForRun(*policyPath, visited["policy"], *stateDir, *name, nameExplicit)
	if err != nil {
		g.event("policy_invalid", map[string]any{"source": source, "reason": err.Error()})
		fmt.Fprintln(os.Stderr, "sylenix-guard:", err)
		os.Exit(2)
	}
	g.policySource = source
	g.policyVersion = pf.Version
	g.policyPath = resolvedPath
	profile := selectPolicyProfile(*name, args, pf.Profile)
	if profile != nil {
		g.profileName = profile.name
		g.profileSource = profile.source
	}
	g.applyPolicy(pf, profile, visited, *readonly, *trust, *approve, flagScratch, *noSpot)
	printPolicyDeprecationNotes(visited, *policyPath, source)
	g.event("policy_loaded", map[string]any{"source": source, "version": pf.Version, "approve": g.approve,
		"profile": g.profileName, "profile_source": g.profileSource})
	if allowed, reason := g.checkServerAllowed(args); !allowed {
		g.event("block", map[string]any{"rule": "SERVER_NOT_ALLOWED", "command": args[0], "detail": reason})
		fmt.Fprintf(os.Stderr, "[sylenix-guard] SERVER_NOT_ALLOWED: %s\n", reason)
		fmt.Fprintf(os.Stderr, "[sylenix-guard] refusing to launch server command %q.\n", args[0])
		fmt.Fprintf(os.Stderr, "[sylenix-guard] approve it with: sylenix-guard allow %q\n", g.name)
		if g.policyPath != "" {
			fmt.Fprintf(os.Stderr, "[sylenix-guard] or add an exact command and args entry to %s\n", g.policyPath)
		}
		os.Exit(2)
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
		"policy_source": g.policySource, "policy_version": g.policyVersion,
		"profile": g.profileName, "profile_source": g.profileSource,
		"allow_write_under": []string(allowWriteUnder), "grants": []string(grantSpecs)})
	control, controlErr := startGuardControl(g)
	if controlErr != nil {
		g.event("control_unavailable", map[string]any{"reason": "cannot create clear-taint control"})
		fmt.Fprintln(os.Stderr, "sylenix-guard: clear-taint unavailable:", controlErr)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		control.stop()
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
	control.stop()
	g.event("exit", map[string]any{"code": code})
	os.Exit(code)
}

// ---------------------------------------------------------------- policy file

// loadPolicyForRun resolves --policy, then <state-dir>/policy.yaml, then the
// built-in defaults. A policy that exists but cannot be read or parsed is a
// startup error; the guard never silently falls back to a weaker policy.
func loadPolicyForRun(explicitPath string, explicit bool, stateDir, serverName string, nameExplicit bool) (*policyFile, string, string, error) {
	var data []byte
	var pathUsed, source string
	if explicit {
		if explicitPath == "" {
			return nil, "flag", "", fmt.Errorf("--policy needs a file path")
		}
		pathUsed, source = explicitPath, "flag"
		b, err := os.ReadFile(pathUsed)
		if err != nil {
			return nil, source, pathUsed, fmt.Errorf("cannot read policy %s: %w", pathUsed, err)
		}
		data = b
	} else {
		pathUsed, source = filepath.Join(stateDir, policyFileName), "state-dir"
		b, err := os.ReadFile(pathUsed)
		if os.IsNotExist(err) {
			return defaultPolicyFile(), "builtin", "", nil
		}
		if err != nil {
			return nil, source, pathUsed, fmt.Errorf("cannot read policy %s: %w", pathUsed, err)
		}
		data = b
	}
	pf, err := parsePolicyBytes(data)
	if err != nil {
		return nil, source, pathUsed, fmt.Errorf("policy %s: %w", pathUsed, err)
	}
	if len(pf.Servers) > 0 {
		if _, ok := pf.Servers[serverName]; !ok && (nameExplicit || len(pf.Servers) != 1) {
			return nil, source, pathUsed, fmt.Errorf("policy %s: no entry for server %q; add servers.%s.tools or remove the servers block", pathUsed, serverName, serverName)
		}
	}
	return pf, source, pathUsed, nil
}

func defaultPolicyFile() *policyFile {
	spot := true
	return &policyFile{
		Version:        policyVersion,
		Approval:       "deny",
		Spotlight:      &spot,
		SensitivePaths: append([]string(nil), defaultSensitivePaths...),
		Egress:         &policyEgress{},
		Servers:        map[string]policyServer{},
	}
}

// UnmarshalJSON accepts both the canonical servers.<name>.tools.<tool> shape
// and the shorter servers.<name>.<tool> shape. A server entry that uses
// "tools" may not carry other keys; tool objects are always decoded strictly.
func (s *policyServer) UnmarshalJSON(data []byte) error {
	trim := bytes.TrimSpace(data)
	if bytes.Equal(trim, []byte("null")) {
		s.Tools = map[string]policyTool{}
		return nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(trim, &raw); err != nil {
		return err
	}
	if toolsRaw, ok := raw["tools"]; ok {
		if len(raw) != 1 {
			return fmt.Errorf("server entry has unknown fields alongside \"tools\"")
		}
		return decodePolicyJSON(toolsRaw, &s.Tools)
	}
	s.Tools = map[string]policyTool{}
	for name, value := range raw {
		var tool policyTool
		if err := decodePolicyJSON(value, &tool); err != nil {
			return fmt.Errorf("tool %q: %w", name, err)
		}
		s.Tools[name] = tool
	}
	return nil
}

func decodePolicyJSON(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("trailing data")
	}
	return nil
}

func parsePolicyBytes(data []byte) (*policyFile, error) {
	raw, err := parsePolicyRaw(data)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, fmt.Errorf("empty policy file")
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("cannot encode policy: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var pf policyFile
	if err := dec.Decode(&pf); err != nil {
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("trailing data after policy")
	}
	if err := validatePolicy(&pf); err != nil {
		return nil, err
	}
	return &pf, nil
}

func parsePolicyRaw(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("policy file is not valid UTF-8")
	}
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	trim := bytes.TrimSpace(data)
	if len(trim) == 0 {
		return nil, fmt.Errorf("empty policy file")
	}
	if trim[0] == '{' {
		if hasDuplicateKeys(trim) {
			return nil, fmt.Errorf("duplicate key in JSON policy")
		}
		dec := json.NewDecoder(bytes.NewReader(trim))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err == nil {
			var extra any
			if err := dec.Decode(&extra); err != io.EOF {
				return nil, fmt.Errorf("trailing data after JSON policy")
			}
			return v, nil
		}
		// Not JSON: accept a one-document flow-style YAML mapping as well.
		return parseYAMLFlow(string(trim))
	}
	if trim[0] == '[' {
		return nil, fmt.Errorf("top-level policy must be a mapping")
	}
	return parseYAML(trim)
}

func validatePolicy(pf *policyFile) error {
	if pf.Version != policyVersion {
		return fmt.Errorf("version must be %d", policyVersion)
	}
	if pf.Profile != "" {
		profile := strings.ToLower(strings.TrimSpace(pf.Profile))
		if profile != "auto" && profile != "none" && findBuiltinProfile(profile) == nil {
			return fmt.Errorf("profile must be auto, none or one of: %s", strings.Join(builtinProfileNames(), ", "))
		}
		pf.Profile = profile
	}
	if pf.Approval != "" && pf.Approval != "deny" && pf.Approval != "dialog" {
		return fmt.Errorf("approval must be deny or dialog")
	}
	for i, entry := range pf.Allowlist {
		if entry.Name != "" {
			if err := validatePolicyName("allowlist", entry.Name); err != nil {
				return fmt.Errorf("allowlist[%d]: %w", i, err)
			}
		}
		if entry.Command == "" || strings.TrimSpace(entry.Command) != entry.Command || hasUnsafePolicyChars(entry.Command) {
			return fmt.Errorf("allowlist[%d]: command must be non-empty without surrounding spaces or control/invisible characters", i)
		}
		if entry.Args == nil {
			return fmt.Errorf("allowlist[%d]: args is required; use [] for no arguments", i)
		}
		for j, arg := range *entry.Args {
			if strings.ContainsRune(arg, 0) {
				return fmt.Errorf("allowlist[%d]: args[%d] contains a NUL byte", i, j)
			}
		}
		if entry.SHA256 != "" {
			hash := strings.ToLower(strings.TrimSpace(entry.SHA256))
			if len(hash) != sha256.Size*2 {
				return fmt.Errorf("allowlist[%d]: sha256 must be 64 hexadecimal characters", i)
			}
			if _, err := hex.DecodeString(hash); err != nil {
				return fmt.Errorf("allowlist[%d]: sha256 must be 64 hexadecimal characters", i)
			}
			pf.Allowlist[i].SHA256 = hash
		}
		if entry.Lockfile != "" {
			if entry.SHA256 == "" {
				return fmt.Errorf("allowlist[%d]: lockfile requires sha256", i)
			}
			if strings.TrimSpace(entry.Lockfile) == "" || strings.ContainsRune(entry.Lockfile, 0) || hasUnsafePolicyChars(entry.Lockfile) {
				return fmt.Errorf("allowlist[%d]: lockfile is empty or contains control/invisible characters", i)
			}
		}
	}
	for i, p := range pf.SensitivePaths {
		norm, err := normalizePolicyGlob(p)
		if err != nil {
			return fmt.Errorf("sensitive_paths[%d]: %w", i, err)
		}
		pf.SensitivePaths[i] = norm
	}
	if pf.Egress != nil {
		for i, h := range pf.Egress.AllowHosts {
			norm, err := normalizePolicyHost(h)
			if err != nil {
				return fmt.Errorf("egress.allow_hosts[%d]: %w", i, err)
			}
			pf.Egress.AllowHosts[i] = norm
		}
		for i, h := range pf.Egress.DenyHosts {
			norm, err := normalizePolicyHost(h)
			if err != nil {
				return fmt.Errorf("egress.deny_hosts[%d]: %w", i, err)
			}
			pf.Egress.DenyHosts[i] = norm
		}
	}
	for name, srv := range pf.Servers {
		if err := validatePolicyName("server", name); err != nil {
			return err
		}
		for tname, tool := range srv.Tools {
			if err := validatePolicyName("tool", tname); err != nil {
				return fmt.Errorf("server %q: %w", name, err)
			}
			switch tool.Class {
			case "read", "write", "exec", "egress":
			default:
				return fmt.Errorf("server %q tool %q: class must be read, write, exec or egress", name, tname)
			}
			if len(tool.AllowPaths) > 0 && tool.Class != "write" {
				return fmt.Errorf("server %q tool %q: allow_paths is only valid for class write", name, tname)
			}
			seen := map[string]bool{}
			for i, k := range tool.PathKeys {
				k = strings.ToLower(strings.TrimSpace(k))
				if k == "" || hasUnsafePolicyChars(k) {
					return fmt.Errorf("server %q tool %q: path_keys[%d] is empty or contains control/invisible characters", name, tname, i)
				}
				if keyMatches(contentKeys, k) || keyMatches(urlKeys, k) || keyMatches(destinationKeys, k) {
					return fmt.Errorf("server %q tool %q: path_keys[%d] conflicts with a content, URL or destination key", name, tname, i)
				}
				norm := keyNormalizer.Replace(k)
				if seen[k] || seen[norm] {
					return fmt.Errorf("server %q tool %q: path_keys[%d] is duplicated", name, tname, i)
				}
				seen[k] = true
				seen[norm] = true
				tool.PathKeys[i] = k
			}
			for i, p := range tool.AllowPaths {
				if strings.TrimSpace(p) == "" || strings.TrimSpace(p) != p || hasUnsafePolicyChars(p) {
					return fmt.Errorf("server %q tool %q: allow_paths[%d] is empty or has surrounding spaces/control characters", name, tname, i)
				}
			}
		}
	}
	return nil
}

func hasUnsafePolicyChars(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) || isInvisible(r) {
			return true
		}
	}
	return false
}

func validatePolicyName(kind, name string) error {
	if name == "" || strings.TrimSpace(name) != name || hasUnsafePolicyChars(name) {
		return fmt.Errorf("%s name is empty or contains control/invisible characters", kind)
	}
	return nil
}

func normalizePolicyGlob(p string) (string, error) {
	if p == "" || strings.TrimSpace(p) != p || hasUnsafePolicyChars(p) {
		return "", fmt.Errorf("must be a non-empty pattern without surrounding spaces or control/invisible characters")
	}
	p = strings.ReplaceAll(p, `\`, "/")
	if _, err := path.Match(strings.ToLower(p), "x"); err != nil {
		return "", fmt.Errorf("invalid glob pattern")
	}
	return p, nil
}

func validHostPort(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535
}

func normalizePolicyHost(h string) (string, error) {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ".")
	if strings.Contains(h, "://") {
		return "", fmt.Errorf("must be a host name or *.host pattern without a scheme, path or spaces")
	}
	if strings.HasPrefix(h, "[") {
		if host, port, err := net.SplitHostPort(h); err == nil {
			if !validHostPort(port) {
				return "", fmt.Errorf("invalid port in host pattern")
			}
			h = host
		} else {
			h = strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
		}
	} else if !strings.Contains(h, "::") {
		if host, port, err := net.SplitHostPort(h); err == nil {
			if !validHostPort(port) {
				return "", fmt.Errorf("invalid port in host pattern")
			}
			h = host
		}
	}
	if h == "" || hasUnsafePolicyChars(h) ||
		strings.ContainsAny(h, " \t\r\n/?#@\\") || strings.Contains(h, "://") {
		return "", fmt.Errorf("must be a host name or *.host pattern without a scheme, path or spaces")
	}
	if _, err := path.Match(h, "host"); err != nil {
		return "", fmt.Errorf("invalid host pattern")
	}
	return h, nil
}

// applyPolicy merges the file with explicitly set flags. Flags replace the
// corresponding policy section rather than adding to it, so an operator can
// always recover the old behaviour with the old flag.
func (g *Guard) applyPolicy(pf *policyFile, profile *policyProfile, visited map[string]bool, readonlyFlag, trustFlag, approveFlag string, flagScratch []scratchRule, noSpot bool) {
	g.classes = map[string]string{}
	g.toolPathKeys = map[string]map[string]bool{}
	g.egressAllow = map[string]bool{}
	g.egressDeny = map[string]bool{}
	if pf.Egress != nil {
		g.egressAllow = policyHostSet(pf.Egress.AllowHosts)
		g.egressDeny = policyHostSet(pf.Egress.DenyHosts)
	}
	g.allowlistEnforced = false
	if pf.AllowlistEnforced != nil {
		g.allowlistEnforced = *pf.AllowlistEnforced
	} else if len(pf.Allowlist) > 0 {
		g.allowlistEnforced = true
	}
	g.allowlist = append([]policyAllowEntry(nil), pf.Allowlist...)

	g.approve = pf.Approval
	if g.approve == "" {
		g.approve = "deny"
	}
	if pf.Spotlight != nil {
		g.spotlight = *pf.Spotlight
	} else {
		g.spotlight = true
	}
	if visited["approve"] {
		g.approve = approveFlag
	}
	if visited["no-spotlight"] {
		g.spotlight = !noSpot
	}

	setSensitivePatterns(mergeSensitivePatterns(pf.SensitivePaths))

	g.readonly = map[string]bool{}
	g.readonlyOverride = visited["readonly"]
	if g.readonlyOverride {
		g.readonly = toSet(readonlyFlag)
	}
	g.trust = map[string]bool{}
	useFlagTrust := visited["trust"]
	if useFlagTrust {
		g.trust = toSet(trustFlag)
	}

	g.scratch = nil
	useFlagScratch := visited["allow-write-under"]
	if useFlagScratch {
		g.scratch = append([]scratchRule(nil), flagScratch...)
	}

	// Built-in profile first; an explicitly configured tool in the policy file
	// replaces its profile entry below.
	g.applyProfile(profile)

	var srv policyServer
	if len(pf.Servers) == 1 {
		for _, only := range pf.Servers {
			srv = only
		}
	} else if len(pf.Servers) > 1 {
		srv = pf.Servers[g.name] // loadPolicyForRun already required this entry
	}
	for tname, tool := range srv.Tools {
		// A policy entry is an explicit override, even when it only changes
		// allow_paths or path_keys, so clear any profile classification first.
		delete(g.readonly, tname)
		delete(g.classes, tname)
		switch tool.Class {
		case "read":
			if !g.readonlyOverride {
				g.readonly[tname] = true
			}
		case "write", "exec", "egress":
			g.classes[tname] = tool.Class
		}
		if len(tool.PathKeys) > 0 {
			keys := map[string]bool{}
			for _, k := range tool.PathKeys {
				keys[strings.ToLower(k)] = true
				keys[keyNormalizer.Replace(strings.ToLower(k))] = true
			}
			g.toolPathKeys[tname] = keys
		}
		if tool.Trust && !useFlagTrust {
			g.trust[tname] = true
		}
		if !useFlagScratch && tool.Class == "write" {
			for _, p := range tool.AllowPaths {
				dir := p
				if real, ok := canonicalPath(dir); ok {
					dir = real
				}
				g.scratch = append(g.scratch, scratchRule{tool: tname, dir: dir})
			}
		}
	}
}

func boolPtr(v bool) *bool { return &v }

func looksLikeCommandPath(s string) bool {
	return strings.ContainsAny(s, `/\`) || filepath.IsAbs(s) || isWindowsDrivePath(s)
}

func matchAllowedCommand(allowed, actual string) bool {
	if allowed == actual {
		return true
	}
	if runtime.GOOS == "windows" && strings.EqualFold(allowed, actual) {
		return true
	}
	if looksLikeCommandPath(allowed) && looksLikeCommandPath(actual) {
		return sameCommandPath(allowed, actual)
	}
	return false
}

func matchArgPattern(pattern, value string) bool {
	if pattern == value {
		return true
	}
	if !strings.ContainsAny(pattern, "*?") {
		return false
	}
	p := []rune(pattern)
	v := []rune(value)
	pi, vi := 0, 0
	star, matched := -1, 0
	for vi < len(v) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == v[vi]):
			pi++
			vi++
		case pi < len(p) && p[pi] == '*':
			star, matched = pi, vi
			pi++
		case star >= 0:
			pi = star + 1
			matched++
			vi = matched
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

func matchAllowedArgs(pattern, actual []string) bool {
	if len(pattern) != len(actual) {
		return false
	}
	for i := range pattern {
		if !matchArgPattern(pattern[i], actual[i]) {
			return false
		}
	}
	return true
}

func resolveCommandFile(command string) (string, bool) {
	if command == "" {
		return "", false
	}
	if looksLikeCommandPath(command) {
		if info, err := os.Stat(command); err == nil && !info.IsDir() {
			return command, true
		}
	}
	if resolved, err := exec.LookPath(command); err == nil {
		return resolved, true
	}
	return "", false
}

func hashFileSHA256(path string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), true
}

func makePolicyAllowEntry(name, command string, args []string) policyAllowEntry {
	copied := append([]string(nil), args...)
	entry := policyAllowEntry{Name: name, Command: command, Args: &copied}
	if path, ok := resolveCommandFile(command); ok {
		if sum, ok := hashFileSHA256(path); ok {
			entry.SHA256 = sum
		}
	}
	return entry
}

// checkServerAllowed enforces the allowlist before the child process is
// created. It never prints or returns argument values in the audit event; the
// caller only logs the command path and a short reason.
func (g *Guard) checkServerAllowed(args []string) (bool, string) {
	if !g.allowlistEnforced {
		return true, ""
	}
	if len(args) == 0 {
		return false, "server command is empty"
	}
	command := args[0]
	serverArgs := args[1:]
	mismatch := ""
	for _, entry := range g.allowlist {
		if !matchAllowedCommand(entry.Command, command) {
			continue
		}
		if entry.Args == nil || !matchAllowedArgs(*entry.Args, serverArgs) {
			continue
		}
		if entry.SHA256 == "" {
			return true, ""
		}
		target := entry.Lockfile
		if target == "" {
			resolved, ok := resolveCommandFile(command)
			if !ok {
				if mismatch == "" {
					mismatch = fmt.Sprintf("cannot resolve %q for SHA-256 verification", command)
				}
				continue
			}
			target = resolved
		}
		sum, ok := hashFileSHA256(target)
		if !ok {
			if mismatch == "" {
				mismatch = fmt.Sprintf("cannot read %s for SHA-256 verification", target)
			}
			continue
		}
		if !strings.EqualFold(sum, entry.SHA256) {
			if mismatch == "" {
				mismatch = fmt.Sprintf("allowlisted command or lockfile changed (SHA-256 mismatch for %q)", command)
			}
			continue
		}
		return true, ""
	}
	if mismatch != "" {
		return false, mismatch
	}
	return false, fmt.Sprintf("server command %q with the configured arguments is not allowlisted", command)
}

func printPolicyDeprecationNotes(visited map[string]bool, explicitPath, source string) {
	where := "the policy file (--policy PATH or <state-dir>/policy.yaml)"
	if explicitPath != "" {
		where = "--policy " + explicitPath
	} else if source == "state-dir" {
		where = "<state-dir>/policy.yaml"
	}
	note := func(flagName, equivalent string) {
		if visited[flagName] {
			fmt.Fprintf(os.Stderr, "[sylenix-guard] note: --%s is deprecated; use %s in %s.\n", flagName, equivalent, where)
		}
	}
	note("readonly", "servers.<name>.tools.<tool>.class: read")
	note("trust", "servers.<name>.tools.<tool>.trust: true")
	note("approve", "approval: deny|dialog")
	note("allow-write-under", "servers.<name>.tools.<tool>.allow_paths")
	note("no-spotlight", "spotlight: false")
}

func runPolicyCommand(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: sylenix-guard policy validate <file> | sylenix-guard policy print-default")
		return 2
	}
	switch args[0] {
	case "validate":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: sylenix-guard policy validate <file>")
			return 2
		}
		data, err := os.ReadFile(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "sylenix-guard policy validate: %v\n", err)
			return 2
		}
		pf, err := parsePolicyBytes(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sylenix-guard policy validate: %s: %v\n", args[1], err)
			return 2
		}
		servers := len(pf.Servers)
		tools := 0
		for _, srv := range pf.Servers {
			tools += len(srv.Tools)
		}
		fmt.Printf("policy %s: valid (version %d, %d server(s), %d tool(s))\n", args[1], pf.Version, servers, tools)
		return 0
	case "print-default":
		if len(args) != 1 {
			fmt.Fprintln(os.Stderr, "usage: sylenix-guard policy print-default")
			return 2
		}
		fmt.Print(defaultPolicyYAML())
		return 0
	default:
		fmt.Fprintf(os.Stderr, "sylenix-guard policy: unknown subcommand %q\n", args[0])
		return 2
	}
}

type allowMatch struct {
	configPath string
	command    string
	args       []string
}

// guardWrapperCommand returns the wrapped server command and its arguments.
// Guard flags may appear before the -- separator, so install can pin a custom
// policy or state directory in the wrapper.
func guardWrapperCommand(args []string) (string, []string, bool) {
	for i, arg := range args {
		if arg != "--" {
			continue
		}
		if i+1 >= len(args) {
			return "", nil, false
		}
		return args[i+1], args[i+2:], true
	}
	return "", nil, false
}

// configuredServerCommand returns the real stdio command for a config entry,
// unwrapping a Guard wrapper when install already wrapped it. Remote entries
// and malformed entries return false.
func configuredServerCommand(entry *configObject) (string, []string, bool) {
	if entry == nil || remoteConfigEntry(entry) {
		return "", nil, false
	}
	if value, ok := entry.get("type"); ok {
		text, ok := value.(string)
		if !ok {
			return "", nil, false
		}
		if text != "" && !strings.EqualFold(strings.TrimSpace(text), "stdio") {
			return "", nil, false
		}
	}
	value, ok := entry.get("command")
	if !ok {
		return "", nil, false
	}
	command, ok := value.(string)
	if !ok || command == "" {
		return "", nil, false
	}
	var args []string
	if value, ok := entry.get("args"); ok {
		list, ok := value.([]any)
		if !ok {
			return "", nil, false
		}
		for _, arg := range list {
			text, ok := arg.(string)
			if !ok {
				return "", nil, false
			}
			args = append(args, text)
		}
	}
	if _, wrapped := entry.get(guardMetaKey); wrapped || isGuardCommand(command, "") {
		return guardWrapperCommand(args)
	}
	return command, args, true
}

func findConfiguredServer(name string) ([]allowMatch, []error) {
	var matches []allowMatch
	var errs []error
	for _, target := range discoverConfigTargets() {
		info, err := os.Stat(target.path)
		if err != nil {
			if !os.IsNotExist(err) {
				errs = append(errs, fmt.Errorf("%s: %w", target.path, err))
			}
			continue
		}
		if info.IsDir() {
			continue
		}
		data, err := os.ReadFile(target.path)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", target.path, err))
			continue
		}
		if hasDuplicateKeys(data) {
			errs = append(errs, fmt.Errorf("%s: duplicate JSON keys", target.path))
			continue
		}
		root, err := parseConfigObject(data)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", target.path, err))
			continue
		}
		for _, serverPath := range target.serverPaths {
			serverMap, exists, err := lookupConfigMap(root, serverPath)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", target.path, err))
				continue
			}
			if !exists {
				continue
			}
			value, ok := serverMap.get(name)
			if !ok {
				continue
			}
			entry, ok := value.(*configObject)
			if !ok {
				errs = append(errs, fmt.Errorf("%s: server %q is not an object", target.path, name))
				continue
			}
			command, args, ok := configuredServerCommand(entry)
			if !ok {
				continue
			}
			matches = append(matches, allowMatch{configPath: target.path, command: command, args: args})
		}
	}
	return matches, errs
}

// collectConfiguredServers reads every supported MCP config and returns one
// allowlist entry per distinct stdio server command. A server name that maps to
// different commands in different configs is a conflict: the caller must not
// guess which one to approve.
func collectConfiguredServers() ([]policyAllowEntry, []error) {
	var entries []policyAllowEntry
	var errs []error
	seen := map[string]bool{}
	byName := map[string]policyAllowEntry{}
	for _, target := range discoverConfigTargets() {
		info, err := os.Stat(target.path)
		if err != nil {
			if !os.IsNotExist(err) {
				errs = append(errs, fmt.Errorf("%s: %w", target.path, err))
			}
			continue
		}
		if info.IsDir() {
			continue
		}
		data, err := os.ReadFile(target.path)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", target.path, err))
			continue
		}
		if hasDuplicateKeys(data) {
			errs = append(errs, fmt.Errorf("%s: refusing to edit a config with duplicate JSON keys", target.path))
			continue
		}
		root, err := parseConfigObject(data)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: cannot parse config: %w", target.path, err))
			continue
		}
		for _, serverPath := range target.serverPaths {
			serverMap, exists, err := lookupConfigMap(root, serverPath)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", target.path, err))
				continue
			}
			if !exists {
				continue
			}
			for _, name := range sortedObjectKeys(serverMap) {
				value, _ := serverMap.get(name)
				entry, ok := value.(*configObject)
				if !ok {
					continue
				}
				command, args, ok := configuredServerCommand(entry)
				if !ok {
					continue
				}
				key := name + "\x00" + command + "\x00" + strings.Join(args, "\x00")
				if seen[key] {
					continue
				}
				seen[key] = true
				candidate := makePolicyAllowEntry(name, command, args)
				if candidate.SHA256 == "" {
					fmt.Fprintf(os.Stderr, "[sylenix-guard] warning: cannot resolve %q for SHA-256 verification; no new hash will be recorded for %q\n", command, name)
				}
				if previous, ok := byName[name]; ok && !sameAllowEntry(previous, candidate) {
					errs = append(errs, fmt.Errorf("server %q has different commands in different configs; edit policy.yaml manually", name))
					continue
				}
				byName[name] = candidate
				entries = append(entries, candidate)
			}
		}
	}
	return entries, errs
}

func runAllowCommand(args []string) int {
	fs := flag.NewFlagSet("allow", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	policyPath := fs.String("policy", "", "policy file to update (default: <state-dir>/policy.yaml)")
	stateDir := fs.String("state-dir", "", "state directory for the default policy file (default ~/.sylenix-poc)")
	yes := fs.Bool("yes", false, "add without asking for confirmation")
	name := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if name == "" {
		if fs.NArg() != 1 {
			fmt.Fprintln(os.Stderr, "usage: sylenix-guard allow <name> [--policy PATH] [--state-dir DIR] [--yes]")
			return 2
		}
		name = fs.Arg(0)
	} else if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: sylenix-guard allow <name> [--policy PATH] [--state-dir DIR] [--yes]")
		return 2
	}
	matches, errs := findConfiguredServer(name)
	if len(errs) > 0 {
		for _, err := range errs {
			fmt.Fprintln(os.Stderr, "sylenix-guard allow:", err)
		}
		fmt.Fprintln(os.Stderr, "sylenix-guard allow: refusing to allow while a supported config cannot be read")
		return 2
	}
	if len(matches) == 0 {
		fmt.Fprintf(os.Stderr, "sylenix-guard allow: no server named %q found in a supported MCP config\n", name)
		return 2
	}
	unique := map[string]bool{}
	for _, match := range matches {
		key := match.command + "\x00" + strings.Join(match.args, "\x00")
		unique[key] = true
	}
	if len(unique) != 1 {
		fmt.Fprintf(os.Stderr, "sylenix-guard allow: server %q has different commands in different configs; edit policy.yaml manually\n", name)
		for _, match := range matches {
			argsJSON, _ := json.Marshal(match.args)
			fmt.Fprintf(os.Stderr, "  %s: %s %s\n", match.configPath, yamlPolicyString(match.command), argsJSON)
		}
		return 2
	}
	match := matches[0]
	path, err := policyWritePath(*policyPath, *stateDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard allow:", err)
		return 2
	}
	argsJSON, _ := json.Marshal(match.args)
	fmt.Printf("Server %q from %s:\n", name, match.configPath)
	fmt.Printf("  command: %s\n", yamlPolicyString(match.command))
	fmt.Printf("  args: %s\n", argsJSON)
	if !*yes {
		fmt.Printf("Add this exact command and arguments to %s? [y/N] ", path)
		answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		answer = strings.ToLower(strings.TrimSpace(answer))
		if answer != "y" && answer != "yes" {
			fmt.Println("not added")
			return 0
		}
	}
	pf, err := loadPolicyForUpdate(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard allow:", err)
		return 2
	}
	entry := makePolicyAllowEntry(name, match.command, match.args)
	if entry.SHA256 == "" {
		fmt.Fprintf(os.Stderr, "[sylenix-guard] warning: cannot resolve %q for SHA-256 verification; no new hash will be recorded\n", match.command)
	}
	if !mergeAllowEntries(pf, []policyAllowEntry{entry}) {
		fmt.Printf("already allowlisted in %s\n", path)
		return 0
	}
	if err := writePolicyFile(path, pf); err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard allow:", err)
		return 2
	}
	fmt.Printf("allowlisted %q in %s\n", name, path)
	return 0
}

func defaultPolicyYAML() string {
	var b strings.Builder
	b.WriteString("version: 1\nprofile: auto\napproval: deny\nspotlight: true\nsensitive_paths:\n")
	for _, p := range defaultSensitivePaths {
		quoted, _ := json.Marshal(p)
		fmt.Fprintf(&b, "  - %s\n", quoted)
	}
	b.WriteString("egress:\n  allow_hosts: []\n  deny_hosts: []\nallowlist_enforced: false\nallowlist: []\nservers: {}\n")
	return b.String()
}

// ---------------------------------------------------------------- built-in profiles

// Profile sources (tool lists read 2026-11-09):
//
//	filesystem  npm @modelcontextprotocol/server-filesystem 2.2.0
//	            https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem
//	git         PyPI mcp-server-git 2026.11.4
//	            https://github.com/modelcontextprotocol/servers/tree/main/src/git
//	github      github/github-mcp-server v2.1.0, plus the archived npm
//	            @modelcontextprotocol/server-github 2025.4.8 aliases
//	            https://github.com/github/github-mcp-server
//	fetch       PyPI mcp-server-fetch 2026.11.4
//	            https://github.com/modelcontextprotocol/servers/tree/main/src/fetch
//	shell       npm mcp-shell 0.1.3, @mkusaka/mcp-shell-server 0.1.1 and
//	            @mako10k/mcp-shell-server 2.8.1
//	            https://github.com/mkusaka/mcp-shell-server
//	            https://github.com/mako10k/mcp-shell-server
//	slack       npm @modelcontextprotocol/server-slack 2025.4.25
//	            https://github.com/modelcontextprotocol/servers-archived/tree/main/src/slack
//	postgres    npm @modelcontextprotocol/server-postgres 0.6.2 and
//	            postgres-mcp 0.3.0 (CrystalDBA)
//	            https://github.com/modelcontextprotocol/servers-archived/tree/main/src/postgres
//	            https://github.com/crystaldba/postgres-mcp
//	browser     npm @playwright/mcp 0.0.84 and
//	            @modelcontextprotocol/server-puppeteer 2025.5.12
//	            https://github.com/microsoft/playwright-mcp
//	            https://github.com/modelcontextprotocol/servers-archived/tree/main/src/puppeteer
//	notion      npm @notionhq/notion-mcp-server 2.6.1 (Notion API 2025-09-03)
//	            https://github.com/makenotion/notion-mcp-server
//	jira        PyPI mcp-atlassian 0.23.1
//	            https://github.com/sooperset/mcp-atlassian
//
// The classifications are deliberately conservative: anything that changes
// state is write, anything that runs code is exec, and anything that opens a
// network destination is egress. A policy file may override any entry.

func profileToolSet(class string, names ...string) map[string]string {
	m := make(map[string]string, len(names))
	for _, name := range names {
		m[name] = class
	}
	return m
}

func mergeProfileTools(sets ...map[string]string) map[string]string {
	m := make(map[string]string)
	for _, set := range sets {
		for name, class := range set {
			m[name] = class
		}
	}
	return m
}

var builtinProfiles = []policyProfile{
	{
		name:   "filesystem",
		source: "npm @modelcontextprotocol/server-filesystem 2.2.0",
		identifiers: []string{
			"@modelcontextprotocol/server-filesystem", "server-filesystem",
			"mcp-server-filesystem", "mcp_server_filesystem", "mcp/filesystem", "filesystem",
		},
		tools: mergeProfileTools(
			profileToolSet("read",
				"read_file", "read_text_file", "read_media_file", "read_multiple_files",
				"list_directory", "list_directory_with_sizes", "directory_tree",
				"search_files", "get_file_info", "list_allowed_directories",
			),
			profileToolSet("write",
				"write_file", "append_file", "edit_file", "create_directory",
				"move_file", "copy_file",
			),
		),
	},
	{
		name:   "git",
		source: "PyPI mcp-server-git 2026.11.4",
		identifiers: []string{
			"mcp-server-git", "mcp_server_git", "server-git", "mcp/git", "git",
		},
		tools: mergeProfileTools(
			profileToolSet("read",
				"git_status", "git_diff_unstaged", "git_diff_staged", "git_diff",
				"git_log", "git_show", "git_branch", "git_remote",
			),
			profileToolSet("write",
				"git_commit", "git_add", "git_reset", "git_create_branch",
				"git_checkout", "git_merge",
			),
		),
	},
	{
		name:   "github",
		source: "github/github-mcp-server v2.1.0; npm @modelcontextprotocol/server-github 2025.4.8",
		identifiers: []string{
			"github/github-mcp-server", "ghcr.io/github/github-mcp-server",
			"github-mcp-server", "@modelcontextprotocol/server-github",
			"server-github", "mcp-server-github", "mcp_server_github", "github",
		},
		tools: mergeProfileTools(
			profileToolSet("read",
				"actions_get", "actions_list", "get_job_logs",
				"get_code_quality_finding", "get_code_scanning_alert",
				"list_code_scanning_alerts", "get_dependabot_alert",
				"list_dependabot_alerts", "get_global_security_advisory",
				"list_global_security_advisories", "get_secret_scanning_alert",
				"list_secret_scanning_alerts", "list_org_repository_security_advisories",
				"list_repository_security_advisories", "get_me", "get_team_members",
				"get_teams", "ui_get", "get_discussion", "get_discussion_comments",
				"list_discussion_categories", "list_discussions", "get_gist", "list_gists",
				"get_label", "list_label", "get_latest_release", "get_release_by_tag",
				"list_releases", "get_notification_details", "list_notifications",
				"get_repository_tree", "get_tag", "list_tags", "issue_read",
				"list_branches", "list_commits", "get_commit", "list_issue_fields",
				"list_issue_types", "list_issues", "list_pull_requests",
				"list_repository_collaborators", "list_starred_repositories",
				"projects_get", "projects_list", "pull_request_read",
				"repository_ruleset_read", "custom_properties_read",
				"get_copilot_space", "list_copilot_spaces", "github_support_docs_search",
				"search_code", "search_commits", "search_issues", "search_orgs",
				"search_pull_requests", "search_repositories", "search_users",
				"get_file_contents", "get_issue", "get_pull_request",
				"get_pull_request_files", "get_pull_request_status",
				"get_pull_request_comments", "get_pull_request_reviews",
			),
			profileToolSet("write",
				"actions_run_trigger", "add_comment_to_pending_review",
				"add_issue_comment", "add_reply_to_pull_request_comment",
				"assign_copilot_to_issue", "assign_copilot_to_issue_with_intent",
				"create_branch", "create_gist", "create_or_update_file",
				"create_pull_request", "create_pull_request_with_copilot",
				"create_repository", "create_repository_ruleset",
				"custom_properties_write", "delete_file", "delete_repository",
				"discussion_comment_write", "dismiss_notification", "fork_repository",
				"issue_write", "label_write", "manage_notification_subscription",
				"manage_repository_notification_subscription", "mark_all_notifications_read",
				"merge_pull_request", "projects_write", "pull_request_review_write",
				"push_files", "request_copilot_review", "star_repository",
				"sub_issue_write", "unstar_repository", "update_gist",
				"update_issue_comment", "update_pull_request", "update_pull_request_branch",
				"create_issue", "update_issue", "create_pull_request_review",
			),
		),
	},
	{
		name:        "fetch",
		source:      "PyPI mcp-server-fetch 2026.11.4",
		identifiers: []string{"mcp-server-fetch", "mcp_server_fetch", "server-fetch", "mcp/fetch", "fetch"},
		tools:       profileToolSet("egress", "fetch"),
	},
	{
		name:   "shell",
		source: "npm mcp-shell 0.1.3; @mkusaka/mcp-shell-server 0.1.1; @mako10k/mcp-shell-server 2.8.1",
		identifiers: []string{
			"@mkusaka/mcp-shell-server", "@mako10k/mcp-shell-server",
			"mcp-shell-server", "mcp-shell", "shell-mcp", "shell",
		},
		tools: mergeProfileTools(
			profileToolSet("read",
				"process_get_execution", "list_execution_outputs", "read_execution_output",
				"get_cleanup_suggestions", "terminal_list", "terminal_get_info",
				"command_history_query",
			),
			profileToolSet("exec",
				"run_command", "shell_exec", "shell_execute", "execute_command",
				"run_shell_command", "shell_set_default_workdir", "delete_execution_outputs",
				"perform_auto_cleanup", "terminal_operate", "terminal_close",
			),
		),
	},
	{
		name:   "slack",
		source: "npm @modelcontextprotocol/server-slack 2025.4.25",
		identifiers: []string{
			"@modelcontextprotocol/server-slack", "server-slack", "mcp-server-slack",
			"mcp_server_slack", "mcp/slack", "slack",
		},
		tools: mergeProfileTools(
			profileToolSet("read",
				"slack_list_channels", "slack_get_channel_history",
				"slack_get_thread_replies", "slack_get_users", "slack_get_user_profile",
			),
			profileToolSet("write",
				"slack_post_message", "slack_reply_to_thread", "slack_add_reaction",
			),
		),
	},
	{
		name:   "postgres",
		source: "npm @modelcontextprotocol/server-postgres 0.6.2; postgres-mcp 0.3.0",
		identifiers: []string{
			"@modelcontextprotocol/server-postgres", "server-postgres",
			"mcp-server-postgres", "mcp_server_postgres", "postgres-mcp",
			"mcp/postgres", "postgres",
		},
		tools: mergeProfileTools(
			profileToolSet("read",
				"query", "list_schemas", "list_objects", "get_object_details",
				"explain_query", "get_top_queries", "analyze_workload_indexes",
				"analyze_query_indexes", "analyze_db_health",
			),
			profileToolSet("write", "execute_sql"),
		),
	},
	{
		// Playwright's readOnlyHint marks some recording/video/PDF helpers
		// read-only; this profile keeps them write because they create files or
		// change page state. wait_for/verify only observe, so they stay read.
		name:   "browser",
		source: "npm @playwright/mcp 0.0.84; @modelcontextprotocol/server-puppeteer 2025.5.12",
		identifiers: []string{
			"@playwright/mcp", "playwright-mcp", "playwright_mcp", "mcp/playwright",
			"playwright", "mcr.microsoft.com/playwright/mcp",
			"@modelcontextprotocol/server-puppeteer", "server-puppeteer",
			"mcp-server-puppeteer", "mcp_server_puppeteer", "mcp/puppeteer",
			"puppeteer", "browser",
		},
		tools: mergeProfileTools(
			profileToolSet("read",
				"browser_console_messages", "browser_cookie_get", "browser_cookie_list",
				"browser_find", "browser_generate_locator", "browser_get_config",
				"browser_localstorage_get", "browser_localstorage_list",
				"browser_network_request", "browser_network_requests",
				"browser_route_list", "browser_sessionstorage_get",
				"browser_sessionstorage_list", "browser_snapshot", "browser_storage_state",
				"browser_take_screenshot", "browser_verify_element_visible",
				"browser_verify_list_visible", "browser_verify_text_visible",
				"browser_verify_value", "browser_wait_for", "puppeteer_screenshot",
			),
			profileToolSet("write",
				"browser_annotate", "browser_click", "browser_close",
				"browser_cookie_clear", "browser_cookie_delete", "browser_cookie_set",
				"browser_drag", "browser_drop", "browser_emulate_media",
				"browser_file_upload", "browser_fill_form", "browser_handle_dialog",
				"browser_hide_highlight", "browser_highlight", "browser_hover",
				"browser_localstorage_clear",
				"browser_localstorage_delete", "browser_localstorage_set",
				"browser_mouse_click_xy", "browser_mouse_down", "browser_mouse_drag_xy",
				"browser_mouse_move_xy", "browser_mouse_up", "browser_mouse_wheel",
				"browser_network_state_set", "browser_pdf_save", "browser_press_key",
				"browser_resize", "browser_resume", "browser_route",
				"browser_sessionstorage_clear", "browser_sessionstorage_delete",
				"browser_sessionstorage_set", "browser_set_storage_state",
				"browser_select_option", "browser_start_recording", "browser_start_tracing",
				"browser_start_video", "browser_stop_recording", "browser_stop_tracing",
				"browser_stop_video", "browser_tabs", "browser_type", "browser_unroute",
				"browser_video_chapter",
				"browser_video_hide_actions", "browser_video_show_actions",
				"puppeteer_click", "puppeteer_fill", "puppeteer_hover", "puppeteer_select",
			),
			profileToolSet("exec",
				"browser_evaluate", "browser_install", "browser_run_code_unsafe",
				"puppeteer_evaluate",
			),
			profileToolSet("egress",
				"browser_navigate", "browser_navigate_back", "browser_navigate_forward",
				"puppeteer_navigate",
			),
		),
	},
	{
		name:   "notion",
		source: "npm @notionhq/notion-mcp-server 2.6.1 (Notion API 2025-09-03)",
		identifiers: []string{
			"@notionhq/notion-mcp-server", "notion-mcp-server", "notion_mcp_server",
			"mcp/notion", "notion",
		},
		tools: mergeProfileTools(
			profileToolSet("read",
				"get-self", "get-user", "get-users", "post-search", "get-block-children",
				"retrieve-a-block", "retrieve-a-page", "retrieve-a-page-property",
				"retrieve-a-comment", "retrieve-a-data-source", "retrieve-a-database",
				"retrieve-page-markdown", "list-data-source-templates", "query-data-source",
				"search", "fetch", "get-comments", "get-teams",
			),
			profileToolSet("write",
				"create-a-comment", "create-a-data-source", "delete-a-block", "move-page",
				"patch-block-children", "patch-page", "post-page", "update-a-block",
				"update-a-data-source", "update-page-markdown", "create-pages",
				"update-page", "move-pages", "duplicate-page", "create-database",
				"update-database", "create-comment",
			),
		),
	},
	{
		name:   "jira",
		source: "PyPI mcp-atlassian 0.23.1",
		identifiers: []string{
			"mcp-atlassian", "@sooperset/mcp-atlassian", "mcp_atlassian",
			"mcp-atlassian-extended", "jira-mcp-atlassian", "atlassian", "jira",
		},
		tools: mergeProfileTools(
			profileToolSet("read",
				"get_user_profile", "search_assignable_users", "get_issue_watchers",
				"get_issue", "search", "search_fields", "get_field_options",
				"get_project_issues", "get_transitions", "get_worklog",
				"download_attachments", "get_issue_images", "get_agile_boards",
				"get_board_issues", "get_sprints_from_board", "get_sprint_issues",
				"get_link_types", "batch_get_changelogs", "get_project_issue_types",
				"get_create_fields", "get_project_versions", "get_project_components",
				"get_all_projects", "search_projects", "get_project_fields",
				"get_service_desk_for_project", "get_service_desk_queues",
				"get_queue_issues", "get_request_types", "get_request_type_fields",
				"get_issue_proforma_forms", "get_proforma_form_details", "get_issue_dates",
				"get_issue_sla", "get_issue_development_info", "get_issues_development_info",
				"get_project_epic_hierarchy", "get_cross_project_dependencies",
				"jira_get_issue", "jira_search", "jira_search_fields",
				"jira_search_assignable_users", "jira_get_transitions", "jira_get_worklog",
				"jira_get_user_profile", "jira_get_issue_watchers", "jira_get_issue_images",
				"jira_download_attachments", "jira_get_project_issues",
				"jira_get_projects", "jira_get_all_projects", "jira_search_projects",
				"jira_get_issue_types", "jira_get_create_fields", "jira_get_project_fields",
				"jira_get_project_versions", "jira_get_project_components",
				"jira_get_agile_boards", "jira_get_board_issues",
				"jira_get_sprints_from_board", "jira_get_sprint_issues",
				"jira_get_link_types", "jira_batch_get_changelogs",
				"jira_get_comments", "jira_get_priorities", "jira_get_statuses",
				"jira_get_service_desk_for_project", "jira_get_service_desk_queues",
				"jira_get_queue_issues", "jira_get_request_types",
				"jira_get_request_type_fields", "jira_get_issue_proforma_forms",
				"jira_get_proforma_form_details", "jira_get_issue_dates", "jira_get_issue_sla",
				"jira_get_issue_development_info", "jira_get_issues_development_info",
				"jira_get_project_epic_hierarchy", "jira_get_cross_project_dependencies",
			),
			profileToolSet("write",
				"add_watcher", "remove_watcher", "create_issue", "batch_create_issues",
				"update_issue", "assign_issue", "delete_issue", "move_issue",
				"add_comment", "edit_comment", "add_worklog", "link_to_epic",
				"create_issue_link", "create_remote_issue_link", "remove_issue_link",
				"transition_issue", "create_sprint", "update_sprint",
				"add_issues_to_sprint", "move_issues_to_backlog", "create_version",
				"batch_create_versions", "update_version", "create_customer_request",
				"update_proforma_form_answers", "jira_add_watcher", "jira_remove_watcher",
				"jira_create_issue", "jira_batch_create_issues", "jira_update_issue",
				"jira_assign_issue", "jira_delete_issue", "jira_move_issue",
				"jira_add_comment", "jira_edit_comment", "jira_add_worklog",
				"jira_link_to_epic", "jira_create_issue_link",
				"jira_create_remote_issue_link", "jira_remove_issue_link",
				"jira_transition_issue", "jira_create_sprint", "jira_update_sprint",
				"jira_add_issues_to_sprint", "jira_move_issues_to_backlog",
				"jira_create_version", "jira_batch_create_versions", "jira_update_version",
				"jira_create_customer_request", "jira_update_proforma_form_answers",
			),
		),
	},
}

func findBuiltinProfile(name string) *policyProfile {
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case "playwright", "puppeteer":
		name = "browser"
	case "postgresql":
		name = "postgres"
	case "atlassian":
		name = "jira"
	}
	for i := range builtinProfiles {
		if builtinProfiles[i].name == name {
			return &builtinProfiles[i]
		}
	}
	return nil
}

func builtinProfileNames() []string {
	names := make([]string, 0, len(builtinProfiles))
	for _, p := range builtinProfiles {
		names = append(names, p.name)
	}
	sort.Strings(names)
	return names
}

func normalizeProfileToken(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	t = strings.Trim(t, `"'`)
	t = strings.TrimSuffix(t, ".exe")
	t = strings.TrimPrefix(t, "./")
	if i := strings.LastIndex(t, "@"); i > 0 {
		t = t[:i] // @scope/pkg@version -> @scope/pkg
	}
	return t
}

func profileMatchTokens(args []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(t string) {
		t = normalizeProfileToken(t)
		if t != "" && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	for _, arg := range args {
		add(arg)
		add(path.Base(strings.ReplaceAll(arg, `\`, "/")))
		add(filepath.Base(arg))
	}
	return out
}

func profileMatchScore(p *policyProfile, tokens []string) int {
	best := 0
	for _, identifier := range p.identifiers {
		id := normalizeProfileToken(identifier)
		for _, token := range tokens {
			score := 0
			switch {
			case token == id:
				score = 1000 + len(id)
			case strings.HasSuffix(token, "/"+id):
				score = 500 + len(id)
			case strings.Contains(token, id):
				score = 100 + len(id)
			}
			if score > best {
				best = score
			}
		}
	}
	return best
}

// selectPolicyProfile applies policy.profile first, then auto-detection by
// server command/package token, then the --name label as a last resort.
func selectPolicyProfile(name string, serverArgs []string, override string) *policyProfile {
	switch strings.ToLower(strings.TrimSpace(override)) {
	case "none":
		return nil
	case "", "auto":
		// auto-detect below
	default:
		return findBuiltinProfile(override)
	}
	tokens := profileMatchTokens(serverArgs)
	var best *policyProfile
	bestScore := 0
	for i := range builtinProfiles {
		score := profileMatchScore(&builtinProfiles[i], tokens)
		if score > bestScore {
			bestScore = score
			best = &builtinProfiles[i]
		}
	}
	if best != nil {
		return best
	}
	return findBuiltinProfile(name)
}

func (g *Guard) applyProfile(profile *policyProfile) {
	if profile == nil {
		return
	}
	// A profile's read tools are allowed after taint without a prompt. This is
	// the default when no --readonly override is set; an explicit --readonly
	// list or policy class remains a replacement, never a widening.
	for tool, class := range profile.tools {
		switch class {
		case "read":
			if !g.readonlyOverride {
				g.readonly[tool] = true
			}
		case "write", "exec", "egress":
			g.classes[tool] = class
		}
	}
}

func yamlPolicyString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func writePolicyYAMLList(b *strings.Builder, indent int, key string, values []string) {
	pad := strings.Repeat(" ", indent)
	if len(values) == 0 {
		fmt.Fprintf(b, "%s%s: []\n", pad, key)
		return
	}
	fmt.Fprintf(b, "%s%s:\n", pad, key)
	for _, value := range values {
		fmt.Fprintf(b, "%s  - %s\n", pad, yamlPolicyString(value))
	}
}

func sortedPolicyServerNames(m map[string]policyServer) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func sortedPolicyToolNames(m map[string]policyTool) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func marshalPolicyYAML(pf *policyFile) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "version: %d\n", pf.Version)
	if pf.Profile != "" {
		fmt.Fprintf(&b, "profile: %s\n", yamlPolicyString(pf.Profile))
	}
	if pf.Approval != "" {
		fmt.Fprintf(&b, "approval: %s\n", yamlPolicyString(pf.Approval))
	}
	if pf.Spotlight != nil {
		fmt.Fprintf(&b, "spotlight: %t\n", *pf.Spotlight)
	}
	if len(pf.SensitivePaths) > 0 {
		writePolicyYAMLList(&b, 0, "sensitive_paths", pf.SensitivePaths)
	}
	if pf.Egress != nil {
		b.WriteString("egress:\n")
		writePolicyYAMLList(&b, 2, "allow_hosts", pf.Egress.AllowHosts)
		writePolicyYAMLList(&b, 2, "deny_hosts", pf.Egress.DenyHosts)
	}
	enforced := false
	if pf.AllowlistEnforced != nil {
		enforced = *pf.AllowlistEnforced
	} else if len(pf.Allowlist) > 0 {
		enforced = true
	}
	if pf.AllowlistEnforced != nil || len(pf.Allowlist) > 0 {
		fmt.Fprintf(&b, "allowlist_enforced: %t\n", enforced)
	}
	if len(pf.Allowlist) > 0 {
		b.WriteString("allowlist:\n")
		for _, entry := range pf.Allowlist {
			fmt.Fprintf(&b, "  - name: %s\n", yamlPolicyString(entry.Name))
			fmt.Fprintf(&b, "    command: %s\n", yamlPolicyString(entry.Command))
			if entry.Args == nil || len(*entry.Args) == 0 {
				b.WriteString("    args: []\n")
			} else {
				b.WriteString("    args:\n")
				for _, arg := range *entry.Args {
					fmt.Fprintf(&b, "      - %s\n", yamlPolicyString(arg))
				}
			}
			if entry.SHA256 != "" {
				fmt.Fprintf(&b, "    sha256: %s\n", yamlPolicyString(entry.SHA256))
			}
			if entry.Lockfile != "" {
				fmt.Fprintf(&b, "    lockfile: %s\n", yamlPolicyString(entry.Lockfile))
			}
		}
	} else if pf.AllowlistEnforced != nil && *pf.AllowlistEnforced {
		b.WriteString("allowlist: []\n")
	}
	if len(pf.Servers) > 0 {
		b.WriteString("servers:\n")
		for _, serverName := range sortedPolicyServerNames(pf.Servers) {
			server := pf.Servers[serverName]
			fmt.Fprintf(&b, "  %s:\n", yamlPolicyString(serverName))
			if len(server.Tools) == 0 {
				b.WriteString("    tools: {}\n")
				continue
			}
			b.WriteString("    tools:\n")
			for _, toolName := range sortedPolicyToolNames(server.Tools) {
				tool := server.Tools[toolName]
				fmt.Fprintf(&b, "      %s:\n", yamlPolicyString(toolName))
				fmt.Fprintf(&b, "        class: %s\n", yamlPolicyString(tool.Class))
				if len(tool.PathKeys) > 0 {
					writePolicyYAMLList(&b, 8, "path_keys", tool.PathKeys)
				}
				if len(tool.AllowPaths) > 0 {
					writePolicyYAMLList(&b, 8, "allow_paths", tool.AllowPaths)
				}
				if tool.Trust {
					b.WriteString("        trust: true\n")
				}
			}
		}
	}
	return []byte(b.String())
}

func policyWritePath(explicit, stateDir string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if stateDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot find home directory; pass --state-dir or --policy")
		}
		stateDir = filepath.Join(home, ".sylenix-poc")
	}
	return filepath.Join(stateDir, policyFileName), nil
}

func loadPolicyForUpdate(path string) (*policyFile, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &policyFile{
			Version:           policyVersion,
			AllowlistEnforced: boolPtr(true),
			Allowlist:         []policyAllowEntry{},
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read policy %s: %w", path, err)
	}
	pf, err := parsePolicyBytes(b)
	if err != nil {
		return nil, fmt.Errorf("policy %s: %w", path, err)
	}
	return pf, nil
}

func sameAllowArgs(a, b *[]string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if len(*a) != len(*b) {
		return false
	}
	for i := range *a {
		if (*a)[i] != (*b)[i] {
			return false
		}
	}
	return true
}

func sameAllowEntry(a, b policyAllowEntry) bool {
	return a.Name == b.Name && a.Command == b.Command && a.SHA256 == b.SHA256 &&
		a.Lockfile == b.Lockfile && sameAllowArgs(a.Args, b.Args)
}

func mergeAllowEntries(pf *policyFile, entries []policyAllowEntry) bool {
	changed := false
	if pf.AllowlistEnforced == nil || !*pf.AllowlistEnforced {
		pf.AllowlistEnforced = boolPtr(true)
		changed = true
	}
	for _, entry := range entries {
		replaced := false
		for i := range pf.Allowlist {
			if entry.Name != "" && pf.Allowlist[i].Name == entry.Name {
				// Do not drop a hash just because the command cannot be
				// resolved right now; keep it while command and args agree.
				if entry.SHA256 == "" && pf.Allowlist[i].SHA256 != "" &&
					entry.Command == pf.Allowlist[i].Command && sameAllowArgs(entry.Args, pf.Allowlist[i].Args) {
					entry.SHA256 = pf.Allowlist[i].SHA256
					entry.Lockfile = pf.Allowlist[i].Lockfile
				}
				if !sameAllowEntry(pf.Allowlist[i], entry) {
					pf.Allowlist[i] = entry
					changed = true
				}
				replaced = true
				break
			}
		}
		if replaced {
			continue
		}
		duplicate := false
		for i := range pf.Allowlist {
			if sameAllowEntry(pf.Allowlist[i], entry) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			pf.Allowlist = append(pf.Allowlist, entry)
			changed = true
		}
	}
	return changed
}

func writePolicyFile(path string, pf *policyFile) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeConfigAtomic(path, marshalPolicyYAML(pf), 0o600)
}

func writeDefaultPolicyFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeConfigAtomic(path, []byte(defaultPolicyYAML()), 0o600)
}

// ---------------------------------------------------------------- strict YAML subset

// The policy loader intentionally supports only the YAML needed by the schema:
// block mappings, block sequences of scalars, flow sequences/mappings, quoted
// and plain scalars, comments and a leading document marker. Anchors, aliases,
// tags, block scalars and multiple documents are refused instead of guessed.

type yamlLine struct {
	indent int
	text   string
	number int
}

func parseYAML(data []byte) (any, error) {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	lines, err := yamlLines(text)
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty YAML document")
	}
	if lines[0].text == "---" {
		lines = lines[1:]
		if len(lines) == 0 {
			return nil, fmt.Errorf("empty YAML document")
		}
	}
	if lines[0].indent != 0 {
		return nil, fmt.Errorf("line %d: top-level mapping must not be indented", lines[0].number)
	}
	pos := 0
	v, err := parseYAMLBlock(lines, &pos, 0)
	if err != nil {
		return nil, err
	}
	if pos < len(lines) {
		if lines[pos].text == "..." {
			pos++
		}
		if pos < len(lines) {
			return nil, fmt.Errorf("line %d: unexpected content", lines[pos].number)
		}
	}
	return v, nil
}

func yamlLines(text string) ([]yamlLine, error) {
	raw := strings.Split(text, "\n")
	out := make([]yamlLine, 0, len(raw))
	for i, line := range raw {
		if strings.ContainsRune(line, 0) {
			return nil, fmt.Errorf("line %d: NUL byte", i+1)
		}
		line = stripYAMLComment(line)
		line = strings.TrimRight(line, " \t")
		if strings.TrimSpace(line) == "" {
			continue
		}
		indent := 0
		for indent < len(line) && line[indent] == ' ' {
			indent++
		}
		if indent < len(line) && line[indent] == '\t' {
			return nil, fmt.Errorf("line %d: tab indentation is not supported", i+1)
		}
		body := line[indent:]
		if body == "" {
			continue
		}
		out = append(out, yamlLine{indent: indent, text: body, number: i + 1})
	}
	return out, nil
}

func stripYAMLComment(s string) string {
	inSingle, inDouble, escaped := false, false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inDouble {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == '"' {
				inDouble = false
			}
			continue
		}
		if inSingle {
			if c == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					i++
					continue
				}
				inSingle = false
			}
			continue
		}
		switch c {
		case '"':
			inDouble = true
		case '\'':
			inSingle = true
		case '#':
			if i == 0 || s[i-1] == ' ' || s[i-1] == '\t' {
				return s[:i]
			}
		}
	}
	return s
}

func isYAMLSequenceLine(text string) bool {
	return text == "-" || strings.HasPrefix(text, "- ")
}

func parseYAMLBlock(lines []yamlLine, pos *int, indent int) (any, error) {
	if *pos >= len(lines) {
		return nil, nil
	}
	if lines[*pos].indent != indent {
		return nil, fmt.Errorf("line %d: unexpected indentation", lines[*pos].number)
	}
	if isYAMLSequenceLine(lines[*pos].text) {
		return parseYAMLSequence(lines, pos, indent)
	}
	return parseYAMLMap(lines, pos, indent)
}

func parseYAMLSequence(lines []yamlLine, pos *int, indent int) ([]any, error) {
	out := []any{}
	for *pos < len(lines) {
		line := lines[*pos]
		if line.indent < indent {
			break
		}
		if line.indent > indent {
			return nil, fmt.Errorf("line %d: unexpected indentation", line.number)
		}
		if !isYAMLSequenceLine(line.text) {
			break
		}
		rest := strings.TrimSpace(line.text[1:])
		*pos = *pos + 1
		if rest == "" {
			if *pos < len(lines) && lines[*pos].indent > indent {
				child, err := parseYAMLBlock(lines, pos, lines[*pos].indent)
				if err != nil {
					return nil, err
				}
				out = append(out, child)
			} else {
				out = append(out, nil)
			}
			continue
		}
		if rest[0] != '[' && rest[0] != '{' {
			if _, _, keyErr := splitYAMLKey(rest); keyErr == nil {
				spaces := 0
				for i := 1; i < len(line.text) && line.text[i] == ' '; i++ {
					spaces++
				}
				itemIndent := indent + 1 + spaces
				sub := []yamlLine{{indent: itemIndent, text: rest, number: line.number}}
				for *pos < len(lines) && lines[*pos].indent > indent {
					sub = append(sub, lines[*pos])
					*pos = *pos + 1
				}
				local := 0
				child, err := parseYAMLBlock(sub, &local, itemIndent)
				if err != nil {
					return nil, err
				}
				if local != len(sub) {
					return nil, fmt.Errorf("line %d: unexpected indentation in sequence item", sub[local].number)
				}
				out = append(out, child)
				continue
			}
		}
		v, err := parseYAMLValue(rest)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line.number, err)
		}
		out = append(out, v)
		if *pos < len(lines) && lines[*pos].indent > indent {
			return nil, fmt.Errorf("line %d: unexpected indentation after sequence item", lines[*pos].number)
		}
	}
	return out, nil
}

func parseYAMLMap(lines []yamlLine, pos *int, indent int) (map[string]any, error) {
	out := map[string]any{}
	for *pos < len(lines) {
		line := lines[*pos]
		if line.indent < indent {
			break
		}
		if line.indent > indent {
			return nil, fmt.Errorf("line %d: unexpected indentation", line.number)
		}
		if isYAMLSequenceLine(line.text) {
			break
		}
		key, rest, err := splitYAMLKey(line.text)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line.number, err)
		}
		if _, exists := out[key]; exists {
			return nil, fmt.Errorf("line %d: duplicate key %q", line.number, key)
		}
		*pos = *pos + 1
		var v any
		if rest == "" {
			// YAML also permits an indentless sequence directly below a key:
			//   sensitive_paths:
			//   - .env
			if *pos < len(lines) && (lines[*pos].indent > indent ||
				(lines[*pos].indent == indent && isYAMLSequenceLine(lines[*pos].text))) {
				child, err := parseYAMLBlock(lines, pos, lines[*pos].indent)
				if err != nil {
					return nil, err
				}
				v = child
			}
		} else {
			v, err = parseYAMLValue(rest)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", line.number, err)
			}
			if *pos < len(lines) && lines[*pos].indent > indent {
				return nil, fmt.Errorf("line %d: unexpected indentation after value", lines[*pos].number)
			}
		}
		out[key] = v
	}
	return out, nil
}

func splitYAMLKey(text string) (string, string, error) {
	if text == "" {
		return "", "", fmt.Errorf("empty mapping line")
	}
	var key string
	var i int
	if text[0] == '"' || text[0] == '\'' {
		q, end, err := parseYAMLQuotedPrefix(text)
		if err != nil {
			return "", "", err
		}
		key = q
		i = end
		for i < len(text) && (text[i] == ' ' || text[i] == '\t') {
			i++
		}
		if i >= len(text) || text[i] != ':' {
			return "", "", fmt.Errorf("expected ':' after quoted key")
		}
	} else {
		found := -1
		for j := 0; j < len(text); j++ {
			if text[j] == ':' && (j+1 == len(text) || text[j+1] == ' ' || text[j+1] == '\t') {
				found = j
				break
			}
		}
		if found < 0 {
			return "", "", fmt.Errorf("expected key: value")
		}
		key = strings.TrimSpace(text[:found])
		i = found
	}
	if key == "" {
		return "", "", fmt.Errorf("empty mapping key")
	}
	return key, strings.TrimSpace(text[i+1:]), nil
}

func parseYAMLValue(s string) (any, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if s == "[]" {
		return []any{}, nil
	}
	if s == "{}" {
		return map[string]any{}, nil
	}
	switch s[0] {
	case '[', '{':
		return parseYAMLFlow(s)
	case '|', '>':
		return nil, fmt.Errorf("block scalars are not supported")
	case '&', '!', '%', '@', '`':
		return nil, fmt.Errorf("unsupported YAML feature")
	case '"', '\'':
		v, end, err := parseYAMLQuotedPrefix(s)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(s[end:]) != "" {
			return nil, fmt.Errorf("unexpected text after quoted value")
		}
		return v, nil
	}
	return parseYAMLPlain(s)
}

func parseYAMLQuotedPrefix(s string) (string, int, error) {
	if s == "" {
		return "", 0, fmt.Errorf("empty quoted value")
	}
	if s[0] == '"' {
		escaped := false
		for i := 1; i < len(s); i++ {
			if escaped {
				escaped = false
				continue
			}
			if s[i] == '\\' {
				escaped = true
				continue
			}
			if s[i] == '"' {
				var out string
				if err := json.Unmarshal([]byte(s[:i+1]), &out); err != nil {
					return "", 0, fmt.Errorf("invalid double-quoted string: %w", err)
				}
				return out, i + 1, nil
			}
		}
		return "", 0, fmt.Errorf("unterminated double-quoted string")
	}
	if s[0] == '\'' {
		var b strings.Builder
		for i := 1; i < len(s); i++ {
			if s[i] == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					b.WriteByte('\'')
					i++
					continue
				}
				return b.String(), i + 1, nil
			}
			b.WriteByte(s[i])
		}
		return "", 0, fmt.Errorf("unterminated single-quoted string")
	}
	return "", 0, fmt.Errorf("not a quoted string")
}

func parseYAMLPlain(s string) (any, error) {
	s = strings.TrimSpace(s)
	if strings.ContainsAny(s, "\n\r") || strings.ContainsRune(s, 0) {
		return nil, fmt.Errorf("invalid scalar")
	}
	// Anchors and tags are rejected above. A bare *name is an alias; wildcard
	// patterns such as *.example.com or *secret* are still plain strings.
	if strings.HasPrefix(s, "*") && len(s) > 1 && s[1] != '.' && !strings.ContainsAny(s, "/*?[].") {
		return nil, fmt.Errorf("YAML aliases are not supported; quote the value")
	}
	switch strings.ToLower(s) {
	case "null", "~":
		return nil, nil
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	if isYAMLInteger(s) {
		n, err := strconv.Atoi(s)
		if err != nil {
			return nil, fmt.Errorf("invalid integer")
		}
		return n, nil
	}
	return s, nil
}

func isYAMLInteger(s string) bool {
	if s == "" {
		return false
	}
	i := 0
	if s[0] == '+' || s[0] == '-' {
		i++
		if i == len(s) {
			return false
		}
	}
	for ; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

type yamlFlowParser struct {
	s string
	i int
}

func parseYAMLFlow(s string) (any, error) {
	p := &yamlFlowParser{s: s}
	v, err := p.value()
	if err != nil {
		return nil, err
	}
	p.skipSpace()
	if p.i != len(p.s) {
		return nil, fmt.Errorf("unexpected text after flow value")
	}
	return v, nil
}

func (p *yamlFlowParser) skipSpace() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t' || p.s[p.i] == '\n' || p.s[p.i] == '\r') {
		p.i++
	}
}

func (p *yamlFlowParser) value() (any, error) {
	p.skipSpace()
	if p.i >= len(p.s) {
		return nil, fmt.Errorf("missing flow value")
	}
	switch p.s[p.i] {
	case '[':
		return p.sequence()
	case '{':
		return p.mapping()
	case '"', '\'':
		v, end, err := parseYAMLQuotedPrefix(p.s[p.i:])
		if err != nil {
			return nil, err
		}
		p.i += end
		return v, nil
	default:
		return p.plain()
	}
}

func (p *yamlFlowParser) sequence() ([]any, error) {
	p.i++ // [
	out := []any{}
	p.skipSpace()
	if p.i < len(p.s) && p.s[p.i] == ']' {
		p.i++
		return out, nil
	}
	for {
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		p.skipSpace()
		if p.i >= len(p.s) {
			return nil, fmt.Errorf("unterminated flow sequence")
		}
		switch p.s[p.i] {
		case ',':
			p.i++
		case ']':
			p.i++
			return out, nil
		default:
			return nil, fmt.Errorf("expected ',' or ']' in flow sequence")
		}
	}
}

func (p *yamlFlowParser) mapping() (map[string]any, error) {
	p.i++ // {
	out := map[string]any{}
	p.skipSpace()
	if p.i < len(p.s) && p.s[p.i] == '}' {
		p.i++
		return out, nil
	}
	for {
		key, err := p.key()
		if err != nil {
			return nil, err
		}
		p.skipSpace()
		if p.i >= len(p.s) || p.s[p.i] != ':' {
			return nil, fmt.Errorf("expected ':' in flow mapping")
		}
		p.i++
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		if _, exists := out[key]; exists {
			return nil, fmt.Errorf("duplicate key %q", key)
		}
		out[key] = v
		p.skipSpace()
		if p.i >= len(p.s) {
			return nil, fmt.Errorf("unterminated flow mapping")
		}
		switch p.s[p.i] {
		case ',':
			p.i++
		case '}':
			p.i++
			return out, nil
		default:
			return nil, fmt.Errorf("expected ',' or '}' in flow mapping")
		}
	}
}

func (p *yamlFlowParser) key() (string, error) {
	p.skipSpace()
	if p.i >= len(p.s) {
		return "", fmt.Errorf("missing flow mapping key")
	}
	if p.s[p.i] == '"' || p.s[p.i] == '\'' {
		v, end, err := parseYAMLQuotedPrefix(p.s[p.i:])
		if err != nil {
			return "", err
		}
		p.i += end
		return v, nil
	}
	start := p.i
	for p.i < len(p.s) && p.s[p.i] != ':' {
		p.i++
	}
	if p.i >= len(p.s) {
		return "", fmt.Errorf("expected ':' in flow mapping")
	}
	key := strings.TrimSpace(p.s[start:p.i])
	if key == "" {
		return "", fmt.Errorf("empty flow mapping key")
	}
	return key, nil
}

func (p *yamlFlowParser) plain() (any, error) {
	start := p.i
	for p.i < len(p.s) && p.s[p.i] != ',' && p.s[p.i] != ']' && p.s[p.i] != '}' {
		p.i++
	}
	return parseYAMLPlain(strings.TrimSpace(p.s[start:p.i]))
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
	class := g.classFor(p.Name)
	if !tainted || class == "read" {
		g.event("allow", map[string]any{"tool": p.Name, "tainted": tainted, "class": class, "arg_keys": argKeys(p.Arguments)})
		g.track(id, method, p.Name)
		return true, nil
	}

	// Tainted session, tool is not read-only: this is a sink. Hard blocks go
	// first, then protected persistence targets, then grants/scratch, then the
	// dialog or default deny. A fast path can never reach a hard-blocked or
	// protected target.
	scan := scanArgs(p.Arguments, g.toolPathKeys[p.Name])
	egressAllowed := false
	if scan.egress {
		egressAllowed = len(scan.egressHosts) > 0
		for _, host := range scan.egressHosts {
			if g.hostDenied(host) || !g.hostAllowed(host) {
				egressAllowed = false
			}
		}
		if !egressAllowed {
			g.event("block", map[string]any{"tool": p.Name, "rule": "EGRESS_TARGET", "origin": origin, "class": class, "arg_keys": argKeys(p.Arguments)})
			alert("tool %q blocked: network target in a session tainted by %q", p.Name, origin)
			return false, replyIfRequest(id, -32000, "Blocked by Sylenix Guard", "EGRESS_TARGET")
		}
	}
	if scan.sensitive {
		g.event("block", map[string]any{"tool": p.Name, "rule": "SENSITIVE_TARGET", "origin": origin, "class": class, "arg_keys": argKeys(p.Arguments)})
		alert("tool %q blocked: sensitive path in a session tainted by %q", p.Name, origin)
		return false, replyIfRequest(id, -32000, "Blocked by Sylenix Guard", "SENSITIVE_TARGET")
	}
	if !scan.protected && g.protectedCall(p.Name, scan.paths) {
		scan.protected = true
	}
	if scan.protected && g.approve != "dialog" {
		g.event("block", map[string]any{"tool": p.Name, "rule": "SENSITIVE_TARGET", "origin": origin, "class": class, "arg_keys": argKeys(p.Arguments)})
		alert("tool %q blocked: protected persistence path in a session tainted by %q", p.Name, origin)
		return false, replyIfRequest(id, -32000, "Blocked by Sylenix Guard", "SENSITIVE_TARGET")
	}
	// An egress-class tool whose every destination is on the policy allowlist
	// is the one place an allowlist authorizes a tainted call without a prompt.
	// Ambiguous values still fail closed; protected targets still ask a human.
	if class == "egress" && scan.egress && egressAllowed {
		if scan.ambiguous {
			g.event("block", map[string]any{"tool": p.Name, "rule": "EGRESS_TARGET", "origin": origin, "class": class, "arg_keys": argKeys(p.Arguments)})
			alert("tool %q blocked: ambiguous network target in a session tainted by %q", p.Name, origin)
			return false, replyIfRequest(id, -32000, "Blocked by Sylenix Guard", "EGRESS_TARGET")
		}
		if !scan.protected {
			g.event("allow", map[string]any{"tool": p.Name, "tainted": true, "class": class, "rule": "EGRESS_ALLOW", "arg_keys": argKeys(p.Arguments)})
			g.track(id, method, p.Name)
			return true, nil
		}
	}
	// A grant or scratch rule may only short-cut a call whose path arguments
	// are all understood and inside the approved tree. Anything ambiguous,
	// and every protected target without a human dialog grant, falls through
	// to denial or a fresh human decision. An allow-listed egress destination
	// on a non-egress tool still needs a fresh human decision, never a fast path.
	if !scan.egress && !scan.ambiguous && g.grantAllows(p.Name, scan.paths, scan.protected) {
		g.event("allow", map[string]any{"tool": p.Name, "tainted": true, "class": class, "rule": "GRANT", "arg_keys": argKeys(p.Arguments)})
		g.track(id, method, p.Name)
		return true, nil
	}
	if !scan.egress && !scan.protected && !scan.ambiguous && g.scratchAllows(p.Name, scan.paths) {
		g.event("allow", map[string]any{"tool": p.Name, "tainted": true, "class": class, "rule": "SCRATCH", "arg_keys": argKeys(p.Arguments)})
		g.track(id, method, p.Name)
		return true, nil
	}
	if g.approve == "dialog" {
		scope := scopeDir(scan.paths)
		decision, note := askHuman(p.Name, p.Arguments, origin, grantScopeNote(p.Name, scope))
		g.event("approval", map[string]any{"tool": p.Name, "granted": decision != "deny", "decision": decision, "class": class, "note": note, "arg_keys": argKeys(p.Arguments)})
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
	g.event("block", map[string]any{"tool": p.Name, "rule": "TAINT_SINK", "origin": origin, "class": class, "arg_keys": argKeys(p.Arguments)})
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

// clearTaint is only called from the human-approved clear-taint control path.
// It never clears a quarantine, a grant, or any other latch.
func (g *Guard) clearTaint() {
	g.mu.Lock()
	g.tainted = false
	g.taintOrigin = ""
	g.mu.Unlock()
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

// defaultSensitivePaths is the built-in sensitive-name list. A policy file may
// add patterns but cannot remove these; the structural .git/.env/key checks
// below remain a floor even if the list is changed.
var defaultSensitivePaths = []string{
	".git",
	".env*",
	"id_rsa*",
	"id_ed25519*",
	"*.pem",
	"*.key",
	"*.p12",
	"*.pfx",
	"go.mod", "go.sum", "package.json", "package-lock.json",
	"makefile", "dockerfile", "docker-compose.yml", "docker-compose.yaml",
	"cargo.toml", "pyproject.toml", "requirements.txt",
	"tsconfig.json", "setup.py", "gemfile", "composer.json",
}

// activeSensitivePatterns is set once at startup, before any proxy goroutine
// starts, and only read afterwards.
var activeSensitivePatterns = append([]string(nil), defaultSensitivePaths...)

func setSensitivePatterns(patterns []string) {
	activeSensitivePatterns = append([]string(nil), patterns...)
}

func mergeSensitivePatterns(extra []string) []string {
	out := append([]string(nil), defaultSensitivePaths...)
	seen := map[string]bool{}
	for _, p := range out {
		seen[strings.ToLower(p)] = true
	}
	for _, p := range extra {
		key := strings.ToLower(p)
		if !seen[key] {
			out = append(out, p)
			seen[key] = true
		}
	}
	return out
}

func sensitivePatternIsGit(p string) bool {
	p = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p), `\`, "/"))
	p = strings.TrimPrefix(p, "./")
	return p == ".git" || strings.HasPrefix(p, ".git/")
}

func sensitivePatternMatches(pattern, p string) bool {
	pattern = strings.ToLower(strings.ReplaceAll(pattern, `\`, "/"))
	p = strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
	p = strings.TrimRight(p, "/")
	components := strings.Split(p, "/")
	if !strings.Contains(pattern, "/") {
		for _, c := range components {
			if ok, err := path.Match(pattern, c); err == nil && ok {
				return true
			}
		}
		return false
	}
	for i := range components {
		suffix := strings.Join(components[i:], "/")
		if ok, err := path.Match(pattern, suffix); err == nil && ok {
			return true
		}
	}
	return false
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
	paths       []string
	egress      bool
	egressHosts []string
	sensitive   bool
	protected   bool
	ambiguous   bool
}

// scanArgs classifies every string inside a call's arguments. Paths are drawn
// only from known path keys: a filename-shaped value under an unknown key is
// not a path we can safely compare, so it disqualifies the fast paths instead.
// extraPathKeys are the per-tool path_keys from the policy file.
func scanArgs(args map[string]any, extraPathKeys map[string]bool) callScan {
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
				if h := hostFromArgument(t); h != "" {
					s.egressHosts = append(s.egressHosts, h)
				}
			case keyMatches(pathKeys, kl) ||
				(extraPathKeys != nil && (extraPathKeys[kl] || extraPathKeys[keyNormalizer.Replace(kl)])):
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
				if h := hostFromArgument(t); h != "" {
					s.egressHosts = append(s.egressHosts, h)
				}
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
func (g *Guard) classFor(tool string) string {
	if g.readonly[tool] {
		return "read"
	}
	if class := g.classes[tool]; class != "" {
		return class
	}
	return "exec"
}

func policyHostSet(hosts []string) map[string]bool {
	m := map[string]bool{}
	for _, h := range hosts {
		if h = normalizePolicyHostValue(h); h != "" {
			m[h] = true
		}
	}
	return m
}

func normalizePolicyHostValue(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	return strings.TrimSuffix(h, ".")
}

func hostMatchesPattern(host string, patterns map[string]bool) bool {
	host = normalizePolicyHostValue(host)
	if host == "" {
		return false
	}
	for p := range patterns {
		if p == host {
			return true
		}
		if strings.ContainsAny(p, "*?[") {
			if ok, err := path.Match(p, host); err == nil && ok {
				return true
			}
		}
	}
	return false
}

func (g *Guard) hostDenied(host string) bool {
	return hostMatchesPattern(host, g.egressDeny)
}

func (g *Guard) hostAllowed(host string) bool {
	return hostMatchesPattern(host, g.egressAllow)
}

// hostFromArgument extracts a lower-case host from a URL, URI, host:port or
// bare destination value. An empty result means the destination is unknown,
// which callers treat as not allow-listed.
func hostFromArgument(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "mailto:") {
		addr := s[len("mailto:"):]
		if i := strings.LastIndex(addr, "@"); i >= 0 {
			return normalizePolicyHostValue(addr[i+1:])
		}
		return ""
	}
	if strings.HasPrefix(s, "//") {
		if u, err := url.Parse("http:" + s); err == nil {
			return normalizePolicyHostValue(u.Hostname())
		}
	}
	if i := strings.Index(s, "://"); i > 0 {
		if u, err := url.Parse(s); err == nil {
			return normalizePolicyHostValue(u.Hostname())
		}
	}
	if i := strings.IndexByte(s, ':'); i > 0 && egressSchemes[strings.ToLower(s[:i])] {
		if u, err := url.Parse(s); err == nil {
			if u.Hostname() != "" {
				return normalizePolicyHostValue(u.Hostname())
			}
			if u.Opaque != "" {
				if j := strings.LastIndex(u.Opaque, "@"); j >= 0 {
					return normalizePolicyHostValue(u.Opaque[j+1:])
				}
			}
		}
		return ""
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.TrimPrefix(strings.TrimSuffix(s, "]"), "[")
	return normalizePolicyHostValue(s)
}

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
	for _, pattern := range activeSensitivePatterns {
		if !checkGit && sensitivePatternIsGit(pattern) {
			continue
		}
		if sensitivePatternMatches(pattern, norm) {
			return true
		}
	}
	return false
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

// askClearTaint is a two-button security decision, not a tool approval. It
// defaults to Deny, times out to Deny, and is only reachable from the local
// clear-taint control file, never from an MCP frame or an environment variable.
func askClearTaint(name, origin string) (bool, string) {
	reason := ""
	if origin != "" {
		reason = " The session was tainted by " + cleanForDialog(origin, 80) + "."
	}
	msg := fmt.Sprintf("Sylenix Guard: clear the taint latch for session %s?%s Clearing it lets non-read-only tools run without further approval until new untrusted content arrives. Deny keeps the latch.",
		cleanForDialog(name, 80), reason)
	switch runtime.GOOS {
	case "darwin":
		script := fmt.Sprintf(`display dialog "%s" with title "Sylenix Guard" buttons {"Deny","Clear Taint"} default button "Deny" with icon caution giving up after 60`, escapeAppleScript(msg))
		out, err := exec.Command("osascript", "-e", script).Output()
		if err != nil {
			return false, "dialog failed: " + err.Error()
		}
		return strings.Contains(string(out), "button returned:Clear Taint"), "osascript"
	case "linux":
		// A list, because zenity --question can only offer two buttons and the
		// first row (Deny) is the safe default. This is the same pattern as the
		// tool-approval dialog.
		out, err := exec.Command("zenity", "--list", "--no-markup", "--hide-header",
			"--title=Sylenix Guard", "--width=520", "--height=220", "--timeout=60",
			"--text="+msg, "--column=Decision", "Deny", "Clear Taint").Output()
		if err != nil {
			return false, "zenity: denied, timed out, or unavailable"
		}
		return strings.Contains(string(out), "Clear Taint"), "zenity"
	case "windows":
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", windowsClearTaintDialogScript)
		cmd.Env = append(os.Environ(), "SYLENIX_MSG="+msg)
		err := cmd.Run()
		if err == nil {
			return true, "powershell"
		}
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
			return false, "powershell: denied"
		}
		return false, "powershell: denied, timed out, or unavailable"
	}
	return false, "no dialog support on " + runtime.GOOS
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

// windowsClearTaintDialogScript is a two-button decision dialog. Deny is
// focused first, is the escape key, and is the result of a timeout.
const windowsClearTaintDialogScript = `
Add-Type -AssemblyName System.Windows.Forms
$f = New-Object System.Windows.Forms.Form
$f.Text = 'Sylenix Guard'; $f.TopMost = $true; $f.StartPosition = 'CenterScreen'
$f.FormBorderStyle = 'FixedDialog'; $f.MinimizeBox = $false; $f.MaximizeBox = $false
$f.ClientSize = New-Object System.Drawing.Size(560, 220)
$l = New-Object System.Windows.Forms.Label
$l.Location = New-Object System.Drawing.Point(12, 12); $l.Size = New-Object System.Drawing.Size(536, 140)
$l.Text = $env:SYLENIX_MSG
$deny = New-Object System.Windows.Forms.Button
$deny.Text = 'Deny'; $deny.Location = New-Object System.Drawing.Point(12, 164); $deny.Size = New-Object System.Drawing.Size(260, 40)
$deny.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$clear = New-Object System.Windows.Forms.Button
$clear.Text = 'Clear Taint'; $clear.Location = New-Object System.Drawing.Point(288, 164); $clear.Size = New-Object System.Drawing.Size(260, 40)
$clear.DialogResult = [System.Windows.Forms.DialogResult]::OK
$f.CancelButton = $deny
$f.Controls.AddRange(@($l, $deny, $clear))
$f.Add_Shown({ $deny.Focus() })
$t = New-Object System.Windows.Forms.Timer; $t.Interval = 60000
$t.Add_Tick({ $f.Close() }); $t.Start()
$r = $f.ShowDialog()
if ($r -eq [System.Windows.Forms.DialogResult]::OK) { exit 0 }
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

// ---------------------------------------------------------------- clear-taint / stats

type controlFile struct {
	Version   int    `json:"version"`
	Name      string `json:"name"`
	PID       int    `json:"pid"`
	Nonce     string `json:"nonce"`
	StartedAt string `json:"started_at"`
	Heartbeat string `json:"heartbeat"`
}

type clearRequest struct {
	Version      int    `json:"version"`
	Nonce        string `json:"nonce"`
	GuardStarted string `json:"guard_started"`
	RequestID    string `json:"request_id"`
	RequestedAt  string `json:"requested_at"`
}

type clearResult struct {
	Version   int    `json:"version"`
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
	Who       string `json:"who,omitempty"`
	At        string `json:"at,omitempty"`
	Note      string `json:"note,omitempty"`
}

type guardControl struct {
	g           *Guard
	stateDir    string
	name        string
	nonce       string
	startedAt   string
	controlPath string
	requestPath string
	done        chan struct{}
	stopOnce    sync.Once
	stopped     atomic.Bool
	fileMu      sync.Mutex
}

func controlHash(name string) string {
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:16])
}

func controlFilePath(stateDir, name string) string {
	return filepath.Join(stateDir, "control-"+controlHash(name)+".json")
}

func clearRequestFilePath(stateDir, name string) string {
	return filepath.Join(stateDir, "clear-taint-request-"+controlHash(name)+".json")
}

func clearResultFilePath(stateDir, name, requestID string) string {
	return filepath.Join(stateDir, "clear-taint-result-"+controlHash(name)+"-"+requestID+".json")
}

// writeFileAtomic writes a small local state file without exposing a partial
// read to another process. O_EXCL keeps a same-user process from turning the
// temp path into a FIFO and blocking the writer.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func validNonce(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func validRequestID(s string) bool {
	if len(s) != 32 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func startGuardControl(g *Guard) (*guardControl, error) {
	nonce, err := randomHex(sha256.Size)
	if err != nil {
		return nil, err
	}
	c := &guardControl{
		g:           g,
		stateDir:    g.stateDir,
		name:        g.name,
		nonce:       nonce,
		startedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		controlPath: controlFilePath(g.stateDir, g.name),
		requestPath: clearRequestFilePath(g.stateDir, g.name),
		done:        make(chan struct{}),
	}
	c.cleanupStaleFiles()
	if err := c.writeControl(); err != nil {
		return nil, err
	}
	go c.run()
	return c, nil
}

func (c *guardControl) run() {
	go c.heartbeatLoop()
	c.pollLoop()
}

func (c *guardControl) heartbeatLoop() {
	t := time.NewTicker(controlHeartbeatEvery)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			_ = c.writeControl()
		}
	}
}

func (c *guardControl) pollLoop() {
	t := time.NewTicker(clearRequestPoll)
	defer t.Stop()
	last := ""
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			last = c.pollRequest(last)
		}
	}
}

func (c *guardControl) writeControl() error {
	c.fileMu.Lock()
	defer c.fileMu.Unlock()
	if c.stopped.Load() {
		return nil
	}
	rec := controlFile{
		Version:   controlVersion,
		Name:      c.name,
		PID:       os.Getpid(),
		Nonce:     c.nonce,
		StartedAt: c.startedAt,
		Heartbeat: time.Now().UTC().Format(time.RFC3339Nano),
	}
	b, _ := json.Marshal(rec)
	return writeFileAtomic(c.controlPath, b, 0o600)
}

func (c *guardControl) pollRequest(last string) string {
	info, err := os.Stat(c.requestPath)
	if os.IsNotExist(err) {
		return last
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > clearFileLimit {
		c.rejectRequest(clearRequest{}, "request cannot be read")
		return last
	}
	b, err := os.ReadFile(c.requestPath)
	if err != nil {
		c.rejectRequest(clearRequest{}, "request cannot be read")
		return last
	}
	var req clearRequest
	if json.Unmarshal(b, &req) != nil {
		c.rejectRequest(clearRequest{}, "malformed request")
		return last
	}
	if validRequestID(req.RequestID) && req.RequestID == last {
		_ = os.RemoveAll(c.requestPath)
		return last
	}
	if req.Version != controlVersion || req.Nonce != c.nonce || req.GuardStarted != c.startedAt || !validRequestID(req.RequestID) {
		c.rejectRequest(req, "invalid or stale request")
		if validRequestID(req.RequestID) {
			last = req.RequestID
		}
		return last
	}
	requested, err := time.Parse(time.RFC3339Nano, req.RequestedAt)
	if err != nil || time.Since(requested) > clearRequestTTL || time.Until(requested) > 5*time.Second {
		c.rejectRequest(req, "stale request")
		last = req.RequestID
		return last
	}
	last = req.RequestID
	_ = os.RemoveAll(c.requestPath)
	c.handleRequest(req)
	return last
}

func (c *guardControl) rejectRequest(req clearRequest, reason string) {
	c.g.event("CLEAR_TAINT_REJECTED", map[string]any{"reason": reason})
	if validRequestID(req.RequestID) {
		_ = c.writeResult(clearResult{
			Version:   controlVersion,
			RequestID: req.RequestID,
			Status:    "rejected",
			At:        time.Now().UTC().Format(time.RFC3339Nano),
			Note:      reason,
		})
	}
	_ = os.RemoveAll(c.requestPath)
}

func (c *guardControl) handleRequest(req clearRequest) {
	c.g.mu.Lock()
	tainted := c.g.tainted
	origin := c.g.taintOrigin
	c.g.mu.Unlock()
	who := cleanForDialog(osUser(), 120)

	if !tainted {
		at := time.Now().UTC().Format(time.RFC3339Nano)
		c.g.event("CLEAR_TAINT_NOT_NEEDED", map[string]any{"request_id": req.RequestID})
		_ = c.writeResult(clearResult{
			Version:   controlVersion,
			RequestID: req.RequestID,
			Status:    "not_tainted",
			Who:       who,
			At:        at,
		})
		return
	}

	allowed, note := askClearTaint(c.g.name, origin)
	at := time.Now().UTC().Format(time.RFC3339Nano)
	note = cleanForDialog(note, 160)
	if allowed {
		c.g.clearTaint()
		c.g.event("CLEAR_TAINT", map[string]any{
			"who":        who,
			"method":     "dialog",
			"granted":    true,
			"request_id": req.RequestID,
		})
		_ = c.writeResult(clearResult{
			Version:   controlVersion,
			RequestID: req.RequestID,
			Status:    "cleared",
			Who:       who,
			At:        at,
		})
		return
	}
	c.g.event("CLEAR_TAINT_DENIED", map[string]any{
		"who":        who,
		"method":     "dialog",
		"granted":    false,
		"request_id": req.RequestID,
		"note":       note,
	})
	_ = c.writeResult(clearResult{
		Version:   controlVersion,
		RequestID: req.RequestID,
		Status:    "denied",
		Who:       who,
		At:        at,
		Note:      note,
	})
}

func (c *guardControl) writeResult(res clearResult) error {
	c.fileMu.Lock()
	defer c.fileMu.Unlock()
	if c.stopped.Load() {
		return nil
	}
	b, _ := json.Marshal(res)
	return writeFileAtomic(clearResultFilePath(c.stateDir, c.name, res.RequestID), b, 0o600)
}

func (c *guardControl) cleanupStaleFiles() {
	_ = os.RemoveAll(c.requestPath)
	_ = os.Remove(c.requestPath + ".tmp")
	pattern := filepath.Join(c.stateDir, "clear-taint-result-"+controlHash(c.name)+"-*.json")
	if matches, err := filepath.Glob(pattern); err == nil {
		for _, match := range matches {
			_ = os.Remove(match)
		}
	}
}

func (c *guardControl) removeRuntimeFiles() {
	_ = os.Remove(c.controlPath)
	_ = os.Remove(c.controlPath + ".tmp")
	_ = os.RemoveAll(c.requestPath)
	_ = os.Remove(c.requestPath + ".tmp")
}

func (c *guardControl) stop() {
	if c == nil {
		return
	}
	c.stopOnce.Do(func() {
		c.stopped.Store(true)
		close(c.done)
		c.fileMu.Lock()
		c.removeRuntimeFiles()
		c.fileMu.Unlock()
	})
}

func osUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	for _, key := range []string{"USER", "USERNAME", "LOGNAME"} {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return "unknown"
}

func runClearTaintCommand(args []string) int {
	fs := flag.NewFlagSet("clear-taint", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	name := fs.String("name", "", "guard session name (the guard --name, or its command basename)")
	stateDir := fs.String("state-dir", "", "guard state directory (default ~/.sylenix-poc)")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "sylenix-guard clear-taint: unexpected arguments")
		return 2
	}
	if strings.TrimSpace(*name) == "" {
		fmt.Fprintln(os.Stderr, "sylenix-guard clear-taint: --name is required")
		return 2
	}
	if hasUnsafePolicyChars(*name) || hasUnsafePolicyChars(*stateDir) {
		fmt.Fprintln(os.Stderr, "sylenix-guard clear-taint: --name or --state-dir contains control or invisible characters")
		return 2
	}
	state := *stateDir
	if state == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, "sylenix-guard clear-taint: cannot find home directory; pass --state-dir")
			return 2
		}
		state = filepath.Join(home, ".sylenix-poc")
	}
	state = resolveDoctorPath(state)
	ctrl, err := readGuardControl(state, *name)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard clear-taint:", err)
		return 2
	}
	requestID, err := randomHex(16)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard clear-taint: cannot create a request id")
		return 2
	}
	req := clearRequest{
		Version:      controlVersion,
		Nonce:        ctrl.Nonce,
		GuardStarted: ctrl.StartedAt,
		RequestID:    requestID,
		RequestedAt:  time.Now().UTC().Format(time.RFC3339Nano),
	}
	b, _ := json.Marshal(req)
	if err := writeFileAtomic(clearRequestFilePath(state, *name), b, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard clear-taint: cannot write the request")
		return 2
	}
	res, err := waitClearResult(state, *name, requestID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard clear-taint:", err)
		return 2
	}
	displayName := cleanForDialog(*name, 80)
	switch res.Status {
	case "cleared":
		fmt.Printf("taint cleared for session %q by %s at %s\n", displayName, cleanForDialog(res.Who, 120), cleanForDialog(res.At, 40))
		return 0
	case "not_tainted":
		fmt.Printf("session %q is not tainted\n", displayName)
		return 0
	case "denied":
		note := res.Note
		if note == "" {
			note = "denied"
		}
		fmt.Printf("clear denied for session %q: %s\n", displayName, cleanForDialog(note, 160))
		return 1
	case "rejected":
		note := res.Note
		if note == "" {
			note = "request rejected"
		}
		fmt.Fprintf(os.Stderr, "sylenix-guard clear-taint: request rejected: %s\n", cleanForDialog(note, 160))
		return 2
	default:
		fmt.Fprintln(os.Stderr, "sylenix-guard clear-taint: unexpected result")
		return 2
	}
}

func readGuardControl(stateDir, name string) (controlFile, error) {
	path := controlFilePath(stateDir, name)
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return controlFile{}, fmt.Errorf("no running guard session named %q in %s", cleanForDialog(name, 80), cleanForDialog(stateDir, 160))
	}
	if err != nil {
		return controlFile{}, fmt.Errorf("cannot read the guard control file")
	}
	if !info.Mode().IsRegular() || info.Size() > clearFileLimit {
		return controlFile{}, fmt.Errorf("the guard control file is not readable")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return controlFile{}, fmt.Errorf("cannot read the guard control file")
	}
	var c controlFile
	if json.Unmarshal(b, &c) != nil {
		return controlFile{}, fmt.Errorf("the guard control file is not valid")
	}
	if c.Version != controlVersion || c.Name != name || !validNonce(c.Nonce) {
		return controlFile{}, fmt.Errorf("the guard control file is not valid for this session")
	}
	if _, err := time.Parse(time.RFC3339Nano, c.StartedAt); err != nil {
		return controlFile{}, fmt.Errorf("the guard control file is not valid for this session")
	}
	heartbeat, err := time.Parse(time.RFC3339Nano, c.Heartbeat)
	if err != nil || time.Since(heartbeat) > controlStaleAfter || time.Until(heartbeat) > 5*time.Second {
		return controlFile{}, fmt.Errorf("the guard session is not running or its control file is stale")
	}
	return c, nil
}

func waitClearResult(stateDir, name, requestID string) (clearResult, error) {
	path := clearResultFilePath(stateDir, name, requestID)
	deadline := time.Now().Add(clearWaitTimeout)
	var lastLiveCheck time.Time
	for time.Now().Before(deadline) {
		info, err := os.Stat(path)
		if err == nil {
			if !info.Mode().IsRegular() || info.Size() > clearFileLimit {
				return clearResult{}, fmt.Errorf("the clear-taint result is not readable")
			}
			b, readErr := os.ReadFile(path)
			if readErr == nil {
				var res clearResult
				if json.Unmarshal(b, &res) == nil && res.Version == controlVersion && res.RequestID == requestID {
					_ = os.Remove(path)
					return res, nil
				}
			}
		} else if !os.IsNotExist(err) {
			return clearResult{}, fmt.Errorf("cannot read the clear-taint result")
		}
		if time.Since(lastLiveCheck) >= time.Second {
			if _, err := readGuardControl(stateDir, name); err != nil {
				return clearResult{}, fmt.Errorf("the guard session is no longer running")
			}
			lastLiveCheck = time.Now()
		}
		time.Sleep(250 * time.Millisecond)
	}
	return clearResult{}, fmt.Errorf("no response from the guard; the dialog may still be open")
}

type auditRow struct {
	TS      string `json:"ts"`
	Event   string `json:"event"`
	Tool    string `json:"tool"`
	Rule    string `json:"rule"`
	Granted bool   `json:"granted"`
	parsed  time.Time
}

type toolRule struct {
	tool string
	rule string
}

func runStatsCommand(args []string) int {
	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	name := fs.String("name", "", "server name; reads <state-dir>/audit-<name>.jsonl")
	file := fs.String("file", "", "path to an audit log")
	stateDir := fs.String("state-dir", "", "state directory for --name (default ~/.sylenix-poc)")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	visited := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { visited[f.Name] = true })
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "sylenix-guard stats: unexpected arguments")
		return 2
	}
	if (*name == "") == (*file == "") {
		fmt.Fprintln(os.Stderr, "sylenix-guard stats: give exactly one of --name or --file")
		return 2
	}
	if visited["state-dir"] && *file != "" {
		fmt.Fprintln(os.Stderr, "sylenix-guard stats: --state-dir is only valid with --name")
		return 2
	}
	if hasUnsafePolicyChars(*name) || hasUnsafePolicyChars(*file) || hasUnsafePolicyChars(*stateDir) {
		fmt.Fprintln(os.Stderr, "sylenix-guard stats: a path or name contains control or invisible characters")
		return 2
	}
	path := *file
	if *name != "" {
		state := *stateDir
		if state == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				fmt.Fprintln(os.Stderr, "sylenix-guard stats: cannot find home directory; pass --state-dir")
				return 2
			}
			state = filepath.Join(home, ".sylenix-poc")
		}
		state = resolveDoctorPath(state)
		path = filepath.Join(state, "audit-"+*name+".jsonl")
	}
	rows, err := readAuditRows(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sylenix-guard stats: %s: %v\n", cleanForDialog(path, 240), err)
		return 2
	}
	printAuditSummary(path, rows)
	return 0
}

func readAuditRows(path string) ([]auditRow, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open the audit log")
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("the audit log is not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open the audit log")
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), maxFrame)
	var rows []auditRow
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var row auditRow
		if err := json.Unmarshal(line, &row); err != nil {
			return nil, fmt.Errorf("invalid JSON at line %d", lineNo)
		}
		if row.TS == "" || row.Event == "" {
			return nil, fmt.Errorf("missing ts or event at line %d", lineNo)
		}
		ts, err := time.Parse(time.RFC3339Nano, row.TS)
		if err != nil {
			return nil, fmt.Errorf("invalid timestamp at line %d", lineNo)
		}
		row.parsed = ts
		rows = append(rows, row)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("cannot read the audit log")
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("audit log is empty")
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].parsed.Before(rows[j].parsed) })
	return rows, nil
}

func printAuditSummary(path string, rows []auditRow) {
	sessions, taintedSessions := 0, 0
	curTainted, open := false, false
	allowed, blocked, granted, denied := 0, 0, 0, 0
	blocks := map[toolRule]int{}
	approvals := map[string][2]int{}
	quarantined := map[string]bool{}
	unparseableServer, unparseableHost, serverRequests := 0, 0, 0
	for _, row := range rows {
		switch row.Event {
		case "start":
			if open && curTainted {
				taintedSessions++
			}
			sessions++
			open, curTainted = true, false
		case "taint_latched":
			curTainted = true
		case "exit":
			if open && curTainted {
				taintedSessions++
			}
			open, curTainted = false, false
		case "allow":
			allowed++
		case "block":
			blocked++
			tool, rule := row.Tool, row.Rule
			if tool == "" {
				tool = "?"
			}
			if rule == "" {
				rule = "?"
			}
			blocks[toolRule{tool: tool, rule: rule}]++
		case "approval":
			tool := row.Tool
			if tool == "" {
				tool = "?"
			}
			counts := approvals[tool]
			if row.Granted {
				granted++
				counts[0]++
			} else {
				denied++
				counts[1]++
			}
			approvals[tool] = counts
		case "tool_quarantined":
			tool := row.Tool
			if tool == "" {
				tool = "?"
			}
			quarantined[tool] = true
		case "unparseable_server_frame":
			unparseableServer++
		case "unparseable_host_frame":
			unparseableHost++
		case "server_request":
			serverRequests++
		}
	}
	if open && curTainted {
		taintedSessions++
	}
	active := 0.0
	for i := 1; i < len(rows); i++ {
		gap := rows[i].parsed.Sub(rows[i-1].parsed).Seconds()
		if gap >= 0 && gap <= auditGapLimit {
			active += gap
		}
	}
	hours := active / 3600
	perHour := "n/a (active time under 300 s)"
	if active >= auditMinActive {
		perHour = fmt.Sprintf("%.1f", float64(granted+denied)/hours)
	}
	fmt.Printf("file: %s\n", cleanForDialog(path, 240))
	fmt.Printf("events: %d   span: %s -> %s\n", len(rows), rows[0].TS, rows[len(rows)-1].TS)
	fmt.Printf("sessions: %d  (tainted: %d)\n", sessions, taintedSessions)
	fmt.Printf("active time: %.2f h   (gaps over 600 s excluded)\n", hours)
	fmt.Printf("tool calls allowed: %d   blocked: %d   approvals granted: %d   approvals denied: %d\n", allowed, blocked, granted, denied)
	fmt.Printf("approval prompts per active hour: %s\n", perHour)
	fmt.Println("blocks by tool/rule:")
	if len(blocks) == 0 {
		fmt.Println("  none")
	} else {
		keys := make([]toolRule, 0, len(blocks))
		for key := range blocks {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i].tool != keys[j].tool {
				return keys[i].tool < keys[j].tool
			}
			return keys[i].rule < keys[j].rule
		})
		for _, key := range keys {
			fmt.Printf("  %s %s : %d\n", cleanForDialog(key.tool, 80), cleanForDialog(key.rule, 80), blocks[key])
		}
	}
	fmt.Println("approvals by tool:")
	if len(approvals) == 0 {
		fmt.Println("  none")
	} else {
		tools := make([]string, 0, len(approvals))
		for tool := range approvals {
			tools = append(tools, tool)
		}
		sort.Strings(tools)
		for _, tool := range tools {
			counts := approvals[tool]
			fmt.Printf("  %s granted=%d denied=%d\n", cleanForDialog(tool, 80), counts[0], counts[1])
		}
	}
	if len(quarantined) == 0 {
		fmt.Println("tools quarantined: none")
	} else {
		tools := make([]string, 0, len(quarantined))
		for tool := range quarantined {
			tools = append(tools, cleanForDialog(tool, 80))
		}
		sort.Strings(tools)
		fmt.Printf("tools quarantined: %s\n", strings.Join(tools, ", "))
	}
	fmt.Printf("unparseable server frames: %d   unparseable host frames: %d   server-initiated requests: %d\n",
		unparseableServer, unparseableHost, serverRequests)
}

// ---------------------------------------------------------------- doctor

// doctorFinding is one issue found by `sylenix-guard doctor`. Detail and Fix
// never contain tool argument values, env values, secrets or file contents.
type doctorFinding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Client   string `json:"client,omitempty"`
	Config   string `json:"config,omitempty"`
	Server   string `json:"server,omitempty"`
	Detail   string `json:"detail"`
	Fix      string `json:"fix"`
}

type doctorReport struct {
	Version  string          `json:"version"`
	Clean    bool            `json:"clean"`
	Configs  []doctorConfig  `json:"configs"`
	Findings []doctorFinding `json:"findings"`
}

type doctorConfig struct {
	Client  string             `json:"client"`
	Path    string             `json:"path"`
	Error   string             `json:"error,omitempty"`
	Servers []doctorServerView `json:"servers"`
}

// doctorServerView deliberately has no command, args or env fields: doctor
// output is not a place for argument values.
type doctorServerView struct {
	Name         string   `json:"name"`
	Map          string   `json:"map"`
	Transport    string   `json:"transport"`
	Wrapped      bool     `json:"wrapped"`
	Allowlisted  bool     `json:"allowlisted"`
	Approval     string   `json:"approval,omitempty"`
	TrustedTools []string `json:"trusted_tools,omitempty"`
	ScratchDirs  []string `json:"scratch_dirs,omitempty"`
	Policy       string   `json:"policy,omitempty"`
	Error        string   `json:"error,omitempty"`
}

// doctorWrapperFlags is the subset of Guard flags doctor understands. An
// unknown flag is a finding, never something to ignore.
type doctorWrapperFlags struct {
	HasName     bool
	Name        string
	HasStateDir bool
	StateDir    string
	HasPolicy   bool
	Policy      string
	HasReadonly bool
	Readonly    string
	HasTrust    bool
	Trust       string
	HasApprove  bool
	Approve     string
	HasScratch  bool
	Scratch     []scratchRule
	NoSpotlight bool
	ResetPins   bool
	HasGrant    bool
	Grants      []string
}

type doctorServer struct {
	Name         string
	Client       string
	ConfigPath   string
	Remote       bool
	Wrapped      bool
	Metadata     bool
	MetaVersion  int
	GuardCommand string
	OriginalCmd  string
	OriginalArgs []string
	Flags        doctorWrapperFlags
}

type doctorPolicy struct {
	pf   *policyFile
	path string
	err  string
}

type doctorEffective struct {
	Approve           string
	Readonly          map[string]bool
	Trust             map[string]bool
	Classes           map[string]string
	Scratch           []scratchRule
	AllowlistEnforced bool
}

type doctorRun struct {
	policyExplicit    bool
	policyPath        string
	stateDir          string
	requireSignatures bool
	home              string
	cwd               string
	repoRoot          string
	configs           []doctorConfig
	findings          []doctorFinding
}

func runDoctorCommand(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOut := fs.Bool("json", false, "print machine-readable JSON")
	policyPath := fs.String("policy", "", "check this policy file instead of the wrapper or default policy")
	stateDir := fs.String("state-dir", "", "state directory used when a wrapper does not pin one (default ~/.sylenix-poc)")
	requireSignatures := fs.Bool("require-signatures", false, "report policy and pin files whose signature cannot be verified")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	visited := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { visited[f.Name] = true })
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "sylenix-guard doctor: unexpected arguments")
		return 2
	}
	if visited["policy"] && *policyPath == "" {
		fmt.Fprintln(os.Stderr, "sylenix-guard doctor: --policy needs a file path")
		return 2
	}
	if visited["state-dir"] && *stateDir == "" {
		fmt.Fprintln(os.Stderr, "sylenix-guard doctor: --state-dir needs a directory")
		return 2
	}
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()
	d := &doctorRun{
		policyExplicit:    visited["policy"],
		policyPath:        *policyPath,
		stateDir:          *stateDir,
		requireSignatures: *requireSignatures,
		home:              home,
		cwd:               cwd,
	}
	report, code := d.run()
	if *jsonOut {
		if writeCode := d.writeJSON(report); writeCode != 0 {
			return writeCode
		}
	} else {
		d.writeHuman(report)
	}
	return code
}

func (d *doctorRun) run() (doctorReport, int) {
	if d.home != "" {
		if canonical, ok := canonicalPath(d.home); ok {
			d.home = canonical
		}
	}
	d.repoRoot = findDoctorRepoRoot(d.cwd)
	if d.repoRoot != "" {
		if canonical, ok := canonicalPath(d.repoRoot); ok {
			d.repoRoot = canonical
		}
	}

	var explicit *doctorPolicy
	if d.policyExplicit {
		pol := readDoctorPolicyFile(d.policyPath)
		if pol.err != "" {
			d.findings = append(d.findings, newDoctorFinding("POLICY_INVALID", "error", "", "", "",
				pol.err, "run `sylenix-guard policy validate <file>` and fix the policy, or pass the right --policy"))
			return d.report(), 1
		}
		explicit = &pol
	}

	for _, target := range discoverConfigTargets() {
		cfg, findings := d.inspectConfig(target, explicit)
		if cfg != nil {
			d.configs = append(d.configs, *cfg)
		}
		d.findings = append(d.findings, findings...)
	}
	sortDoctorFindings(d.findings)
	report := d.report()
	if report.Clean {
		return report, 0
	}
	return report, 1
}

func (d *doctorRun) inspectConfig(target configTarget, explicit *doctorPolicy) (*doctorConfig, []doctorFinding) {
	cfg := &doctorConfig{Client: target.client, Path: target.path, Servers: []doctorServerView{}}
	info, err := os.Stat(target.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		cfg.Error = "config cannot be inspected"
		return cfg, []doctorFinding{newDoctorFinding("CONFIG_UNREADABLE", "error", target.client, target.path, "",
			"config cannot be inspected", "check file permissions or repair the config")}
	}
	if info.IsDir() {
		cfg.Error = "config path is a directory"
		return cfg, []doctorFinding{newDoctorFinding("CONFIG_UNREADABLE", "error", target.client, target.path, "",
			"config path is a directory", "remove the directory or fix the client config path")}
	}
	data, err := os.ReadFile(target.path)
	if err != nil {
		cfg.Error = "config cannot be read"
		return cfg, []doctorFinding{newDoctorFinding("CONFIG_UNREADABLE", "error", target.client, target.path, "",
			"config cannot be read", "check file permissions")}
	}
	if hasDuplicateKeys(data) {
		cfg.Error = "config has duplicate JSON keys"
		return cfg, []doctorFinding{newDoctorFinding("CONFIG_UNREADABLE", "error", target.client, target.path, "",
			"config has duplicate JSON keys", "remove the duplicate keys; the guard refuses ambiguous configs")}
	}
	root, err := parseConfigObject(data)
	if err != nil {
		cfg.Error = "config is not valid JSON"
		return cfg, []doctorFinding{newDoctorFinding("CONFIG_UNREADABLE", "error", target.client, target.path, "",
			"config is not valid JSON", "repair the JSON or remove the config")}
	}

	var findings []doctorFinding
	for _, serverPath := range target.serverPaths {
		serverMap, exists, err := lookupConfigMap(root, serverPath)
		mapName := strings.Join(serverPath, ".")
		if err != nil {
			cfg.Error = "server map is not an object"
			findings = append(findings, newDoctorFinding("CONFIG_UNREADABLE", "error", target.client, target.path, "",
				fmt.Sprintf("server map %q is not an object", mapName), "make the server map a JSON object"))
			continue
		}
		if !exists {
			continue
		}
		for _, name := range sortedObjectKeys(serverMap) {
			value, _ := serverMap.get(name)
			entry, ok := value.(*configObject)
			if !ok {
				view := doctorServerView{Name: name, Map: mapName, Transport: "stdio", Error: "server entry is not an object"}
				cfg.Servers = append(cfg.Servers, view)
				findings = append(findings, newDoctorFinding("SERVER_INVALID", "error", target.client, target.path, name,
					"server entry is not an object", "make the server entry a JSON object"))
				continue
			}
			if name == "" || hasUnsafePolicyChars(name) {
				view := doctorServerView{Name: name, Map: mapName, Transport: "stdio", Error: "server name is empty or contains control characters"}
				cfg.Servers = append(cfg.Servers, view)
				findings = append(findings, newDoctorFinding("SERVER_INVALID", "error", target.client, target.path, name,
					"server name is empty or contains control or invisible characters", "give the server a plain non-empty name"))
				continue
			}
			server, code, detail := inspectDoctorServer(entry, name, target.client, target.path)
			view := doctorServerView{Name: name, Map: mapName, Transport: "stdio", Wrapped: server.Wrapped}
			if server.Remote {
				view.Transport = "remote"
			}
			if code != "" {
				view.Error = detail
				cfg.Servers = append(cfg.Servers, view)
				findings = append(findings, newDoctorFinding(code, "error", target.client, target.path, name, detail, doctorFixForCode(code)))
				continue
			}
			serverFindings := d.inspectServer(&server, &view, explicit)
			cfg.Servers = append(cfg.Servers, view)
			findings = append(findings, serverFindings...)
		}
	}
	return cfg, findings
}

func inspectDoctorServer(entry *configObject, name, client, configPath string) (doctorServer, string, string) {
	s := doctorServer{Name: name, Client: client, ConfigPath: configPath}
	if remoteConfigEntry(entry) {
		s.Remote = true
		return s, "", ""
	}
	if value, ok := entry.get("type"); ok {
		text, ok := value.(string)
		if !ok {
			return s, "SERVER_INVALID", "server type is not a string"
		}
		if text != "" && !strings.EqualFold(strings.TrimSpace(text), "stdio") {
			return s, "SERVER_INVALID", "server type is not stdio"
		}
	}
	commandValue, ok := entry.get("command")
	if !ok {
		return s, "SERVER_INVALID", "server has no command"
	}
	command, ok := commandValue.(string)
	if !ok || command == "" || strings.TrimSpace(command) == "" {
		return s, "SERVER_INVALID", "server command is not a non-empty string"
	}
	if strings.TrimSpace(command) != command {
		return s, "SERVER_INVALID", "server command has surrounding spaces"
	}
	if hasUnsafePolicyChars(command) {
		return s, "SERVER_INVALID", "server command contains control or invisible characters"
	}
	argsValue, ok := entry.get("args")
	var args []string
	if ok {
		list, ok := argsValue.([]any)
		if !ok {
			return s, "SERVER_INVALID", "server args is not an array"
		}
		for _, item := range list {
			text, ok := item.(string)
			if !ok {
				return s, "SERVER_INVALID", "server args contains a non-string value"
			}
			args = append(args, text)
		}
	}
	metaValue, hasMeta := entry.get(guardMetaKey)
	if hasMeta {
		meta, ok := metaValue.(*configObject)
		if !ok {
			return s, "WRAPPER_INVALID", "Guard metadata is not an object"
		}
		versionValue, _ := meta.get("version")
		metaVersion, ok := jsonIntValue(versionValue)
		if !ok {
			return s, "WRAPPER_INVALID", "Guard metadata version is not an integer"
		}
		if metaVersion > guardMetaVersion {
			return s, "WRAPPER_INVALID", "Guard metadata version is newer than this build"
		}
		s.Metadata = true
		s.MetaVersion = metaVersion
		if metaVersion == guardMetaVersion {
			hadArgsValue, _ := meta.get("hadArgs")
			if _, ok := hadArgsValue.(bool); !ok {
				return s, "WRAPPER_INVALID", "Guard metadata hadArgs is not a boolean"
			}
			hadEnvValue, _ := meta.get("hadEnv")
			if _, ok := hadEnvValue.(bool); !ok {
				return s, "WRAPPER_INVALID", "Guard metadata hadEnv is not a boolean"
			}
		}
	}
	s.GuardCommand = command
	if hasMeta || isGuardCommand(command, "") {
		s.Wrapped = true
		sep := findDoctorSeparator(args)
		if sep < 0 {
			return s, "WRAPPER_INVALID", "Guard wrapper has no -- separator"
		}
		flags, detail := parseDoctorWrapperFlags(args[:sep])
		if detail != "" {
			return s, "WRAPPER_INVALID", detail
		}
		if sep+1 >= len(args) || args[sep+1] == "" {
			return s, "WRAPPER_INVALID", "Guard wrapper has no server command after --"
		}
		s.Flags = flags
		s.OriginalCmd = args[sep+1]
		s.OriginalArgs = append([]string(nil), args[sep+2:]...)
		if strings.TrimSpace(s.OriginalCmd) == "" || strings.TrimSpace(s.OriginalCmd) != s.OriginalCmd {
			return s, "WRAPPER_INVALID", "wrapped server command is empty or has surrounding spaces"
		}
		if hasUnsafePolicyChars(s.OriginalCmd) {
			return s, "WRAPPER_INVALID", "wrapped server command contains control or invisible characters"
		}
		return s, "", ""
	}
	s.OriginalCmd = command
	s.OriginalArgs = args
	return s, "", ""
}

func (d *doctorRun) inspectServer(s *doctorServer, view *doctorServerView, explicit *doctorPolicy) []doctorFinding {
	var findings []doctorFinding
	add := func(code, severity, detail, fix string) {
		findings = append(findings, newDoctorFinding(code, severity, s.Client, s.ConfigPath, s.Name, detail, fix))
	}

	if s.Remote {
		add("REMOTE_NOT_COVERED", "risk", "remote MCP transport is not covered by Guard",
			"use a local stdio server if you need Guard coverage")
		return findings
	}
	if !s.Wrapped {
		add("NOT_WRAPPED", "risk", "stdio server is not wrapped by Guard",
			"run `sylenix-guard install` (or wrap the entry manually)")
	}
	metadataOutdated := s.Metadata && s.MetaVersion < guardMetaVersion
	if metadataOutdated {
		add("OUTDATED_GUARD", "risk",
			fmt.Sprintf("Guard wrapper metadata version %d is older than %d", s.MetaVersion, guardMetaVersion),
			"re-run `sylenix-guard install` with this build")
	}
	if s.Wrapped {
		if f := d.checkGuardBinary(*s); f != nil {
			// The metadata finding already tells the user to re-run install;
			// keep a missing or unreadable binary finding, but not a duplicate
			// "outdated" for the same wrapper.
			if !(metadataOutdated && f.Code == "OUTDATED_GUARD") {
				findings = append(findings, *f)
			}
		}
	}

	pol := d.resolvePolicy(*s, explicit)
	view.Policy = pol.path
	if pol.err != "" {
		add("POLICY_INVALID", "error", pol.err,
			"run `sylenix-guard policy validate <file>` and fix the policy, or pass the right --policy")
		view.Error = pol.err
		return findings
	}
	pf := pol.pf

	srv := policyServer{}
	if s.Wrapped {
		var detail string
		srv, detail = doctorServerPolicy(pf, s.effectiveName(), s.Flags.HasName)
		if detail != "" {
			add("POLICY_INVALID", "error", detail, "add the server entry or pass the matching --name")
			view.Error = detail
			return findings
		}
	}
	profile := selectPolicyProfile(s.effectiveName(), append([]string{s.OriginalCmd}, s.OriginalArgs...), pf.Profile)
	eff := computeDoctorEffective(pf, srv, profile, s.Flags)

	allowlisted, hashDetail := doctorAllowlisted(pf, s.OriginalCmd, s.OriginalArgs)
	view.Allowlisted = allowlisted
	if !eff.AllowlistEnforced {
		add("ALLOWLIST_NOT_ENFORCED", "risk", "the policy allowlist is not enforced",
			"set `allowlist_enforced: true` and add exact server entries")
	}
	if !allowlisted {
		add("NOT_ALLOWLISTED", "risk", "server command and arguments are not in the policy allowlist",
			fmt.Sprintf("run `sylenix-guard allow %q`", cleanForDialog(s.Name, 80)))
	}
	if hashDetail != "" {
		add("ALLOWLIST_HASH_MISMATCH", "error", hashDetail,
			"re-run `sylenix-guard allow <name>` to refresh the SHA-256")
	}

	if !s.Wrapped {
		return findings
	}

	view.Approval = eff.Approve
	if eff.Approve != "dialog" {
		add("APPROVALS_OFF", "risk",
			fmt.Sprintf("approval mode is %q; tainted sinks are hard-blocked instead of reviewed", eff.Approve),
			"set `--approve dialog` in the wrapper or `approval: dialog` in the policy")
	}
	trusted := sortedKeys(eff.Trust)
	if len(trusted) > 0 {
		view.TrustedTools = trusted
	}
	if len(trusted) > 0 && doctorHasEgress(eff) {
		add("TRUST_ON_EGRESS", "risk",
			fmt.Sprintf("trusted tools %q on a server with egress-class tools; their results will not latch taint",
				cleanForDialog(strings.Join(trusted, ","), 120)),
			"remove `--trust` (or `trust: true`) for this server")
	}
	view.ScratchDirs = d.checkScratch(*s, eff.Scratch, &findings)
	pinsExists, pinsValid := d.checkPins(*s, &findings)
	if d.requireSignatures {
		// Policy and pin signing is not implemented yet (Prompt 13). Until it
		// is, an unverified file is reported as unsigned; it is never assumed
		// to be safe.
		if pol.path != "" {
			add("UNSIGNED_POLICY", "risk",
				fmt.Sprintf("policy %q is not verifiably signed by this build", cleanForDialog(pol.path, 160)),
				"upgrade to a build with policy/pin signing and sign the policy")
		}
		if pinsExists && pinsValid {
			add("UNSIGNED_PINS", "risk",
				fmt.Sprintf("pin file %q is not verifiably signed by this build", cleanForDialog(d.pinsPath(*s), 160)),
				"upgrade to a build with policy/pin signing and sign the pin file")
		}
	}
	return findings
}

func (d *doctorRun) checkGuardBinary(s doctorServer) *doctorFinding {
	path, detail := resolveDoctorGuardCommand(s.GuardCommand)
	if detail != "" {
		f := newDoctorFinding("GUARD_NOT_FOUND", "error", s.Client, s.ConfigPath, s.Name,
			detail, "install Guard at that path or re-run `sylenix-guard install`")
		return &f
	}
	target, known, reason := guardBinaryVersion(path)
	if !known {
		f := newDoctorFinding("GUARD_VERSION_UNKNOWN", "risk", s.Client, s.ConfigPath, s.Name,
			fmt.Sprintf("cannot determine the Guard version at %q: %s", cleanForDialog(path, 160), reason),
			"point the config at the Guard binary or re-run `sylenix-guard install` with a released build")
		return &f
	}
	if target == version {
		return nil
	}
	current, currentKnown := parseDoctorVersion(version)
	other, otherKnown := parseDoctorVersion(target)
	if !otherKnown {
		f := newDoctorFinding("GUARD_VERSION_UNKNOWN", "risk", s.Client, s.ConfigPath, s.Name,
			fmt.Sprintf("Guard binary %q reports version %q, which cannot be compared", cleanForDialog(path, 160), cleanForDialog(target, 40)),
			"reinstall Guard from a released build")
		return &f
	}
	if currentKnown && compareDoctorVersions(other, current) < 0 {
		f := newDoctorFinding("OUTDATED_GUARD", "risk", s.Client, s.ConfigPath, s.Name,
			fmt.Sprintf("Guard binary %q is version %s; this doctor is %s", cleanForDialog(path, 160), cleanForDialog(target, 40), cleanForDialog(version, 40)),
			"upgrade Guard and re-run `sylenix-guard install`")
		return &f
	}
	return nil
}

func (d *doctorRun) checkScratch(s doctorServer, scratch []scratchRule, findings *[]doctorFinding) []string {
	var dirs []string
	seenDirs := map[string]bool{}
	seenDetail := map[string]bool{}
	seenUnresolved := false
	source := "allow_paths"
	if s.Flags.HasScratch {
		source = "--allow-write-under"
	}
	for _, rule := range scratch {
		if rule.dir == "" {
			*findings = append(*findings, newDoctorFinding("WRAPPER_INVALID", "error", s.Client, s.ConfigPath, s.Name,
				"a scratch rule has an empty directory", "remove the empty scratch entry"))
			continue
		}
		dir, ok := canonicalPath(rule.dir)
		if !ok {
			if !seenDirs["<unresolved>"] {
				seenDirs["<unresolved>"] = true
				dirs = append(dirs, "<unresolved>")
			}
			if !seenUnresolved {
				seenUnresolved = true
				*findings = append(*findings, newDoctorFinding("RISKY_SCRATCH", "risk", s.Client, s.ConfigPath, s.Name,
					"a scratch root cannot be resolved and cannot be proven safe",
					"use an absolute directory under the project, for example <repo>/out"))
			}
			continue
		}
		if !seenDirs[dir] {
			seenDirs[dir] = true
			dirs = append(dirs, dir)
		}
		var reasons []string
		if d.home != "" {
			if samePath(dir, d.home) {
				reasons = append(reasons, "the home directory")
			} else if insideDir(dir, d.home) {
				reasons = append(reasons, "an ancestor of the home directory")
			}
		}
		if d.repoRoot != "" {
			if samePath(dir, d.repoRoot) {
				reasons = append(reasons, "the repository root")
			} else if insideDir(dir, d.repoRoot) {
				reasons = append(reasons, "an ancestor of the repository root")
			}
		}
		if filepath.Dir(dir) == dir {
			reasons = append(reasons, "a filesystem root")
		}
		if len(reasons) == 0 {
			continue
		}
		detail := fmt.Sprintf("%s %q covers %s", source, cleanForDialog(rule.dir, 160), strings.Join(reasons, " and "))
		if seenDetail[detail] {
			continue
		}
		seenDetail[detail] = true
		*findings = append(*findings, newDoctorFinding("RISKY_SCRATCH", "risk", s.Client, s.ConfigPath, s.Name,
			detail, "narrow it to a project subdirectory, for example <repo>/out"))
	}
	sort.Strings(dirs)
	return dirs
}

func (d *doctorRun) checkPins(s doctorServer, findings *[]doctorFinding) (bool, bool) {
	if s.Flags.ResetPins {
		return false, false
	}
	path := d.pinsPath(s)
	if path == "" {
		return false, false
	}
	info, statErr := os.Stat(path)
	if os.IsNotExist(statErr) {
		return false, false
	}
	if statErr != nil {
		*findings = append(*findings, newDoctorFinding("PINS_UNREADABLE", "error", s.Client, s.ConfigPath, s.Name,
			fmt.Sprintf("pin file %q cannot be inspected", cleanForDialog(path, 160)),
			"inspect the file, or restart with `--reset-pins` to trust every tool as new"))
		return true, false
	}
	if !info.Mode().IsRegular() {
		*findings = append(*findings, newDoctorFinding("PINS_UNREADABLE", "error", s.Client, s.ConfigPath, s.Name,
			fmt.Sprintf("pin file %q is not a regular file", cleanForDialog(path, 160)),
			"replace it with a regular file, or restart with `--reset-pins` to trust every tool as new"))
		return true, false
	}
	if info.Size() > 16<<20 {
		*findings = append(*findings, newDoctorFinding("PINS_UNREADABLE", "error", s.Client, s.ConfigPath, s.Name,
			fmt.Sprintf("pin file %q is too large to inspect", cleanForDialog(path, 160)),
			"inspect the file, or restart with `--reset-pins` to trust every tool as new"))
		return true, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		*findings = append(*findings, newDoctorFinding("PINS_UNREADABLE", "error", s.Client, s.ConfigPath, s.Name,
			fmt.Sprintf("pin file %q cannot be read", cleanForDialog(path, 160)),
			"inspect the file, or restart with `--reset-pins` to trust every tool as new"))
		return true, false
	}
	var pins map[string]string
	if json.Unmarshal(b, &pins) != nil || pins == nil {
		*findings = append(*findings, newDoctorFinding("PINS_UNREADABLE", "error", s.Client, s.ConfigPath, s.Name,
			fmt.Sprintf("pin file %q is not a valid JSON hash map", cleanForDialog(path, 160)),
			"inspect the file, or restart with `--reset-pins` to trust every tool as new"))
		return true, false
	}
	for name, h := range pins {
		if name == "" || len(h) != sha256.Size*2 {
			*findings = append(*findings, newDoctorFinding("PINS_UNREADABLE", "error", s.Client, s.ConfigPath, s.Name,
				fmt.Sprintf("pin file %q contains a value that is not a SHA-256 hash", cleanForDialog(path, 160)),
				"inspect the file, or restart with `--reset-pins` to trust every tool as new"))
			return true, false
		}
		if _, err := hex.DecodeString(h); err != nil {
			*findings = append(*findings, newDoctorFinding("PINS_UNREADABLE", "error", s.Client, s.ConfigPath, s.Name,
				fmt.Sprintf("pin file %q contains a value that is not a SHA-256 hash", cleanForDialog(path, 160)),
				"inspect the file, or restart with `--reset-pins` to trust every tool as new"))
			return true, false
		}
	}
	return true, true
}

func (d *doctorRun) resolvePolicy(s doctorServer, explicit *doctorPolicy) doctorPolicy {
	if explicit != nil {
		return *explicit
	}
	if s.Flags.HasPolicy {
		return readDoctorPolicyFile(s.Flags.Policy)
	}
	state := d.defaultStateDir()
	if s.Flags.HasStateDir {
		state = resolveDoctorPath(s.Flags.StateDir)
	}
	if state == "" {
		return doctorPolicy{err: "cannot determine the state directory; pass --state-dir"}
	}
	path := filepath.Join(state, policyFileName)
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return doctorPolicy{pf: defaultPolicyFile()}
	}
	if err != nil {
		return doctorPolicy{path: path, err: fmt.Sprintf("policy %q cannot be read", cleanForDialog(path, 160))}
	}
	pf, err := parsePolicyBytes(b)
	if err != nil {
		return doctorPolicy{path: path, err: fmt.Sprintf("policy %q is not valid; run `sylenix-guard policy validate %q`",
			cleanForDialog(path, 160), cleanForDialog(path, 160))}
	}
	return doctorPolicy{pf: pf, path: path}
}

func (d *doctorRun) defaultStateDir() string {
	if d.stateDir != "" {
		return resolveDoctorPath(d.stateDir)
	}
	if d.home == "" {
		return ""
	}
	return filepath.Join(d.home, ".sylenix-poc")
}

func (d *doctorRun) pinsPath(s doctorServer) string {
	state := d.defaultStateDir()
	if s.Flags.HasStateDir {
		state = resolveDoctorPath(s.Flags.StateDir)
	}
	if state == "" {
		return ""
	}
	name := s.effectiveName()
	if name == "" {
		return ""
	}
	return filepath.Join(state, "pins-"+name+".json")
}

func (d *doctorRun) report() doctorReport {
	findings := d.findings
	if findings == nil {
		findings = []doctorFinding{}
	}
	configs := d.configs
	if configs == nil {
		configs = []doctorConfig{}
	}
	return doctorReport{Version: version, Clean: len(findings) == 0, Configs: configs, Findings: findings}
}

func (d *doctorRun) writeJSON(report doctorReport) int {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard doctor:", err)
		return 2
	}
	return 0
}

func (d *doctorRun) writeHuman(report doctorReport) {
	fmt.Printf("Sylenix Guard doctor %s\n", cleanForDialog(report.Version, 40))
	if len(report.Configs) == 0 && len(report.Findings) == 0 {
		fmt.Println("No supported MCP client configs found.")
	}
	for _, cfg := range report.Configs {
		fmt.Printf("\nConfig: %s (%s)\n", cleanForDialog(cfg.Path, 240), cleanForDialog(cfg.Client, 80))
		if cfg.Error != "" {
			fmt.Printf("  cannot inspect: %s\n", cleanForDialog(cfg.Error, 240))
		}
		if len(cfg.Servers) == 0 && cfg.Error == "" {
			fmt.Println("  no MCP server map found")
		}
		for _, srv := range cfg.Servers {
			name := fmt.Sprintf("%q", cleanForDialog(srv.Name, 80))
			mapName := cleanForDialog(srv.Map, 80)
			switch {
			case srv.Transport == "remote":
				fmt.Printf("  server %s [%s]: NOT covered (remote transport)\n", name, mapName)
			case srv.Error != "":
				status := "not wrapped"
				if srv.Wrapped {
					status = "wrapped"
				}
				fmt.Printf("  server %s [%s]: INVALID (%s): %s\n", name, mapName, status, cleanForDialog(srv.Error, 240))
			case srv.Wrapped:
				parts := []string{"wrapped by Guard"}
				if srv.Allowlisted {
					parts = append(parts, "allowlisted")
				} else {
					parts = append(parts, "NOT allowlisted")
				}
				if srv.Approval != "" {
					parts = append(parts, "approval="+srv.Approval)
				}
				if len(srv.TrustedTools) > 0 {
					parts = append(parts, "trust="+cleanForDialog(strings.Join(srv.TrustedTools, ","), 120))
				}
				if len(srv.ScratchDirs) > 0 {
					parts = append(parts, "scratch="+cleanForDialog(strings.Join(srv.ScratchDirs, ","), 160))
				}
				fmt.Printf("  server %s [%s]: %s\n", name, mapName, strings.Join(parts, ", "))
			default:
				fmt.Printf("  server %s [%s]: NOT wrapped by Guard (stdio)\n", name, mapName)
			}
		}
	}
	if len(report.Findings) == 0 {
		fmt.Println("\nNo findings.")
		return
	}
	fmt.Printf("\nFindings: %d\n", len(report.Findings))
	for _, f := range report.Findings {
		where := ""
		if f.Config != "" {
			where = " in " + cleanForDialog(f.Config, 240)
		}
		if f.Server != "" {
			where = fmt.Sprintf(" server %q", cleanForDialog(f.Server, 80)) + where
		}
		fmt.Printf("  [%s]%s: %s\n", f.Code, where, cleanForDialog(f.Detail, 400))
		fmt.Printf("    fix: %s\n", cleanForDialog(f.Fix, 240))
	}
}

func newDoctorFinding(code, severity, client, configPath, server, detail, fix string) doctorFinding {
	return doctorFinding{
		Code: code, Severity: severity, Client: client, Config: configPath,
		Server: server, Detail: detail, Fix: fix,
	}
}

func doctorFixForCode(code string) string {
	switch code {
	case "SERVER_INVALID":
		return "make the server a stdio entry with a string command and a string args array"
	case "WRAPPER_INVALID":
		return "re-run `sylenix-guard install` to rewrite the wrapper, or fix the Guard flags in the config"
	default:
		return "fix the client config"
	}
}

func sortDoctorFindings(findings []doctorFinding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Config != b.Config {
			return a.Config < b.Config
		}
		if a.Server != b.Server {
			return a.Server < b.Server
		}
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		return a.Detail < b.Detail
	})
}

func findDoctorSeparator(args []string) int {
	valueFlags := map[string]bool{
		"name": true, "state-dir": true, "policy": true, "readonly": true,
		"trust": true, "approve": true, "allow-write-under": true, "grant": true,
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return i
		}
		name := strings.TrimLeft(arg, "-")
		if name == "" {
			continue
		}
		if strings.Contains(name, "=") {
			continue
		}
		if valueFlags[name] {
			i++ // the next argument is this flag's value, even if it is "--"
		}
	}
	return -1
}

func parseDoctorWrapperFlags(args []string) (doctorWrapperFlags, string) {
	var f doctorWrapperFlags
	for i := 0; i < len(args); i++ {
		raw := args[i]
		name := raw
		inline := ""
		hasInline := false
		if eq := strings.Index(name, "="); eq >= 0 {
			name, inline, hasInline = name[:eq], name[eq+1:], true
		}
		name = strings.TrimLeft(name, "-")
		if name == "" {
			return f, "empty Guard flag"
		}
		safeName := cleanForDialog(name, 80)
		value := func() (string, string) {
			if hasInline {
				if inline == "--" {
					return "", safeName + " has an empty value"
				}
				return inline, ""
			}
			if i+1 >= len(args) {
				return "", safeName + " needs a value"
			}
			i++
			if args[i] == "--" {
				return "", safeName + " has an empty value"
			}
			return args[i], ""
		}
		switch name {
		case "name":
			v, detail := value()
			if detail != "" {
				return f, detail
			}
			if !validDoctorName(v) {
				return f, "name contains a path separator, a reserved character or control characters"
			}
			f.HasName, f.Name = true, v
		case "state-dir":
			v, detail := value()
			if detail != "" {
				return f, detail
			}
			if v == "" || strings.TrimSpace(v) != v || hasUnsafePolicyChars(v) {
				return f, "state-dir is empty or contains surrounding spaces/control characters"
			}
			f.HasStateDir, f.StateDir = true, v
		case "policy":
			v, detail := value()
			if detail != "" {
				return f, detail
			}
			if v == "" || strings.TrimSpace(v) != v || hasUnsafePolicyChars(v) {
				return f, "policy is empty or contains surrounding spaces/control characters"
			}
			f.HasPolicy, f.Policy = true, v
		case "readonly":
			v, detail := value()
			if detail != "" {
				return f, detail
			}
			if hasUnsafePolicyChars(v) {
				return f, "readonly contains control or invisible characters"
			}
			f.HasReadonly, f.Readonly = true, v
		case "trust":
			v, detail := value()
			if detail != "" {
				return f, detail
			}
			if hasUnsafePolicyChars(v) {
				return f, "trust contains control or invisible characters"
			}
			f.HasTrust, f.Trust = true, v
		case "approve":
			v, detail := value()
			if detail != "" {
				return f, detail
			}
			if v != "deny" && v != "dialog" {
				return f, "approve must be deny or dialog"
			}
			f.HasApprove, f.Approve = true, v
		case "allow-write-under":
			v, detail := value()
			if detail != "" {
				return f, detail
			}
			if hasUnsafePolicyChars(v) {
				return f, "allow-write-under contains control or invisible characters"
			}
			tool, dir := "", v
			if eq := strings.Index(v, "="); eq >= 0 {
				tool, dir = v[:eq], v[eq+1:]
			}
			if dir == "" || strings.ContainsAny(tool, `/\`) || hasUnsafePolicyChars(tool) {
				return f, "allow-write-under must be DIR or TOOL=DIR"
			}
			f.HasScratch = true
			f.Scratch = append(f.Scratch, scratchRule{tool: tool, dir: dir})
		case "grant":
			v, detail := value()
			if detail != "" {
				return f, detail
			}
			if hasUnsafePolicyChars(v) {
				return f, "grant contains control or invisible characters"
			}
			if detail := validateDoctorGrantSpec(v); detail != "" {
				return f, detail
			}
			f.HasGrant = true
			f.Grants = append(f.Grants, v)
		case "no-spotlight", "reset-pins":
			v := true
			if hasInline {
				parsed, err := strconv.ParseBool(inline)
				if err != nil {
					return f, safeName + " has an invalid boolean value"
				}
				v = parsed
			}
			if name == "no-spotlight" {
				f.NoSpotlight = v
			} else {
				f.ResetPins = v
			}
		default:
			return f, "unknown Guard flag " + safeName
		}
	}
	return f, ""
}

func validateDoctorGrantSpec(spec string) string {
	i := strings.LastIndex(spec, "=")
	if i <= 0 {
		return "grant must be TOOL[:DIR]=DURATION"
	}
	dur, err := time.ParseDuration(spec[i+1:])
	if err != nil || dur <= 0 {
		return "grant duration must be positive"
	}
	tool := spec[:i]
	if j := strings.Index(tool, ":"); j >= 0 {
		tool = tool[:j]
	}
	if tool == "" || strings.ContainsAny(tool, `/\`) {
		return "grant must name a tool"
	}
	return ""
}

func validDoctorName(s string) bool {
	if s == "" || s == "." || s == ".." || strings.TrimSpace(s) != s {
		return false
	}
	if strings.ContainsAny(s, `/\`) {
		return false
	}
	if runtime.GOOS == "windows" && strings.ContainsAny(s, `<>:"|?*`) {
		return false
	}
	return !hasUnsafePolicyChars(s)
}

func (s doctorServer) effectiveName() string {
	if s.Flags.HasName {
		return s.Flags.Name
	}
	if s.OriginalCmd == "" {
		return s.Name
	}
	return filepath.Base(s.OriginalCmd)
}

func doctorServerPolicy(pf *policyFile, name string, nameExplicit bool) (policyServer, string) {
	if pf == nil || len(pf.Servers) == 0 {
		return policyServer{}, ""
	}
	if len(pf.Servers) == 1 && !nameExplicit {
		for _, srv := range pf.Servers {
			return srv, ""
		}
	}
	srv, ok := pf.Servers[name]
	if !ok {
		return policyServer{}, fmt.Sprintf("policy has no entry for server %q", cleanForDialog(name, 80))
	}
	return srv, ""
}

func computeDoctorEffective(pf *policyFile, srv policyServer, profile *policyProfile, f doctorWrapperFlags) doctorEffective {
	e := doctorEffective{
		Approve:  "deny",
		Readonly: map[string]bool{},
		Trust:    map[string]bool{},
		Classes:  map[string]string{},
	}
	if pf != nil {
		if pf.Approval != "" {
			e.Approve = pf.Approval
		}
		if pf.AllowlistEnforced != nil {
			e.AllowlistEnforced = *pf.AllowlistEnforced
		} else {
			e.AllowlistEnforced = len(pf.Allowlist) > 0
		}
	}
	if f.HasApprove {
		e.Approve = f.Approve
	}
	if profile != nil {
		for tool, class := range profile.tools {
			switch class {
			case "read":
				if !f.HasReadonly {
					e.Readonly[tool] = true
				}
			case "write", "exec", "egress":
				e.Classes[tool] = class
			}
		}
	}
	for tname, tool := range srv.Tools {
		delete(e.Readonly, tname)
		delete(e.Classes, tname)
		switch tool.Class {
		case "read":
			if !f.HasReadonly {
				e.Readonly[tname] = true
			}
		case "write", "exec", "egress":
			e.Classes[tname] = tool.Class
		}
		if tool.Trust && !f.HasTrust {
			e.Trust[tname] = true
		}
		if !f.HasScratch && tool.Class == "write" {
			for _, p := range tool.AllowPaths {
				e.Scratch = append(e.Scratch, scratchRule{tool: tname, dir: p})
			}
		}
	}
	if f.HasReadonly {
		e.Readonly = toSet(f.Readonly)
	}
	if f.HasTrust {
		e.Trust = toSet(f.Trust)
	}
	if f.HasScratch {
		e.Scratch = append([]scratchRule(nil), f.Scratch...)
	}
	return e
}

func doctorHasEgress(e doctorEffective) bool {
	for tool, class := range e.Classes {
		if e.Readonly[tool] {
			continue
		}
		if class == "egress" {
			return true
		}
	}
	return false
}

func doctorAllowlisted(pf *policyFile, command string, args []string) (bool, string) {
	if pf == nil {
		return false, ""
	}
	matched := false
	mismatch := ""
	for _, entry := range pf.Allowlist {
		if !matchAllowedCommand(entry.Command, command) {
			continue
		}
		if entry.Args == nil || !matchAllowedArgs(*entry.Args, args) {
			continue
		}
		matched = true
		if entry.SHA256 == "" {
			return true, ""
		}
		target := entry.Lockfile
		if target == "" {
			resolved, ok := resolveCommandFile(command)
			if !ok {
				if mismatch == "" {
					mismatch = fmt.Sprintf("cannot resolve %q to verify the allowlisted SHA-256", cleanForDialog(command, 160))
				}
				continue
			}
			target = resolved
		}
		sum, ok := hashFileSHA256(target)
		if !ok {
			if mismatch == "" {
				mismatch = fmt.Sprintf("cannot read %q to verify the allowlisted SHA-256", cleanForDialog(target, 160))
			}
			continue
		}
		if !strings.EqualFold(sum, entry.SHA256) {
			if mismatch == "" {
				mismatch = "the allowlisted SHA-256 does not match the resolved command"
			}
			continue
		}
		return true, ""
	}
	if matched {
		return true, mismatch
	}
	return false, ""
}

func findDoctorRepoRoot(start string) string {
	if start == "" {
		return ""
	}
	dir, err := filepath.Abs(start)
	if err != nil {
		return start
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return start
}

func resolveDoctorPath(p string) string {
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

func readDoctorPolicyFile(path string) doctorPolicy {
	if path == "" {
		return doctorPolicy{err: "policy path is empty"}
	}
	path = resolveDoctorPath(path)
	b, err := os.ReadFile(path)
	if err != nil {
		return doctorPolicy{path: path, err: fmt.Sprintf("policy %q cannot be read", cleanForDialog(path, 160))}
	}
	pf, err := parsePolicyBytes(b)
	if err != nil {
		return doctorPolicy{path: path, err: fmt.Sprintf("policy %q is not valid; run `sylenix-guard policy validate %q`",
			cleanForDialog(path, 160), cleanForDialog(path, 160))}
	}
	return doctorPolicy{pf: pf, path: path}
}

func resolveDoctorGuardCommand(command string) (string, string) {
	if command == "" {
		return "", "Guard command is empty"
	}
	if hasUnsafePolicyChars(command) {
		return "", "Guard command contains control or invisible characters"
	}
	if strings.ContainsAny(command, `/\`) || filepath.IsAbs(command) || isWindowsDrivePath(command) {
		p := resolveDoctorPath(command)
		info, err := os.Stat(p)
		if err != nil {
			return "", fmt.Sprintf("Guard command %q does not exist", cleanForDialog(command, 160))
		}
		if info.IsDir() {
			return "", fmt.Sprintf("Guard command %q is a directory", cleanForDialog(command, 160))
		}
		if !info.Mode().IsRegular() {
			return "", fmt.Sprintf("Guard command %q is not a regular file", cleanForDialog(command, 160))
		}
		if info.Size() > 1<<30 {
			return "", fmt.Sprintf("Guard command %q is too large to inspect", cleanForDialog(command, 160))
		}
		return p, ""
	}
	p, err := exec.LookPath(command)
	if err != nil {
		return "", fmt.Sprintf("Guard command %q is not on PATH", cleanForDialog(command, 160))
	}
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	info, err := os.Stat(p)
	if err != nil || info.IsDir() {
		return "", fmt.Sprintf("Guard command %q cannot be resolved to a file", cleanForDialog(command, 160))
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Sprintf("Guard command %q is not a regular file", cleanForDialog(command, 160))
	}
	if info.Size() > 1<<30 {
		return "", fmt.Sprintf("Guard command %q is too large to inspect", cleanForDialog(command, 160))
	}
	return p, ""
}

func guardBinaryVersion(path string) (string, bool, string) {
	if self, err := os.Executable(); err == nil && sameExecutablePath(path, self) {
		return version, true, ""
	}
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return "", false, "not a readable Go binary"
	}
	if info.Main.Path != "sylenix-guard-poc" {
		return "", false, "not a Sylenix Guard binary"
	}
	for _, setting := range info.Settings {
		if setting.Key != "-ldflags" {
			continue
		}
		if v, ok := versionFromLDFlags(setting.Value); ok {
			return v, true, ""
		}
	}
	if v := info.Main.Version; v != "" && v != "(devel)" && !strings.ContainsAny(v, "-+") {
		return v, true, ""
	}
	return "", false, "the binary has no embedded version (built without -X main.version)"
}

func sameExecutablePath(a, b string) bool {
	if sameCommandPath(a, b) {
		return true
	}
	aa, err1 := filepath.EvalSymlinks(a)
	bb, err2 := filepath.EvalSymlinks(b)
	if err1 == nil && err2 == nil {
		return sameCommandPath(aa, bb)
	}
	return false
}

func versionFromLDFlags(s string) (string, bool) {
	fields := strings.Fields(s)
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		if f == "-X" && i+1 < len(fields) {
			if v, ok := versionAssignment(fields[i+1]); ok {
				return v, true
			}
			i++
			continue
		}
		if strings.HasPrefix(f, "-X=") {
			if v, ok := versionAssignment(strings.TrimPrefix(f, "-X=")); ok {
				return v, true
			}
		}
	}
	return "", false
}

func versionAssignment(s string) (string, bool) {
	s = strings.Trim(s, `"'`)
	const prefix = "main.version="
	if !strings.HasPrefix(s, prefix) {
		return "", false
	}
	v := strings.Trim(s[len(prefix):], `"'`)
	if v == "" {
		return "", false
	}
	return v, true
}

func parseDoctorVersion(s string) ([]int, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	if s == "" || strings.EqualFold(s, "dev") || s == "(devel)" {
		return nil, false
	}
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 4 {
		return nil, false
	}
	out := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}

func compareDoctorVersions(a, b []int) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}

// ---------------------------------------------------------------- install / uninstall

func runConfigCommand(action string, args []string) int {
	fs := flag.NewFlagSet(action, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	yes := fs.Bool("yes", false, "apply changes without asking for confirmation")
	dryRun := fs.Bool("dry-run", false, "show the diff but do not write")
	policyPath := ""
	stateDir := ""
	if action == "install" {
		fs.StringVar(&policyPath, "policy", "", "policy file to update with the server allowlist (default: <state-dir>/policy.yaml)")
		fs.StringVar(&stateDir, "state-dir", "", "state directory for the default policy file (default ~/.sylenix-poc)")
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "sylenix-guard %s: unexpected arguments: %s\n", action, strings.Join(fs.Args(), " "))
		return 2
	}
	guardPath, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard:", err)
		return 2
	}
	if abs, err := filepath.Abs(guardPath); err == nil {
		guardPath = abs
	}

	// Pin custom policy/state paths in the wrapper, otherwise the installed
	// config would launch the guard with the default paths and never load the
	// allowlist install just wrote.
	var wrapperFlags []string
	if action == "install" {
		if policyPath != "" {
			abs, err := filepath.Abs(policyPath)
			if err != nil {
				fmt.Fprintln(os.Stderr, "sylenix-guard install:", err)
				return 2
			}
			wrapperFlags = append(wrapperFlags, "--policy="+abs)
		}
		if stateDir != "" {
			abs, err := filepath.Abs(stateDir)
			if err != nil {
				fmt.Fprintln(os.Stderr, "sylenix-guard install:", err)
				return 2
			}
			wrapperFlags = append(wrapperFlags, "--state-dir="+abs)
		}
	}

	var entries []policyAllowEntry
	var pf *policyFile
	var policyFile string
	if action == "install" && !*dryRun {
		policyFile, err = policyWritePath(policyPath, stateDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "sylenix-guard install:", err)
			return 2
		}
		var errs []error
		entries, errs = collectConfiguredServers()
		if len(errs) > 0 {
			for _, err := range errs {
				fmt.Fprintln(os.Stderr, "sylenix-guard install:", err)
			}
			fmt.Fprintln(os.Stderr, "sylenix-guard install: refusing to change configs or the allowlist while a supported config cannot be read")
			return 1
		}
		if len(entries) > 0 {
			// Validate an existing policy before touching any config, and make
			// sure a custom --policy path exists for the wrapper to load even if
			// the allowlist prompt is declined.
			if _, statErr := os.Stat(policyFile); policyPath != "" && os.IsNotExist(statErr) {
				if err := writeDefaultPolicyFile(policyFile); err != nil {
					fmt.Fprintln(os.Stderr, "sylenix-guard install:", err)
					return 1
				}
			}
			pf, err = loadPolicyForUpdate(policyFile)
			if err != nil {
				fmt.Fprintln(os.Stderr, "sylenix-guard install:", err)
				return 2
			}
		}
	}

	found := false
	failures := 0
	for _, target := range discoverConfigTargets() {
		if _, err := os.Stat(target.path); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			fmt.Fprintf(os.Stderr, "%s: cannot inspect %s: %v\n", action, target.path, err)
			failures++
			continue
		}
		found = true
		if err := processConfigFile(action, target, guardPath, wrapperFlags, *yes, *dryRun); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s: %v\n", action, target.path, err)
			failures++
		}
	}
	if !found {
		fmt.Println("No supported MCP config files found.")
	}
	if failures > 0 {
		return 1
	}
	if action == "install" && !*dryRun && len(entries) > 0 {
		if changed := mergeAllowEntries(pf, entries); changed {
			if !*yes {
				fmt.Printf("Add these server commands to the allowlist in %s?\n", policyFile)
				for _, entry := range entries {
					args, _ := json.Marshal(entry.Args)
					fmt.Printf("  %s: %s %s\n", entry.Name, yamlPolicyString(entry.Command), args)
				}
				fmt.Printf("Approve the allowlist? [y/N] ")
				answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
				answer = strings.ToLower(strings.TrimSpace(answer))
				if answer != "y" && answer != "yes" {
					fmt.Println("allowlist not changed; use sylenix-guard allow <name> later")
					return 0
				}
			}
			if err := writePolicyFile(policyFile, pf); err != nil {
				fmt.Fprintln(os.Stderr, "sylenix-guard install:", err)
				return 1
			}
			fmt.Printf("wrote allowlist entries to %s\n", policyFile)
		} else {
			fmt.Printf("allowlist in %s is already up to date\n", policyFile)
		}
	}
	return 0
}

func discoverConfigTargets() []configTarget {
	var targets []configTarget
	home, _ := os.UserHomeDir()
	configDir, _ := os.UserConfigDir()
	cwd, _ := os.Getwd()

	add := func(client, path string, paths ...[]string) {
		if path == "" {
			return
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return
		}
		targets = append(targets, configTarget{client: client, path: abs, serverPaths: paths})
	}
	mcpServers := func() []string { return []string{"mcpServers"} }
	servers := func() []string { return []string{"servers"} }
	vscodeSettings := func() []string { return []string{"mcp", "servers"} }

	if configDir != "" {
		add("Claude Desktop", filepath.Join(configDir, "Claude", "claude_desktop_config.json"), mcpServers())
		add("VS Code settings", filepath.Join(configDir, "Code", "User", "settings.json"), vscodeSettings(), mcpServers())
		add("VS Code user MCP", filepath.Join(configDir, "Code", "User", "mcp.json"), servers(), mcpServers())
	}
	if home != "" {
		add("Claude Code", filepath.Join(home, ".claude.json"), mcpServers())
		add("Cursor", filepath.Join(home, ".cursor", "mcp.json"), mcpServers())
	}
	if cwd != "" {
		add("Claude Code project", filepath.Join(cwd, ".mcp.json"), mcpServers())
		add("Cursor project", filepath.Join(cwd, ".cursor", "mcp.json"), mcpServers())
		add("VS Code workspace", filepath.Join(cwd, ".vscode", "mcp.json"), servers(), mcpServers())
	}

	seen := map[string]bool{}
	out := targets[:0]
	for _, target := range targets {
		key := target.path
		if runtime.GOOS == "windows" {
			key = strings.ToLower(key)
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, target)
	}
	return out
}

func processConfigFile(action string, target configTarget, guardPath string, wrapperFlags []string, yes, dryRun bool) error {
	info, err := os.Stat(target.path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("path is a directory")
	}
	oldData, err := os.ReadFile(target.path)
	if err != nil {
		return err
	}
	if hasDuplicateKeys(oldData) {
		return fmt.Errorf("refusing to edit a config with duplicate JSON keys")
	}
	root, err := parseConfigObject(oldData)
	if err != nil {
		return fmt.Errorf("cannot parse config: %w", err)
	}

	changed := false
	seenMap := false
	for _, path := range target.serverPaths {
		serverMap, exists, err := lookupConfigMap(root, path)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		seenMap = true
		for _, name := range sortedObjectKeys(serverMap) {
			value, _ := serverMap.get(name)
			entry, ok := value.(*configObject)
			if !ok {
				fmt.Printf("skip %s [%s] %s: entry is not an object\n", target.client, strings.Join(path, "."), name)
				continue
			}
			if action == "install" {
				wrapped, report := wrapConfigEntry(entry, guardPath, wrapperFlags)
				if wrapped {
					changed = true
					fmt.Printf("wrap %s [%s] %s\n", target.client, strings.Join(path, "."), name)
				} else {
					fmt.Printf("skip %s [%s] %s: %s\n", target.client, strings.Join(path, "."), name, report)
				}
			} else {
				unwrapped, report := unwrapConfigEntry(entry, guardPath)
				if unwrapped {
					changed = true
					fmt.Printf("unwrap %s [%s] %s\n", target.client, strings.Join(path, "."), name)
				} else if report != "" {
					fmt.Printf("skip %s [%s] %s: %s\n", target.client, strings.Join(path, "."), name, report)
				}
			}
		}
	}
	if !seenMap {
		fmt.Printf("%s: no MCP server map found\n", target.path)
		return nil
	}
	if !changed {
		fmt.Printf("%s: no changes\n", target.path)
		return nil
	}

	newData, err := marshalConfigObject(root)
	if err != nil {
		return err
	}
	if bytes.Equal(oldData, newData) {
		fmt.Printf("%s: no changes\n", target.path)
		return nil
	}
	printConfigDiff(target.path, oldData, newData)
	if dryRun {
		fmt.Printf("dry-run: would write %s\n", target.path)
		return nil
	}
	if !yes {
		fmt.Printf("Apply changes to %s? [y/N] ", target.path)
		answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		answer = strings.ToLower(strings.TrimSpace(answer))
		if answer != "y" && answer != "yes" {
			fmt.Printf("skipped %s\n", target.path)
			return nil
		}
	}
	backup, err := writeConfigBackup(target.path, oldData, info.Mode().Perm())
	if err != nil {
		return fmt.Errorf("backup failed: %w", err)
	}
	if err := writeConfigAtomic(target.path, newData, info.Mode().Perm()); err != nil {
		return fmt.Errorf("write failed after backup %s: %w", backup, err)
	}
	fmt.Printf("wrote %s (backup: %s)\n", target.path, backup)
	return nil
}

// configObject preserves the original JSON key order while allowing targeted
// edits, so an install/uninstall round trip does not reorder unrelated config.
type configObject struct {
	keys   []string
	values map[string]any
}

func newConfigObject() *configObject {
	return &configObject{values: map[string]any{}}
}

func (o *configObject) get(key string) (any, bool) {
	value, ok := o.values[key]
	return value, ok
}

func (o *configObject) set(key string, value any) {
	if _, exists := o.values[key]; !exists {
		o.keys = append(o.keys, key)
	}
	o.values[key] = value
}

func (o *configObject) del(key string) {
	if _, exists := o.values[key]; !exists {
		return
	}
	delete(o.values, key)
	for i, k := range o.keys {
		if k == key {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			break
		}
	}
}

func (o *configObject) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, key := range o.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		keyJSON, err := marshalJSONNoHTML(key)
		if err != nil {
			return nil, err
		}
		valueJSON, err := marshalJSONNoHTML(o.values[key])
		if err != nil {
			return nil, err
		}
		buf.Write(keyJSON)
		buf.WriteByte(':')
		buf.Write(valueJSON)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func marshalJSONNoHTML(value any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func decodeConfigValue(dec *json.Decoder) (any, error) {
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := token.(json.Delim); ok {
		switch delim {
		case '{':
			object := newConfigObject()
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, fmt.Errorf("object key is not a string")
				}
				value, err := decodeConfigValue(dec)
				if err != nil {
					return nil, err
				}
				object.set(key, value)
			}
			if end, err := dec.Token(); err != nil || end != json.Delim('}') {
				return nil, fmt.Errorf("unterminated object")
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for dec.More() {
				value, err := decodeConfigValue(dec)
				if err != nil {
					return nil, err
				}
				array = append(array, value)
			}
			if end, err := dec.Token(); err != nil || end != json.Delim(']') {
				return nil, fmt.Errorf("unterminated array")
			}
			return array, nil
		default:
			return nil, fmt.Errorf("unexpected JSON delimiter %q", delim)
		}
	}
	return token, nil
}

func parseConfigObject(data []byte) (*configObject, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	value, err := decodeConfigValue(dec)
	if err != nil {
		return nil, err
	}
	root, ok := value.(*configObject)
	if !ok {
		return nil, fmt.Errorf("top-level JSON value must be an object")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("trailing data after JSON object")
		}
		return nil, err
	}
	return root, nil
}

func marshalConfigObject(root *configObject) ([]byte, error) {
	compact, err := marshalJSONNoHTML(root)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := json.Indent(&out, compact, "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

func lookupConfigMap(root *configObject, path []string) (*configObject, bool, error) {
	var current any = root
	for i, key := range path {
		obj, ok := current.(*configObject)
		if !ok {
			return nil, false, fmt.Errorf("%s is not an object", strings.Join(path[:i], "."))
		}
		value, exists := obj.get(key)
		if !exists {
			return nil, false, nil
		}
		if i == len(path)-1 {
			serverMap, ok := value.(*configObject)
			if !ok {
				return nil, false, fmt.Errorf("%s is not an object", strings.Join(path[:i+1], "."))
			}
			return serverMap, true, nil
		}
		current = value
	}
	return root, true, nil
}

func sortedObjectKeys(o *configObject) []string {
	keys := append([]string(nil), o.keys...)
	sort.Strings(keys)
	return keys
}

func remoteConfigEntry(entry *configObject) bool {
	if _, ok := entry.get("url"); ok {
		return true
	}
	value, ok := entry.get("type")
	if !ok {
		return false
	}
	typ, ok := value.(string)
	if !ok {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(typ)) {
	case "http", "sse", "ws", "websocket", "streamable-http", "streamable_http":
		return true
	}
	return false
}

func wrapConfigEntry(entry *configObject, guardPath string, wrapperFlags []string) (bool, string) {
	if _, ok := entry.get(guardMetaKey); ok {
		return false, "already wrapped"
	}
	if value, ok := entry.get("command"); ok {
		if command, ok := value.(string); ok && isGuardCommand(command, guardPath) {
			return false, "already uses Guard"
		}
	}
	if remoteConfigEntry(entry) {
		return false, "remote entry (url/type)"
	}
	if typ, ok := entry.get("type"); ok {
		text, ok := typ.(string)
		if !ok {
			return false, "type is not a string"
		}
		if text != "" && !strings.EqualFold(strings.TrimSpace(text), "stdio") {
			return false, fmt.Sprintf("unsupported transport %q", text)
		}
	}
	value, ok := entry.get("command")
	if !ok {
		return false, "no stdio command"
	}
	command, ok := value.(string)
	if !ok || command == "" {
		return false, "no stdio command"
	}
	hadArgs := false
	var originalArgs []any
	if value, ok := entry.get("args"); ok {
		hadArgs = true
		args, ok := value.([]any)
		if !ok {
			return false, "args is not an array"
		}
		for _, arg := range args {
			if _, ok := arg.(string); !ok {
				return false, "args contains a non-string value"
			}
		}
		originalArgs = args
	}
	hadEnv := false
	if value, ok := entry.get("env"); ok {
		hadEnv = true
		env, ok := value.(*configObject)
		if !ok {
			return false, "env is not an object"
		}
		for _, key := range env.keys {
			if _, ok := env.values[key].(string); !ok {
				return false, "env contains a non-string value"
			}
		}
	}

	wrapperArgs := make([]any, 0, len(originalArgs)+len(wrapperFlags)+2)
	for _, flag := range wrapperFlags {
		wrapperArgs = append(wrapperArgs, flag)
	}
	wrapperArgs = append(wrapperArgs, "--", command)
	wrapperArgs = append(wrapperArgs, originalArgs...)
	entry.set("command", guardPath)
	entry.set("args", wrapperArgs)
	meta := newConfigObject()
	meta.set("version", guardMetaVersion)
	meta.set("hadArgs", hadArgs)
	meta.set("hadEnv", hadEnv)
	entry.set(guardMetaKey, meta)
	return true, ""
}

func unwrapConfigEntry(entry *configObject, guardPath string) (bool, string) {
	command := ""
	if value, ok := entry.get("command"); ok {
		command, _ = value.(string)
	}
	metaValue, hasMeta := entry.get(guardMetaKey)
	hadArgs := false
	hadEnv := false
	if hasMeta {
		meta, ok := metaValue.(*configObject)
		if !ok {
			return false, "Guard metadata is not an object"
		}
		versionValue, _ := meta.get("version")
		version, ok := jsonIntValue(versionValue)
		if !ok || version != guardMetaVersion {
			return false, "unsupported Guard metadata version"
		}
		hadArgsValue, _ := meta.get("hadArgs")
		if hadArgs, ok = hadArgsValue.(bool); !ok {
			return false, "Guard metadata hadArgs is invalid"
		}
		hadEnvValue, _ := meta.get("hadEnv")
		if hadEnv, ok = hadEnvValue.(bool); !ok {
			return false, "Guard metadata hadEnv is invalid"
		}
	} else if !isGuardCommand(command, guardPath) {
		return false, ""
	}

	value, ok := entry.get("args")
	if !ok {
		return false, "cannot restore: wrapper args are missing"
	}
	args, ok := value.([]any)
	if !ok || len(args) < 2 {
		return false, "cannot restore: wrapper args are missing"
	}
	rawArgs := make([]string, 0, len(args))
	for _, arg := range args {
		text, ok := arg.(string)
		if !ok {
			return false, "cannot restore: wrapper args contain a non-string"
		}
		rawArgs = append(rawArgs, text)
	}
	originalCommand, originalStrings, ok := guardWrapperCommand(rawArgs)
	if !ok || originalCommand == "" {
		return false, "cannot restore: wrapper args do not contain -- <command>"
	}
	originalArgs := make([]any, len(originalStrings))
	for i, arg := range originalStrings {
		originalArgs[i] = arg
	}
	if hasMeta && hadEnv {
		if _, ok := entry.get("env"); !ok {
			return false, "cannot restore: original env is missing"
		}
	}
	if hasMeta {
		if !hadArgs {
			entry.del("args")
		} else {
			entry.set("args", originalArgs)
		}
		if !hadEnv {
			entry.del("env")
		}
	} else if len(originalArgs) > 0 {
		entry.set("args", originalArgs)
	} else {
		entry.del("args")
	}
	entry.set("command", originalCommand)
	entry.del(guardMetaKey)
	return true, ""
}

func jsonIntValue(v any) (int, bool) {
	switch value := v.(type) {
	case json.Number:
		n, err := value.Int64()
		if err != nil {
			return 0, false
		}
		return int(n), true
	case float64:
		n := int(value)
		return n, float64(n) == value
	case int:
		return value, true
	}
	return 0, false
}

func isGuardCommand(command, guardPath string) bool {
	if command == "" {
		return false
	}
	if sameCommandPath(command, guardPath) {
		return true
	}
	base := strings.ToLower(filepath.Base(command))
	return base == "sylenix-guard" || base == "sylenix-guard.exe"
}

func sameCommandPath(a, b string) bool {
	aa, err := filepath.Abs(a)
	if err != nil {
		aa = filepath.Clean(a)
	}
	bb, err := filepath.Abs(b)
	if err != nil {
		bb = filepath.Clean(b)
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(aa), filepath.Clean(bb))
	}
	return filepath.Clean(aa) == filepath.Clean(bb)
}

func writeConfigBackup(path string, data []byte, mode os.FileMode) (string, error) {
	stamp := time.Now().UTC().Format("20060102-150405.000000000")
	base := path + ".sylenix-backup-" + stamp
	for i := 0; i < 100; i++ {
		candidate := base
		if i > 0 {
			candidate = fmt.Sprintf("%s-%d", base, i)
		}
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			if err := os.WriteFile(candidate, data, mode); err != nil {
				return "", err
			}
			return candidate, nil
		} else if err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("could not choose a backup name")
}

func writeConfigAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".sylenix-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func printConfigDiff(path string, oldData, newData []byte) {
	fmt.Printf("--- %s (current)\n+++ %s (proposed)\n", path, path)
	for _, line := range configLineDiff(string(oldData), string(newData)) {
		fmt.Println(line)
	}
}

func configLineDiff(oldText, newText string) []string {
	oldLines := splitConfigLines(oldText)
	newLines := splitConfigLines(newText)
	prefix := 0
	for prefix < len(oldLines) && prefix < len(newLines) && oldLines[prefix] == newLines[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < len(oldLines)-prefix && suffix < len(newLines)-prefix &&
		oldLines[len(oldLines)-1-suffix] == newLines[len(newLines)-1-suffix] {
		suffix++
	}
	var out []string
	contextStart := prefix - 2
	if contextStart < 0 {
		contextStart = 0
	}
	for i := contextStart; i < prefix; i++ {
		out = append(out, " "+oldLines[i])
	}
	for i := prefix; i < len(oldLines)-suffix; i++ {
		out = append(out, "-"+oldLines[i])
	}
	for i := prefix; i < len(newLines)-suffix; i++ {
		out = append(out, "+"+newLines[i])
	}
	contextEnd := len(oldLines) - suffix + 2
	if contextEnd > len(oldLines) {
		contextEnd = len(oldLines)
	}
	for i := len(oldLines) - suffix; i < contextEnd; i++ {
		out = append(out, " "+oldLines[i])
	}
	return out
}

func splitConfigLines(text string) []string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.TrimSuffix(text, "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

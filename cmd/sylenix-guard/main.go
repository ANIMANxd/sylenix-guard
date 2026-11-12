// SPDX-License-Identifier: Apache-2.0

// Sylenix Guard POC: a transparent stdio wrapper for one MCP server.
//
//	sylenix-guard [flags] -- <server command> [args...]
//
// What it does: pins tool definitions (trust on first use), latches session
// taint when untrusted content comes back from a tool, blocks every tool that
// is not on the read-only list once the session is tainted, and can ask a human
// through an OS dialog instead of blocking. The proxy core uses only the
// standard library; the optional team policy and audit shipper use in-repo
// packages under teams/.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"sylenix-guard-poc/teams/auditevent"
	"sylenix-guard-poc/teams/auditshipper"
)

const maxFrame = 10 << 20      // longest accepted JSON-RPC line: 10 MiB
const discardBudget = 64 << 20 // most bytes thrown away while skipping one oversize line

const signatureSuffix = ".sig"

const grantTTL = 15 * time.Minute // how long a "Allow Tool for 15m" click stays valid

const guardMetaKey = "_sylenixGuard"
const guardMetaVersion = 1

const sessionEnvKey = "SYLENIX_SESSION"
const sessionFileVersion = 1
const sessionFileLimit = 1 << 20 // the shared latch is tiny; anything larger is corrupt

// sessionTaintFile is the shared latch content. It never contains tool output,
// argument values or file content.
type sessionTaintFile struct {
	Version      int    `json:"version"`
	KeyHash      string `json:"key_hash"`
	OriginServer string `json:"origin_server,omitempty"`
	Origin       string `json:"origin,omitempty"`
	TS           string `json:"ts,omitempty"`
	ParentPID    int    `json:"parent_pid,omitempty"`
	ParentStart  string `json:"parent_start,omitempty"`
}

// sessionClearFile tells running Guards that the shared latch was removed by a
// human-approved clear-taint. It never contains content.
type sessionClearFile struct {
	Version   int    `json:"version"`
	KeyHash   string `json:"key_hash"`
	RequestID string `json:"request_id"`
	TS        string `json:"ts"`
}

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
var version = "0.1.1"

// commit is the source revision. Release builds set it with
// -ldflags "-X main.commit=<sha>"; local builds fall back to VCS build info.
var commit = ""

func versionString() string {
	c := commit
	if c == "" {
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, s := range info.Settings {
				if s.Key == "vcs.revision" && s.Value != "" {
					c = s.Value
					break
				}
			}
		}
	}
	if c == "" {
		c = "unknown"
	}
	return fmt.Sprintf("sylenix-guard %s (%s, %s)", version, c, runtime.Version())
}

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

// grant is a time-bounded approval. A protected grant covers only the exact
// canonical files the human approved; any other grant covers calls to tool
// whose every path argument stays inside dir (any path when dir is empty).
type grant struct {
	tool      string
	dir       string
	files     []string // exact canonical files for a protected grant
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

// policyState is the immutable decision state read by request handlers. Team
// policy refreshes build a new value and swap the pointer, so a call never sees
// a half-applied policy.
type policyState struct {
	readonly          map[string]bool
	trust             map[string]bool
	approve           string
	spotlight         bool
	scratch           []scratchRule
	classes           map[string]string
	toolPathKeys      map[string]map[string]bool
	egressAllow       map[string]bool
	egressDeny        map[string]bool
	allowlistEnforced bool
	allowlist         []policyAllowEntry
}

func (s *policyState) clone() *policyState {
	if s == nil {
		return &policyState{
			readonly:     map[string]bool{},
			trust:        map[string]bool{},
			approve:      "deny",
			spotlight:    true,
			classes:      map[string]string{},
			toolPathKeys: map[string]map[string]bool{},
			egressAllow:  map[string]bool{},
			egressDeny:   map[string]bool{},
		}
	}
	out := &policyState{
		readonly:          cloneBoolMap(s.readonly),
		trust:             cloneBoolMap(s.trust),
		approve:           s.approve,
		spotlight:         s.spotlight,
		scratch:           append([]scratchRule(nil), s.scratch...),
		classes:           cloneStringMap(s.classes),
		toolPathKeys:      map[string]map[string]bool{},
		egressAllow:       cloneBoolMap(s.egressAllow),
		egressDeny:        cloneBoolMap(s.egressDeny),
		allowlistEnforced: s.allowlistEnforced,
		allowlist:         append([]policyAllowEntry(nil), s.allowlist...),
	}
	for tool, keys := range s.toolPathKeys {
		out.toolPathKeys[tool] = cloneBoolMap(keys)
	}
	return out
}

func cloneBoolMap(m map[string]bool) map[string]bool {
	out := make(map[string]bool, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func cloneStringMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (s *policyState) classFor(tool string) string {
	if s == nil {
		return "exec"
	}
	if s.readonly[tool] {
		return "read"
	}
	if class := s.classes[tool]; class != "" {
		return class
	}
	return "exec"
}

func (s *policyState) hostDenied(host string) bool {
	return s != nil && hostMatchesPattern(host, s.egressDeny)
}

func (s *policyState) hostAllowed(host string) bool {
	return s != nil && hostMatchesPattern(host, s.egressAllow)
}

func (s *policyState) scratchAllows(tool string, paths []string) bool {
	if s == nil || len(paths) == 0 {
		return false
	}
	for _, e := range s.scratch {
		if e.tool != "" && e.tool != tool {
			continue
		}
		if allInside(e.dir, paths) {
			return true
		}
	}
	return false
}

// teamPolicyRuntime holds the pull configuration. It never logs or persists the
// bearer token.
type teamPolicyRuntime struct {
	url          string
	token        string
	pub          ed25519.PublicKey
	interval     time.Duration
	client       *http.Client
	cachePolicy  string
	cacheSig     string
	local        *policyFile
	localSource  string
	localPath    string
	nameExplicit bool
	lastHash     [sha256.Size]byte
	opts         teamApplyOptions
}

type teamApplyOptions struct {
	visited     map[string]bool
	readonly    string
	trust       string
	approve     string
	flagScratch []scratchRule
	noSpotlight bool
	serverArgs  []string
}

type Guard struct {
	name      string
	stateDir  string
	readonly  map[string]bool // tools allowed even when the session is tainted
	trust     map[string]bool // tools whose results do not taint the session
	approve   string          // "deny" or "dialog"
	spotlight bool
	scratch   []scratchRule // --allow-write-under or policy allow_paths, fixed after startup

	protectedDirs []string // resolved Guard state/key directories, protected like the built-in table

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
	taintSince  time.Time
	pending     map[string]pendingReq
	pins        map[string]string
	quarantined map[string]string
	grants      []grant // live time-bounded approvals

	sessionKey      string
	sessionHash     string
	sessionFile     string
	sessionClear    string
	sessionWeak     bool
	sessionExplicit bool
	parentPID       int
	parentStart     string

	sessionMu                sync.Mutex
	sessionCacheValid        bool
	sessionCacheMod          time.Time
	sessionCacheSize         int64
	sessionCacheOriginServer string
	sessionCacheOrigin       string
	sessionLastClear         string

	serverGone  atomic.Bool // set once the server's stdout has closed
	taintedFlag atomic.Bool
	policy      atomic.Pointer[policyState]
	team        *teamPolicyRuntime
	audit       *auditshipper.Shipper
	auditID     string

	outMu sync.Mutex // serializes every write to the host's stdout
	out   io.Writer

	logMu sync.Mutex
	log   *os.File

	verifyKey ed25519.PublicKey  // nil means signature verification is disabled
	signKey   ed25519.PrivateKey // nil means pin writes cannot be signed
}

// guardOptions are the settings shared by the stdio proxy and the Streamable
// HTTP proxy. The transport-specific code is only the wiring around them.
type guardOptions struct {
	Name            string
	DefaultName     string
	StateDir        string
	PolicyPath      string
	PolicyPubKey    string
	PolicyKey       string
	Readonly        string
	Trust           string
	Approve         string
	NoSpotlight     bool
	AllowWriteUnder []string
	GrantSpecs      []string
	Visited         map[string]bool
	ServerArgs      []string
	TeamURL         string
	TeamTokenFile   string
	TeamPubKey      string
	TeamCA          string
	TeamInterval    string
	AuditURL        string
	AuditTokenFile  string
	AuditCA         string
	AuditID         string
	AuditInterval   string
	AuditBatch      int
	SessionKey      string
	SessionWeak     bool
	SessionExplicit bool
	ParentPID       int
	ParentStart     string
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-version":
			fmt.Println(versionString())
			return
		case "install":
			os.Exit(runConfigCommand("install", os.Args[2:]))
		case "uninstall":
			os.Exit(runConfigCommand("uninstall", os.Args[2:]))
		case "policy":
			os.Exit(runPolicyCommand(os.Args[2:]))
		case "pins":
			os.Exit(runPinsCommand(os.Args[2:]))
		case "keys":
			os.Exit(runKeysCommand(os.Args[2:]))
		case "allow":
			os.Exit(runAllowCommand(os.Args[2:]))
		case "doctor":
			os.Exit(runDoctorCommand(os.Args[2:]))
		case "proxy":
			os.Exit(runProxyCommand(os.Args[2:]))
		case "clear-taint":
			os.Exit(runClearTaintCommand(os.Args[2:]))
		case "stats":
			os.Exit(runStatsCommand(os.Args[2:]))
		}
	}
	name := flag.String("name", "", "label for this server; names the pin and log files (default: command name)")
	stateDir := flag.String("state-dir", "", "directory for pins and the audit log (default ~/.sylenix-poc)")
	session := flag.String("session", "", "share taint with other Guard processes in this client session (default: parent process)")
	policyPath := flag.String("policy", "", "path to a versioned policy file (default: <state-dir>/policy.yaml, else built-in defaults)")
	policyPubKey := flag.String("policy-pubkey", "", "Ed25519 public key used to verify policy and pin signatures")
	policyKey := flag.String("policy-key", "", "Ed25519 private key used to sign the pin store on write")
	teamURL := flag.String("team-url", "", "HTTPS URL of the team policy service")
	teamTokenFile := flag.String("team-token-file", "", "file containing the per-team bearer token (or SYLENIX_TEAM_TOKEN)")
	teamPubKey := flag.String("team-pubkey", "", "Ed25519 public key used to verify the team policy")
	teamCA := flag.String("team-ca", "", "optional extra CA certificate PEM for the team policy service")
	teamInterval := flag.String("team-interval", "15m", "how often to pull the team policy")
	auditURL := flag.String("audit-url", "", "HTTPS collector endpoint for sanitized audit events")
	auditTokenFile := flag.String("audit-token-file", "", "collector token file (default: --team-token-file or SYLENIX_TEAM_TOKEN)")
	auditCA := flag.String("audit-ca", "", "optional extra CA certificate PEM for the collector")
	auditID := flag.String("audit-id", "", "machine/developer ID attached to shipped events")
	auditInterval := flag.String("audit-interval", "5s", "maximum time between audit batches")
	auditBatch := flag.Int("audit-batch", 50, "number of audit events per batch")
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

	sessionKey, sessionParentPID, sessionParentStart, sessionWeak, sessionExplicit := resolveStdioSession(*session)
	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: sylenix-guard [flags] -- <server command> [args...]\n       sylenix-guard proxy --listen ADDR --upstream URL [flags]")
		os.Exit(2)
	}
	g, err := prepareGuard(guardOptions{
		Name:            *name,
		DefaultName:     filepath.Base(args[0]),
		StateDir:        *stateDir,
		PolicyPath:      *policyPath,
		PolicyPubKey:    *policyPubKey,
		PolicyKey:       *policyKey,
		Readonly:        *readonly,
		Trust:           *trust,
		Approve:         *approve,
		NoSpotlight:     *noSpot,
		AllowWriteUnder: allowWriteUnder,
		GrantSpecs:      grantSpecs,
		Visited:         visited,
		ServerArgs:      args,
		TeamURL:         *teamURL,
		TeamTokenFile:   *teamTokenFile,
		TeamPubKey:      *teamPubKey,
		TeamCA:          *teamCA,
		TeamInterval:    *teamInterval,
		AuditURL:        *auditURL,
		AuditTokenFile:  *auditTokenFile,
		AuditCA:         *auditCA,
		AuditID:         *auditID,
		AuditInterval:   *auditInterval,
		AuditBatch:      *auditBatch,
		SessionKey:      sessionKey,
		SessionWeak:     sessionWeak,
		SessionExplicit: sessionExplicit,
		ParentPID:       sessionParentPID,
		ParentStart:     sessionParentStart,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard:", err)
		os.Exit(2)
	}
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
	if err := g.loadPins(*resetPins); err != nil {
		fmt.Fprintf(os.Stderr, "[sylenix-guard] pin file %s cannot be trusted: %v; refusing to start. Inspect it, or restart with --reset-pins to trust every tool as new.\n", g.pinsPath(), err)
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
		"allow_write_under": []string(allowWriteUnder), "grants": []string(grantSpecs),
		"session_explicit": g.sessionExplicit})
	if g.sessionWeak {
		g.event("session_key_weak", map[string]any{"reason": "start time unavailable"})
	}
	g.sessionTainted()
	g.startTeamPoller()
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
			if forward != nil {
				_, _ = childIn.Write(append(forward, '\n'))
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

// prepareGuard builds the shared Guard state used by both transports. It does
// not launch anything and does not check the server-command allowlist, because
// that check belongs to the stdio transport that has a child command.
func prepareGuard(opts guardOptions) (*Guard, error) {
	visited := opts.Visited
	if visited == nil {
		visited = map[string]bool{}
	}
	if strings.TrimSpace(opts.SessionKey) == "" {
		return nil, fmt.Errorf("session key is empty")
	}
	if visited["approve"] && opts.Approve != "deny" && opts.Approve != "dialog" {
		return nil, fmt.Errorf("--approve must be deny or dialog")
	}

	var flagScratch []scratchRule
	for _, spec := range opts.AllowWriteUnder {
		tool, dir := "", spec
		if i := strings.Index(spec, "="); i >= 0 {
			tool, dir = spec[:i], spec[i+1:]
		}
		if dir == "" || strings.ContainsAny(tool, `/\`) {
			return nil, fmt.Errorf("--allow-write-under wants DIR or TOOL=DIR")
		}
		if real, ok := canonicalPath(dir); ok {
			dir = real
		}
		flagScratch = append(flagScratch, scratchRule{tool: tool, dir: dir})
	}

	var seeded []grant
	for _, spec := range opts.GrantSpecs {
		i := strings.LastIndex(spec, "=")
		if i <= 0 {
			return nil, fmt.Errorf("--grant wants TOOL[:DIR]=DURATION, for example write_file=15m")
		}
		dur, err := time.ParseDuration(spec[i+1:])
		if err != nil || dur <= 0 {
			return nil, fmt.Errorf("--grant duration must be positive, for example write_file=15m")
		}
		tool, dir := spec[:i], ""
		if j := strings.Index(tool, ":"); j >= 0 {
			tool, dir = tool[:j], tool[j+1:]
		}
		if tool == "" || strings.ContainsAny(tool, `/\`) {
			return nil, fmt.Errorf("--grant wants TOOL[:DIR]=DURATION, for example write_file=15m")
		}
		if dir != "" {
			if real, ok := canonicalPath(dir); ok {
				dir = real
			}
		}
		seeded = append(seeded, grant{tool: tool, dir: dir, expires: time.Now().Add(dur)})
	}
	teamMode := strings.TrimSpace(opts.TeamURL) != ""
	droppedGrants := false
	if teamMode && len(seeded) > 0 {
		// A pre-approved grant is local authority and could loosen the team
		// policy. Team mode accepts only the policy and the human dialog.
		seeded = nil
		droppedGrants = true
	}

	name := opts.Name
	nameExplicit := visited["name"] && name != ""
	if name == "" {
		name = opts.DefaultName
	}
	if name == "" {
		return nil, fmt.Errorf("--name is required")
	}
	if !validDoctorName(name) {
		return nil, fmt.Errorf("--name must be a simple name without path separators or control characters")
	}

	stateDir := opts.StateDir
	if stateDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("cannot find home directory; pass --state-dir")
		}
		stateDir = filepath.Join(home, ".sylenix-poc")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	stateDirAbs, err := filepath.Abs(stateDir)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve state directory: %w", err)
	}
	stateDirReal, err := evalSymlinks(stateDirAbs)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve state directory: %w", err)
	}
	// Protect the state directory actually in use, plus the default state and
	// key directories when they exist as symlinks. The built-in table covers
	// the literal names; this covers custom --state-dir paths and symlinks.
	protectedDirs := []string{filepath.Clean(stateDirReal)}
	if home, err := os.UserHomeDir(); err == nil {
		for _, dir := range []string{
			filepath.Join(home, ".sylenix-poc"),
			filepath.Join(home, ".sylenix-keys"),
		} {
			if real, err := evalSymlinks(dir); err == nil {
				protectedDirs = append(protectedDirs, filepath.Clean(real))
			}
		}
	}
	logf, err := os.OpenFile(filepath.Join(stateDir, "audit-"+name+".jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}

	verifyKey, signKey, err := loadGuardSigningKeys(opts.PolicyPubKey, opts.PolicyKey)
	if err != nil {
		_ = logf.Close()
		return nil, err
	}

	g := &Guard{
		name:          name,
		stateDir:      stateDir,
		protectedDirs: protectedDirs,
		approve:       "deny",
		spotlight:     true,
		pending:       map[string]pendingReq{},
		pins:          map[string]string{},
		quarantined:   map[string]string{},
		grants:        seeded,
		out:           os.Stdout,
		log:           logf,
		verifyKey:     verifyKey,
		signKey:       signKey,

		sessionKey:      opts.SessionKey,
		sessionHash:     sessionKeyHash(opts.SessionKey),
		sessionWeak:     opts.SessionWeak,
		sessionExplicit: opts.SessionExplicit,
		parentPID:       opts.ParentPID,
		parentStart:     opts.ParentStart,
	}
	g.sessionFile = sessionTaintPath(stateDir, g.sessionHash)
	g.sessionClear = sessionClearPath(stateDir, g.sessionHash)
	g.gcStaleSessionFiles()
	if err := g.startAuditShipper(opts); err != nil {
		g.event("audit_config_invalid", map[string]any{"reason": "invalid_audit_configuration"})
		_ = logf.Close()
		return nil, err
	}
	if teamMode {
		localPF, localSource, localPath, localPresent, err := loadLocalPolicyForTeam(opts.PolicyPath, visited["policy"], stateDir, name, nameExplicit, g.verifyKey)
		if err != nil {
			g.event("policy_invalid", map[string]any{"source": localSource, "reason": "local_overlay_invalid"})
			_ = logf.Close()
			return nil, err
		}
		tr, remotePF, policyBytes, sig, fromCache, err := newTeamPolicyRuntime(g, opts, localPF, localSource, localPath, flagScratch)
		if err != nil {
			g.event("team_policy_unavailable", map[string]any{"reason": teamReason(err)})
			_ = logf.Close()
			return nil, err
		}
		g.team = tr
		ignored, profile, err := g.applyTeamPolicy(remotePF, tr)
		if err != nil {
			g.event("team_policy_rejected", map[string]any{"reason": "invalid_policy"})
			_ = logf.Close()
			return nil, err
		}
		tr.lastHash = sha256.Sum256(policyBytes)
		if !fromCache {
			if err := tr.writeCache(policyBytes, sig); err != nil {
				g.event("team_policy_cache_error", map[string]any{"reason": teamReason(err)})
				tr.lastHash = [sha256.Size]byte{}
			}
		}
		if droppedGrants {
			g.event("team_policy_loosen_ignored", map[string]any{"fields": []string{"grant"}})
		}
		if len(ignored) > 0 {
			g.event("team_policy_loosen_ignored", map[string]any{"fields": ignored})
		}
		source := "team"
		if fromCache {
			source = "cache"
		}
		g.event("team_policy_loaded", map[string]any{"source": source, "version": remotePF.Version,
			"local_source": localSource, "local_present": localPresent, "approve": g.approve,
			"profile": profile, "url": redactTeamURL(tr.url)})
		return g, nil
	}

	pf, source, resolvedPath, err := loadPolicyForRun(opts.PolicyPath, visited["policy"], stateDir, name, nameExplicit, g.verifyKey)
	if err != nil {
		g.event("policy_invalid", map[string]any{"source": source, "reason": err.Error()})
		_ = logf.Close()
		return nil, err
	}
	g.policySource = source
	g.policyVersion = pf.Version
	g.policyPath = resolvedPath
	profile := selectPolicyProfile(name, opts.ServerArgs, pf.Profile)
	if profile != nil {
		g.profileName = profile.name
		g.profileSource = profile.source
	}
	g.applyPolicy(pf, profile, visited, opts.Readonly, opts.Trust, opts.Approve, flagScratch, opts.NoSpotlight)
	printPolicyDeprecationNotes(visited, opts.PolicyPath, source)
	g.event("policy_loaded", map[string]any{"source": source, "version": pf.Version, "approve": g.approve,
		"profile": g.profileName, "profile_source": g.profileSource})
	return g, nil
}

func sessionOverride(flagValue string) string {
	if value := strings.TrimSpace(flagValue); value != "" {
		return value
	}
	return strings.TrimSpace(os.Getenv(sessionEnvKey))
}

// resolveStdioSession uses the flag, then SYLENIX_SESSION, then the parent MCP
// client process: "<ppid>-<parent start time>". The start time protects the key
// from PID reuse. If it cannot be read, the key falls back to the PID alone and
// the caller logs session_key_weak.
func resolveStdioSession(flagValue string) (key string, parentPID int, parentStart string, weak, explicit bool) {
	ppid := os.Getppid()
	start, _ := processStartTime(ppid)
	if value := sessionOverride(flagValue); value != "" {
		return value, ppid, start, false, true
	}
	if ppid <= 0 {
		return "0", 0, "", true, false
	}
	if start == "" {
		return strconv.Itoa(ppid), ppid, "", true, false
	}
	return fmt.Sprintf("%d-%s", ppid, start), ppid, start, false, false
}

// resolveProxySession has no MCP host parent, so its default is a per-process
// key. --session or SYLENIX_SESSION can share it with stdio Guards. The proxy
// process itself owns the session file for garbage-collection purposes.
func resolveProxySession(flagValue string) (key string, parentPID int, parentStart string, weak, explicit bool) {
	pid := os.Getpid()
	start, _ := processStartTime(pid)
	if value := sessionOverride(flagValue); value != "" {
		return value, pid, start, false, true
	}
	if start == "" {
		return fmt.Sprintf("proxy-%d", pid), pid, "", true, false
	}
	return fmt.Sprintf("proxy-%d-%s", pid, start), pid, start, false, false
}

func sessionKeyHash(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func sessionTaintPath(stateDir, keyHash string) string {
	return filepath.Join(stateDir, "session-"+keyHash[:32]+".taint")
}

func sessionClearPath(stateDir, keyHash string) string {
	return filepath.Join(stateDir, "session-"+keyHash[:32]+".cleared")
}

func redactTeamURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host + u.Path
}

func (g *Guard) startAuditShipper(opts guardOptions) error {
	if strings.TrimSpace(opts.AuditURL) == "" {
		return nil
	}
	tokenFile := opts.AuditTokenFile
	if tokenFile == "" {
		tokenFile = opts.TeamTokenFile
	}
	token, err := readTeamToken(tokenFile)
	if err != nil {
		return fmt.Errorf("cannot read audit token: %w", err)
	}
	caFile := opts.AuditCA
	if caFile == "" {
		caFile = opts.TeamCA
	}
	interval := 5 * time.Second
	if strings.TrimSpace(opts.AuditInterval) != "" {
		interval, err = time.ParseDuration(opts.AuditInterval)
		if err != nil || interval <= 0 {
			return fmt.Errorf("--audit-interval must be a positive duration, for example 5s")
		}
	}
	if opts.AuditBatch <= 0 {
		return fmt.Errorf("--audit-batch must be positive")
	}
	id := normalizeAuditID(opts.AuditID)
	if id == "" {
		id = defaultAuditID()
	}
	if id == "" {
		return fmt.Errorf("--audit-id is empty after removing unsupported characters")
	}
	sh, err := auditshipper.New(auditshipper.Config{
		URL:           opts.AuditURL,
		Token:         token,
		CAFile:        caFile,
		OutboxPath:    filepath.Join(g.stateDir, "audit-outbox-"+g.name+".jsonl"),
		BatchSize:     opts.AuditBatch,
		FlushInterval: interval,
		Logger: func(err error) {
			alert("audit shipper: %v", err)
		},
	})
	if err != nil {
		return err
	}
	g.auditID = id
	g.audit = sh
	sh.Start()
	return nil
}

func defaultAuditID() string {
	user := osUser()
	if user == "" {
		user = "unknown"
	}
	host, _ := os.Hostname()
	if host == "" {
		host = "unknown"
	}
	return normalizeAuditID(user + "@" + host)
}

func normalizeAuditID(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		if r > 32 && r < 127 {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 256 {
		out = out[:256]
	}
	return out
}

// ---------------------------------------------------------------- streamable HTTP proxy

// guardFlagValues is the common proxy configuration. The stdio path keeps its
// own flag declarations because it also has a positional server command.
type guardFlagValues struct {
	Name            string
	StateDir        string
	PolicyPath      string
	PolicyPubKey    string
	PolicyKey       string
	TeamURL         string
	TeamTokenFile   string
	TeamPubKey      string
	TeamCA          string
	TeamInterval    string
	AuditURL        string
	AuditTokenFile  string
	AuditCA         string
	AuditID         string
	AuditInterval   string
	AuditBatch      int
	Readonly        string
	Trust           string
	Approve         string
	NoSpotlight     bool
	ResetPins       bool
	AllowWriteUnder stringList
	GrantSpecs      stringList
	Session         string
}

func registerGuardFlags(fs *flag.FlagSet, v *guardFlagValues) {
	fs.StringVar(&v.Name, "name", "", "label for this server; names the pin and log files (default: upstream host)")
	fs.StringVar(&v.StateDir, "state-dir", "", "directory for pins and the audit log (default ~/.sylenix-poc)")
	fs.StringVar(&v.PolicyPath, "policy", "", "path to a versioned policy file (default: <state-dir>/policy.yaml, else built-in defaults)")
	fs.StringVar(&v.PolicyPubKey, "policy-pubkey", "", "Ed25519 public key used to verify policy and pin signatures")
	fs.StringVar(&v.PolicyKey, "policy-key", "", "Ed25519 private key used to sign the pin store on write")
	fs.StringVar(&v.TeamURL, "team-url", "", "HTTPS URL of the team policy service")
	fs.StringVar(&v.TeamTokenFile, "team-token-file", "", "file containing the per-team bearer token (or SYLENIX_TEAM_TOKEN)")
	fs.StringVar(&v.TeamPubKey, "team-pubkey", "", "Ed25519 public key used to verify the team policy")
	fs.StringVar(&v.TeamCA, "team-ca", "", "optional extra CA certificate PEM for the team policy service")
	fs.StringVar(&v.TeamInterval, "team-interval", "15m", "how often to pull the team policy")
	fs.StringVar(&v.AuditURL, "audit-url", "", "HTTPS collector endpoint for sanitized audit events")
	fs.StringVar(&v.AuditTokenFile, "audit-token-file", "", "collector token file (default: --team-token-file or SYLENIX_TEAM_TOKEN)")
	fs.StringVar(&v.AuditCA, "audit-ca", "", "optional extra CA certificate PEM for the collector")
	fs.StringVar(&v.AuditID, "audit-id", "", "machine/developer ID attached to shipped events")
	fs.StringVar(&v.AuditInterval, "audit-interval", "5s", "maximum time between audit batches")
	fs.IntVar(&v.AuditBatch, "audit-batch", 50, "number of audit events per batch")
	fs.StringVar(&v.Readonly, "readonly", "", "comma-separated tools that stay allowed when the session is tainted")
	fs.StringVar(&v.Trust, "trust", "", "comma-separated tools whose results do NOT taint the session")
	fs.StringVar(&v.Approve, "approve", "deny", "what to do with a blocked call: deny | dialog")
	fs.BoolVar(&v.NoSpotlight, "no-spotlight", false, "do not datamark untrusted tool results")
	fs.BoolVar(&v.ResetPins, "reset-pins", false, "discard existing pins and trust every tool as new on first sight")
	fs.Var(&v.AllowWriteUnder, "allow-write-under", "tainted calls need no prompt while every path argument stays inside DIR, or TOOL=DIR to scope it to one tool; repeatable")
	fs.Var(&v.GrantSpecs, "grant", "pre-approved sink calls: TOOL[:DIR]=DURATION (for example write_file=15m); repeatable")
	fs.StringVar(&v.Session, "session", "", "share taint with other Guard processes in this session (default: per-process for proxy)")
}

type sseEvent struct {
	event   string
	id      string
	retry   string
	data    []string
	hasData bool
}

func (e *sseEvent) reset() {
	*e = sseEvent{}
}

type proxyHandler struct {
	g        *Guard
	upstream *url.URL
	client   *http.Client
	listen   string // normalized --listen address, accepted as an exact Host value
}

var hopHeaders = map[string]bool{
	"connection":          true,
	"proxy-connection":    true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

func isHopHeader(k string) bool {
	return hopHeaders[strings.ToLower(k)]
}

func runProxyCommand(args []string) int {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	listen := fs.String("listen", "127.0.0.1:8080", "local address to bind (default 127.0.0.1:8080)")
	upstreamRaw := fs.String("upstream", "", "upstream Streamable HTTP MCP endpoint, for example https://example.com/mcp")
	var vals guardFlagValues
	registerGuardFlags(fs, &vals)
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	visited := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { visited[f.Name] = true })
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "sylenix-guard proxy: unexpected arguments")
		return 2
	}
	if strings.TrimSpace(*upstreamRaw) == "" {
		fmt.Fprintln(os.Stderr, "sylenix-guard proxy: --upstream is required")
		return 2
	}
	upstream, err := url.Parse(strings.TrimSpace(*upstreamRaw))
	if err != nil || upstream.Scheme == "" || upstream.Host == "" {
		fmt.Fprintln(os.Stderr, "sylenix-guard proxy: --upstream must be an absolute http(s) URL")
		return 2
	}
	if !strings.EqualFold(upstream.Scheme, "http") && !strings.EqualFold(upstream.Scheme, "https") {
		fmt.Fprintln(os.Stderr, "sylenix-guard proxy: --upstream must use http or https")
		return 2
	}
	if upstream.Fragment != "" {
		fmt.Fprintln(os.Stderr, "sylenix-guard proxy: --upstream must not contain a fragment")
		return 2
	}
	listenAddr, err := normalizeListenAddr(*listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard proxy:", err)
		return 2
	}

	sessionKey, sessionParentPID, sessionParentStart, sessionWeak, sessionExplicit := resolveProxySession(vals.Session)
	g, err := prepareGuard(guardOptions{
		Name:            vals.Name,
		DefaultName:     defaultProxyName(upstream),
		StateDir:        vals.StateDir,
		PolicyPath:      vals.PolicyPath,
		PolicyPubKey:    vals.PolicyPubKey,
		PolicyKey:       vals.PolicyKey,
		TeamURL:         vals.TeamURL,
		TeamTokenFile:   vals.TeamTokenFile,
		TeamPubKey:      vals.TeamPubKey,
		TeamCA:          vals.TeamCA,
		TeamInterval:    vals.TeamInterval,
		AuditURL:        vals.AuditURL,
		AuditTokenFile:  vals.AuditTokenFile,
		AuditCA:         vals.AuditCA,
		AuditID:         vals.AuditID,
		AuditInterval:   vals.AuditInterval,
		AuditBatch:      vals.AuditBatch,
		Readonly:        vals.Readonly,
		Trust:           vals.Trust,
		Approve:         vals.Approve,
		NoSpotlight:     vals.NoSpotlight,
		AllowWriteUnder: vals.AllowWriteUnder,
		GrantSpecs:      vals.GrantSpecs,
		Visited:         visited,
		ServerArgs:      []string{upstream.Hostname(), upstream.Path},
		SessionKey:      sessionKey,
		SessionWeak:     sessionWeak,
		SessionExplicit: sessionExplicit,
		ParentPID:       sessionParentPID,
		ParentStart:     sessionParentStart,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard proxy:", err)
		return 2
	}
	defer func() { _ = g.log.Close() }()
	g.out = io.Discard
	if err := g.loadPins(vals.ResetPins); err != nil {
		fmt.Fprintf(os.Stderr, "[sylenix-guard] pin file %s cannot be trusted: %v; refusing to start. Inspect it, or restart with --reset-pins to trust every tool as new.\n", g.pinsPath(), err)
		return 2
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard proxy: cannot listen:", err)
		return 1
	}
	defer func() { _ = ln.Close() }()

	control, controlErr := startGuardControl(g)
	if controlErr != nil {
		g.event("control_unavailable", map[string]any{"reason": "cannot create clear-taint control"})
		fmt.Fprintln(os.Stderr, "sylenix-guard: clear-taint unavailable:", controlErr)
	}

	g.event("start", map[string]any{
		"transport":         "streamable-http",
		"listen":            ln.Addr().String(),
		"upstream":          redactURL(upstream),
		"readonly":          sortedKeys(g.readonly),
		"trust":             sortedKeys(g.trust),
		"approve":           g.approve,
		"policy_source":     g.policySource,
		"policy_version":    g.policyVersion,
		"profile":           g.profileName,
		"profile_source":    g.profileSource,
		"allow_write_under": []string(vals.AllowWriteUnder),
		"grants":            []string(vals.GrantSpecs),
		"session_explicit":  g.sessionExplicit,
	})
	if g.sessionWeak {
		g.event("session_key_weak", map[string]any{"reason": "start time unavailable"})
	}
	g.sessionTainted()
	g.startTeamPoller()

	handler := &proxyHandler{g: g, upstream: upstream, client: newProxyClient(), listen: listenAddr}
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	fmt.Fprintf(os.Stderr, "[sylenix-guard] proxy listening on http://%s/mcp (upstream %s)\n",
		ln.Addr().String(), redactURL(upstream))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sig:
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = srv.Shutdown(ctx)
		cancel()
		_ = srv.Close()
		control.stop()
		g.event("exit", map[string]any{"code": 0})
		return 0
	case serveErr := <-errCh:
		control.stop()
		code := 0
		if serveErr != nil && serveErr != http.ErrServerClosed {
			code = 1
			fmt.Fprintln(os.Stderr, "sylenix-guard proxy:", serveErr)
		}
		g.event("exit", map[string]any{"code": code})
		return code
	}
}

func normalizeListenAddr(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		s = "127.0.0.1:8080"
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", fmt.Errorf("--listen must be host:port, for example 127.0.0.1:8080: %w", err)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return "", fmt.Errorf("--listen has an invalid port")
	}
	if host == "" || strings.EqualFold(host, "localhost") {
		host = "127.0.0.1"
	}
	if host == "*" {
		host = "0.0.0.0"
	}
	return net.JoinHostPort(host, port), nil
}

func defaultProxyName(u *url.URL) string {
	host := u.Hostname()
	if host == "" {
		return "proxy"
	}
	var b strings.Builder
	for _, r := range host {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	name := strings.Trim(b.String(), "._-")
	if name == "" {
		return "proxy"
	}
	return name
}

func redactURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	c := *u
	c.User = nil
	c.RawQuery = ""
	c.Fragment = ""
	return c.String()
}

func newProxyClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (p *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !originAllowed(r, p.listen) {
		writeMCPError(w, http.StatusForbidden, nil, -32600, "Forbidden", "ORIGIN_FORBIDDEN", r.Header.Get("Mcp-Session-Id"))
		return
	}
	switch r.Method {
	case http.MethodPost:
		p.handlePost(w, r)
	case http.MethodGet:
		p.handleGet(w, r)
	case http.MethodDelete:
		p.handleDelete(w, r)
	case http.MethodOptions:
		w.Header().Set("Allow", "POST, GET, DELETE, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "POST, GET, DELETE, OPTIONS")
		writeMCPError(w, http.StatusMethodNotAllowed, nil, -32600, "Method not allowed", "METHOD_NOT_ALLOWED", r.Header.Get("Mcp-Session-Id"))
	}
}

func originAllowed(r *http.Request, listen string) bool {
	// The Host header must name this listener. A browser or a rebinding
	// attacker can set Origin freely, so the Host check is the part that
	// binds the request to the address the operator actually asked for.
	if !hostHeaderAllowed(r.Host, listen) {
		return false
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if isLoopbackHost(host) {
		return true
	}
	return host == strings.ToLower(stripHostPort(r.Host))
}

func isLoopbackHost(host string) bool {
	host = strings.ToLower(host)
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func hostHeaderAllowed(h, listen string) bool {
	h = strings.TrimSpace(h)
	host := strings.ToLower(stripHostPort(h))
	if isLoopbackHost(host) {
		return true
	}
	if listen == "" {
		return false
	}
	if host != strings.ToLower(stripHostPort(listen)) {
		return false
	}
	// A non-loopback address is accepted only as the exact --listen address.
	_, reqPort, reqErr := net.SplitHostPort(h)
	_, listenPort, listenErr := net.SplitHostPort(listen)
	return reqErr == nil && listenErr == nil && reqPort == listenPort
}

func stripHostPort(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return strings.Trim(h, "[]")
}

func (p *proxyHandler) handlePost(w http.ResponseWriter, r *http.Request) {
	body, tooLarge, err := readLimited(r.Body)
	if err != nil {
		writeMCPError(w, http.StatusBadRequest, nil, -32700, "Parse error", "UNPARSEABLE", r.Header.Get("Mcp-Session-Id"))
		return
	}
	if tooLarge {
		writeMCPError(w, http.StatusRequestEntityTooLarge, nil, -32600, "Frame too large", "FRAME_TOO_LARGE", r.Header.Get("Mcp-Session-Id"))
		return
	}
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		writeMCPError(w, http.StatusBadRequest, nil, -32700, "Parse error", "UNPARSEABLE", r.Header.Get("Mcp-Session-Id"))
		return
	}

	forward, reply := p.g.fromHost(body)
	if reply != nil {
		writeJSONRPC(w, http.StatusOK, reply, r.Header.Get("Mcp-Session-Id"))
		return
	}
	if forward == nil {
		w.Header().Set("Mcp-Session-Id", r.Header.Get("Mcp-Session-Id"))
		w.WriteHeader(http.StatusAccepted)
		return
	}

	resp, ok := p.doUpstream(w, r, http.MethodPost, forward)
	if !ok {
		return
	}
	defer func() { _ = resp.Body.Close() }()
	copyResponseHeaders(w.Header(), resp.Header)

	reqID := idFromBody(forward)
	if isEventStream(resp.Header.Get("Content-Type")) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache, no-transform")
		w.Header().Set("X-Accel-Buffering", "no")
		w.Header().Del("Content-Length")
		w.WriteHeader(resp.StatusCode)
		p.streamSSE(w, resp.Body, reqID)
		return
	}

	data, tooLarge, err := readLimited(resp.Body)
	if err != nil {
		p.failHTTPRequest(w, reqID, http.StatusBadGateway, "Upstream read failed", "UPSTREAM_ERROR", r.Header.Get("Mcp-Session-Id"))
		return
	}
	if tooLarge {
		p.g.latch("oversize_server_frame")
		p.g.event("server_frame_too_large", map[string]any{"fatal": false})
		p.failHTTPRequest(w, reqID, http.StatusBadGateway, "Server frame too large", "SERVER_FRAME_TOO_LARGE", r.Header.Get("Mcp-Session-Id"))
		return
	}
	if len(data) > 0 && (isJSONRPC(data) || (resp.StatusCode >= 200 && resp.StatusCode < 300)) {
		data = p.g.fromServer(data)
	}
	if len(reqID) > 0 && p.g.isPending(reqID) {
		switch {
		case len(data) == 0 && resp.StatusCode >= 200 && resp.StatusCode < 300:
			data = p.g.failOne(reqID, -32000, "Server stream closed", "SERVER_STREAM_CLOSED")
		case isJSONRPC(data):
			p.g.take(reqID)
		default:
			p.g.take(reqID)
		}
	}
	if isJSONRPC(data) {
		w.Header().Set("Content-Type", "application/json")
	}
	w.Header().Del("Content-Length")
	w.Header().Del("Content-Encoding")
	if len(data) > 0 && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotModified {
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	}
	w.WriteHeader(resp.StatusCode)
	if len(data) > 0 && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotModified {
		_, _ = w.Write(data)
	}
}

func (p *proxyHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	resp, ok := p.doUpstream(w, r, http.MethodGet, nil)
	if !ok {
		return
	}
	defer func() { _ = resp.Body.Close() }()
	copyResponseHeaders(w.Header(), resp.Header)
	if isEventStream(resp.Header.Get("Content-Type")) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache, no-transform")
		w.Header().Set("X-Accel-Buffering", "no")
		w.Header().Del("Content-Length")
		w.WriteHeader(resp.StatusCode)
		p.streamSSE(w, resp.Body, nil)
		return
	}
	data, tooLarge, err := readLimited(resp.Body)
	if err != nil || tooLarge {
		http.Error(w, "upstream read failed", http.StatusBadGateway)
		return
	}
	w.Header().Del("Content-Length")
	w.Header().Del("Content-Encoding")
	if len(data) > 0 && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotModified {
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	}
	w.WriteHeader(resp.StatusCode)
	if len(data) > 0 && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotModified {
		_, _ = w.Write(data)
	}
}

func (p *proxyHandler) handleDelete(w http.ResponseWriter, r *http.Request) {
	resp, ok := p.doUpstream(w, r, http.MethodDelete, nil)
	if !ok {
		return
	}
	defer func() { _ = resp.Body.Close() }()
	copyResponseHeaders(w.Header(), resp.Header)
	data, tooLarge, err := readLimited(resp.Body)
	if err != nil || tooLarge {
		http.Error(w, "upstream read failed", http.StatusBadGateway)
		return
	}
	w.Header().Del("Content-Length")
	w.Header().Del("Content-Encoding")
	if len(data) > 0 && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotModified {
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	}
	w.WriteHeader(resp.StatusCode)
	if len(data) > 0 && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotModified {
		_, _ = w.Write(data)
	}
}

func (p *proxyHandler) doUpstream(w http.ResponseWriter, r *http.Request, method string, body []byte) (*http.Response, bool) {
	u := p.resolveUpstream(r)
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(r.Context(), method, u.String(), reader)
	if err != nil {
		p.failHTTPRequest(w, idFromBody(body), http.StatusBadGateway, "Upstream request failed", "UPSTREAM_ERROR", r.Header.Get("Mcp-Session-Id"))
		return nil, false
	}
	copyRequestHeaders(req.Header, r.Header)
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
		if req.Header.Get("Accept") == "" {
			req.Header.Set("Accept", "application/json, text/event-stream")
		}
	} else if method == http.MethodGet {
		if req.Header.Get("Accept") == "" {
			req.Header.Set("Accept", "text/event-stream")
		}
	}
	resp, err := p.client.Do(req)
	if err != nil {
		p.failHTTPRequest(w, idFromBody(body), http.StatusBadGateway, "Upstream request failed", "UPSTREAM_ERROR", r.Header.Get("Mcp-Session-Id"))
		return nil, false
	}
	return resp, true
}

func (p *proxyHandler) failHTTPRequest(w http.ResponseWriter, id json.RawMessage, status int, msg, rule, session string) {
	if len(id) > 0 {
		if reply := p.g.failOne(id, -32000, msg, rule); reply != nil {
			writeJSONRPC(w, status, reply, session)
			return
		}
	}
	http.Error(w, msg, status)
}

func (p *proxyHandler) resolveUpstream(r *http.Request) *url.URL {
	u := *p.upstream
	if u.Path == "" || u.Path == "/" {
		u.Path = r.URL.Path
		if u.Path == "" {
			u.Path = "/"
		}
		u.RawPath = ""
	}
	if r.URL.RawQuery != "" {
		if u.RawQuery == "" {
			u.RawQuery = r.URL.RawQuery
		} else {
			u.RawQuery += "&" + r.URL.RawQuery
		}
	}
	return &u
}

func copyRequestHeaders(dst, src http.Header) {
	for k, values := range src {
		if isHopHeader(k) || strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") ||
			strings.EqualFold(k, "Accept-Encoding") || strings.EqualFold(k, "Origin") {
			continue
		}
		for _, v := range values {
			dst.Add(k, v)
		}
	}
}

func copyResponseHeaders(dst, src http.Header) {
	for k, values := range src {
		if isHopHeader(k) || strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Content-Encoding") {
			continue
		}
		for _, v := range values {
			dst.Add(k, v)
		}
	}
}

func readLimited(r io.Reader) ([]byte, bool, error) {
	b, err := io.ReadAll(io.LimitReader(r, int64(maxFrame)+1))
	if err != nil {
		return nil, false, err
	}
	if len(b) > maxFrame {
		return nil, true, nil
	}
	return b, false, nil
}

func idFromBody(body []byte) json.RawMessage {
	var f frame
	if json.Unmarshal(bytes.TrimSpace(body), &f) != nil {
		return nil
	}
	return f["id"]
}

func isJSONRPC(b []byte) bool {
	var f frame
	if json.Unmarshal(bytes.TrimSpace(b), &f) != nil {
		return false
	}
	_, ok := f["jsonrpc"]
	return ok
}

func isEventStream(contentType string) bool {
	contentType = strings.ToLower(strings.TrimSpace(contentType))
	return strings.HasPrefix(contentType, "text/event-stream")
}

func writeJSONRPC(w http.ResponseWriter, status int, body []byte, session string) {
	w.Header().Set("Content-Type", "application/json")
	if session != "" {
		w.Header().Set("Mcp-Session-Id", session)
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writeMCPError(w http.ResponseWriter, status int, id json.RawMessage, code int, msg, rule, session string) {
	writeJSONRPC(w, status, errorFrame(id, code, msg, rule), session)
}

func (p *proxyHandler) streamSSE(w http.ResponseWriter, body io.Reader, reqID json.RawMessage) {
	defer p.finishPending(w, reqID)
	reader := bufio.NewReaderSize(body, 64*1024)
	var ev sseEvent

	dispatch := func() error {
		if !ev.hasData && ev.event == "" && ev.id == "" && ev.retry == "" {
			ev.reset()
			return nil
		}
		var data []byte
		if ev.hasData {
			payload := strings.Join(ev.data, "\n")
			if strings.TrimSpace(payload) != "" {
				data = p.g.fromServer([]byte(payload))
				if data == nil {
					ev.reset()
					return nil
				}
			}
		}
		err := writeSSEEvent(w, ev, data)
		ev.reset()
		return err
	}

	for {
		line, tooLong, broken, err := readFrame(reader, maxFrame)
		if tooLong {
			p.g.latch("oversize_server_frame")
			p.g.event("server_frame_too_large", map[string]any{"fatal": broken})
			if b := p.g.failOne(reqID, -32000, "Server frame too large", "SERVER_FRAME_TOO_LARGE"); b != nil {
				_ = writeSSEEvent(w, sseEvent{hasData: true}, b)
			}
			return
		}
		if len(line) == 0 {
			if err != nil {
				_ = dispatch()
				return
			}
			if err := dispatch(); err != nil {
				return
			}
			continue
		}
		s := strings.TrimSuffix(string(line), "\r")
		if s == "" {
			if err := dispatch(); err != nil {
				return
			}
			continue
		}
		if strings.HasPrefix(s, ":") {
			if _, err := io.WriteString(w, s+"\n"); err != nil {
				return
			}
			flushResponse(w)
			continue
		}
		field, value := s, ""
		if i := strings.IndexByte(s, ':'); i >= 0 {
			field, value = s[:i], s[i+1:]
			if strings.HasPrefix(value, " ") {
				value = value[1:]
			}
		}
		switch field {
		case "event":
			ev.event = value
		case "id":
			ev.id = value
		case "retry":
			ev.retry = value
		case "data":
			ev.data = append(ev.data, value)
			ev.hasData = true
		}
		if err != nil {
			_ = dispatch()
			return
		}
	}
}

func writeSSEEvent(w http.ResponseWriter, ev sseEvent, data []byte) error {
	var b strings.Builder
	if ev.event != "" {
		fmt.Fprintf(&b, "event: %s\n", ev.event)
	}
	if ev.id != "" {
		fmt.Fprintf(&b, "id: %s\n", ev.id)
	}
	if ev.retry != "" {
		fmt.Fprintf(&b, "retry: %s\n", ev.retry)
	}
	if ev.hasData {
		if len(data) == 0 {
			b.WriteString("data:\n")
		} else {
			for _, line := range strings.Split(string(data), "\n") {
				b.WriteString("data: ")
				b.WriteString(line)
				b.WriteByte('\n')
			}
		}
	}
	b.WriteByte('\n')
	if _, err := io.WriteString(w, b.String()); err != nil {
		return err
	}
	flushResponse(w)
	return nil
}

func flushResponse(w http.ResponseWriter) {
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func (p *proxyHandler) finishPending(w http.ResponseWriter, reqID json.RawMessage) {
	if len(reqID) == 0 {
		return
	}
	if _, ok := p.g.take(reqID); !ok {
		return
	}
	b := errorFrame(reqID, -32000, "Server stream closed", "SERVER_STREAM_CLOSED")
	_ = writeSSEEvent(w, sseEvent{hasData: true}, b)
}

// ---------------------------------------------------------------- signing keys

func defaultSigningKeyPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot find home directory; pass --key")
	}
	return filepath.Join(home, ".sylenix-keys", "policy-signing.key"), nil
}

func loadGuardSigningKeys(pubPath, privPath string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	var verifyKey ed25519.PublicKey
	var signKey ed25519.PrivateKey
	if privPath != "" {
		key, err := loadPrivateKeyFile(privPath)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot load --policy-key: %w", err)
		}
		signKey = key
		verifyKey = key.Public().(ed25519.PublicKey)
	}
	if pubPath != "" {
		key, err := loadPublicKeyFile(pubPath)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot load --policy-pubkey: %w", err)
		}
		if verifyKey != nil && !bytes.Equal(verifyKey, key) {
			return nil, nil, fmt.Errorf("--policy-pubkey does not match --policy-key")
		}
		verifyKey = key
	}
	return verifyKey, signKey, nil
}

func loadPrivateKeyFile(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(data); block != nil {
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			if ed, ok := key.(ed25519.PrivateKey); ok {
				return ed, nil
			}
			return nil, fmt.Errorf("key is not Ed25519")
		}
		if len(block.Bytes) == ed25519.PrivateKeySize {
			return ed25519.PrivateKey(append([]byte(nil), block.Bytes...)), nil
		}
		if len(block.Bytes) == ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(block.Bytes), nil
		}
		return nil, fmt.Errorf("unsupported private key encoding")
	}
	raw := bytes.TrimSpace(data)
	if len(raw) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(append([]byte(nil), raw...)), nil
	}
	if len(raw) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(raw), nil
	}
	return nil, fmt.Errorf("unsupported private key encoding")
}

func loadPublicKeyFile(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(data); block != nil {
		if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
			if ed, ok := key.(ed25519.PublicKey); ok {
				return ed, nil
			}
			return nil, fmt.Errorf("key is not Ed25519")
		}
		if len(block.Bytes) == ed25519.PublicKeySize {
			return ed25519.PublicKey(append([]byte(nil), block.Bytes...)), nil
		}
		return nil, fmt.Errorf("unsupported public key encoding")
	}
	raw := bytes.TrimSpace(data)
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("unsupported public key encoding")
	}
	return ed25519.PublicKey(append([]byte(nil), raw...)), nil
}

func encodePrivateKeyPEM(key ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func encodePublicKeyPEM(key ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func verifyDetachedSignature(path string, data []byte, pub ed25519.PublicKey) error {
	sig, err := os.ReadFile(path + signatureSuffix)
	if os.IsNotExist(err) {
		return fmt.Errorf("signature file %s is missing", path+signatureSuffix)
	}
	if err != nil {
		return fmt.Errorf("cannot read signature file %s: %w", path+signatureSuffix, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("signature file %s has the wrong size", path+signatureSuffix)
	}
	if !ed25519.Verify(pub, data, sig) {
		return fmt.Errorf("signature does not verify (file changed or wrong key)")
	}
	return nil
}

func signFileDetached(path string, key ed25519.PrivateKey) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(key, data)
	return writeFileAtomic(path+signatureSuffix, sig, 0o600)
}

func runKeysCommand(args []string) int {
	if len(args) == 0 || args[0] != "init" {
		fmt.Fprintln(os.Stderr, "usage: sylenix-guard keys init [--out PATH|--key PATH] [--force] [--state-dir DIR]")
		return 2
	}
	fs := flag.NewFlagSet("keys init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	out := fs.String("out", "", "directory to hold policy-signing.key and its .pub")
	keyFlag := fs.String("key", "", "explicit private key file path")
	force := fs.Bool("force", false, "overwrite an existing keypair")
	stateDir := fs.String("state-dir", "", "state directory the private key must stay outside of (default ~/.sylenix-poc)")
	if err := fs.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "sylenix-guard keys init: unexpected arguments")
		return 2
	}
	keyPath := *keyFlag
	if keyPath == "" {
		if *out != "" {
			keyPath = filepath.Join(*out, "policy-signing.key")
		} else {
			var err error
			keyPath, err = defaultSigningKeyPath()
			if err != nil {
				fmt.Fprintln(os.Stderr, "sylenix-guard keys init:", err)
				return 2
			}
		}
	}
	pubPath := keyPath + ".pub"

	state := *stateDir
	if state == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, "sylenix-guard keys init: cannot find home directory; pass --state-dir")
			return 2
		}
		state = filepath.Join(home, ".sylenix-poc")
	}
	stateReal, stateOK := canonicalPath(state)
	keyReal, keyOK := canonicalPath(keyPath)
	absState, absStateErr := filepath.Abs(state)
	absKey, absKeyErr := filepath.Abs(keyPath)
	if (stateOK && keyOK && insideDir(stateReal, keyReal)) ||
		(absStateErr == nil && absKeyErr == nil && insideDir(absState, absKey)) {
		fmt.Fprintln(os.Stderr, "sylenix-guard keys init: refusing to put the private key inside the state directory; choose a path outside it")
		return 2
	}
	if !*force {
		for _, path := range []string{keyPath, pubPath} {
			if _, err := os.Stat(path); err == nil {
				fmt.Fprintf(os.Stderr, "sylenix-guard keys init: %s already exists; use --force to replace it\n", path)
				return 2
			}
		}
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard keys init:", err)
		return 2
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard keys init:", err)
		return 2
	}
	privPEM, err := encodePrivateKeyPEM(priv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard keys init:", err)
		return 2
	}
	pubPEM, err := encodePublicKeyPEM(pub)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard keys init:", err)
		return 2
	}
	if *force {
		_ = os.Remove(keyPath)
		_ = os.Remove(pubPath)
	}
	if err := writeFileAtomic(keyPath, privPEM, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard keys init: cannot write private key:", err)
		return 2
	}
	if err := writeFileAtomic(pubPath, pubPEM, 0o600); err != nil {
		_ = os.Remove(keyPath)
		fmt.Fprintln(os.Stderr, "sylenix-guard keys init: cannot write public key:", err)
		return 2
	}
	fmt.Fprintf(os.Stderr, "WARNING: the private key at %s can sign policy and pin files. Anyone who can read it can loosen Guard. Keep it off the agent machine or in a protected team store; never commit it.\n", keyPath)
	fmt.Printf("private key: %s\n", keyPath)
	fmt.Printf("public key:  %s\n", pubPath)
	fmt.Printf("sign a policy with: sylenix-guard policy sign --policy PATH --key %s\n", keyPath)
	return 0
}

func runPinsCommand(args []string) int {
	if len(args) == 0 || (args[0] != "sign" && args[0] != "verify") {
		fmt.Fprintln(os.Stderr, "usage: sylenix-guard pins sign|verify --name NAME [--state-dir DIR] [--key PATH|--pubkey PATH]")
		return 2
	}
	action := args[0]
	fs := flag.NewFlagSet("pins "+action, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	name := fs.String("name", "", "guard session name used for pins-<name>.json")
	stateDir := fs.String("state-dir", "", "state directory (default ~/.sylenix-poc)")
	keyPath := fs.String("key", "", "Ed25519 private key (sign)")
	pubPath := fs.String("pubkey", "", "Ed25519 public key (verify)")
	if err := fs.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "sylenix-guard pins:", action, "unexpected arguments")
		return 2
	}
	if strings.TrimSpace(*name) == "" || !validDoctorName(*name) {
		fmt.Fprintln(os.Stderr, "sylenix-guard pins:", action, "--name is required and must be a simple name")
		return 2
	}
	state := *stateDir
	if state == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, "sylenix-guard pins:", action, "cannot find home directory; pass --state-dir")
			return 2
		}
		state = filepath.Join(home, ".sylenix-poc")
	}
	path := filepath.Join(state, "pins-"+*name+".json")
	if action == "sign" {
		keyFile := *keyPath
		if keyFile == "" {
			var err error
			keyFile, err = defaultSigningKeyPath()
			if err != nil {
				fmt.Fprintln(os.Stderr, "sylenix-guard pins sign:", err)
				return 2
			}
		}
		key, err := loadPrivateKeyFile(keyFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "sylenix-guard pins sign:", err)
			return 2
		}
		if err := signFileDetached(path, key); err != nil {
			fmt.Fprintln(os.Stderr, "sylenix-guard pins sign:", err)
			return 2
		}
		fmt.Printf("signed %s -> %s\n", path, path+signatureSuffix)
		return 0
	}
	pubFile := *pubPath
	if pubFile == "" {
		fmt.Fprintln(os.Stderr, "sylenix-guard pins verify: --pubkey is required")
		return 2
	}
	pub, err := loadPublicKeyFile(pubFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard pins verify:", err)
		return 2
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard pins verify:", err)
		return 2
	}
	if err := verifyDetachedSignature(path, data, pub); err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard pins verify:", err)
		return 1
	}
	fmt.Printf("signature valid: %s\n", path)
	return 0
}

// ---------------------------------------------------------------- policy file

// loadPolicyForRun resolves --policy, then <state-dir>/policy.yaml, then the
// built-in defaults. A policy that exists but cannot be read or parsed is a
// startup error; the guard never silently falls back to a weaker policy.
func loadPolicyForRun(explicitPath string, explicit bool, stateDir, serverName string, nameExplicit bool, verifyKey ed25519.PublicKey) (*policyFile, string, string, error) {
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
			if verifyKey != nil {
				return nil, source, pathUsed, fmt.Errorf("signing is enabled but the policy file %s is missing; create and sign it with `sylenix-guard policy sign`", pathUsed)
			}
			return defaultPolicyFile(), "builtin", "", nil
		}
		if err != nil {
			return nil, source, pathUsed, fmt.Errorf("cannot read policy %s: %w", pathUsed, err)
		}
		data = b
	}
	if verifyKey != nil {
		if err := verifyDetachedSignature(pathUsed, data, verifyKey); err != nil {
			return nil, source, pathUsed, fmt.Errorf("policy signature verification failed for %s: %w", pathUsed, err)
		}
	}
	pf, err := parsePolicyBytes(data)
	if err != nil {
		return nil, source, pathUsed, fmt.Errorf("policy %s: %w", pathUsed, err)
	}
	if err := validatePolicyServerEntry(pf, serverName, nameExplicit); err != nil {
		return nil, source, pathUsed, fmt.Errorf("policy %s: %w", pathUsed, err)
	}
	return pf, source, pathUsed, nil
}

func validatePolicyServerEntry(pf *policyFile, serverName string, nameExplicit bool) error {
	if len(pf.Servers) == 0 {
		return nil
	}
	if _, ok := pf.Servers[serverName]; !ok && (nameExplicit || len(pf.Servers) != 1) {
		return fmt.Errorf("no entry for server %q; add servers.%s.tools or remove the servers block", serverName, serverName)
	}
	return nil
}

// ---------------------------------------------------------------- team policy

const teamPolicyMaxBody = 4 << 20

type teamPolicyEnvelope struct {
	Policy    []byte `json:"policy"`
	Signature []byte `json:"signature"`
}

// loadLocalPolicyForTeam reads only the local overlay. Missing is not an error:
// with a team policy the overlay is optional, but if present it must parse.
func loadLocalPolicyForTeam(explicitPath string, explicit bool, stateDir, serverName string, nameExplicit bool, verifyKey ed25519.PublicKey) (*policyFile, string, string, bool, error) {
	pathUsed, source := explicitPath, "flag"
	if !explicit {
		pathUsed, source = filepath.Join(stateDir, policyFileName), "state-dir"
	}
	if explicit && explicitPath == "" {
		return nil, source, "", false, fmt.Errorf("--policy needs a file path")
	}
	data, err := os.ReadFile(pathUsed)
	if os.IsNotExist(err) {
		if explicit {
			return nil, source, pathUsed, false, fmt.Errorf("cannot read policy %s: %w", pathUsed, err)
		}
		return nil, source, pathUsed, false, nil
	}
	if err != nil {
		return nil, source, pathUsed, false, fmt.Errorf("cannot read policy %s: %w", pathUsed, err)
	}
	if verifyKey != nil {
		if err := verifyDetachedSignature(pathUsed, data, verifyKey); err != nil {
			return nil, source, pathUsed, false, fmt.Errorf("policy signature verification failed for %s: %w", pathUsed, err)
		}
	}
	pf, err := parsePolicyBytes(data)
	if err != nil {
		return nil, source, pathUsed, false, fmt.Errorf("policy %s: %w", pathUsed, err)
	}
	if err := validatePolicyServerEntry(pf, serverName, nameExplicit); err != nil {
		return nil, source, pathUsed, false, fmt.Errorf("policy %s: %w", pathUsed, err)
	}
	return pf, source, pathUsed, true, nil
}

func readTeamToken(path string) (string, error) {
	var raw []byte
	var err error
	if path != "" {
		raw, err = os.ReadFile(path)
		if err != nil {
			return "", err
		}
	} else {
		raw = []byte(os.Getenv("SYLENIX_TEAM_TOKEN"))
		if len(raw) == 0 {
			return "", fmt.Errorf("pass --team-token-file or set SYLENIX_TEAM_TOKEN")
		}
	}
	token := strings.TrimRight(string(raw), "\r\n")
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", fmt.Errorf("team token must be non-empty and contain no whitespace")
	}
	return token, nil
}

func newTeamPolicyRuntime(g *Guard, opts guardOptions, local *policyFile, localSource, localPath string, flagScratch []scratchRule) (*teamPolicyRuntime, *policyFile, []byte, []byte, bool, error) {
	if opts.TeamPubKey == "" {
		return nil, nil, nil, nil, false, fmt.Errorf("--team-pubkey is required with --team-url")
	}
	u, err := url.Parse(opts.TeamURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, nil, nil, nil, false, fmt.Errorf("--team-url must be an absolute https URL without userinfo, query or fragment")
	}
	pub, err := loadPublicKeyFile(opts.TeamPubKey)
	if err != nil {
		return nil, nil, nil, nil, false, fmt.Errorf("cannot load --team-pubkey: %w", err)
	}
	token, err := readTeamToken(opts.TeamTokenFile)
	if err != nil {
		return nil, nil, nil, nil, false, err
	}
	interval := 15 * time.Minute
	if strings.TrimSpace(opts.TeamInterval) != "" {
		interval, err = time.ParseDuration(opts.TeamInterval)
		if err != nil || interval <= 0 {
			return nil, nil, nil, nil, false, fmt.Errorf("--team-interval must be a positive duration, for example 15m")
		}
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if opts.TeamCA != "" {
		raw, err := os.ReadFile(opts.TeamCA)
		if err != nil {
			return nil, nil, nil, nil, false, fmt.Errorf("cannot read --team-ca: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(raw) {
			return nil, nil, nil, nil, false, fmt.Errorf("--team-ca contains no PEM certificates")
		}
		tlsConfig.RootCAs = pool
	}
	tr := &teamPolicyRuntime{
		url:          u.String(),
		token:        token,
		pub:          pub,
		interval:     interval,
		cachePolicy:  filepath.Join(g.stateDir, "team-policy-"+g.name+".yaml"),
		local:        local,
		localSource:  localSource,
		localPath:    localPath,
		nameExplicit: opts.Visited["name"] && opts.Name != "",
		opts: teamApplyOptions{
			visited:     opts.Visited,
			readonly:    opts.Readonly,
			trust:       opts.Trust,
			approve:     opts.Approve,
			flagScratch: flagScratch,
			noSpotlight: opts.NoSpotlight,
			serverArgs:  opts.ServerArgs,
		},
	}
	tr.cacheSig = tr.cachePolicy + signatureSuffix
	tr.client = &http.Client{
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			ForceAttemptHTTP2:   true,
			TLSClientConfig:     tlsConfig,
			TLSHandshakeTimeout: 10 * time.Second,
		},
		Timeout: 15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	pf, raw, sig, err := tr.fetch()
	if err == nil {
		if err = validatePolicyServerEntry(pf, g.name, tr.nameExplicit); err == nil {
			return tr, pf, raw, sig, false, nil
		}
	}
	cachePF, cacheRaw, cacheSig, cacheErr := tr.readCache()
	if cacheErr == nil {
		cacheErr = validatePolicyServerEntry(cachePF, g.name, tr.nameExplicit)
	}
	if cacheErr != nil {
		return nil, nil, nil, nil, false, fmt.Errorf("team policy fetch failed (%s) and no valid cached policy is available (%s)", teamReason(err), teamReason(cacheErr))
	}
	return tr, cachePF, cacheRaw, cacheSig, true, nil
}

// teamReason maps transport and parse failures to stable audit reason codes. It
// deliberately does not echo URLs, tokens or policy contents.
func teamReason(err error) string {
	if err == nil {
		return "ok"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "signature"):
		return "bad_signature"
	case strings.Contains(msg, "parse") || strings.Contains(msg, "yaml") || strings.Contains(msg, "policy") || strings.Contains(msg, "no entry"):
		return "invalid_policy"
	case strings.Contains(msg, "not found"), strings.Contains(msg, "no policy"), strings.Contains(msg, "returned 404"):
		return "not_found"
	case strings.Contains(msg, "401"), strings.Contains(msg, "unauthorized"):
		return "unauthorized"
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline"):
		return "timeout"
	case strings.Contains(msg, "tls"), strings.Contains(msg, "certificate"):
		return "tls"
	default:
		return "unavailable"
	}
}

func (t *teamPolicyRuntime) fetch() (*policyFile, []byte, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.url, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+t.token)
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, nil, fmt.Errorf("team policy service returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, teamPolicyMaxBody+1))
	if err != nil {
		return nil, nil, nil, err
	}
	if len(body) > teamPolicyMaxBody {
		return nil, nil, nil, fmt.Errorf("team policy envelope is too large")
	}
	policy, sig, err := decodeTeamPolicyEnvelope(body)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := verifyTeamPolicy(t.pub, policy, sig); err != nil {
		return nil, nil, nil, err
	}
	pf, err := parsePolicyBytes(policy)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse team policy: %w", err)
	}
	return pf, policy, sig, nil
}

func decodeTeamPolicyEnvelope(data []byte) ([]byte, []byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var env teamPolicyEnvelope
	if err := dec.Decode(&env); err != nil {
		return nil, nil, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, nil, fmt.Errorf("trailing data after team policy envelope")
	}
	if len(env.Policy) == 0 {
		return nil, nil, fmt.Errorf("team policy is empty")
	}
	if len(env.Signature) != ed25519.SignatureSize {
		return nil, nil, fmt.Errorf("team policy signature has the wrong size")
	}
	return env.Policy, env.Signature, nil
}

func verifyTeamPolicy(pub ed25519.PublicKey, policy, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid team public key")
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, policy, sig) {
		return fmt.Errorf("team policy signature does not verify (policy changed or wrong key)")
	}
	return nil
}

func (t *teamPolicyRuntime) readCache() (*policyFile, []byte, []byte, error) {
	policy, err := os.ReadFile(t.cachePolicy)
	if err != nil {
		return nil, nil, nil, err
	}
	sig, err := os.ReadFile(t.cacheSig)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := verifyTeamPolicy(t.pub, policy, sig); err != nil {
		return nil, nil, nil, err
	}
	pf, err := parsePolicyBytes(policy)
	if err != nil {
		return nil, nil, nil, err
	}
	return pf, policy, sig, nil
}

func (t *teamPolicyRuntime) writeCache(policy, sig []byte) error {
	if err := verifyTeamPolicy(t.pub, policy, sig); err != nil {
		return err
	}
	if err := writeFileAtomic(t.cachePolicy, policy, 0o600); err != nil {
		return err
	}
	return writeFileAtomic(t.cacheSig, sig, 0o600)
}

func (g *Guard) startTeamPoller() {
	if g.team == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(g.team.interval)
		defer ticker.Stop()
		for range ticker.C {
			g.refreshTeamPolicy()
		}
	}()
}

func (g *Guard) refreshTeamPolicy() {
	tr := g.team
	if tr == nil {
		return
	}
	pf, policy, sig, err := tr.fetch()
	if err == nil {
		err = validatePolicyServerEntry(pf, g.name, tr.nameExplicit)
	}
	if err != nil {
		g.event("team_policy_rejected", map[string]any{"reason": teamReason(err)})
		alert("team policy pull rejected: %s; keeping the last good policy", teamReason(err))
		return
	}
	hash := sha256.Sum256(policy)
	if hash == tr.lastHash {
		return
	}
	ignored, profile, err := g.applyTeamPolicy(pf, tr)
	if err != nil {
		g.event("team_policy_rejected", map[string]any{"reason": "invalid_policy"})
		alert("team policy rejected: %s; keeping the last good policy", err)
		return
	}
	if err := tr.writeCache(policy, sig); err != nil {
		g.event("team_policy_cache_error", map[string]any{"reason": teamReason(err)})
		tr.lastHash = [sha256.Size]byte{}
	} else {
		tr.lastHash = hash
	}
	if len(ignored) > 0 {
		g.event("team_policy_loosen_ignored", map[string]any{"fields": ignored})
	}
	g.event("team_policy_reloaded", map[string]any{"version": pf.Version, "profile": profile})
}

func (g *Guard) applyTeamPolicy(remote *policyFile, tr *teamPolicyRuntime) ([]string, string, error) {
	effective, ignored := tightenPolicy(remote, tr.local)
	remoteProfile := selectPolicyProfile(g.name, tr.opts.serverArgs, remote.Profile)
	profile := selectPolicyProfile(g.name, tr.opts.serverArgs, effective.Profile)
	oldPatterns := append([]string(nil), currentSensitivePatterns()...)
	floor := stateFromPolicy(remote, remoteProfile, g.name)
	safeOpts := sanitizeTeamFlags(floor, tr.opts)
	candidate := stateFromPolicyWithFlags(effective, profile, g.name, safeOpts)
	merged := tightenPolicyState(floor, candidate)
	newPatterns := mergeSensitivePatterns(effective.SensitivePaths)
	// The temporary policy builds above set the process-wide pattern list.
	// Publish a superset before swapping the policy snapshot, then narrow to the
	// new list, so a request never sees fewer patterns than either old or new.
	setSensitivePatterns(mergeSensitivePatterns(append(oldPatterns, newPatterns...)))
	g.assignPolicyState(merged)
	setSensitivePatterns(newPatterns)
	g.policyVersion = effective.Version
	g.policySource = "team"
	g.policyPath = tr.url
	g.profileName = ""
	g.profileSource = ""
	if profile != nil {
		g.profileName = profile.name
		g.profileSource = profile.source
	}
	return ignored, g.profileName, nil
}

func stateFromPolicy(pf *policyFile, profile *policyProfile, name string) *policyState {
	tmp := &Guard{name: name}
	tmp.applyPolicy(pf, profile, map[string]bool{}, "", "", "", nil, false)
	return tmp.stateFromFields()
}

func stateFromPolicyWithFlags(pf *policyFile, profile *policyProfile, name string, opts teamApplyOptions) *policyState {
	// applyPolicy's --readonly path deletes the flag entries for every tool
	// named in the policy file. In team mode build the policy state first and
	// narrow it below instead, so a valid --readonly subset is not lost.
	visited := cloneVisited(opts.visited)
	delete(visited, "readonly")
	tmp := &Guard{name: name}
	tmp.applyPolicy(pf, profile, visited, "", opts.trust, opts.approve, opts.flagScratch, opts.noSpotlight)
	st := tmp.stateFromFields()
	if opts.visited["readonly"] {
		requested := toSet(opts.readonly)
		for tool := range st.readonly {
			if !requested[tool] {
				delete(st.readonly, tool)
				st.classes[tool] = "exec"
			}
		}
	}
	return st
}

func cloneVisited(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// sanitizeTeamFlags drops flag values that would loosen the team floor. A flag
// that cannot be applied as a narrowing is ignored entirely, so it does not
// accidentally remove team permissions either.
func sanitizeTeamFlags(floor *policyState, opts teamApplyOptions) teamApplyOptions {
	out := opts
	out.visited = map[string]bool{}
	for k, v := range opts.visited {
		out.visited[k] = v
	}
	if out.visited["approve"] && out.approve == "dialog" && floor.approve == "deny" {
		delete(out.visited, "approve")
		out.approve = ""
	}
	if out.visited["no-spotlight"] && out.noSpotlight && floor.spotlight {
		delete(out.visited, "no-spotlight")
		out.noSpotlight = false
	}
	if out.visited["readonly"] {
		requested := toSet(out.readonly)
		kept := []string{}
		for name := range requested {
			if floor.readonly[name] {
				kept = append(kept, name)
			}
		}
		sort.Strings(kept)
		if len(kept) == 0 && len(requested) > 0 {
			delete(out.visited, "readonly")
			out.readonly = ""
		} else {
			out.readonly = strings.Join(kept, ",")
		}
	}
	if out.visited["trust"] {
		requested := toSet(out.trust)
		kept := []string{}
		for name := range requested {
			if floor.trust[name] {
				kept = append(kept, name)
			}
		}
		sort.Strings(kept)
		if len(kept) == 0 && len(requested) > 0 {
			delete(out.visited, "trust")
			out.trust = ""
		} else {
			out.trust = strings.Join(kept, ",")
		}
	}
	if out.visited["allow-write-under"] {
		kept := []scratchRule{}
		for _, cand := range out.flagScratch {
			for _, fl := range floor.scratch {
				if scratchRuleCovered(fl, cand) {
					kept = append(kept, cand)
					break
				}
			}
		}
		if len(kept) == 0 && len(out.flagScratch) > 0 {
			delete(out.visited, "allow-write-under")
			out.flagScratch = nil
		} else {
			out.flagScratch = kept
		}
	}
	return out
}

func tightenPolicyState(floor, candidate *policyState) *policyState {
	out := candidate.clone()
	tools := map[string]bool{}
	for name := range floor.readonly {
		tools[name] = true
	}
	for name := range floor.classes {
		tools[name] = true
	}
	for name := range candidate.readonly {
		tools[name] = true
	}
	for name := range candidate.classes {
		tools[name] = true
	}
	out.readonly = map[string]bool{}
	out.classes = map[string]string{}
	for name := range tools {
		rank := policyClassRank(floor, name)
		if r := policyClassRank(candidate, name); r > rank {
			rank = r
		}
		switch rank {
		case 0:
			out.readonly[name] = true
		case 1:
			out.classes[name] = "write"
		case 2:
			out.classes[name] = "egress"
		default:
			out.classes[name] = "exec"
		}
	}
	out.trust = map[string]bool{}
	for name := range candidate.trust {
		if floor.trust[name] {
			out.trust[name] = true
		}
	}
	out.toolPathKeys = map[string]map[string]bool{}
	for name, keys := range floor.toolPathKeys {
		out.toolPathKeys[name] = cloneBoolMap(keys)
	}
	for name, keys := range candidate.toolPathKeys {
		if out.toolPathKeys[name] == nil {
			out.toolPathKeys[name] = map[string]bool{}
		}
		for k := range keys {
			out.toolPathKeys[name][k] = true
		}
	}
	out.approve = "dialog"
	if floor.approve == "deny" || candidate.approve == "deny" || floor.approve == "" || candidate.approve == "" {
		out.approve = "deny"
	}
	out.spotlight = floor.spotlight || candidate.spotlight
	out.scratch = nil
	for _, cand := range candidate.scratch {
		for _, fl := range floor.scratch {
			if scratchRuleCovered(fl, cand) {
				out.scratch = append(out.scratch, cand)
				break
			}
		}
	}
	out.egressDeny = cloneBoolMap(floor.egressDeny)
	for host := range candidate.egressDeny {
		out.egressDeny[host] = true
	}
	out.egressAllow = map[string]bool{}
	for host := range candidate.egressAllow {
		for allowed := range floor.egressAllow {
			if hostPatternCovered(allowed, host) {
				out.egressAllow[host] = true
				break
			}
		}
	}
	if floor.allowlistEnforced {
		out.allowlistEnforced = true
		out.allowlist = intersectAllowEntries(floor.allowlist, candidate.allowlist)
	} else if candidate.allowlistEnforced {
		out.allowlistEnforced = true
		out.allowlist = append([]policyAllowEntry(nil), candidate.allowlist...)
	} else {
		out.allowlistEnforced = false
		out.allowlist = append([]policyAllowEntry(nil), floor.allowlist...)
	}
	return out
}

func policyClassRank(st *policyState, tool string) int {
	if st == nil {
		return 3
	}
	if st.readonly[tool] {
		return 0
	}
	switch st.classes[tool] {
	case "read":
		return 0
	case "write":
		return 1
	case "egress":
		return 2
	default:
		return 3
	}
}

func scratchRuleCovered(floor, cand scratchRule) bool {
	if floor.tool != "" && floor.tool != cand.tool {
		return false
	}
	if floor.dir == cand.dir {
		return true
	}
	return insideDir(floor.dir, cand.dir)
}

func hostPatternCovered(floor, cand string) bool {
	floor = normalizePolicyHostValue(floor)
	cand = normalizePolicyHostValue(cand)
	if floor == "" || cand == "" {
		return false
	}
	if floor == cand {
		return true
	}
	if strings.HasPrefix(floor, "*.") && !strings.ContainsAny(floor[2:], "*?[") {
		suffix := floor[1:] // include the leading dot
		return cand != suffix && strings.HasSuffix(cand, suffix)
	}
	return false
}

func intersectAllowEntries(floor, candidate []policyAllowEntry) []policyAllowEntry {
	out := []policyAllowEntry{}
	for _, want := range candidate {
		for _, have := range floor {
			if sameAllowEntry(have, want) {
				out = append(out, want)
				break
			}
		}
	}
	return out
}

func clonePolicyFile(pf *policyFile) *policyFile {
	if pf == nil {
		return nil
	}
	out := *pf
	out.SensitivePaths = append([]string(nil), pf.SensitivePaths...)
	if pf.Spotlight != nil {
		out.Spotlight = boolPtr(*pf.Spotlight)
	}
	if pf.AllowlistEnforced != nil {
		out.AllowlistEnforced = boolPtr(*pf.AllowlistEnforced)
	}
	if pf.Egress != nil {
		out.Egress = &policyEgress{
			AllowHosts: append([]string(nil), pf.Egress.AllowHosts...),
			DenyHosts:  append([]string(nil), pf.Egress.DenyHosts...),
		}
	}
	out.Allowlist = make([]policyAllowEntry, len(pf.Allowlist))
	for i, e := range pf.Allowlist {
		out.Allowlist[i] = e
		if e.Args != nil {
			args := append([]string(nil), (*e.Args)...)
			out.Allowlist[i].Args = &args
		}
	}
	out.Servers = make(map[string]policyServer, len(pf.Servers))
	for sname, srv := range pf.Servers {
		ns := policyServer{Tools: make(map[string]policyTool, len(srv.Tools))}
		for tname, tool := range srv.Tools {
			nt := tool
			nt.PathKeys = append([]string(nil), tool.PathKeys...)
			nt.AllowPaths = append([]string(nil), tool.AllowPaths...)
			ns.Tools[tname] = nt
		}
		out.Servers[sname] = ns
	}
	return &out
}

func policyAllowlistEnforced(pf *policyFile) bool {
	if pf == nil {
		return false
	}
	if pf.AllowlistEnforced != nil {
		return *pf.AllowlistEnforced
	}
	return len(pf.Allowlist) > 0
}

func classAtLeastAsStrict(floor, candidate string) bool {
	if floor == candidate {
		return true
	}
	switch floor {
	case "read":
		return true
	case "write":
		return candidate == "write" || candidate == "exec"
	case "egress":
		return candidate == "egress" || candidate == "exec"
	case "exec":
		return candidate == "exec"
	}
	return false
}

func insideAllowRoot(root, p string) bool {
	rr, ok := canonicalPath(root)
	if !ok {
		return false
	}
	pp, ok := canonicalPath(p)
	if !ok {
		return false
	}
	return insideDir(rr, pp)
}

// tightenPolicy overlays the local policy on the team policy. Every accepted
// local change is equal or stricter; loosening fields are reported and ignored.
func tightenPolicy(remote, local *policyFile) (*policyFile, []string) {
	out := clonePolicyFile(remote)
	if out.Approval == "" {
		out.Approval = "deny"
	}
	if local == nil {
		return out, nil
	}
	var ignored []string
	if local.Profile != "" && local.Profile != out.Profile {
		ignored = append(ignored, "profile")
	}
	if local.Approval == "deny" && out.Approval != "deny" {
		out.Approval = "deny"
	} else if local.Approval != "" && local.Approval != out.Approval && out.Approval == "deny" {
		ignored = append(ignored, "approval")
	}
	remoteSpotlight := true
	if out.Spotlight != nil {
		remoteSpotlight = *out.Spotlight
	}
	if local.Spotlight != nil {
		if *local.Spotlight {
			out.Spotlight = boolPtr(true)
		} else if remoteSpotlight {
			ignored = append(ignored, "spotlight")
		}
	}
	seenSensitive := map[string]bool{}
	for _, p := range out.SensitivePaths {
		seenSensitive[strings.ToLower(p)] = true
	}
	for _, p := range local.SensitivePaths {
		if !seenSensitive[strings.ToLower(p)] {
			out.SensitivePaths = append(out.SensitivePaths, p)
			seenSensitive[strings.ToLower(p)] = true
		}
	}
	remoteEnforced := policyAllowlistEnforced(out)
	if local.AllowlistEnforced != nil && !*local.AllowlistEnforced && remoteEnforced {
		ignored = append(ignored, "allowlist_enforced")
	}
	if local.Allowlist != nil {
		if remoteEnforced {
			matched := intersectAllowEntries(out.Allowlist, local.Allowlist)
			if len(matched) != len(local.Allowlist) {
				ignored = append(ignored, "allowlist")
			}
			out.Allowlist = matched
			out.AllowlistEnforced = boolPtr(true)
		} else {
			out.Allowlist = clonePolicyFile(&policyFile{Allowlist: local.Allowlist}).Allowlist
			out.AllowlistEnforced = boolPtr(true)
		}
	} else if local.AllowlistEnforced != nil && *local.AllowlistEnforced {
		if remoteEnforced {
			out.AllowlistEnforced = boolPtr(true)
		} else {
			out.Allowlist = nil
			out.AllowlistEnforced = boolPtr(true)
		}
	}
	if local.Egress != nil {
		if out.Egress == nil {
			out.Egress = &policyEgress{}
		}
		if local.Egress.AllowHosts != nil {
			kept := []string{}
			for _, want := range local.Egress.AllowHosts {
				covered := false
				for _, have := range out.Egress.AllowHosts {
					if hostPatternCovered(have, want) {
						covered = true
						break
					}
				}
				if covered {
					kept = append(kept, want)
				}
			}
			if len(local.Egress.AllowHosts) > len(kept) {
				ignored = append(ignored, "egress.allow_hosts")
			}
			out.Egress.AllowHosts = kept
		}
		seenDeny := map[string]bool{}
		for _, h := range out.Egress.DenyHosts {
			seenDeny[normalizePolicyHostValue(h)] = true
		}
		for _, h := range local.Egress.DenyHosts {
			if !seenDeny[normalizePolicyHostValue(h)] {
				out.Egress.DenyHosts = append(out.Egress.DenyHosts, h)
				seenDeny[normalizePolicyHostValue(h)] = true
			}
		}
	}
	if out.Servers == nil {
		out.Servers = map[string]policyServer{}
	}
	localServers := make([]string, 0, len(local.Servers))
	for name := range local.Servers {
		localServers = append(localServers, name)
	}
	sort.Strings(localServers)
	for _, sname := range localServers {
		lsrv := local.Servers[sname]
		rsrv, ok := out.Servers[sname]
		if !ok {
			rsrv = policyServer{Tools: map[string]policyTool{}}
		}
		if rsrv.Tools == nil {
			rsrv.Tools = map[string]policyTool{}
		}
		localTools := make([]string, 0, len(lsrv.Tools))
		for name := range lsrv.Tools {
			localTools = append(localTools, name)
		}
		sort.Strings(localTools)
		for _, tname := range localTools {
			lt := lsrv.Tools[tname]
			rt, exists := rsrv.Tools[tname]
			if !exists {
				if lt.Class != "exec" {
					ignored = append(ignored, "servers."+sname+".tools."+tname)
					continue
				}
				rt = policyTool{Class: "exec"}
			}
			if !classAtLeastAsStrict(rt.Class, lt.Class) {
				ignored = append(ignored, "servers."+sname+".tools."+tname+".class")
				lt.Class = rt.Class
			}
			rt.Class = lt.Class
			if lt.Trust && !rt.Trust {
				ignored = append(ignored, "servers."+sname+".tools."+tname+".trust")
			} else if !lt.Trust && rt.Trust {
				rt.Trust = false
			}
			seen := map[string]bool{}
			for _, k := range rt.PathKeys {
				seen[strings.ToLower(k)] = true
			}
			for _, k := range lt.PathKeys {
				if !seen[strings.ToLower(k)] {
					rt.PathKeys = append(rt.PathKeys, k)
					seen[strings.ToLower(k)] = true
				}
			}
			if rt.Class != "write" {
				if len(lt.AllowPaths) > 0 && exists {
					ignored = append(ignored, "servers."+sname+".tools."+tname+".allow_paths")
				}
				rt.AllowPaths = nil
			} else if lt.AllowPaths != nil {
				kept := []string{}
				for _, p := range lt.AllowPaths {
					for _, root := range rt.AllowPaths {
						if insideAllowRoot(root, p) {
							kept = append(kept, p)
							break
						}
					}
				}
				if len(kept) != len(lt.AllowPaths) {
					ignored = append(ignored, "servers."+sname+".tools."+tname+".allow_paths")
				}
				rt.AllowPaths = kept
			}
			rsrv.Tools[tname] = rt
		}
		out.Servers[sname] = rsrv
	}
	return out, ignored
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
	g.policy.Store(g.stateFromFields())
}

// stateFromFields captures the current policy fields. Callers must not mutate
// the returned maps or slices.
func (g *Guard) stateFromFields() *policyState {
	st := &policyState{
		readonly:          cloneBoolMap(g.readonly),
		trust:             cloneBoolMap(g.trust),
		approve:           g.approve,
		spotlight:         g.spotlight,
		scratch:           append([]scratchRule(nil), g.scratch...),
		classes:           cloneStringMap(g.classes),
		toolPathKeys:      map[string]map[string]bool{},
		egressAllow:       cloneBoolMap(g.egressAllow),
		egressDeny:        cloneBoolMap(g.egressDeny),
		allowlistEnforced: g.allowlistEnforced,
		allowlist:         append([]policyAllowEntry(nil), g.allowlist...),
	}
	for tool, keys := range g.toolPathKeys {
		st.toolPathKeys[tool] = cloneBoolMap(keys)
	}
	if st.approve == "" {
		st.approve = "deny"
	}
	return st
}

// assignPolicyState installs a fully built state and publishes it atomically.
func (g *Guard) assignPolicyState(st *policyState) {
	st = st.clone()
	g.readonly = cloneBoolMap(st.readonly)
	g.trust = cloneBoolMap(st.trust)
	g.approve = st.approve
	g.spotlight = st.spotlight
	g.scratch = append([]scratchRule(nil), st.scratch...)
	g.classes = cloneStringMap(st.classes)
	g.toolPathKeys = map[string]map[string]bool{}
	for tool, keys := range st.toolPathKeys {
		g.toolPathKeys[tool] = cloneBoolMap(keys)
	}
	g.egressAllow = cloneBoolMap(st.egressAllow)
	g.egressDeny = cloneBoolMap(st.egressDeny)
	g.allowlistEnforced = st.allowlistEnforced
	g.allowlist = append([]policyAllowEntry(nil), st.allowlist...)
	g.policy.Store(st)
}

func (g *Guard) currentPolicy() *policyState {
	if st := g.policy.Load(); st != nil {
		return st
	}
	st := g.stateFromFields()
	g.policy.Store(st)
	return st
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

func runPolicySignCommand(args []string) int {
	fs := flag.NewFlagSet("policy sign", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	policyPath := fs.String("policy", "", "policy file to sign (default: <state-dir>/policy.yaml)")
	stateDir := fs.String("state-dir", "", "state directory for the default policy path (default ~/.sylenix-poc)")
	keyPath := fs.String("key", "", "Ed25519 private key (default ~/.sylenix-keys/policy-signing.key)")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "sylenix-guard policy sign: unexpected arguments")
		return 2
	}
	path, err := policySignPath(*policyPath, *stateDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard policy sign:", err)
		return 2
	}
	keyFile := *keyPath
	if keyFile == "" {
		keyFile, err = defaultSigningKeyPath()
		if err != nil {
			fmt.Fprintln(os.Stderr, "sylenix-guard policy sign:", err)
			return 2
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard policy sign:", err)
		return 2
	}
	if _, err := parsePolicyBytes(data); err != nil {
		fmt.Fprintf(os.Stderr, "sylenix-guard policy sign: %s: %v\n", path, err)
		return 2
	}
	key, err := loadPrivateKeyFile(keyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard policy sign:", err)
		return 2
	}
	if err := signFileDetached(path, key); err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard policy sign:", err)
		return 2
	}
	fmt.Printf("signed %s -> %s\n", path, path+signatureSuffix)
	return 0
}

func runPolicyVerifyCommand(args []string) int {
	fs := flag.NewFlagSet("policy verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	policyPath := fs.String("policy", "", "policy file to verify (default: <state-dir>/policy.yaml)")
	stateDir := fs.String("state-dir", "", "state directory for the default policy path (default ~/.sylenix-poc)")
	pubPath := fs.String("pubkey", "", "Ed25519 public key")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "sylenix-guard policy verify: unexpected arguments")
		return 2
	}
	if strings.TrimSpace(*pubPath) == "" {
		fmt.Fprintln(os.Stderr, "sylenix-guard policy verify: --pubkey is required")
		return 2
	}
	path, err := policySignPath(*policyPath, *stateDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard policy verify:", err)
		return 2
	}
	pub, err := loadPublicKeyFile(*pubPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard policy verify:", err)
		return 2
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard policy verify:", err)
		return 2
	}
	if err := verifyDetachedSignature(path, data, pub); err != nil {
		fmt.Fprintln(os.Stderr, "sylenix-guard policy verify:", err)
		return 1
	}
	fmt.Printf("signature valid: %s\n", path)
	return 0
}

func policySignPath(explicit, stateDir string) (string, error) {
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

func runPolicyCommand(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: sylenix-guard policy validate <file> | sign | verify | print-default")
		return 2
	}
	switch args[0] {
	case "sign":
		return runPolicySignCommand(args[1:])
	case "verify":
		return runPolicyVerifyCommand(args[1:])
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
	if err := writeConfigAtomic(path, marshalPolicyYAML(pf), 0o600); err != nil {
		return err
	}
	// A rewritten policy no longer matches its old detached signature. Remove
	// it so a signing-enabled start reports a missing signature, not a stale
	// one that might be mistaken for a valid file.
	_ = os.Remove(path + signatureSuffix)
	return nil
}

func writeDefaultPolicyFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := writeConfigAtomic(path, []byte(defaultPolicyYAML()), 0o600); err != nil {
		return err
	}
	_ = os.Remove(path + signatureSuffix)
	return nil
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

// fromHost inspects one host frame. A non-nil forward slice is the exact frame
// to send to the server: original bytes for pass-through frames, or a frame
// rebuilt from the tools/call name and arguments the Guard checked.
func (g *Guard) fromHost(line []byte) (forward []byte, reply []byte) {
	trim := bytes.TrimSpace(line)
	if len(trim) > 0 && trim[0] == '[' {
		g.event("batch_dropped", nil)
		return nil, errorFrame(nil, -32600, "Batch frames are not supported", "BATCH_UNSUPPORTED")
	}
	var f frame
	if err := json.Unmarshal(trim, &f); err != nil {
		g.event("unparseable_host_frame", map[string]any{"bytes": len(line)})
		return nil, errorFrame(nil, -32700, "Parse error", "UNPARSEABLE")
	}
	if hasDuplicateKeys(trim) || hasFoldCollidingKeys(trim) {
		g.event("block", map[string]any{"rule": "DUPLICATE_KEYS"})
		return nil, errorFrame(nil, -32600, "Invalid request", "DUPLICATE_KEYS")
	}
	var method string
	_ = json.Unmarshal(f["method"], &method)
	id := f["id"]
	if method == "" {
		return line, nil // a response from the host to a server request
	}
	if g.serverGone.Load() {
		return nil, replyIfRequest(id, -32000, "Server stream closed", "SERVER_STREAM_CLOSED")
	}
	if len(id) > 0 && g.isPending(id) {
		// A response must only ever carry the identity of the request it answers.
		// The reply uses id null so it cannot be mistaken for the answer to the first request.
		g.event("block", map[string]any{"rule": "DUPLICATE_ID", "method": method})
		return nil, errorFrame(nil, -32600, "Invalid request", "DUPLICATE_ID")
	}
	if method != "tools/call" {
		g.track(id, method, "")
		return line, nil
	}

	// Only the exact lower-case keys are the call the Guard evaluates. A
	// case-insensitive struct decode used to let a decoy key win here while an
	// exact-matching MCP server executed the other value.
	unparseable := func() ([]byte, []byte) {
		g.event("block", map[string]any{"rule": "UNPARSEABLE_CALL"})
		return nil, replyIfRequest(id, -32000, "Blocked by Sylenix Guard", "UNPARSEABLE_CALL")
	}
	var params map[string]json.RawMessage
	if err := json.Unmarshal(f["params"], &params); err != nil || params == nil {
		return unparseable()
	}
	nameRaw, ok := params["name"]
	if !ok {
		return unparseable()
	}
	var name string
	if err := json.Unmarshal(nameRaw, &name); err != nil || name == "" {
		return unparseable()
	}
	var args map[string]any
	argsRaw, argsPresent := params["arguments"]
	if argsPresent && !bytes.Equal(bytes.TrimSpace(argsRaw), []byte("null")) {
		if err := json.Unmarshal(argsRaw, &args); err != nil || args == nil {
			return unparseable()
		}
	}
	forwardFrame, ok := rebuildCallFrame(f, params, name, argsRaw, argsPresent)
	if !ok {
		return unparseable()
	}

	g.mu.Lock()
	reason, quarantined := g.quarantined[name]
	g.mu.Unlock()
	tainted, origin := g.taintState()
	pol := g.currentPolicy()

	if quarantined {
		g.event("block", map[string]any{"tool": name, "rule": "MANIFEST_QUARANTINE", "detail": reason})
		alert("tool %q blocked: %s", name, reason)
		return nil, replyIfRequest(id, -32001, "Blocked by Sylenix Guard", "MANIFEST_QUARANTINE")
	}
	class := pol.classFor(name)
	if !tainted || class == "read" {
		if tainted && class == "read" {
			// Read-class tools stay prompt-free only for non-credential,
			// non-sensitive targets. A tainted read must not become a way to
			// read credentials that a write would refuse.
			scan := scanArgs(args, pol.toolPathKeys[name], g.protectedDirs)
			if !scan.sensitive && g.hardSensitiveCall(name, scan.paths, pol.scratch) {
				scan.sensitive = true
			}
			if scan.sensitive {
				g.event("block", map[string]any{"tool": name, "rule": "SENSITIVE_TARGET", "origin": origin, "class": class, "arg_keys": argKeys(args)})
				alert("tool %q blocked: sensitive path in a session tainted by %q", name, origin)
				return nil, replyIfRequest(id, -32000, "Blocked by Sylenix Guard", "SENSITIVE_TARGET")
			}
			if scan.protected && scan.credential {
				if g.grantAllows(name, scan.paths, scan.protected) {
					g.event("allow", map[string]any{"tool": name, "tainted": true, "class": class, "rule": "GRANT", "arg_keys": argKeys(args)})
					g.track(id, method, name)
					return forwardFrame, nil
				}
				if pol.approve == "dialog" {
					scope := scopeDir(scan.paths)
					decision, note := askHuman(name, args, scan, origin, grantScopeNote(name, scope, scan.protected, len(scan.paths)))
					g.event("approval", map[string]any{"tool": name, "granted": decision != "deny", "decision": decision, "class": class, "note": note, "arg_keys": argKeys(args)})
					if decision == "grant" {
						var files []string
						if scan.protected {
							files = canonicalPathList(scan.paths)
						}
						g.addGrant(name, scope, files, grantTTL, scan.protected)
						g.event("grant_recorded", map[string]any{"tool": name, "scope": scopeKind(scope), "ttl_seconds": int(grantTTL.Seconds())})
					}
					if decision != "deny" {
						g.track(id, method, name)
						return forwardFrame, nil
					}
					return nil, replyIfRequest(id, -32002, "Authorization denied", "APPROVAL_DENIED")
				}
				g.event("block", map[string]any{"tool": name, "rule": "SENSITIVE_TARGET", "origin": origin, "class": class, "arg_keys": argKeys(args)})
				alert("tool %q blocked: credential path in a session tainted by %q", name, origin)
				return nil, replyIfRequest(id, -32000, "Blocked by Sylenix Guard", "SENSITIVE_TARGET")
			}
		}
		g.event("allow", map[string]any{"tool": name, "tainted": tainted, "class": class, "arg_keys": argKeys(args)})
		g.track(id, method, name)
		return forwardFrame, nil
	}

	// Tainted session, tool is not read-only: this is a sink. Hard blocks go
	// first, then protected persistence targets, then grants/scratch, then the
	// dialog or default deny. A fast path can never reach a hard-blocked or
	// protected target.
	scan := scanArgs(args, pol.toolPathKeys[name], g.protectedDirs)
	if !scan.sensitive && g.hardSensitiveCall(name, scan.paths, pol.scratch) {
		scan.sensitive = true
	}
	egressAllowed := false
	if scan.egress {
		egressAllowed = len(scan.egressHosts) > 0
		for _, host := range scan.egressHosts {
			if pol.hostDenied(host) || !pol.hostAllowed(host) {
				egressAllowed = false
			}
		}
		if !egressAllowed {
			g.event("block", map[string]any{"tool": name, "rule": "EGRESS_TARGET", "origin": origin, "class": class, "arg_keys": argKeys(args)})
			alert("tool %q blocked: network target in a session tainted by %q", name, origin)
			return nil, replyIfRequest(id, -32000, "Blocked by Sylenix Guard", "EGRESS_TARGET")
		}
	}
	if scan.sensitive {
		g.event("block", map[string]any{"tool": name, "rule": "SENSITIVE_TARGET", "origin": origin, "class": class, "arg_keys": argKeys(args)})
		alert("tool %q blocked: sensitive path in a session tainted by %q", name, origin)
		return nil, replyIfRequest(id, -32000, "Blocked by Sylenix Guard", "SENSITIVE_TARGET")
	}
	if !scan.protected && g.protectedCall(name, scan.paths, pol.scratch) {
		scan.protected = true
	}
	if scan.protected && pol.approve != "dialog" {
		g.event("block", map[string]any{"tool": name, "rule": "SENSITIVE_TARGET", "origin": origin, "class": class, "arg_keys": argKeys(args)})
		alert("tool %q blocked: protected persistence path in a session tainted by %q", name, origin)
		return nil, replyIfRequest(id, -32000, "Blocked by Sylenix Guard", "SENSITIVE_TARGET")
	}
	// An egress-class tool whose every destination is on the policy allowlist
	// is the one place an allowlist authorizes a tainted call without a prompt.
	// Ambiguous values still fail closed; protected targets still ask a human.
	if class == "egress" && scan.egress && egressAllowed {
		if scan.ambiguous {
			g.event("block", map[string]any{"tool": name, "rule": "EGRESS_TARGET", "origin": origin, "class": class, "arg_keys": argKeys(args)})
			alert("tool %q blocked: ambiguous network target in a session tainted by %q", name, origin)
			return nil, replyIfRequest(id, -32000, "Blocked by Sylenix Guard", "EGRESS_TARGET")
		}
		if !scan.protected {
			g.event("allow", map[string]any{"tool": name, "tainted": true, "class": class, "rule": "EGRESS_ALLOW", "arg_keys": argKeys(args)})
			g.track(id, method, name)
			return forwardFrame, nil
		}
	}
	// A grant or scratch rule may only short-cut a call whose path arguments
	// are all understood and inside the approved tree. Anything ambiguous,
	// and every protected target without a human dialog grant, falls through
	// to denial or a fresh human decision. An allow-listed egress destination
	// on a non-egress tool still needs a fresh human decision, never a fast path.
	if !scan.egress && !scan.ambiguous && g.grantAllows(name, scan.paths, scan.protected) {
		g.event("allow", map[string]any{"tool": name, "tainted": true, "class": class, "rule": "GRANT", "arg_keys": argKeys(args)})
		g.track(id, method, name)
		return forwardFrame, nil
	}
	if !scan.egress && !scan.protected && !scan.ambiguous && pol.scratchAllows(name, scan.paths) {
		g.event("allow", map[string]any{"tool": name, "tainted": true, "class": class, "rule": "SCRATCH", "arg_keys": argKeys(args)})
		g.track(id, method, name)
		return forwardFrame, nil
	}
	if pol.approve == "dialog" {
		scope := scopeDir(scan.paths)
		decision, note := askHuman(name, args, scan, origin, grantScopeNote(name, scope, scan.protected, len(scan.paths)))
		g.event("approval", map[string]any{"tool": name, "granted": decision != "deny", "decision": decision, "class": class, "note": note, "arg_keys": argKeys(args)})
		if decision == "grant" {
			var files []string
			if scan.protected {
				files = canonicalPathList(scan.paths)
			}
			g.addGrant(name, scope, files, grantTTL, scan.protected)
			g.event("grant_recorded", map[string]any{"tool": name, "scope": scopeKind(scope), "ttl_seconds": int(grantTTL.Seconds())})
		}
		if decision != "deny" {
			g.track(id, method, name)
			return forwardFrame, nil
		}
		return nil, replyIfRequest(id, -32002, "Authorization denied", "APPROVAL_DENIED")
	}
	g.event("block", map[string]any{"tool": name, "rule": "TAINT_SINK", "origin": origin, "class": class, "arg_keys": argKeys(args)})
	alert("tool %q blocked: session tainted by %q", name, origin)
	return nil, replyIfRequest(id, -32000, "Blocked by Sylenix Guard", "TAINT_SINK")
}

// rebuildCallFrame returns the tools/call frame the server may receive. It
// keeps the parsed top-level frame, replaces params with the exact checked
// name, the checked arguments, and every other params key copied unchanged
// (for example _meta).
func rebuildCallFrame(f frame, params map[string]json.RawMessage, name string, argsRaw json.RawMessage, argsPresent bool) ([]byte, bool) {
	rebuiltParams := make(map[string]json.RawMessage, len(params))
	for k, v := range params {
		if k == "name" || k == "arguments" {
			continue
		}
		rebuiltParams[k] = v
	}
	nameJSON, err := json.Marshal(name)
	if err != nil {
		return nil, false
	}
	rebuiltParams["name"] = nameJSON
	if argsPresent {
		rebuiltParams["arguments"] = argsRaw
	}
	paramsJSON, err := json.Marshal(rebuiltParams)
	if err != nil {
		return nil, false
	}
	rebuilt := make(map[string]json.RawMessage, len(f))
	for k, v := range f {
		rebuilt[k] = v
	}
	rebuilt["params"] = paramsJSON
	out, err := json.Marshal(rebuilt)
	if err != nil {
		return nil, false
	}
	return out, true
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
		pol := g.currentPolicy()
		if p.method == "tools/call" && pol.trust[p.tool] {
			return line
		}
		g.latch(origin) // latch BEFORE the host can see the content
		if pol.spotlight && p.method == "tools/call" {
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
	g.taintedFlag.Store(true)
	if first {
		g.taintOrigin = origin
		g.taintSince = time.Now()
	}
	g.mu.Unlock()
	if first {
		fields := map[string]any{"origin": origin}
		if reason != "" {
			fields["reason"] = reason
		}
		g.event("taint_latched", fields)
		g.writeSessionTaint(origin)
		alert("session tainted by %q; non-read-only tools now need approval", origin)
	}
}

// sessionTainted returns the effective taint: the local latch or the shared
// session latch. A remote taint is adopted once and audited. An unreadable or
// corrupt shared file is treated as tainted.
func (g *Guard) sessionTainted() bool {
	if g.taintedFlag.Load() {
		return true
	}
	info, err := os.Stat(g.sessionFile)
	if err != nil {
		if os.IsNotExist(err) {
			g.sessionMu.Lock()
			g.sessionCacheValid = false
			g.sessionMu.Unlock()
			return false
		}
		g.adoptSessionTaint("unknown", "session_unreadable", time.Now())
		return true
	}
	if !info.Mode().IsRegular() || info.Size() > sessionFileLimit {
		g.adoptSessionTaint("unknown", "session_unreadable", time.Now())
		return true
	}
	g.sessionMu.Lock()
	if g.sessionCacheValid && info.ModTime().Equal(g.sessionCacheMod) && info.Size() == g.sessionCacheSize {
		originServer, origin := g.sessionCacheOriginServer, g.sessionCacheOrigin
		g.sessionMu.Unlock()
		g.adoptSessionTaint(originServer, origin, time.Now())
		return true
	}
	g.sessionMu.Unlock()

	b, err := os.ReadFile(g.sessionFile)
	if err != nil {
		g.adoptSessionTaint("unknown", "session_unreadable", time.Now())
		return true
	}
	var rec sessionTaintFile
	if json.Unmarshal(b, &rec) != nil || rec.Version != sessionFileVersion || rec.KeyHash != g.sessionHash {
		g.cacheSessionTaint(info, "unknown", "session_unreadable")
		g.adoptSessionTaint("unknown", "session_unreadable", time.Now())
		return true
	}
	since, err := time.Parse(time.RFC3339Nano, rec.TS)
	if err != nil {
		since = time.Now()
	}
	g.cacheSessionTaint(info, rec.OriginServer, rec.Origin)
	g.adoptSessionTaint(rec.OriginServer, rec.Origin, since)
	return true
}

func (g *Guard) cacheSessionTaint(info os.FileInfo, originServer, origin string) {
	g.sessionMu.Lock()
	g.sessionCacheValid = true
	g.sessionCacheMod = info.ModTime()
	g.sessionCacheSize = info.Size()
	g.sessionCacheOriginServer = originServer
	g.sessionCacheOrigin = origin
	g.sessionMu.Unlock()
}

func (g *Guard) adoptSessionTaint(originServer, origin string, since time.Time) {
	if originServer == "" {
		originServer = "unknown"
	}
	if origin == "" {
		origin = originServer
	}
	g.mu.Lock()
	first := !g.tainted
	g.tainted = true
	g.taintedFlag.Store(true)
	if first {
		g.taintOrigin = origin
		g.taintSince = since
	}
	g.mu.Unlock()
	if first {
		g.event("taint_adopted", map[string]any{"origin_server": cleanForDialog(originServer, 80)})
		alert("session tainted by another server (%q); non-read-only tools now need approval", originServer)
	}
}

// taintState is the sink-decision view of the session.
func (g *Guard) taintState() (bool, string) {
	if !g.sessionTainted() {
		return false, ""
	}
	g.mu.Lock()
	origin := g.taintOrigin
	g.mu.Unlock()
	if origin == "" {
		origin = "session"
	}
	return true, origin
}

// writeSessionTaint records the first local latch in the shared session file.
// It never stores content or argument values.
func (g *Guard) writeSessionTaint(origin string) {
	if g.sessionFile == "" {
		return
	}
	if _, err := os.Stat(g.sessionFile); err == nil {
		return
	}
	if origin == "" {
		origin = "unknown"
	}
	parentPID, parentStart := g.parentPID, g.parentStart
	rec := sessionTaintFile{
		Version:      sessionFileVersion,
		KeyHash:      g.sessionHash,
		OriginServer: g.name,
		Origin:       origin,
		TS:           time.Now().UTC().Format(time.RFC3339Nano),
		ParentPID:    parentPID,
		ParentStart:  parentStart,
	}
	b, err := json.Marshal(rec)
	if err != nil {
		g.event("session_taint_write_failed", map[string]any{"reason": "cannot encode shared session latch"})
		return
	}
	if err := writeFileAtomic(g.sessionFile, b, 0o600); err != nil {
		if _, statErr := os.Stat(g.sessionFile); statErr != nil {
			g.event("session_taint_write_failed", map[string]any{"reason": "cannot write shared session latch"})
		}
	}
}

// gcStaleSessionFiles removes session files whose recorded parent process is
// gone. This also handles a new client instance reusing an explicit session
// key; a restarted server inside one client keeps the live parent and its
// taint.
func (g *Guard) gcStaleSessionFiles() {
	matches, err := filepath.Glob(filepath.Join(g.stateDir, "session-*.taint"))
	if err != nil {
		return
	}
	for _, path := range matches {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() > sessionFileLimit {
			continue
		}
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var rec sessionTaintFile
		if json.Unmarshal(b, &rec) != nil || rec.Version != sessionFileVersion || rec.ParentPID <= 0 {
			continue
		}
		start, ok := processStartTime(rec.ParentPID)
		if rec.ParentStart == "" {
			// The key was weak when this latch was written; the best we can
			// do is keep it while the parent PID is alive.
			if processAlive(rec.ParentPID) {
				continue
			}
		} else if ok && start == rec.ParentStart {
			continue // same live parent process
		} else if !ok && processAlive(rec.ParentPID) {
			continue // ambiguous; keep rather than risk a live session
		}
		_ = os.Remove(path)
		_ = os.Remove(strings.TrimSuffix(path, ".taint") + ".cleared")
	}
}

func (g *Guard) readSessionClear() (sessionClearFile, bool) {
	info, err := os.Stat(g.sessionClear)
	if err != nil || !info.Mode().IsRegular() || info.Size() > sessionFileLimit {
		return sessionClearFile{}, false
	}
	b, err := os.ReadFile(g.sessionClear)
	if err != nil {
		return sessionClearFile{}, false
	}
	var rec sessionClearFile
	if json.Unmarshal(b, &rec) != nil || rec.Version != sessionFileVersion ||
		rec.KeyHash != g.sessionHash || !validRequestID(rec.RequestID) {
		return sessionClearFile{}, false
	}
	if _, err := time.Parse(time.RFC3339Nano, rec.TS); err != nil {
		return sessionClearFile{}, false
	}
	return rec, true
}

// pollSharedClear drops the local latch when the shared file is gone and a new
// human-approved clear marker is present. A missing file without a new marker
// leaves the local latch alone.
func (g *Guard) pollSharedClear() {
	if g.sessionFile == "" {
		return
	}
	if _, err := os.Stat(g.sessionFile); err == nil {
		return
	}
	rec, ok := g.readSessionClear()
	if !ok {
		return
	}
	g.sessionMu.Lock()
	if rec.RequestID == g.sessionLastClear {
		g.sessionMu.Unlock()
		return
	}
	g.sessionLastClear = rec.RequestID
	g.sessionMu.Unlock()

	if !g.taintedFlag.Load() {
		return
	}
	since := g.taintContext()
	markerTS, err := time.Parse(time.RFC3339Nano, rec.TS)
	if err != nil || since.IsZero() || markerTS.Before(since) {
		return
	}
	g.clearTaintLocal()
	g.event("clear_taint_adopted", map[string]any{"request_id": rec.RequestID})
}

func (g *Guard) taintContext() time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.taintSince
}

// clearTaint is only called from the human-approved clear-taint control path.
// It removes the shared session latch, writes a clear marker for the other
// Guards, and clears this Guard's local latch. It never clears a quarantine,
// a grant, or any other latch.
func (g *Guard) clearTaint(requestID string) error {
	var before os.FileInfo
	var beforeExists bool
	info, err := os.Stat(g.sessionFile)
	if err == nil {
		before, beforeExists = info, true
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("cannot inspect the shared session latch")
	}
	rec := sessionClearFile{
		Version:   sessionFileVersion,
		KeyHash:   g.sessionHash,
		RequestID: requestID,
		TS:        time.Now().UTC().Format(time.RFC3339Nano),
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("cannot encode the clear marker")
	}
	if err := writeFileAtomic(g.sessionClear, b, 0o600); err != nil {
		return fmt.Errorf("cannot write the clear marker")
	}
	if beforeExists {
		after, err := os.Stat(g.sessionFile)
		if err == nil {
			if !after.ModTime().Equal(before.ModTime()) || after.Size() != before.Size() {
				_ = os.Remove(g.sessionClear)
				return fmt.Errorf("the session was tainted again during the clear")
			}
			if err := os.Remove(g.sessionFile); err != nil && !os.IsNotExist(err) {
				_ = os.Remove(g.sessionClear)
				return fmt.Errorf("cannot remove the shared session latch")
			}
		} else if !os.IsNotExist(err) {
			_ = os.Remove(g.sessionClear)
			return fmt.Errorf("cannot inspect the shared session latch")
		}
	}
	g.sessionMu.Lock()
	g.sessionLastClear = requestID
	g.sessionMu.Unlock()
	g.clearTaintLocal()
	return nil
}

// clearTaintLocal drops only this process's latch. It never touches the shared
// file or marker; only the human-approved clearTaint path removes the shared
// latch.
func (g *Guard) clearTaintLocal() {
	g.mu.Lock()
	g.tainted = false
	g.taintOrigin = ""
	g.taintSince = time.Time{}
	g.taintedFlag.Store(false)
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

// loadPins returns an error when a pin file exists but cannot be trusted.
// Trust on first use applies only to genuine first sight, never to a file that
// is damaged or whose signature does not verify.
func (g *Guard) loadPins(reset bool) error {
	if reset {
		_ = os.Remove(g.pinsPath())
		_ = os.Remove(g.pinsSignaturePath())
		g.event("pins_reset", nil)
		return nil
	}
	b, err := os.ReadFile(g.pinsPath())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		g.event("pins_unreadable", nil)
		return fmt.Errorf("cannot read pin file: %w", err)
	}
	if g.verifyKey != nil {
		if err := verifyDetachedSignature(g.pinsPath(), b, g.verifyKey); err != nil {
			g.event("pins_signature_invalid", map[string]any{"reason": err.Error()})
			return fmt.Errorf("pin signature verification failed: %w", err)
		}
	}
	var pins map[string]string
	if json.Unmarshal(b, &pins) != nil || pins == nil {
		g.event("pins_unreadable", nil)
		return fmt.Errorf("pin file is not a JSON object")
	}
	// A null or malformed value unmarshals into an empty string without an
	// error and would brick that tool on the next tools/list. Refuse the whole
	// file instead: only a hex SHA-256 is a pin this build wrote.
	for name, h := range pins {
		if name == "" || len(h) != sha256.Size*2 {
			g.event("pins_unreadable", nil)
			return fmt.Errorf("pin file contains an empty name or a value that is not a SHA-256 hash")
		}
		if _, err := hex.DecodeString(h); err != nil {
			g.event("pins_unreadable", nil)
			return fmt.Errorf("pin file contains a value that is not a SHA-256 hash")
		}
	}
	g.pins = pins
	return nil
}

func (g *Guard) pinsSignaturePath() string { return g.pinsPath() + signatureSuffix }

func (g *Guard) savePins() {
	g.mu.Lock()
	b, _ := json.MarshalIndent(g.pins, "", "  ")
	signKey := g.signKey
	verifyKey := g.verifyKey
	g.mu.Unlock()

	path := g.pinsPath()
	sigPath := g.pinsSignaturePath()
	if signKey == nil {
		if verifyKey != nil {
			// Verification is enabled but this process has no private key.
			// Keep the pins in memory and never write an unsigned store that
			// the next start would have to reject.
			g.event("pins_not_persisted", map[string]any{"reason": "no private signing key"})
			return
		}
		if err := writeFileAtomic(path, b, 0o600); err != nil {
			g.event("pins_save_failed", map[string]any{"reason": "cannot write pin file"})
			return
		}
		_ = os.Remove(sigPath)
		return
	}

	sig := ed25519.Sign(signKey, b)
	if err := writeFileAtomic(path, b, 0o600); err != nil {
		g.event("pins_save_failed", map[string]any{"reason": "cannot write pin file"})
		return
	}
	if err := writeFileAtomic(sigPath, sig, 0o600); err != nil {
		// Do not leave an unsigned pin file behind under a signing key.
		_ = os.Remove(path)
		_ = os.Remove(sigPath)
		g.event("pins_save_failed", map[string]any{"reason": "cannot write pin signature"})
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

// activeSensitivePatterns is an immutable slice swapped atomically. Team
// policy refreshes can change it while request handlers are classifying paths.
var activeSensitivePatterns atomic.Value

func init() {
	activeSensitivePatterns.Store(append([]string(nil), defaultSensitivePaths...))
}

func setSensitivePatterns(patterns []string) {
	activeSensitivePatterns.Store(append([]string(nil), patterns...))
}

func currentSensitivePatterns() []string {
	if v := activeSensitivePatterns.Load(); v != nil {
		return v.([]string)
	}
	return defaultSensitivePaths
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
	{category: "agent instructions", parts: []string{".claude"}, subtree: true},
	{category: "agent instructions", parts: []string{".codex"}, subtree: true},
	{category: "agent instructions", parts: []string{".gemini"}, subtree: true},
	{category: "agent instructions", parts: []string{".continue"}, subtree: true},

	{category: "mcp and editor config", parts: []string{".mcp.json"}},
	{category: "mcp and editor config", parts: []string{"mcp.json"}},
	{category: "mcp and editor config", parts: []string{"claude_desktop_config.json"}},
	{category: "mcp and editor config", parts: []string{".vscode"}, subtree: true},
	{category: "mcp and editor config", parts: []string{".idea"}, subtree: true},

	{category: "ci and hooks", parts: []string{".github", "workflows"}, subtree: true},
	{category: "ci and hooks", parts: []string{".gitlab-ci.yml"}},
	{category: "ci and hooks", parts: []string{".git", "hooks"}, subtree: true},
	{category: "ci and hooks", parts: []string{".husky"}, subtree: true},

	{category: "git config", parts: []string{".gitconfig"}},
	{category: "git config", parts: []string{".git", "config"}},

	{category: "credentials", parts: []string{".ssh"}, subtree: true},
	{category: "credentials", parts: []string{".npmrc"}},
	{category: "credentials", parts: []string{".pypirc"}},
	{category: "credentials", parts: []string{".netrc"}},

	{category: "shell startup", parts: []string{".bashrc"}},
	{category: "shell startup", parts: []string{".zshrc"}},
	{category: "shell startup", parts: []string{".profile"}},
	{category: "shell startup", parts: []string{".bash_profile"}},
	{category: "shell startup", parts: []string{".bash_login"}},
	{category: "shell startup", parts: []string{".zshenv"}},
	{category: "shell startup", parts: []string{".zprofile"}},
	{category: "shell startup", parts: []string{".zlogin"}},
	{category: "shell startup", parts: []string{".config", "fish"}, subtree: true},
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

	{category: "desktop autostart", parts: []string{".config", "autostart"}, subtree: true},

	{category: "guard state", parts: []string{".sylenix-poc"}, subtree: true},
	{category: "guard state", parts: []string{".sylenix-keys"}, subtree: true},
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

// protectedCanonicalPathWithDirs adds Guard's resolved state/key directories
// to the compiled-in table. The active --state-dir can have any name, so it
// cannot be a static entry; resolving it also catches a symlinked directory.
func protectedCanonicalPathWithDirs(p string, extraDirs []string) bool {
	if protectedCanonicalPath(p) {
		return true
	}
	for _, dir := range extraDirs {
		if dir != "" && insideDir(dir, p) {
			return true
		}
	}
	return false
}

func protectedTargetPathWithDirs(p string, extraDirs []string) bool {
	if canonical, ok := canonicalPath(p); ok {
		return protectedCanonicalPathWithDirs(canonical, extraDirs)
	}
	// Even when a host would expand an environment variable or the path is
	// otherwise unresolvable, an obvious protected shape must not be missed.
	// The path itself is still refused by the normal canonicalisation rules.
	return protectedCanonicalPathWithDirs(filepath.Clean(strings.ReplaceAll(p, `\`, "/")), extraDirs)
}

// credentialProtectedCanonicalPath reports whether p matches a protected
// target in the credential or Guard-state category. Reads of these paths are
// blocked or dialog-approved after taint; other protected targets stay readable.
func credentialProtectedCanonicalPath(p string) bool {
	components := pathComponents(p)
	if len(components) == 0 {
		return false
	}
	fold := caseInsensitiveFS(filepath.Dir(p))
	for _, target := range protectedTargets {
		if target.category != "credentials" && target.category != "guard state" {
			continue
		}
		if target.matches(components, fold) {
			return true
		}
	}
	return false
}

func credentialProtectedCanonicalPathWithDirs(p string, extraDirs []string) bool {
	if credentialProtectedCanonicalPath(p) {
		return true
	}
	// The active --state-dir and key directory can have any name, so they
	// cannot be static table entries.
	for _, dir := range extraDirs {
		if dir != "" && insideDir(dir, p) {
			return true
		}
	}
	return false
}

func credentialProtectedTargetPathWithDirs(p string, extraDirs []string) bool {
	if canonical, ok := canonicalPath(p); ok {
		return credentialProtectedCanonicalPathWithDirs(canonical, extraDirs)
	}
	return credentialProtectedCanonicalPathWithDirs(filepath.Clean(strings.ReplaceAll(p, `\`, "/")), extraDirs)
}

// protectedCategory returns the first protectedTargets category for p, or an
// empty string when p is not a protected target. Guard's configured state/key
// directories are reported as "guard state" by protectedCategoryWithDirs.
func protectedCategory(p string) string {
	return protectedCategoryCanonical(canonicalOrClean(p))
}

func protectedCategoryWithDirs(p string, extraDirs []string) string {
	canonical := canonicalOrClean(p)
	for _, dir := range extraDirs {
		if dir != "" && insideDir(dir, canonical) {
			return "guard state"
		}
	}
	return protectedCategoryCanonical(canonical)
}

func protectedCategoryCanonical(p string) string {
	components := pathComponents(p)
	if len(components) == 0 {
		return ""
	}
	fold := caseInsensitiveFS(filepath.Dir(p))
	for _, target := range protectedTargets {
		if target.matches(components, fold) {
			return target.category
		}
	}
	return ""
}

func canonicalOrClean(p string) string {
	if resolved, ok := canonicalPath(p); ok {
		return resolved
	}
	return filepath.Clean(strings.ReplaceAll(p, `\`, "/"))
}

func (g *Guard) protectedCanonicalPath(p string) bool {
	return protectedCanonicalPathWithDirs(p, g.protectedDirs)
}

// isHardSensitivePath is the subset of protected paths that no human grant or
// scratch rule may cover: .git, .env, key/certificate names, known config
// names, and Guard's own state/key directories.
func isHardSensitivePath(p string, extraDirs []string) bool {
	if isSensitivePath(p) {
		return true
	}
	canonical := p
	if resolved, ok := canonicalPath(p); ok {
		canonical = resolved
	}
	for _, dir := range extraDirs {
		if dir != "" && insideDir(dir, canonical) {
			return true
		}
	}
	components := pathComponents(canonical)
	fold := caseInsensitiveFS(filepath.Dir(canonical))
	for _, c := range components {
		if componentEqual(c, ".sylenix-poc", fold) || componentEqual(c, ".sylenix-keys", fold) {
			return true
		}
	}
	return false
}

// protectedCall also checks relative names against the approved roots, so a
// symlink inside a scratch or grant directory cannot hide a protected target.
func (g *Guard) protectedCall(tool string, paths []string, scratch []scratchRule) bool {
	for _, p := range paths {
		if protectedTargetPathWithDirs(p, g.protectedDirs) {
			return true
		}
		if isExplicitlyRooted(p) {
			continue
		}
		for _, rule := range scratch {
			if rule.tool != "" && rule.tool != tool {
				continue
			}
			if canonical, ok := canonicalPath(rule.dir + string(os.PathSeparator) + p); ok && g.protectedCanonicalPath(canonical) {
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
			if canonical, ok := canonicalPath(gr.dir + string(os.PathSeparator) + p); ok && g.protectedCanonicalPath(canonical) {
				return true
			}
		}
	}
	return false
}

// hardSensitiveCall repeats protectedCall's relative-path resolution so a
// scratch or grant root cannot hide a hard-sensitive path from the pre-grant
// check.
func (g *Guard) hardSensitiveCall(tool string, paths []string, scratch []scratchRule) bool {
	for _, p := range paths {
		if isHardSensitivePath(p, g.protectedDirs) {
			return true
		}
		if isExplicitlyRooted(p) {
			continue
		}
		for _, rule := range scratch {
			if rule.tool != "" && rule.tool != tool {
				continue
			}
			if canonical, ok := canonicalPath(rule.dir + string(os.PathSeparator) + p); ok && isHardSensitivePath(canonical, g.protectedDirs) {
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
			if canonical, ok := canonicalPath(gr.dir + string(os.PathSeparator) + p); ok && isHardSensitivePath(canonical, g.protectedDirs) {
				return true
			}
		}
	}
	return false
}

type callTarget struct {
	value    string
	category string
}

// callScan is the classification of one tools/call's arguments. Only values
// under a known path key are paths. ambiguous means the call contains a
// non-content value that could be a path or destination but is not under a
// known path key; such a call must never take a grant or scratch shortcut.
type callScan struct {
	paths       []string
	targets     []callTarget
	egress      bool
	egressHosts []string
	sensitive   bool
	protected   bool
	credential  bool
	ambiguous   bool
}

// scanArgs classifies every string inside a call's arguments. Paths are drawn
// only from known path keys: a filename-shaped value under an unknown key is
// not a path we can safely compare, so it disqualifies the fast paths instead.
// extraPathKeys are the per-tool path_keys from the policy file. extraDirs are
// Guard's resolved state/key directories, which are protected like the table.
func scanArgs(args map[string]any, extraPathKeys map[string]bool, extraDirs []string) callScan {
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
				s.targets = append(s.targets, callTarget{
					value: t, category: protectedCategoryWithDirs(t, extraDirs)})
				if h := hostFromArgument(t); h != "" {
					s.egressHosts = append(s.egressHosts, h)
				}
			case keyMatches(pathKeys, kl) ||
				(extraPathKeys != nil && (extraPathKeys[kl] || extraPathKeys[keyNormalizer.Replace(kl)])):
				// Keep the raw value: cleaning before symlink resolution can
				// turn "link/../x" into a path the server never opens.
				s.paths = append(s.paths, t)
				resolved, resolvedOK := canonicalPath(t)
				s.targets = append(s.targets, callTarget{
					value: t, category: protectedCategoryWithDirs(t, extraDirs)})
				protected := resolvedOK && protectedCanonicalPathWithDirs(resolved, extraDirs)
				if !protected {
					protected = protectedTargetPathWithDirs(t, extraDirs)
				}
				if protected {
					// Protected targets are dialog-approvable unless they are
					// hard-sensitive: .git, .env, key files, or Guard state.
					s.protected = true
					if credentialProtectedTargetPathWithDirs(t, extraDirs) ||
						(resolvedOK && credentialProtectedCanonicalPathWithDirs(resolved, extraDirs)) {
						s.credential = true
					}
					if isHardSensitivePath(t, extraDirs) ||
						(resolvedOK && isHardSensitivePath(resolved, extraDirs)) {
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
				s.targets = append(s.targets, callTarget{
					value: t, category: protectedCategoryWithDirs(t, extraDirs)})
				if h := hostFromArgument(t); h != "" {
					s.egressHosts = append(s.egressHosts, h)
				}
			case protectedTargetPathWithDirs(t, extraDirs):
				s.protected = true
				s.targets = append(s.targets, callTarget{
					value: t, category: protectedCategoryWithDirs(t, extraDirs)})
				if credentialProtectedTargetPathWithDirs(t, extraDirs) {
					s.credential = true
				}
				if isHardSensitivePath(t, extraDirs) {
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
	for _, pattern := range currentSensitivePatterns() {
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
	real, err := evalSymlinks(abs)
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
			real, err := evalSymlinks(prefix)
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

// evalSymlinks resolves symlinks and Windows junctions. On Windows, a
// directory junction is not always reported as a symlink by os.Lstat, so
// filepath.EvalSymlinks can return the junction path unchanged. os.Readlink
// still returns the junction target, so resolve that explicitly.
func evalSymlinks(p string) (string, error) {
	for i := 0; i < 255; i++ {
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			return "", err
		}
		if runtime.GOOS != "windows" {
			return real, nil
		}
		target, err := os.Readlink(p)
		if err != nil {
			return real, nil
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(p), target)
		}
		p = target
	}
	return "", fmt.Errorf("too many links")
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

// scopeDir narrows a non-protected grant to the deepest directory that holds
// every path of the approved call. No paths, an unresolvable path, or a
// filesystem root all mean the grant covers the whole tool (which is what the
// button says). Protected grants keep this directory for relative-path
// resolution, but their authority is their exact files list.
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

// canonicalPathList returns the canonical form of each path, de-duplicated.
// Paths that cannot be canonicalized are omitted, so the resulting grant covers
// less than the call, never more.
func canonicalPathList(paths []string) []string {
	out := make([]string, 0, len(paths))
	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		canonical, ok := canonicalPath(p)
		if !ok {
			continue
		}
		if !seen[canonical] {
			out = append(out, canonical)
			seen[canonical] = true
		}
	}
	return out
}

// allPathsInGrantFiles reports whether every call path is one of the exact
// canonical files in the grant. Empty path or file sets never match.
func allPathsInGrantFiles(paths, files []string) bool {
	if len(paths) == 0 || len(files) == 0 {
		return false
	}
	approved := make(map[string]bool, len(files))
	for _, file := range files {
		approved[file] = true
	}
	for _, p := range paths {
		canonical, ok := canonicalPath(p)
		if !ok || !approved[canonical] {
			return false
		}
	}
	return true
}

// addGrant records one time-bounded approval from the dialog. A protected
// approval also carries the exact canonical files the human approved.
func (g *Guard) addGrant(tool, dir string, files []string, ttl time.Duration, protected bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.grants = append(g.grants, grant{
		tool: tool, dir: dir, files: append([]string(nil), files...),
		expires: time.Now().Add(ttl), human: true, protected: protected,
	})
}

// grantAllows reports whether a live grant covers this call. Expired grants are
// dropped along the way. A protected grant matches only the exact canonical
// files it recorded; a non-protected grant keeps the directory scope. A
// protected call never uses a non-protected grant.
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
		if gr.protected {
			if gr.human && allPathsInGrantFiles(paths, gr.files) {
				allowed = true
			}
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

// ---------------------------------------------------------------- approval dialog

// dialogTargets lists every path and destination value in full, one per line.
// Each value gets its own 300-character budget and is never dropped. A
// protected value is prefixed with the category that made it protected.
func dialogTargets(scan callScan) string {
	if len(scan.targets) == 0 {
		return "Targets: none"
	}
	var b strings.Builder
	b.WriteString("Targets:")
	for _, target := range scan.targets {
		b.WriteString("\n")
		if target.category != "" {
			fmt.Fprintf(&b, "[%s] ", target.category)
		}
		b.WriteString(cleanForDialog(target.value, 300))
	}
	return b.String()
}

// dialogOtherArguments shows non-target, non-content arguments as short
// key/value lines. Each value has its own budget.
func dialogOtherArguments(args map[string]any, scan callScan) string {
	targets := make(map[string]bool, len(scan.targets))
	for _, target := range scan.targets {
		targets[target.value] = true
	}
	var lines []string
	for _, key := range argKeys(args) {
		kl := strings.ToLower(key)
		if keyMatches(contentKeys, kl) {
			continue
		}
		if keyMatches(pathKeys, kl) || keyMatches(urlKeys, kl) || keyMatches(destinationKeys, kl) {
			continue
		}
		value := args[key]
		if dialogTargetLikeValue(value, targets) {
			continue
		}
		raw, err := json.Marshal(value)
		if err != nil {
			continue
		}
		lines = append(lines, cleanForDialog(key, 80)+": "+cleanForDialog(string(raw), 120))
	}
	if len(lines) == 0 {
		return "Other arguments: none"
	}
	return "Other arguments:\n" + strings.Join(lines, "\n")
}

func dialogTargetLikeValue(v any, targets map[string]bool) bool {
	switch t := v.(type) {
	case string:
		return targets[t]
	case []any:
		if len(t) == 0 {
			return false
		}
		for _, x := range t {
			if !dialogTargetLikeValue(x, targets) {
				return false
			}
		}
		return true
	case map[string]any:
		if len(t) == 0 {
			return false
		}
		for _, x := range t {
			if !dialogTargetLikeValue(x, targets) {
				return false
			}
		}
		return true
	}
	return false
}

// dialogContent summarizes each content-key value by byte count and its first
// 120 characters, so a padded body cannot hide another field or a payload.
func dialogContent(args map[string]any) string {
	var lines []string
	for _, key := range argKeys(args) {
		kl := strings.ToLower(key)
		if !keyMatches(contentKeys, kl) {
			continue
		}
		value := args[key]
		var text string
		switch v := value.(type) {
		case string:
			text = v
		default:
			raw, err := json.Marshal(v)
			if err != nil {
				continue
			}
			text = string(raw)
		}
		lines = append(lines, fmt.Sprintf("%s: %d bytes, starts: %s",
			cleanForDialog(key, 80), len(text), cleanForDialog(text, 120)))
	}
	if len(lines) == 0 {
		return "Content: none"
	}
	return "Content:\n" + strings.Join(lines, "\n")
}

// askHuman shows one OS dialog with three outcomes: deny, allow this one call,
// or allow this tool for 15m. A protected call's grant covers the exact files
// it touched; any other grant covers the call's directory when it has one.
// The message keeps classified targets in full and summarizes content, so one
// padded field cannot hide the field a human needs to see.
func askHuman(tool string, args map[string]any, scan callScan, origin, scopeNote string) (decision, note string) {
	originText := cleanForDialog(origin, 80)
	if originText == "" {
		originText = "unknown"
	}
	msg := fmt.Sprintf("Tool: %s\n%s\n%s\n%s\nThis session read untrusted content (%s).\nDeny blocks the call. Allow Once permits this one call. Allow Tool for 15m permits %s",
		cleanForDialog(tool, 80), dialogTargets(scan), dialogOtherArguments(args, scan),
		dialogContent(args), originText, scopeNote)
	switch runtime.GOOS {
	case "darwin":
		script := fmt.Sprintf(`display dialog "%s" with title "Sylenix Guard" buttons {"Deny","Allow Once","Allow Tool for 15m"} default button "Deny" with icon caution giving up after 60`, escapeAppleScript(msg))
		out, err := exec.Command("osascript", "-e", script).Output()
		if err != nil {
			return "deny", "dialog failed: " + err.Error()
		}
		return appleScriptChoice(string(out)), "osascript"
	case "linux":
		// A list, because zenity --question can only offer two buttons. The
		// message is deliberately long, so give it room.
		out, err := exec.Command("zenity", "--list", "--no-markup", "--hide-header",
			"--title=Sylenix Guard", "--width=520", "--height=600", "--timeout=60",
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
func grantScopeNote(tool, scope string, protected bool, fileCount int) string {
	if protected {
		switch {
		case fileCount == 1:
			return "this exact file for 15 minutes (this session only)"
		case fileCount > 1:
			return fmt.Sprintf("these %d exact files for 15 minutes (this session only)", fileCount)
		default:
			return "this exact protected target for 15 minutes (this session only)"
		}
	}
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
// instead of guessing which value the server will act on. Case variants are
// handled by hasFoldCollidingKeys.
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

// hasFoldCollidingKeys reports whether any JSON object inside b contains two
// keys that are equal under Unicode simple folding. encoding/json matches
// struct fields that way, while MCP servers match object keys exactly, so a
// case variant gives the same frame two meanings. Every host frame is checked
// at every depth, next to hasDuplicateKeys.
func hasFoldCollidingKeys(b []byte) bool {
	type level struct {
		isObj     bool
		expectKey bool
		keys      map[string]string
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
				stack = append(stack, level{isObj: true, expectKey: true, keys: map[string]string{}})
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
				folded := simpleFoldKey(key)
				if seen, ok := stack[n-1].keys[folded]; ok {
					if strings.EqualFold(seen, key) {
						return true
					}
					// A fold-index collision that EqualFold does not confirm is
					// still a frame we cannot classify safely.
					return true
				}
				stack[n-1].keys[folded] = key
				stack[n-1].expectKey = false
			} else {
				stack[n-1].expectKey = true
			}
		}
	}
}

// simpleFoldKey maps every rune to the smallest rune in its Unicode
// simple-fold orbit. That is the canonical form strings.EqualFold compares, so
// two keys collide here exactly when EqualFold reports them equal.
func simpleFoldKey(s string) string {
	var b strings.Builder
	for _, r := range s {
		min := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < min {
				min = f
			}
		}
		b.WriteRune(min)
	}
	return b.String()
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

// failOne removes one pending request and returns an error frame for it. It is
// used by the HTTP transport when an upstream failure means no response will
// ever arrive.
func (g *Guard) failOne(id json.RawMessage, code int, msg, rule string) []byte {
	if len(id) == 0 {
		return nil
	}
	g.take(id)
	return errorFrame(id, code, msg, rule)
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
// values, only their key names. The shipped event is built from an allowlist of
// fields, so argument values, content, URLs and free-form notes cannot escape.
func (g *Guard) event(kind string, fields map[string]any) {
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	rec := map[string]any{"ts": ts, "server": g.name, "event": kind}
	for k, v := range fields {
		rec[k] = v
	}
	b, _ := json.Marshal(rec)
	g.logMu.Lock()
	_, _ = g.log.Write(append(b, '\n'))
	g.logMu.Unlock()

	if g.audit == nil {
		return
	}
	ev := auditevent.Event{
		Timestamp:   ts,
		DeveloperID: g.auditID,
		Server:      g.name,
		Tool:        auditTool(fields),
		Decision:    auditDecision(kind, fields),
		ReasonCode:  auditReason(kind, fields),
		TaintState:  "clean",
	}
	if g.taintedFlag.Load() {
		ev.TaintState = "tainted"
	}
	if err := g.audit.Enqueue(ev); err != nil {
		alert("audit event not buffered: %v", err)
	}
}

func auditTool(fields map[string]any) string {
	tool, _ := fields["tool"].(string)
	return auditText(tool, 256)
}

func auditDecision(kind string, fields map[string]any) string {
	lower := strings.ToLower(kind)
	switch lower {
	case "allow":
		return "allow"
	case "block", "tool_quarantined":
		return "block"
	case "approval":
		if granted, _ := fields["granted"].(bool); granted {
			return "allow"
		}
		if decision, _ := fields["decision"].(string); decision == "grant" || decision == "once" {
			return "allow"
		}
		return "deny"
	case "taint_latched":
		return "taint"
	}
	if strings.HasPrefix(lower, "clear_taint") {
		return "clear_taint"
	}
	return "info"
}

func auditReason(kind string, fields map[string]any) string {
	lower := strings.ToLower(kind)
	switch lower {
	case "block", "allow":
		if rule, _ := fields["rule"].(string); rule != "" {
			return auditText(rule, 128)
		}
		if lower == "allow" {
			return "ALLOW"
		}
		return "BLOCK"
	case "tool_quarantined":
		return "MANIFEST_QUARANTINE"
	case "approval":
		if auditDecision(kind, fields) == "allow" {
			return "APPROVAL_GRANTED"
		}
		return "APPROVAL_DENIED"
	case "taint_latched":
		if reason, _ := fields["reason"].(string); reason != "" {
			return auditText(reason, 128)
		}
		return "TAINT"
	default:
		reason := strings.ToUpper(kind)
		if reason == "" {
			reason = "EVENT"
		}
		return auditText(reason, 128)
	}
}

func auditText(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if r > 32 && r < 127 && r != '"' && r != '\\' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	out := b.String()
	if len(out) > max {
		out = out[:max]
	}
	return out
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
			c.g.pollSharedClear()
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
	tainted, origin := c.g.taintState()
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
		if err := c.g.clearTaint(req.RequestID); err != nil {
			c.g.event("CLEAR_TAINT_FAILED", map[string]any{
				"request_id": req.RequestID,
				"reason":     "cannot clear shared session state",
			})
			_ = c.writeResult(clearResult{
				Version:   controlVersion,
				RequestID: req.RequestID,
				Status:    "rejected",
				Who:       who,
				At:        at,
				Note:      "cannot clear shared session state",
			})
			return
		}
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
	HasName         bool
	Name            string
	HasStateDir     bool
	StateDir        string
	HasPolicy       bool
	Policy          string
	HasPolicyPubKey bool
	PolicyPubKey    string
	HasReadonly     bool
	Readonly        string
	HasTrust        bool
	Trust           string
	HasApprove      bool
	Approve         string
	HasScratch      bool
	Scratch         []scratchRule
	NoSpotlight     bool
	ResetPins       bool
	HasGrant        bool
	Grants          []string
	HasSession      bool
	Session         string
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
	SessionSet   bool
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
	wrappedCount := 0
	var missingSession []string
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
			if server.Wrapped {
				wrappedCount++
				if !server.SessionSet {
					missingSession = append(missingSession, name)
				}
			}
			serverFindings := d.inspectServer(&server, &view, explicit)
			cfg.Servers = append(cfg.Servers, view)
			findings = append(findings, serverFindings...)
		}
	}
	if wrappedCount >= 2 && len(missingSession) > 0 {
		sort.Strings(missingSession)
		findings = append(findings, newDoctorFinding("SHARED_TAINT_OFF", "risk", target.client, target.path, "",
			fmt.Sprintf("%d wrapped servers do not share a session key (missing %s on %s)",
				wrappedCount, sessionEnvKey, strings.Join(missingSession, ", ")),
			"re-run `sylenix-guard install` (or add SYLENIX_SESSION to each wrapper)"))
	}
	return cfg, findings
}

func entrySessionSet(entry *configObject) bool {
	value, ok := entry.get("env")
	if !ok {
		return false
	}
	env, ok := value.(*configObject)
	if !ok {
		return false
	}
	value, ok = env.get(sessionEnvKey)
	if !ok {
		return false
	}
	text, ok := value.(string)
	return ok && strings.TrimSpace(text) != ""
}

func inspectDoctorServer(entry *configObject, name, client, configPath string) (doctorServer, string, string) {
	s := doctorServer{Name: name, Client: client, ConfigPath: configPath, SessionSet: entrySessionSet(entry)}
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
		s.SessionSet = s.SessionSet || (flags.HasSession && strings.TrimSpace(flags.Session) != "")
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
		add("REMOTE_NOT_COVERED", "risk", "remote MCP transport is not wrapped by install",
			"configure `sylenix-guard proxy --upstream <url>` manually, or use a local stdio server")
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
		// Without a configured public key nothing can be verified. With one,
		// verify the exact bytes on disk; an unsigned or tampered file is a
		// finding, never assumed safe.
		var pub ed25519.PublicKey
		if s.Flags.HasPolicyPubKey {
			pub, _ = loadPublicKeyFile(s.Flags.PolicyPubKey)
		}
		policyVerified := false
		if pub != nil && pol.path != "" {
			if data, err := os.ReadFile(pol.path); err == nil && verifyDetachedSignature(pol.path, data, pub) == nil {
				policyVerified = true
			}
		}
		pinsVerified := false
		if pub != nil && pinsExists && pinsValid {
			path := d.pinsPath(*s)
			if data, err := os.ReadFile(path); err == nil && verifyDetachedSignature(path, data, pub) == nil {
				pinsVerified = true
			}
		}
		if pol.path != "" && !policyVerified {
			add("UNSIGNED_POLICY", "risk",
				fmt.Sprintf("policy %q has no valid signature for the configured public key", cleanForDialog(pol.path, 160)),
				"run `sylenix-guard policy sign --policy <file> --key <private-key>`; add --policy-pubkey to the wrapper")
		}
		if pinsExists && pinsValid && !pinsVerified {
			add("UNSIGNED_PINS", "risk",
				fmt.Sprintf("pin file %q has no valid signature for the configured public key", cleanForDialog(d.pinsPath(*s), 160)),
				"run the guard with --policy-key so it signs new pins, or sign the file with `sylenix-guard pins sign`")
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
		"name": true, "state-dir": true, "policy": true, "policy-pubkey": true, "policy-key": true,
		"readonly": true, "trust": true, "approve": true, "allow-write-under": true, "grant": true,
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
		case "session":
			v, detail := value()
			if detail != "" {
				return f, detail
			}
			if v == "" || strings.TrimSpace(v) != v || hasUnsafePolicyChars(v) {
				return f, "session is empty or contains surrounding spaces/control characters"
			}
			f.HasSession, f.Session = true, v
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
		case "policy-pubkey":
			v, detail := value()
			if detail != "" {
				return f, detail
			}
			if v == "" || strings.TrimSpace(v) != v || hasUnsafePolicyChars(v) {
				return f, "policy-pubkey is empty or contains surrounding spaces/control characters"
			}
			f.HasPolicyPubKey, f.PolicyPubKey = true, v
		case "policy-key":
			v, detail := value()
			if detail != "" {
				return f, detail
			}
			if v == "" || strings.TrimSpace(v) != v || hasUnsafePolicyChars(v) {
				return f, "policy-key is empty or contains surrounding spaces/control characters"
			}
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
	aa, err1 := evalSymlinks(a)
	bb, err2 := evalSymlinks(b)
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
				wrapped, report := wrapConfigEntry(entry, guardPath, wrapperFlags, target.client)
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

func wrapConfigEntry(entry *configObject, guardPath string, wrapperFlags []string, sessionName string) (bool, string) {
	if strings.TrimSpace(sessionName) == "" {
		return false, "client name is empty"
	}
	if metaValue, ok := entry.get(guardMetaKey); ok {
		meta, ok := metaValue.(*configObject)
		if !ok {
			return false, "already wrapped"
		}
		changed, report := ensureSessionEnv(entry, meta, sessionName)
		if report != "" {
			return false, report
		}
		if changed {
			return true, ""
		}
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
	meta := newConfigObject()
	meta.set("version", guardMetaVersion)
	meta.set("hadArgs", hadArgs)
	meta.set("hadEnv", hadEnv)
	if _, report := ensureSessionEnv(entry, meta, sessionName); report != "" {
		return false, report
	}
	entry.set("command", guardPath)
	entry.set("args", wrapperArgs)
	entry.set(guardMetaKey, meta)
	return true, ""
}

// ensureSessionEnv gives every wrapped server in one client config the same
// SYLENIX_SESSION value. It records the original value so uninstall can restore
// it exactly.
func ensureSessionEnv(entry, meta *configObject, sessionName string) (bool, string) {
	value, hasEnv := entry.get("env")
	var env *configObject
	if hasEnv {
		var ok bool
		env, ok = value.(*configObject)
		if !ok {
			return false, "env is not an object"
		}
		for _, key := range env.keys {
			if _, ok := env.values[key].(string); !ok {
				return false, "env contains a non-string value"
			}
		}
	} else {
		env = newConfigObject()
	}
	current, hasSession := env.get(sessionEnvKey)
	currentText := ""
	if hasSession {
		var ok bool
		currentText, ok = current.(string)
		if !ok {
			return false, "env contains a non-string value"
		}
	}
	if hasSession && currentText == sessionName {
		return false, ""
	}
	meta.set("sessionInstalled", true)
	meta.set("sessionHad", hasSession)
	if hasSession {
		meta.set("sessionValue", currentText)
	}
	env.set(sessionEnvKey, sessionName)
	if !hasEnv {
		entry.set("env", env)
	}
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
	sessionInstalled := false
	sessionHad := false
	sessionValue := ""
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
		if value, ok := meta.get("sessionInstalled"); ok {
			if sessionInstalled, ok = value.(bool); !ok {
				return false, "Guard metadata sessionInstalled is invalid"
			}
		}
		if sessionInstalled {
			value, ok := meta.get("sessionHad")
			if !ok {
				return false, "Guard metadata sessionHad is missing"
			}
			if sessionHad, ok = value.(bool); !ok {
				return false, "Guard metadata sessionHad is invalid"
			}
			if sessionHad {
				if value, ok := meta.get("sessionValue"); ok {
					if sessionValue, ok = value.(string); !ok {
						return false, "Guard metadata sessionValue is invalid"
					}
				}
			}
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
	if hasMeta && sessionInstalled {
		if value, ok := entry.get("env"); ok {
			env, ok := value.(*configObject)
			if !ok {
				return false, "cannot restore: env is not an object"
			}
			if sessionHad {
				env.set(sessionEnvKey, sessionValue)
			} else {
				env.del(sessionEnvKey)
			}
		} else if hadEnv {
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

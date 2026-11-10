// SPDX-License-Identifier: Apache-2.0

// Package policyserver implements the minimal paid-tier policy service.
//
// It stores one signed policy per team and exposes it over one HTTPS-only
// endpoint. Authentication is a per-team bearer token; only SHA-256 hashes of
// those tokens are ever read from disk, and no request body or authorization
// header is logged.
package policyserver

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"sylenix-guard-poc/teams/auditevent"
)

const (
	// APIPath is the policy endpoint. GET pulls the caller's team policy; PUT
	// publishes a signed replacement for the caller's team.
	APIPath = "/v1/policy"
	// EventsAPI accepts batches of sanitized audit events (POST) and exposes a
	// JSON export of the caller team's events (GET).
	EventsAPI = "/v1/events"
	// SyslogAPI exposes the caller team's events as RFC 5424 lines.
	SyslogAPI = "/v1/events/syslog"

	maxEnvelope  = 4 << 20
	maxEventBody = 2 << 20
	maxEvents    = 1000
	hashHexLen   = sha256.Size * 2
)

// Config is the complete server configuration.
type Config struct {
	DataDir   string
	PublicKey ed25519.PublicKey
	// Tokens maps a team name to the lower-case hex SHA-256 of its bearer
	// token. Plaintext tokens are never accepted here.
	Tokens map[string]string
	Logger *log.Logger
}

// Server serves signed per-team policies over HTTPS.
type Server struct {
	dataDir string
	pub     ed25519.PublicKey
	tokens  map[string][sha256.Size]byte
	logger  *log.Logger

	eventsMu sync.Mutex
}

// New validates the configuration and returns a server. It does not create the
// data directory until the first policy is stored.
func New(cfg Config) (*Server, error) {
	if strings.TrimSpace(cfg.DataDir) == "" {
		return nil, errors.New("policy data directory is required")
	}
	if len(cfg.PublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("team public key must be a 32-byte Ed25519 key")
	}
	if len(cfg.Tokens) == 0 {
		return nil, errors.New("at least one team token hash is required")
	}
	tokens := make(map[string][sha256.Size]byte, len(cfg.Tokens))
	for team, hashHex := range cfg.Tokens {
		if err := ValidateTeamName(team); err != nil {
			return nil, err
		}
		raw, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(hashHex)))
		if err != nil || len(raw) != sha256.Size {
			return nil, fmt.Errorf("team %q: token hash must be 64 hexadecimal characters", team)
		}
		var sum [sha256.Size]byte
		copy(sum[:], raw)
		tokens[team] = sum
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	return &Server{
		dataDir: filepath.Clean(cfg.DataDir),
		pub:     append(ed25519.PublicKey(nil), cfg.PublicKey...),
		tokens:  tokens,
		logger:  logger,
	}, nil
}

// ValidateTeamName rejects names that could escape the data directory or
// confuse the token file parser.
func ValidateTeamName(team string) error {
	if team == "" || strings.TrimSpace(team) != team || len(team) > 128 {
		return errors.New("team name is empty or has surrounding spaces")
	}
	for _, r := range team {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			continue
		}
		return fmt.Errorf("team %q contains unsupported characters", team)
	}
	if team == "." || team == ".." {
		return fmt.Errorf("team %q is not a valid name", team)
	}
	return nil
}

// HashToken returns the lower-case hex SHA-256 of a bearer token. Tokens must
// be high-entropy; this is a lookup hash, not a password KDF.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// LoadTokenFile reads one "team:sha256hex" entry per line. Blank lines and
// lines beginning with # are ignored. Duplicate team names are an error.
func LoadTokenFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tokens := map[string]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		team, hashHex, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("%s:%d: want team:sha256hex", path, lineNo)
		}
		if err := ValidateTeamName(team); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
		if _, seen := tokens[team]; seen {
			return nil, fmt.Errorf("%s:%d: duplicate team %q", path, lineNo, team)
		}
		hashHex = strings.ToLower(strings.TrimSpace(hashHex))
		if len(hashHex) != hashHexLen {
			return nil, fmt.Errorf("%s:%d: token hash must be 64 hexadecimal characters", path, lineNo)
		}
		if _, err := hex.DecodeString(hashHex); err != nil {
			return nil, fmt.Errorf("%s:%d: token hash must be 64 hexadecimal characters", path, lineNo)
		}
		tokens[team] = hashHex
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return tokens, nil
}

// Envelope is the HTTP representation of the existing signed-policy format:
// the exact policy bytes plus the detached Ed25519 signature over those bytes.
// encoding/json represents both fields as base64 strings.
type Envelope struct {
	Policy    []byte `json:"policy"`
	Signature []byte `json:"signature"`
}

func EncodeEnvelope(policy, signature []byte) ([]byte, error) {
	return json.Marshal(Envelope{Policy: policy, Signature: signature})
}

func DecodeEnvelope(data []byte) (policy, signature []byte, err error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var env Envelope
	if err := dec.Decode(&env); err != nil {
		return nil, nil, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, nil, errors.New("trailing data after policy envelope")
	}
	if len(env.Policy) == 0 {
		return nil, nil, errors.New("policy is empty")
	}
	if len(env.Signature) != ed25519.SignatureSize {
		return nil, nil, fmt.Errorf("signature must be %d bytes", ed25519.SignatureSize)
	}
	return env.Policy, env.Signature, nil
}

// VerifySignature checks the detached signature over the exact policy bytes.
func VerifySignature(pub ed25519.PublicKey, policy, signature []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid team public key")
	}
	if len(signature) != ed25519.SignatureSize {
		return errors.New("invalid signature length")
	}
	if !ed25519.Verify(pub, policy, signature) {
		return errors.New("signature does not verify (policy changed or wrong key)")
	}
	return nil
}

// PolicyPath is the on-disk location of one team's policy. The signature is at
// PolicyPath+".sig", matching the Guard's existing detached-signature format.
func (s *Server) PolicyPath(team string) string {
	return filepath.Join(s.dataDir, "policy-"+team+".yaml")
}

// ReadStored returns the stored policy and signature after re-verifying them.
func (s *Server) ReadStored(team string) ([]byte, []byte, error) {
	policy, err := os.ReadFile(s.PolicyPath(team))
	if err != nil {
		return nil, nil, err
	}
	sig, err := os.ReadFile(s.PolicyPath(team) + ".sig")
	if err != nil {
		return nil, nil, err
	}
	if err := VerifySignature(s.pub, policy, sig); err != nil {
		return nil, nil, err
	}
	return policy, sig, nil
}

// WriteStored verifies a candidate policy before replacing the stored one. The
// signature is written first: a crash between the two renames leaves a pair
// that fails verification rather than one that is silently accepted.
func (s *Server) WriteStored(team string, policy, signature []byte) error {
	if err := ValidateTeamName(team); err != nil {
		return err
	}
	if err := VerifySignature(s.pub, policy, signature); err != nil {
		return err
	}
	if err := os.MkdirAll(s.dataDir, 0o700); err != nil {
		return err
	}
	path := s.PolicyPath(team)
	if err := writeAtomic(path+".sig", signature); err != nil {
		return err
	}
	return writeAtomic(path, policy)
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// EventLogPath is the append-only JSONL file for one team's events.
func (s *Server) EventLogPath(team string) string {
	return filepath.Join(s.dataDir, "events-"+team+".jsonl")
}

// AppendEvents validates and stores one batch. The caller is authenticated as
// the team before this is called.
func (s *Server) AppendEvents(team string, events []auditevent.Event) error {
	if err := ValidateTeamName(team); err != nil {
		return err
	}
	if len(events) > maxEvents {
		return fmt.Errorf("batch has too many events")
	}
	var buf bytes.Buffer
	for _, ev := range events {
		line, err := auditevent.EncodeLine(ev)
		if err != nil {
			return err
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	s.eventsMu.Lock()
	defer s.eventsMu.Unlock()
	if err := os.MkdirAll(s.dataDir, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(s.EventLogPath(team), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// ReadEvents returns the stored events for one team. A malformed stored line is
// an error, never a silently skipped event.
func (s *Server) ReadEvents(team string) ([]auditevent.Event, error) {
	if err := ValidateTeamName(team); err != nil {
		return nil, err
	}
	s.eventsMu.Lock()
	defer s.eventsMu.Unlock()
	f, err := os.Open(s.EventLogPath(team))
	if os.IsNotExist(err) {
		return []auditevent.Event{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), maxEventBody)
	events := []auditevent.Event{}
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		ev, err := auditevent.DecodeLine(line)
		if err != nil {
			return nil, fmt.Errorf("event line %d: %w", lineNo, err)
		}
		events = append(events, ev)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

func (s *Server) handleEventsPost(w http.ResponseWriter, r *http.Request, team string) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxEventBody))
	if err != nil {
		s.fail(w, http.StatusRequestEntityTooLarge, "EVENTS_TOO_LARGE", "event batch is too large")
		return
	}
	events, err := auditevent.DecodeBatch(body)
	if err != nil {
		s.logger.Printf("event batch rejected team=%s reason=invalid_schema", team)
		s.fail(w, http.StatusBadRequest, "BAD_EVENT", "event batch does not match the sanitized schema")
		return
	}
	if len(events) > maxEvents {
		s.fail(w, http.StatusBadRequest, "TOO_MANY_EVENTS", "event batch is too large")
		return
	}
	if err := s.AppendEvents(team, events); err != nil {
		s.logger.Printf("event batch rejected team=%s reason=storage", team)
		s.fail(w, http.StatusInternalServerError, "EVENT_STORE_FAILED", "cannot store event batch")
		return
	}
	s.logger.Printf("events accepted team=%s count=%d", team, len(events))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]int{"accepted": len(events)})
}

func (s *Server) handleEventsGet(w http.ResponseWriter, team string) {
	events, err := s.ReadEvents(team)
	if err != nil {
		s.logger.Printf("event export rejected team=%s reason=storage", team)
		s.fail(w, http.StatusInternalServerError, "EVENT_READ_FAILED", "cannot read stored events")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(events)
}

func (s *Server) handleEventsSyslog(w http.ResponseWriter, team string) {
	events, err := s.ReadEvents(team)
	if err != nil {
		s.logger.Printf("syslog export rejected team=%s reason=storage", team)
		s.fail(w, http.StatusInternalServerError, "EVENT_READ_FAILED", "cannot read stored events")
		return
	}
	var buf bytes.Buffer
	for _, ev := range events {
		line, err := ev.SyslogLine()
		if err != nil {
			s.fail(w, http.StatusInternalServerError, "EVENT_FORMAT_FAILED", "cannot format stored event")
			return
		}
		buf.WriteString(line)
		buf.WriteByte('\n')
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// ServeHTTP exposes the policy endpoint plus the audit event collector.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case APIPath:
		team, ok := s.requireTeam(w, r)
		if !ok {
			return
		}
		switch r.Method {
		case http.MethodGet:
			s.handleGet(w, team)
		case http.MethodPut:
			s.handlePut(w, r, team)
		default:
			w.Header().Set("Allow", "GET, PUT")
			s.fail(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use GET or PUT")
		}
	case EventsAPI:
		team, ok := s.requireTeam(w, r)
		if !ok {
			return
		}
		switch r.Method {
		case http.MethodPost:
			s.handleEventsPost(w, r, team)
		case http.MethodGet:
			s.handleEventsGet(w, team)
		default:
			w.Header().Set("Allow", "GET, POST")
			s.fail(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use GET or POST")
		}
	case SyslogAPI:
		team, ok := s.requireTeam(w, r)
		if !ok {
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			s.fail(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use GET")
			return
		}
		s.handleEventsSyslog(w, team)
	default:
		s.fail(w, http.StatusNotFound, "NOT_FOUND", "unknown endpoint")
	}
}

func (s *Server) requireTeam(w http.ResponseWriter, r *http.Request) (string, bool) {
	team, ok := s.authenticate(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="sylenix-teams"`)
		s.fail(w, http.StatusUnauthorized, "UNAUTHORIZED", "valid team token required")
		return "", false
	}
	return team, true
}

func (s *Server) authenticate(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return "", false
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	if token == "" || len(token) > 4096 || strings.ContainsAny(token, " \t\r\n") {
		return "", false
	}
	sum := sha256.Sum256([]byte(token))
	match := ""
	for team, want := range s.tokens {
		if subtle.ConstantTimeCompare(sum[:], want[:]) == 1 {
			match = team
		}
	}
	return match, match != ""
}

func (s *Server) handleGet(w http.ResponseWriter, team string) {
	policy, sig, err := s.ReadStored(team)
	if err != nil {
		if os.IsNotExist(err) {
			s.fail(w, http.StatusNotFound, "POLICY_NOT_FOUND", "no policy has been published for this team")
			return
		}
		s.logger.Printf("policy read rejected team=%s reason=signature_or_io", team)
		s.fail(w, http.StatusInternalServerError, "POLICY_UNREADABLE", "stored policy cannot be verified")
		return
	}
	body, err := EncodeEnvelope(policy, sig)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "ENCODE_FAILED", "cannot encode policy")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) handlePut(w http.ResponseWriter, r *http.Request, team string) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxEnvelope))
	if err != nil {
		s.fail(w, http.StatusRequestEntityTooLarge, "POLICY_TOO_LARGE", "policy envelope is too large")
		return
	}
	policy, sig, err := DecodeEnvelope(body)
	if err != nil {
		s.logger.Printf("policy publish rejected team=%s reason=bad_envelope", team)
		s.fail(w, http.StatusBadRequest, "BAD_ENVELOPE", "body must be a policy and signature envelope")
		return
	}
	if err := s.WriteStored(team, policy, sig); err != nil {
		s.logger.Printf("policy publish rejected team=%s reason=signature", team)
		s.fail(w, http.StatusBadRequest, "BAD_SIGNATURE", "policy signature does not verify")
		return
	}
	s.logger.Printf("policy published team=%s bytes=%d", team, len(policy))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func (s *Server) fail(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
}

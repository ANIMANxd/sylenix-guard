// SPDX-License-Identifier: Apache-2.0

package policyserver

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// PolicyHistoryEntry is one successful publication of a team policy. The
// revision is the 1-based position in this team's history.
type PolicyHistoryEntry struct {
	Revision    int    `json:"revision"`
	PublishedAt string `json:"published_at"`
	SHA256      string `json:"sha256"`
	Bytes       int    `json:"bytes"`
}

func (s *Server) PolicyHistoryPath(team string) string {
	return filepath.Join(s.dataDir, "policy-history-"+team+".jsonl")
}

// ReadPolicyHistory returns all recorded publications for the team.
func (s *Server) ReadPolicyHistory(team string) ([]PolicyHistoryEntry, error) {
	if err := ValidateTeamName(team); err != nil {
		return nil, err
	}
	s.historyMu.Lock()
	defer s.historyMu.Unlock()
	return s.readPolicyHistoryLocked(team)
}

func (s *Server) readPolicyHistoryLocked(team string) ([]PolicyHistoryEntry, error) {
	f, err := os.Open(s.PolicyHistoryPath(team))
	if os.IsNotExist(err) {
		return []PolicyHistoryEntry{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	var entries []PolicyHistoryEntry
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		var entry PolicyHistoryEntry
		if err := dec.Decode(&entry); err != nil {
			return nil, fmt.Errorf("policy history line %d: %w", lineNo, err)
		}
		if entry.Revision != lineNo {
			return nil, fmt.Errorf("policy history line %d: revision %d is out of sequence", lineNo, entry.Revision)
		}
		if _, err := time.Parse(time.RFC3339Nano, entry.PublishedAt); err != nil {
			return nil, fmt.Errorf("policy history line %d: bad published_at", lineNo)
		}
		if len(entry.SHA256) != sha256.Size*2 {
			return nil, fmt.Errorf("policy history line %d: bad sha256", lineNo)
		}
		if _, err := hex.DecodeString(entry.SHA256); err != nil {
			return nil, fmt.Errorf("policy history line %d: bad sha256", lineNo)
		}
		entries = append(entries, entry)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func (s *Server) appendPolicyHistory(team string, policy []byte) error {
	s.historyMu.Lock()
	defer s.historyMu.Unlock()
	entries, err := s.readPolicyHistoryLocked(team)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(policy)
	entry := PolicyHistoryEntry{
		Revision:    len(entries) + 1,
		PublishedAt: time.Now().UTC().Format(time.RFC3339Nano),
		SHA256:      hex.EncodeToString(sum[:]),
		Bytes:       len(policy),
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.dataDir, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(s.PolicyHistoryPath(team), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(append(line, '\n'))
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	return err
}

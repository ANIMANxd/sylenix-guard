// SPDX-License-Identifier: Apache-2.0

// Package auditevent defines the only fields a Guard ships to the team
// collector. It deliberately has no argument, content, URL or free-text field.
package auditevent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
)

// Event is the sanitized audit record. The JSON field names are the collector
// contract; unknown fields are rejected on ingest and export.
type Event struct {
	Timestamp   string `json:"timestamp"`
	DeveloperID string `json:"developer_id"`
	Server      string `json:"server"`
	Tool        string `json:"tool"`
	Decision    string `json:"decision"`
	ReasonCode  string `json:"reason_code"`
	TaintState  string `json:"taint_state"`
}

// Validate checks the bounded schema. It is intentionally strict: adding a
// field later requires a deliberate change to this type.
func (e Event) Validate() error {
	if _, err := time.Parse(time.RFC3339Nano, e.Timestamp); err != nil {
		return fmt.Errorf("timestamp must be RFC3339: %w", err)
	}
	if err := checkText("developer_id", e.DeveloperID, 256, false); err != nil {
		return err
	}
	if err := checkText("server", e.Server, 256, false); err != nil {
		return err
	}
	if err := checkText("tool", e.Tool, 256, true); err != nil {
		return err
	}
	switch e.Decision {
	case "allow", "block", "deny", "taint", "clear_taint", "info":
	default:
		return fmt.Errorf("decision must be allow, block, deny, taint, clear_taint or info")
	}
	if err := checkText("reason_code", e.ReasonCode, 128, false); err != nil {
		return err
	}
	switch e.TaintState {
	case "clean", "tainted":
	default:
		return fmt.Errorf("taint_state must be clean or tainted")
	}
	return nil
}

func checkText(name, value string, max int, allowEmpty bool) error {
	if value == "" {
		if allowEmpty {
			return nil
		}
		return fmt.Errorf("%s is required", name)
	}
	if len(value) > max {
		return fmt.Errorf("%s is too long", name)
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("%s has surrounding whitespace", name)
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return fmt.Errorf("%s contains whitespace or control characters", name)
		}
	}
	return nil
}

// DecodeBatch parses a strict JSON array of events. Unknown keys, trailing
// data and invalid field values are errors; the collector does not guess.
func DecodeBatch(data []byte) ([]Event, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var events []Event
	if err := dec.Decode(&events); err != nil {
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("trailing data after event batch")
	}
	for i, ev := range events {
		if err := ev.Validate(); err != nil {
			return nil, fmt.Errorf("event[%d]: %w", i, err)
		}
	}
	return events, nil
}

// DecodeLine parses one stored event.
func DecodeLine(data []byte) (Event, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var ev Event
	if err := dec.Decode(&ev); err != nil {
		return Event{}, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return Event{}, fmt.Errorf("trailing data after event")
	}
	if err := ev.Validate(); err != nil {
		return Event{}, err
	}
	return ev, nil
}

// EncodeLine returns one canonical JSON line, without the trailing newline.
func EncodeLine(ev Event) ([]byte, error) {
	if err := ev.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(ev)
}

// SyslogLine renders RFC 5424. Field values are escaped for STRUCTURED-DATA;
// the message contains only the sanitized event fields.
func (e Event) SyslogLine() (string, error) {
	if err := e.Validate(); err != nil {
		return "", err
	}
	pri := 134 // local0.info
	if e.Decision == "block" || e.Decision == "deny" {
		pri = 132 // local0.warning
	}
	host := headerToken(e.DeveloperID, 255)
	msgID := headerToken(e.ReasonCode, 32)
	msg := fmt.Sprintf("server=%s tool=%s decision=%s reason=%s taint=%s",
		msgToken(e.Server), msgToken(e.Tool), msgToken(e.Decision), msgToken(e.ReasonCode), msgToken(e.TaintState))
	sd := fmt.Sprintf(`[sylenix@32473 developer_id="%s" server="%s" tool="%s" decision="%s" reason_code="%s" taint_state="%s"]`,
		sdEscape(e.DeveloperID), sdEscape(e.Server), sdEscape(e.Tool), sdEscape(e.Decision), sdEscape(e.ReasonCode), sdEscape(e.TaintState))
	return fmt.Sprintf("<%d>1 %s %s sylenix-guard - %s %s %s", pri, e.Timestamp, host, msgID, sd, msg), nil
}

func headerToken(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 33 && r <= 126 {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	out := b.String()
	if len(out) > max {
		out = out[:max]
	}
	if out == "" {
		return "-"
	}
	return out
}

func msgToken(s string) string {
	if s == "" {
		return "-"
	}
	return headerToken(s, 256)
}

func sdEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, `]`, `\]`)
	return s
}

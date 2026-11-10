// SPDX-License-Identifier: Apache-2.0

package auditevent_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"sylenix-guard-poc/teams/auditevent"
)

func validEvent() auditevent.Event {
	return auditevent.Event{
		Timestamp:   time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
		DeveloperID: "dev-01",
		Server:      "demo",
		Tool:        "write_file",
		Decision:    "block",
		ReasonCode:  "TAINT_SINK",
		TaintState:  "tainted",
	}
}

func TestEventHasNoArgumentFields(t *testing.T) {
	ev := validEvent()
	if err := ev.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 7 {
		t.Fatalf("event has %d fields, want exactly 7: %s", len(fields), raw)
	}
	for _, forbidden := range []string{"arguments", "args", "content", "body", "url", "note", "origin"} {
		if _, ok := fields[forbidden]; ok {
			t.Fatalf("event contains forbidden field %q: %s", forbidden, raw)
		}
	}
}

func TestBatchRejectsUnknownFields(t *testing.T) {
	body := `[{"timestamp":"2026-11-10T12:00:00Z","developer_id":"dev-01","server":"demo","tool":"write_file","decision":"block","reason_code":"TAINT_SINK","taint_state":"tainted","content":"SECRET-ARGUMENT-VALUE"}]`
	if _, err := auditevent.DecodeBatch([]byte(body)); err == nil {
		t.Fatal("batch with a content field was accepted")
	}
}

func TestSyslogIsRFC5424AndEscapesStructuredData(t *testing.T) {
	ev := validEvent()
	ev.Tool = `write"file]`
	line, err := ev.SyslogLine()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, "<132>1 ") {
		t.Fatalf("wrong PRI/version: %s", line)
	}
	if !strings.Contains(line, `[sylenix@32473 `) {
		t.Fatalf("missing structured data: %s", line)
	}
	if !strings.Contains(line, `tool="write\"file\]"`) {
		t.Fatalf("structured data was not escaped: %s", line)
	}
	if strings.Count(line, "\n") != 0 {
		t.Fatalf("syslog line contains a newline: %q", line)
	}
}

func TestInvalidEventIsRejected(t *testing.T) {
	cases := []auditevent.Event{
		func() auditevent.Event { e := validEvent(); e.Timestamp = "yesterday"; return e }(),
		func() auditevent.Event { e := validEvent(); e.Decision = "maybe"; return e }(),
		func() auditevent.Event { e := validEvent(); e.TaintState = "unknown"; return e }(),
		func() auditevent.Event { e := validEvent(); e.DeveloperID = "two words"; return e }(),
		func() auditevent.Event { e := validEvent(); e.Tool = "line\nbreak"; return e }(),
	}
	for i, ev := range cases {
		if err := ev.Validate(); err == nil {
			t.Fatalf("case %d was accepted: %+v", i, ev)
		}
	}
}

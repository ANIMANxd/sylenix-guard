// SPDX-License-Identifier: Apache-2.0

package auditshipper_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sylenix-guard-poc/teams/auditevent"
	"sylenix-guard-poc/teams/auditshipper"
)

type collector struct {
	offline  atomic.Bool
	mu       sync.Mutex
	events   []auditevent.Event
	requests int
}

func (c *collector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	c.requests++
	c.mu.Unlock()
	if c.offline.Load() {
		http.Error(w, "offline", http.StatusServiceUnavailable)
		return
	}
	body, _ := io.ReadAll(r.Body)
	events, err := auditevent.DecodeBatch(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	c.events = append(c.events, events...)
	c.mu.Unlock()
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"accepted":1}`))
}

func (c *collector) snapshot() []auditevent.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]auditevent.Event(nil), c.events...)
}

func event(i int) auditevent.Event {
	return auditevent.Event{
		Timestamp:   time.Date(2026, 11, 10, 12, 0, i, 0, time.UTC).Format(time.RFC3339Nano),
		DeveloperID: "dev-01",
		Server:      "demo",
		Tool:        "write_file",
		Decision:    "block",
		ReasonCode:  "TAINT_SINK",
		TaintState:  "tainted",
	}
}

func waitFor(t *testing.T, timeout time.Duration, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestOfflineOutboxSurvivesRestart(t *testing.T) {
	c := &collector{}
	c.offline.Store(true)
	srv := httptest.NewTLSServer(c)
	defer srv.Close()
	outbox := filepath.Join(t.TempDir(), "outbox.jsonl")

	cfg := auditshipper.Config{
		URL:           srv.URL,
		Token:         "token",
		OutboxPath:    outbox,
		BatchSize:     10,
		FlushInterval: 20 * time.Millisecond,
		BackoffBase:   10 * time.Millisecond,
		BackoffMax:    20 * time.Millisecond,
		Client:        srv.Client(),
	}
	first, err := auditshipper.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	first.Start()
	for i := 0; i < 3; i++ {
		if err := first.Enqueue(event(i)); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, time.Second, "offline outbox", func() bool {
		raw, err := os.ReadFile(outbox)
		return err == nil && countLines(raw) == 3
	})
	first.Close()

	c.offline.Store(false)
	second, err := auditshipper.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	second.Start()
	defer second.Close()
	waitFor(t, 2*time.Second, "buffered events to arrive", func() bool {
		return len(c.snapshot()) == 3
	})
	waitFor(t, time.Second, "outbox drain", func() bool {
		raw, err := os.ReadFile(outbox)
		return err == nil && countLines(raw) == 0
	})
}

func TestBatchesAndRetriesWithoutLoss(t *testing.T) {
	c := &collector{}
	c.offline.Store(true)
	srv := httptest.NewTLSServer(c)
	defer srv.Close()
	outbox := filepath.Join(t.TempDir(), "outbox.jsonl")
	sh, err := auditshipper.New(auditshipper.Config{
		URL:           srv.URL,
		Token:         "token",
		OutboxPath:    outbox,
		BatchSize:     2,
		FlushInterval: 15 * time.Millisecond,
		BackoffBase:   10 * time.Millisecond,
		BackoffMax:    25 * time.Millisecond,
		Client:        srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	sh.Start()
	defer sh.Close()
	for i := 0; i < 5; i++ {
		if err := sh.Enqueue(event(i)); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(80 * time.Millisecond)
	if len(c.snapshot()) != 0 {
		t.Fatal("events arrived while the collector was offline")
	}
	c.offline.Store(false)
	waitFor(t, 2*time.Second, "all events after retry", func() bool {
		return len(c.snapshot()) == 5
	})
	c.mu.Lock()
	requests := c.requests
	c.mu.Unlock()
	if requests < 2 {
		t.Fatalf("expected retries/backoff attempts, got %d request(s)", requests)
	}
}

func countLines(raw []byte) int {
	var count int
	for _, line := range bytesSplitLines(raw) {
		if len(line) > 0 {
			count++
		}
	}
	return count
}

func bytesSplitLines(raw []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, b := range raw {
		if b == '\n' {
			if i > start {
				out = append(out, raw[start:i])
			}
			start = i + 1
		}
	}
	if start < len(raw) {
		out = append(out, raw[start:])
	}
	return out
}

func TestEnqueueRejectsExtraFieldsByConstruction(t *testing.T) {
	ev := event(1)
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 7 {
		t.Fatalf("event has unexpected fields: %s", raw)
	}
}

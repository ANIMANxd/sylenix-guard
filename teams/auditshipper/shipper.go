// SPDX-License-Identifier: Apache-2.0

// Package auditshipper batches sanitized audit events, retries with
// exponential backoff, and keeps an append-only disk outbox while the collector
// is unavailable.
package auditshipper

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"sylenix-guard-poc/teams/auditevent"
)

const (
	defaultBatchSize     = 50
	defaultFlushInterval = 5 * time.Second
	defaultBackoffBase   = time.Second
	defaultBackoffMax    = time.Minute
	maxOutboxLine        = 64 << 10
)

type Config struct {
	URL           string
	Token         string
	CAFile        string
	OutboxPath    string
	BatchSize     int
	FlushInterval time.Duration
	BackoffBase   time.Duration
	BackoffMax    time.Duration
	Client        *http.Client
	Logger        func(error)
}

type Shipper struct {
	url        string
	token      string
	outboxPath string
	batchSize  int
	interval   time.Duration
	backoffMin time.Duration
	backoffMax time.Duration
	client     *http.Client
	logger     func(error)

	mu      sync.Mutex
	pending int
	wake    chan struct{}
	stop    chan struct{}
	once    sync.Once
	wg      sync.WaitGroup
}

func New(cfg Config) (*Shipper, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("collector URL must be an absolute https URL without userinfo, query or fragment")
	}
	if cfg.Token == "" || strings.ContainsAny(cfg.Token, " \t\r\n") {
		return nil, fmt.Errorf("collector token is required")
	}
	if strings.TrimSpace(cfg.OutboxPath) == "" {
		return nil, fmt.Errorf("outbox path is required")
	}
	batch := cfg.BatchSize
	if batch <= 0 {
		batch = defaultBatchSize
	}
	interval := cfg.FlushInterval
	if interval <= 0 {
		interval = defaultFlushInterval
	}
	backoffMin := cfg.BackoffBase
	if backoffMin <= 0 {
		backoffMin = defaultBackoffBase
	}
	backoffMax := cfg.BackoffMax
	if backoffMax <= 0 {
		backoffMax = defaultBackoffMax
	}
	if backoffMax < backoffMin {
		backoffMax = backoffMin
	}
	if err := os.MkdirAll(filepath.Dir(cfg.OutboxPath), 0o700); err != nil {
		return nil, err
	}
	client := cfg.Client
	if client == nil {
		client, err = newClient(cfg.CAFile)
		if err != nil {
			return nil, err
		}
	}
	logger := cfg.Logger
	if logger == nil {
		logger = func(error) {}
	}
	s := &Shipper{
		url:        u.String(),
		token:      cfg.Token,
		outboxPath: cfg.OutboxPath,
		batchSize:  batch,
		interval:   interval,
		backoffMin: backoffMin,
		backoffMax: backoffMax,
		client:     client,
		logger:     logger,
		wake:       make(chan struct{}, 1),
		stop:       make(chan struct{}),
	}
	lines, err := readLines(cfg.OutboxPath)
	if err != nil {
		return nil, err
	}
	s.pending = len(lines)
	return s, nil
}

func newClient(caFile string) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		raw, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(raw) {
			return nil, fmt.Errorf("%s contains no PEM certificates", caFile)
		}
		tlsConfig.RootCAs = pool
	}
	return &http.Client{
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
	}, nil
}

func (s *Shipper) Start() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.run()
	}()
}

func (s *Shipper) run() {
	next := time.Now()
	backoff := s.backoffMin
	// Drain a pre-existing outbox immediately after startup.
	if err := s.flush(); err != nil {
		s.logger(err)
		next = time.Now().Add(backoff)
		backoff = nextBackoff(backoff, s.backoffMax)
	}
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
		case <-s.wake:
		}
		if time.Now().Before(next) {
			continue
		}
		if err := s.flush(); err != nil {
			s.logger(err)
			next = time.Now().Add(backoff)
			backoff = nextBackoff(backoff, s.backoffMax)
			continue
		}
		backoff = s.backoffMin
	}
}

func nextBackoff(current, max time.Duration) time.Duration {
	next := current * 2
	if next > max {
		return max
	}
	return next
}

// Enqueue validates, appends to the disk outbox, and wakes the sender when a
// batch is ready. The local audit path never blocks on the network.
func (s *Shipper) Enqueue(ev auditevent.Event) error {
	line, err := auditevent.EncodeLine(ev)
	if err != nil {
		return err
	}
	if len(line) > maxOutboxLine {
		return fmt.Errorf("event is too large for the outbox")
	}
	s.mu.Lock()
	f, err := os.OpenFile(s.outboxPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		s.mu.Unlock()
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
	if err != nil {
		s.mu.Unlock()
		return err
	}
	s.pending++
	ready := s.pending >= s.batchSize
	s.mu.Unlock()
	if ready {
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
	return nil
}

func (s *Shipper) flush() error {
	s.mu.Lock()
	data, err := os.ReadFile(s.outboxPath)
	if os.IsNotExist(err) {
		s.pending = 0
		s.mu.Unlock()
		return nil
	}
	if err != nil {
		s.mu.Unlock()
		return err
	}
	lines := splitLines(data)
	if len(lines) == 0 {
		s.pending = 0
		s.mu.Unlock()
		return nil
	}
	if len(lines) > s.batchSize {
		lines = lines[:s.batchSize]
	}
	s.mu.Unlock()

	events := make([]auditevent.Event, 0, len(lines))
	sentBytes := 0
	for _, line := range lines {
		ev, err := auditevent.DecodeLine(line)
		if err != nil {
			return fmt.Errorf("outbox contains an invalid event: %w", err)
		}
		events = append(events, ev)
		sentBytes += len(line) + 1
	}
	if sentBytes > len(data) {
		return errors.New("outbox framing error")
	}
	body, err := json.Marshal(events)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.token)
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("collector returned %s", resp.Status)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := os.ReadFile(s.outboxPath)
	if os.IsNotExist(err) {
		s.pending = 0
		return nil
	}
	if err != nil {
		return err
	}
	if len(current) < sentBytes || !bytes.Equal(current[:sentBytes], data[:sentBytes]) {
		return errors.New("outbox changed while a batch was in flight")
	}
	if err := writeAtomic(s.outboxPath, current[sentBytes:]); err != nil {
		return err
	}
	s.pending -= len(events)
	if s.pending < 0 {
		s.pending = 0
	}
	return nil
}

func splitLines(data []byte) [][]byte {
	var out [][]byte
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) > 0 {
			out = append(out, line)
		}
	}
	return out
}

func readLines(path string) ([][]byte, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return splitLines(data), nil
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// Close stops the background sender. Any unsent events remain in the outbox.
func (s *Shipper) Close() {
	s.once.Do(func() { close(s.stop) })
	s.wg.Wait()
}

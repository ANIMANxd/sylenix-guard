// SPDX-License-Identifier: Apache-2.0

package policyserver

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"sylenix-guard-poc/teams/auditevent"
)

type exportRange struct {
	From time.Time
	To   time.Time
}

type machineExport struct {
	Events    int
	Blocks    int
	Approvals int
	Prompts   int
	LastSeen  time.Time
}

type exportSummary struct {
	Range          exportRange
	Events         int
	Blocks         int
	Approvals      int
	Prompts        int
	BlocksByReason map[string]int
	Machines       map[string]*machineExport
}

func (s *Server) handleExportCSV(w http.ResponseWriter, r *http.Request, team string) {
	rg, err := parseExportRange(r)
	if err != nil {
		s.fail(w, http.StatusBadRequest, "BAD_RANGE", err.Error())
		return
	}
	events, err := s.ReadEvents(team)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "EVENT_READ_FAILED", "cannot read stored events")
		return
	}
	filtered, err := filterExportEvents(events, rg)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "EVENT_READ_FAILED", "cannot parse stored events")
		return
	}
	var buf bytes.Buffer
	cw := csv.NewWriter(&buf)
	_ = cw.Write([]string{"timestamp", "developer_id", "server", "tool", "decision", "reason_code", "taint_state"})
	for _, ev := range filtered {
		_ = cw.Write([]string{ev.Timestamp, ev.DeveloperID, ev.Server, ev.Tool, ev.Decision, ev.ReasonCode, ev.TaintState})
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		s.fail(w, http.StatusInternalServerError, "EXPORT_FAILED", "cannot build CSV")
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", exportFilename(team, "csv", rg)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) handleExportPDF(w http.ResponseWriter, r *http.Request, team string) {
	rg, err := parseExportRange(r)
	if err != nil {
		s.fail(w, http.StatusBadRequest, "BAD_RANGE", err.Error())
		return
	}
	events, err := s.ReadEvents(team)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "EVENT_READ_FAILED", "cannot read stored events")
		return
	}
	filtered, err := filterExportEvents(events, rg)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "EVENT_READ_FAILED", "cannot parse stored events")
		return
	}
	summary := summarizeExport(rg, filtered)
	history, err := s.exportPolicyHistory(team, rg)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "POLICY_HISTORY_FAILED", "cannot read policy history")
		return
	}
	pdf := buildEvidencePDF(team, summary, history, time.Now().UTC())
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", exportFilename(team, "pdf", rg)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pdf)
}

func exportFilename(team, extension string, rg exportRange) string {
	return fmt.Sprintf("sylenix-audit-%s-%s-%s.%s", team,
		rg.From.UTC().Format("20060102"), rg.To.UTC().Format("20060102"), extension)
}

func parseExportRange(r *http.Request) (exportRange, error) {
	fromRaw := strings.TrimSpace(r.URL.Query().Get("from"))
	toRaw := strings.TrimSpace(r.URL.Query().Get("to"))
	if fromRaw == "" || toRaw == "" {
		return exportRange{}, fmt.Errorf("from and to are required (YYYY-MM-DD or RFC3339)")
	}
	from, err := parseExportBoundary(fromRaw, false)
	if err != nil {
		return exportRange{}, fmt.Errorf("invalid from: %w", err)
	}
	to, err := parseExportBoundary(toRaw, true)
	if err != nil {
		return exportRange{}, fmt.Errorf("invalid to: %w", err)
	}
	if from.After(to) {
		return exportRange{}, fmt.Errorf("from must not be after to")
	}
	return exportRange{From: from, To: to}, nil
}

func parseExportBoundary(raw string, endOfDay bool) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse("2006-01-02", raw); err == nil {
		if endOfDay {
			return t.UTC().Add(24*time.Hour - time.Nanosecond), nil
		}
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("use YYYY-MM-DD or RFC3339")
}

func filterExportEvents(events []auditevent.Event, rg exportRange) ([]auditevent.Event, error) {
	type timed struct {
		event auditevent.Event
		ts    time.Time
	}
	var selected []timed
	for _, ev := range events {
		ts, err := time.Parse(time.RFC3339Nano, ev.Timestamp)
		if err != nil {
			return nil, err
		}
		if ts.Before(rg.From) || ts.After(rg.To) {
			continue
		}
		selected = append(selected, timed{event: ev, ts: ts})
	}
	sort.SliceStable(selected, func(i, j int) bool {
		a, b := selected[i], selected[j]
		if !a.ts.Equal(b.ts) {
			return a.ts.Before(b.ts)
		}
		if a.event.DeveloperID != b.event.DeveloperID {
			return a.event.DeveloperID < b.event.DeveloperID
		}
		if a.event.Server != b.event.Server {
			return a.event.Server < b.event.Server
		}
		return a.event.Tool < b.event.Tool
	})
	out := make([]auditevent.Event, len(selected))
	for i := range selected {
		out[i] = selected[i].event
	}
	return out, nil
}

func summarizeExport(rg exportRange, events []auditevent.Event) exportSummary {
	s := exportSummary{
		Range:          rg,
		BlocksByReason: map[string]int{},
		Machines:       map[string]*machineExport{},
	}
	for _, ev := range events {
		s.Events++
		m := s.Machines[ev.DeveloperID]
		if m == nil {
			m = &machineExport{}
			s.Machines[ev.DeveloperID] = m
		}
		m.Events++
		if ts, err := time.Parse(time.RFC3339Nano, ev.Timestamp); err == nil && ts.After(m.LastSeen) {
			m.LastSeen = ts
		}
		if ev.Decision == "block" {
			s.Blocks++
			m.Blocks++
			reason := ev.ReasonCode
			if reason == "" {
				reason = "UNKNOWN"
			}
			s.BlocksByReason[reason]++
		}
		if ev.ReasonCode == "APPROVAL_GRANTED" {
			s.Approvals++
			m.Approvals++
		}
		if ev.ReasonCode == "APPROVAL_GRANTED" || ev.ReasonCode == "APPROVAL_DENIED" {
			s.Prompts++
			m.Prompts++
		}
	}
	return s
}

func (s *Server) exportPolicyHistory(team string, rg exportRange) ([]PolicyHistoryEntry, error) {
	all, err := s.ReadPolicyHistory(team)
	if err != nil {
		return nil, err
	}
	var out []PolicyHistoryEntry
	for _, entry := range all {
		ts, err := time.Parse(time.RFC3339Nano, entry.PublishedAt)
		if err != nil {
			return nil, err
		}
		if ts.Before(rg.From) || ts.After(rg.To) {
			continue
		}
		out = append(out, entry)
	}
	return out, nil
}

// ---------------------------------------------------------------- simple PDF

type pdfLine struct {
	text string
	size int
	bold bool
}

type pdfPlaced struct {
	text string
	size int
	bold bool
	y    float64
}

func buildEvidencePDF(team string, summary exportSummary, history []PolicyHistoryEntry, generated time.Time) []byte {
	var lines []pdfLine
	add := func(text string, size int, bold bool) {
		lines = append(lines, pdfLine{text: text, size: size, bold: bold})
	}
	addWrapped := func(text string, size int, bold bool) {
		for _, part := range wrapPDFText(text, 104) {
			add(part, size, bold)
		}
	}

	add("Sylenix Guard Audit Evidence Summary", 17, true)
	add("Team: "+team, 10, false)
	add("Range: "+summary.Range.From.UTC().Format(displayTime)+" to "+summary.Range.To.UTC().Format(displayTime), 10, false)
	add("Generated: "+generated.UTC().Format(displayTime), 10, false)
	add("", 10, false)
	add("What this export records", 12, true)
	addWrapped("This document describes sanitized audit events recorded by Sylenix Guard for the selected period. It is an operational record, not a legal opinion, certification, or compliance attestation.", 10, false)
	addWrapped("Counts use the same definitions as the dashboard: blocks are decision=block; approvals are APPROVAL_GRANTED; prompts are APPROVAL_GRANTED or APPROVAL_DENIED.", 10, false)
	add("", 10, false)

	add("Totals", 12, true)
	add(fmt.Sprintf("Events: %d", summary.Events), 10, false)
	add(fmt.Sprintf("Blocks: %d", summary.Blocks), 10, false)
	add(fmt.Sprintf("Approvals: %d", summary.Approvals), 10, false)
	add(fmt.Sprintf("Prompts: %d", summary.Prompts), 10, false)
	add(fmt.Sprintf("Machines covered: %d", len(summary.Machines)), 10, false)
	add("", 10, false)

	add("Blocks by reason", 12, true)
	add("Reason code | Blocks", 10, true)
	reasons := make([]string, 0, len(summary.BlocksByReason))
	for reason := range summary.BlocksByReason {
		reasons = append(reasons, reason)
	}
	sort.Slice(reasons, func(i, j int) bool {
		a, b := summary.BlocksByReason[reasons[i]], summary.BlocksByReason[reasons[j]]
		if a != b {
			return a > b
		}
		return reasons[i] < reasons[j]
	})
	if len(reasons) == 0 {
		add("No blocks recorded in this range.", 10, false)
	} else {
		for _, reason := range reasons {
			add(fmt.Sprintf("%s | %d", reason, summary.BlocksByReason[reason]), 10, false)
		}
	}
	add("", 10, false)

	add("Policy version history", 12, true)
	add("Revision | Published | SHA-256 | Bytes", 10, true)
	if len(history) == 0 {
		add("No policy publication history recorded for this range.", 10, false)
	} else {
		for _, entry := range history {
			hash := entry.SHA256
			if len(hash) > 16 {
				hash = hash[:16] + "..."
			}
			add(fmt.Sprintf("%d | %s | %s | %d", entry.Revision, entry.PublishedAt, hash, entry.Bytes), 10, false)
		}
	}
	add("", 10, false)

	add("Machines covered", 12, true)
	add("Developer / machine | Events | Blocks | Approvals | Prompts | Last event", 10, true)
	machines := make([]string, 0, len(summary.Machines))
	for name := range summary.Machines {
		machines = append(machines, name)
	}
	sort.Strings(machines)
	if len(machines) == 0 {
		add("No machines recorded in this range.", 10, false)
	} else {
		for _, name := range machines {
			m := summary.Machines[name]
			last := "never"
			if !m.LastSeen.IsZero() {
				last = m.LastSeen.UTC().Format(displayTime)
			}
			add(fmt.Sprintf("%s | %d | %d | %d | %d | %s", name, m.Events, m.Blocks, m.Approvals, m.Prompts, last), 10, false)
		}
	}
	add("", 10, false)

	add("Mapping to DPDP security safeguards (to be reviewed by counsel)", 12, true)
	addWrapped("[This section is intentionally blank. Counsel must review and complete any mapping. No safeguards mapping or compliance claim is made in this export.]", 10, false)

	return renderSimplePDF(lines)
}

func wrapPDFText(text string, width int) []string {
	if len(text) <= width {
		return []string{text}
	}
	var out []string
	words := strings.Fields(text)
	var line string
	for _, word := range words {
		if line == "" {
			line = word
			continue
		}
		if len(line)+1+len(word) > width {
			out = append(out, line)
			line = word
		} else {
			line += " " + word
		}
	}
	if line != "" {
		out = append(out, line)
	}
	return out
}

func renderSimplePDF(lines []pdfLine) []byte {
	const (
		pageWidth  = 595.0
		pageHeight = 842.0
		marginX    = 50.0
		topY       = 792.0
		bottomY    = 55.0
	)
	pages := [][]pdfPlaced{}
	var page []pdfPlaced
	y := topY
	for _, line := range lines {
		size := line.size
		if size <= 0 {
			size = 10
		}
		height := float64(size) + 5
		if y-height < bottomY && len(page) > 0 {
			pages = append(pages, page)
			page = nil
			y = topY
		}
		y -= float64(size)
		page = append(page, pdfPlaced{text: line.text, size: size, bold: line.bold, y: y})
		y -= 5
	}
	if len(page) > 0 || len(pages) == 0 {
		pages = append(pages, page)
	}

	pageCount := len(pages)
	pageObjectStart := 5
	contentObjectStart := pageObjectStart + pageCount
	var objects []string
	objects = append(objects,
		"<< /Type /Catalog /Pages 2 0 R >>",
		fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", pageKids(pageCount), pageCount),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
	)
	for i := range pages {
		objects = append(objects, fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.0f %.0f] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents %d 0 R >>", pageWidth, pageHeight, contentObjectStart+i))
	}
	for i, page := range pages {
		content := pageContent(page, i+1, pageCount, marginX, bottomY)
		objects = append(objects, fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(content), content))
	}

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n%\xE2\xE3\xCF\xD3\n")
	offsets := make([]int, len(objects))
	for i, obj := range objects {
		offsets[i] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", i+1, obj)
	}
	xref := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n", len(objects)+1)
	buf.WriteString("0000000000 65535 f \n")
	for _, off := range offsets {
		fmt.Fprintf(&buf, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	return buf.Bytes()
}

func pageKids(count int) string {
	var parts []string
	for i := 0; i < count; i++ {
		parts = append(parts, fmt.Sprintf("%d 0 R", 5+i))
	}
	return strings.Join(parts, " ")
}

func pageContent(page []pdfPlaced, number, total int, marginX, bottomY float64) string {
	var b strings.Builder
	for _, line := range page {
		font := "/F1"
		if line.bold {
			font = "/F2"
		}
		fmt.Fprintf(&b, "BT %s %d Tf 1 0 0 1 %.1f %.1f Tm (%s) Tj ET\n", font, line.size, marginX, line.y, pdfEscape(line.text))
	}
	footer := fmt.Sprintf("Page %d of %d", number, total)
	fmt.Fprintf(&b, "BT /F1 8 Tf 1 0 0 1 %.1f %.1f Tm (%s) Tj ET\n", marginX, bottomY-20, pdfEscape(footer))
	return b.String()
}

func pdfEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 32 || r > 126 {
			b.WriteByte('?')
			continue
		}
		switch r {
		case '\\', '(', ')':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
)

// processStartTime reads field 22 (starttime) from /proc/<pid>/stat. The comm
// field is in parentheses and may contain spaces or parentheses; split after
// the last ')'.
func processStartTime(pid int) (string, bool) {
	if pid <= 0 {
		return "", false
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", false
	}
	end := bytes.LastIndexByte(b, ')')
	if end < 0 || end+2 >= len(b) {
		return "", false
	}
	fields := strings.Fields(string(b[end+2:]))
	// After the comm field, state is field 3 and starttime is field 22.
	if len(fields) <= 19 {
		return "", false
	}
	return fields[19], true
}

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

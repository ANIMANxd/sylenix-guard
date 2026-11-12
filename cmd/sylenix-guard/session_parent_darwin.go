// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package main

import (
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// processStartTime uses ps on macOS. lstart is a stable human-readable
// timestamp for the process incarnation.
func processStartTime(pid int) (string, bool) {
	if pid <= 0 {
		return "", false
	}
	out, err := exec.Command("ps", "-o", "lstart=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return "", false
	}
	start := strings.TrimSpace(string(out))
	if start == "" {
		return "", false
	}
	return start, true
}

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

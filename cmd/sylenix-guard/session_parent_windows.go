// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"syscall"
	"time"
)

// processStartTime uses GetProcessTimes through the standard library syscall
// package. The creation time identifies a process incarnation across PID reuse.
func processStartTime(pid int) (string, bool) {
	if pid <= 0 {
		return "", false
	}
	handle, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", false
	}
	defer syscall.CloseHandle(handle)
	var creation, exit, kernel, user syscall.Filetime
	if err := syscall.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return "", false
	}
	return time.Unix(0, creation.Nanoseconds()).UTC().Format(time.RFC3339Nano), true
}

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	handle, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	_ = syscall.CloseHandle(handle)
	return true
}

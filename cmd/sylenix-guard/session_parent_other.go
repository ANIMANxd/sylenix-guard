// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin && !windows

package main

// processStartTime is unavailable on this platform, so the session key falls
// back to the parent PID alone and is logged as weak.
func processStartTime(pid int) (string, bool) {
	return "", false
}

// processAlive is conservative on unsupported platforms: keep session files
// rather than deleting a possibly live session.
func processAlive(pid int) bool {
	return pid > 0
}

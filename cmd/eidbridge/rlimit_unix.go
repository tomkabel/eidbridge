//go:build unix

package main

import "syscall"

// disableCoreDumps sets RLIMIT_CORE to zero so a crash cannot write process
// memory (identity data, keys) to disk (ADR-002).
func disableCoreDumps() { syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0}) }

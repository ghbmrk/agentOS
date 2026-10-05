//go:build !linux

package main

// delegateMarked: cgroup v2 delegation exists only on Linux.
func delegateMarked(string) bool { return false }

package pubid

// countOK reports whether a day may be counted under OSS-6 W5.
// verified nil means not wired yet (count as today). When set, an
// unverified clock must not count; the day stays unseen.
func countOK(verified func() bool) bool {
	return verified == nil || verified()
}

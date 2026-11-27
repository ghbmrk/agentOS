package modemlink

import "time"

// Hooks for the external zz_usable_test.go, which runs after every older
// test (mutgate reads run order, #6385). No test functions live here, so
// the package's run list is as before.

// SetLineForTest sets the owner line's state as the bridge last reported
// it, and when it was last heard.
func SetLineForTest(l *Link, state string, seen time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.state, l.seen = state, seen
}

// OutageOpenForTest says an outage is open.
func OutageOpenForTest(l *Link) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.outage != nil
}

// ConfigForTest is the config New settled on.
func ConfigForTest(l *Link) Config { return l.cfg }

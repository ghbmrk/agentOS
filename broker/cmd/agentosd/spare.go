package main

import "sync"

// spareNote is STATUS's spare-time-work line (W3-off, W3-off-a).
// Empty once the learning plane is running; otherwise a fixed sentence,
// optionally with a one-word cause ("disk", "memory").
type spareNote struct {
	mu   sync.Mutex
	line string
}

// Line is the STATUS note callback.
func (n *spareNote) Line() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.line
}

// Off sets the not-running line. cause is one word or empty.
func (n *spareNote) Off(cause string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if cause == "" {
		n.line = "Spare-time work: not running."
	} else {
		n.line = "Spare-time work: not running (" + cause + ")."
	}
}

// Clear blanks the note once the learning plane is running (W3-off-a).
func (n *spareNote) Clear() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.line = ""
}

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"
)

// secondLineDigestKey is the digest key for a second-line line first seen
// at shown (W5; potency on #142, UX-159-1): daily for 7 days from the
// first digest, then weekly, and a changed line is a new key at once.
// Unlike the rollback line (stepDigestKey), the first digest after the
// line appears carries it: the second line waits on the owner.
func secondLineDigestKey(line string, shown, now time.Time) (string, bool) {
	if line == "" {
		return "", false
	}
	d := 0
	if now.After(shown) {
		d = int(now.Sub(shown) / digestPeriod)
	}
	if d > 7 {
		d = 8 + (d-8)/7
	}
	// The first-seen time keeps a line that cleared and came back from
	// reusing a key Notice already holds.
	return fmt.Sprintf("second-line:%d:%d:%s", shown.Unix(), d, line), true
}

// secondLineDigest queues the second line's STATUS lines for the owner's
// digest on secondLineDigestKey's cadence. shown is when each current line
// was first seen; a line that clears is forgotten, so its return counts
// from day 0. shown is not persisted: after a restart each current line
// counts from then, so it is said once more.
type secondLineDigest struct {
	line  *secondLine
	shown map[string]time.Time
}

// tick queues each current line under its key. Notice drops a key it
// already holds, so calling it every minute queues each key once.
func (d *secondLineDigest) tick(now time.Time, notice func(key, line string) error) error {
	cur := d.line.Digest()
	keep := make(map[string]time.Time, len(cur))
	var errs []error
	for _, l := range cur {
		at, ok := d.shown[l]
		if !ok {
			at = now
		}
		keep[l] = at
		if key, ok := secondLineDigestKey(l, at, now); ok {
			errs = append(errs, notice(key, l))
		}
	}
	d.shown = keep
	return errors.Join(errs...)
}

// run ticks each minute until ctx ends. Wire beside steps.open with the
// learning plane's change.Pipeline.Notice once it is open.
func (d *secondLineDigest) run(ctx context.Context, notice func(key, line string) error) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := d.tick(time.Now(), notice); err != nil {
			log.Printf("second-line digest line: %v", err)
		}
	}
}

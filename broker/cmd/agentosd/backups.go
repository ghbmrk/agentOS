package main

import (
	"context"
	"errors"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/owner/kernelsock"
)

// The owner side of backups (BAK-1, BAK-2; MIG-4-recovery-e4a, #3252).
// The kernel holds the destinations, writes each backup, reads it back and
// marks it verified itself (e3); agentosd only triggers and tells. It
// takes a backup once a day while a destination exists, at once when a
// current destination holds no backup that counts (the first one, and
// after a recovery-key rotation changes the recipient: REC-4's trigger),
// and backs off after a call that failed or left a backup unverified.
// STATUS says the box is the only copy of the owner's data until the
// kernel reports a verified backup sealed to the current recipient, never
// by a timestamp (brief decision 6).

// backupKernel is the owner seam the schedule calls (kernelsock.Owner).
type backupKernel interface {
	Backups(ctx context.Context) (kernelsock.BackupsView, error)
	Backup(ctx context.Context) ([]kernelsock.Taken, error)
}

const (
	// backupDaily is the most time between two backups to one destination.
	backupDaily = 24 * time.Hour
	// backupRetry is the first wait after a failed or unverified backup;
	// each failure in a row doubles it, up to backupRetryMax.
	backupRetry    = 5 * time.Minute
	backupRetryMax = 6 * time.Hour
	// backupCheckEvery is how often the schedule reads the kernel.
	backupCheckEvery = time.Minute
)

// The STATUS lines (ownerWorded). Steps the owner page does not serve
// yet say a later box version adds them, as modelNoGrant does; the
// choice page (e4b) rewords them to name itself.
const (
	backupUnread   = "Backups: I cannot check them now, so I may hold the only copy of your data; restart me."
	backupNoKey    = "Backups: cannot start, I have no backup key yet; a later box version adds it."
	backupNoTarget = "Backups: none, so I hold the only copy of your data; a later box version adds this."
	backupNotYet   = "Backups: none checked yet, so I hold the only copy of your data; I keep trying."
	backupFailed   = "Backups: the last one failed, so I hold the only copy of your data; check the drive."
	backupOnePlace = "Backups: only one place holds them, so one fire or theft can take all; add a second."
)

// backupWipeable is the line for n current destinations that keep no old
// copies (not append-only), so a hacked box could wipe them (BAK-2).
func backupWipeable(n int) string {
	if n == 1 {
		return "Backups: 1 place keeps no old copies, so a hacked box could wipe it; use one that does."
	}
	return "Backups: " + strconv.Itoa(n) + " places keep no old copies, so a hacked box could wipe them; use ones that do."
}

// backupSchedule is the schedule and the lines it feeds STATUS.
type backupSchedule struct {
	K   backupKernel
	Now func() time.Time

	mu        sync.Mutex
	view      *kernelsock.BackupsView // the last read; nil until one answers
	setupOnly bool                    // the kernel waits for setup: no line, no backup
	fails     int                     // failed or unverified backup calls in a row
	next      time.Time               // no backup call before this (backoff)
	said      string                  // the lines last logged
}

func newBackupSchedule(k backupKernel) *backupSchedule {
	return &backupSchedule{K: k, Now: time.Now}
}

// wire puts the lines into STATUS's notes, before daemon.Run.
func (s *backupSchedule) wire(cfg *daemon.Config) {
	cfg.Notes = append(cfg.Notes, s.onlyCopyNote, s.onePlaceNote, s.wipeableNote)
}

// run checks every interval until ctx ends, starting at once.
func (s *backupSchedule) run(ctx context.Context, every time.Duration) {
	for {
		s.tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// counts reports whether b counts under v (brief decision 6): verified by
// the kernel, finished, and sealed to the current recipient.
func counts(v kernelsock.BackupsView, b kernelsock.BackupView) bool {
	return v.Recipient != "" && b.Recipient == v.Recipient && b.Verified && !b.Pending
}

// current is v's destinations that take new backups.
func current(v kernelsock.BackupsView) []kernelsock.TargetView {
	var out []kernelsock.TargetView
	for _, t := range v.Targets {
		if !t.Removed {
			out = append(out, t)
		}
	}
	return out
}

// newest is the Created (kernel ms) of target's newest backup that counts,
// and whether it has one.
func newest(v kernelsock.BackupsView, target string) (int64, bool) {
	var at int64
	ok := false
	for _, b := range v.Backups {
		if b.Target == target && counts(v, b) && (!ok || b.Created > at) {
			at, ok = b.Created, true
		}
	}
	return at, ok
}

// due reports whether a backup is owed at now: a recipient and a current
// destination with no backup that counts, or whose newest is a day old.
func due(v kernelsock.BackupsView, now time.Time) bool {
	if v.Recipient == "" {
		return false
	}
	for _, t := range current(v) {
		at, ok := newest(v, t.Name)
		if !ok || now.Sub(time.UnixMilli(at)) >= backupDaily {
			return true
		}
	}
	return false
}

// tookAll reports whether every destination's outcome is a verified backup.
func tookAll(taken []kernelsock.Taken) bool {
	if len(taken) == 0 {
		return false
	}
	for _, t := range taken {
		if t.Error != "" || t.Backup == nil || !t.Backup.Verified || t.Backup.Pending {
			return false
		}
	}
	return true
}

// backoff is the wait after fails failures in a row.
func backoff(fails int) time.Duration {
	d := backupRetry
	for i := 1; i < fails && d < backupRetryMax; i++ {
		d *= 2
	}
	return min(d, backupRetryMax)
}

// tick reads the kernel and takes a backup when one is owed and no
// backoff holds it.
func (s *backupSchedule) tick(ctx context.Context) {
	defer s.logLines()
	if !s.read(ctx) {
		return
	}
	now := s.Now()
	s.mu.Lock()
	owed := due(*s.view, now) && !now.Before(s.next)
	s.mu.Unlock()
	if !owed {
		return
	}
	taken, err := s.K.Backup(ctx)
	s.mu.Lock()
	if err == nil && tookAll(taken) {
		s.fails, s.next = 0, time.Time{}
	} else {
		s.fails++
		s.next = now.Add(backoff(s.fails))
	}
	s.mu.Unlock()
	if err != nil {
		log.Printf("backups: the kernel took none: %v", err)
	}
	for _, t := range taken {
		if t.Error != "" {
			log.Printf("backups: destination %q: %s", t.Target, t.Error)
		}
	}
	s.read(ctx)
}

// read keeps the kernel's view, and reports whether one is kept. A kernel
// not answering keeps the last view: the kernel's own state is unchanged
// by agentosd failing to read it.
func (s *backupSchedule) read(ctx context.Context) bool {
	v, err := s.K.Backups(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case err == nil:
		s.view, s.setupOnly = &v, false
	case errors.Is(err, kernelsock.ErrSetupOnly):
		s.view, s.setupOnly = nil, true
	}
	return s.view != nil
}

// onlyCopyNote is the only-copy notice, "" once a backup counts.
func (s *backupSchedule) onlyCopyNote() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.setupOnly:
		return ""
	case s.view == nil:
		return backupUnread
	case s.view.Recipient == "":
		return backupNoKey
	case len(current(*s.view)) == 0:
		return backupNoTarget
	}
	for _, t := range current(*s.view) {
		if _, ok := newest(*s.view, t.Name); ok {
			return ""
		}
	}
	if s.fails > 0 {
		return backupFailed
	}
	return backupNotYet
}

// onePlaceNote says when only one destination holds a backup that counts
// (BAK-2 asks for two, in different failure domains).
func (s *backupSchedule) onePlaceNote() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.view == nil {
		return ""
	}
	n := 0
	for _, t := range current(*s.view) {
		if _, ok := newest(*s.view, t.Name); ok {
			n++
		}
	}
	if n == 1 {
		return backupOnePlace
	}
	return ""
}

// wipeableNote names how many current destinations are not append-only.
func (s *backupSchedule) wipeableNote() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.view == nil {
		return ""
	}
	n := 0
	for _, t := range current(*s.view) {
		if !t.AppendOnly {
			n++
		}
	}
	if n == 0 {
		return ""
	}
	return backupWipeable(n)
}

// lines is every standing line, in STATUS's order.
func (s *backupSchedule) lines() []string {
	var out []string
	for _, l := range []string{s.onlyCopyNote(), s.onePlaceNote(), s.wipeableNote()} {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

// logLines logs the lines when they change, so the box log says what
// STATUS says about backups.
func (s *backupSchedule) logLines() {
	l := strings.Join(s.lines(), " ")
	s.mu.Lock()
	changed := l != s.said
	s.said = l
	s.mu.Unlock()
	if changed && l != "" {
		log.Printf("backups: %s", l)
	} else if changed {
		log.Printf("backups: a verified backup counts; nothing to say")
	}
}

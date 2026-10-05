package vm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ForgetSince takes back from a lineage everything it may hold since a
// time (CAP-3 deletion reach): the broker gave the lineage a deleted
// record at since, and forks share memory, so any of its machines, layers
// and snapshots from then on may hold it.
//
// Every machine of the lineage goes back to its newest usable snapshot
// taken before since (its own, or the one it was forked from), or to a
// fresh layer from its image when there is none. A running machine
// restarts there, memory restored from a full checkpoint, as Rollback; a
// stopped or preempted one gets the layer on disk and stays as it is. Then
// every snapshot of the lineage taken at or after since is deleted,
// including those of destroyed machines. A snapshot taken before this
// release recorded lineages has none: if its machine is gone, it is
// deleted when taken at or after since, whatever lineage it was.
//
// Labels do not fall (REV-5). Replay machines are never in a live lineage.
// ForgetSince is idempotent and may be repeated after a failure; a
// repeat rolls back work done after the first call too, so callers stop
// repeating once it has succeeded.
func (m *Manager) ForgetSince(ctx context.Context, lineage string, since time.Time) error {
	if lineage == "" {
		return errors.New("vm: ForgetSince needs a lineage")
	}
	var errs []error
	done := map[string]bool{}
	for {
		// Repeat until no new machine joined the lineage meanwhile (a fork
		// started from a checkpoint taken before its source was reset).
		var next []*machine
		m.mu.Lock()
		for id, mc := range m.machines {
			if mc.Lineage == lineage && !done[id] && !strings.HasPrefix(id, EvalPrefix) {
				next = append(next, mc)
			}
		}
		m.mu.Unlock()
		if len(next) == 0 {
			break
		}
		for _, mc := range next {
			done[mc.ID] = true
			if err := m.forgetMachine(ctx, mc, since); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", mc.ID, err))
			}
		}
	}
	// Snapshots of destroyed machines, and any a failed reset left.
	for _, s := range m.lineageSnaps(lineage, since) {
		if err := m.removeSnapshot(s.ID); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// forgetMachine resets one machine of the lineage and deletes its own
// snapshots at or after since, under its lock, so no Step lands between.
func (m *Manager) forgetMachine(ctx context.Context, mc *machine, since time.Time) error {
	stopped := false
	defer func() {
		// As Rollback: a failed restart leaves the machine stopped, and its
		// admission goes, outside the machine's lock.
		if stopped {
			m.cfg.Admit.Release(mc.ID)
		}
	}()
	mc.mu.Lock()
	defer mc.mu.Unlock()
	var target *Snapshot
	m.mu.Lock()
	for _, s := range m.snaps {
		if inLineage(mc, s) && s.Taken.Before(since) && (target == nil || s.ID > target.ID) {
			s := s
			target = &s
		}
	}
	m.mu.Unlock()
	if mc.State == Running {
		// Running is admitted already; restart on that admission.
		if err := m.restartLocked(ctx, mc, target); err != nil {
			stopped = mc.State != Running
			return err
		}
	} else if err := m.resetStopped(mc, target); err != nil {
		return err
	}
	if target != nil {
		mc.Label = maxLabel(mc.Label, target.Label)
		mc.Last = target.ID
	} else {
		mc.Last = ""
	}
	if mc.ForkBase != "" && (target == nil || target.ID < mc.ForkBase) {
		// The fork point itself was taken at or after since; it goes.
		mc.ForkBase = ""
	}
	var errs []error
	if err := m.saveMachine(mc); err != nil {
		errs = append(errs, err)
	}
	for _, s := range m.Snapshots(mc.ID) {
		if !s.Taken.Before(since) {
			if err := m.removeSnapshot(s.ID); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// resetStopped replaces a stopped or preempted machine's layer, reserving
// the disk first; it does not start the machine.
func (m *Manager) resetStopped(mc *machine, s *Snapshot) error {
	var h *diskHold
	var err error
	if s == nil {
		h, err = m.reserveSeed(mc)
	} else {
		h, err = m.reserveRestore(1, s.ID)
	}
	if err != nil {
		return err
	}
	defer h.release()
	l := m.launch(mc)
	if err := os.MkdirAll(l.Dir, 0o700); err != nil {
		return err
	}
	return m.writeLayer(l, mc, s)
}

// lineageSnaps lists the snapshots of lineage taken at or after since.
func (m *Manager) lineageSnaps(lineage string, since time.Time) []Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Snapshot
	for _, s := range m.snaps {
		if s.Taken.Before(since) {
			continue
		}
		l := s.Lineage
		if l == "" {
			if mc, ok := m.machines[s.Machine]; ok {
				l = mc.Lineage
			} else {
				l = lineage // unknown: delete rather than keep
			}
		}
		if l == lineage {
			out = append(out, s)
		}
	}
	return out
}

// removeSnapshot deletes a snapshot: its metadata first, so a crash
// part-way leaves a directory Open drops as never published.
func (m *Manager) removeSnapshot(id string) error {
	dir := m.snapDir(id)
	if err := os.Remove(filepath.Join(dir, "meta.json")); err != nil && !os.IsNotExist(err) {
		return err
	}
	m.mu.Lock()
	delete(m.snaps, id)
	m.mu.Unlock()
	return os.RemoveAll(dir)
}

package vm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/vm/overlay"
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
	target := m.restoreTarget(mc, since)
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

// restoreTarget is the snapshot ForgetSince takes mc back to: its newest
// usable one taken before since, or nil for its image.
func (m *Manager) restoreTarget(mc *machine, since time.Time) *Snapshot {
	var target *Snapshot
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.snaps {
		if inLineage(mc, s) && s.Taken.Before(since) && (target == nil || s.ID > target.ID) {
			s := s
			target = &s
		}
	}
	return target
}

func (m *Manager) contained(mc *machine) bool {
	if m.cfg.Contained == nil {
		return false
	}
	mc.mu.Lock()
	l := mc.Lineage
	mc.mu.Unlock()
	return m.cfg.Contained(l)
}

// ResetPlan says what ForgetSince(lineage, since) would take back now.
type ResetPlan struct {
	// To is the oldest restore point among the lineage's machines; zero
	// when some machine would go back to its image (a fresh start).
	To time.Time
	// Changes counts the files and directories that differ between each
	// machine's restore point and its layer now: in-machine work a reset
	// loses. Memory is not measured. A layer that cannot be read counts
	// as changed.
	Changes int
}

// ResetPlan measures what a ForgetSince from since would lose, without
// changing anything (recall W10: in-machine work counts as work, and the
// owner's question names the real restore point).
func (m *Manager) ResetPlan(lineage string, since time.Time) (ResetPlan, error) {
	if lineage == "" {
		return ResetPlan{}, errors.New("vm: ResetPlan needs a lineage")
	}
	var ms []*machine
	m.mu.Lock()
	for id, mc := range m.machines {
		if mc.Lineage == lineage && !strings.HasPrefix(id, EvalPrefix) {
			ms = append(ms, mc)
		}
	}
	m.mu.Unlock()
	var p ResetPlan
	fresh := false
	for _, mc := range ms {
		target := m.restoreTarget(mc, since)
		mc.mu.Lock()
		now := overlay.View{Lower: m.cfg.Images[mc.Spec.Image], Upper: m.launch(mc).Upper}
		mc.mu.Unlock()
		if target == nil {
			fresh = true
			ents, err := overlay.Scan(now.Upper)
			switch {
			case errors.Is(err, os.ErrNotExist):
			case err != nil:
				p.Changes++
			default:
				p.Changes += len(ents)
			}
			continue
		}
		if p.To.IsZero() || target.Taken.Before(p.To) {
			p.To = target.Taken
		}
		ch, err := overlay.Diff(m.view(*target), now)
		if err != nil {
			p.Changes++
			continue
		}
		p.Changes += len(ch)
	}
	if fresh {
		p.To = time.Time{}
	}
	return p, nil
}

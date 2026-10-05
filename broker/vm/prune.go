package vm

import (
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// PrunePolicy says which snapshots are kept (RES-4). Zero fields take the
// defaults.
type PrunePolicy struct {
	KeepFS   int // newest file-system snapshots kept per machine (default 50)
	KeepFull int // newest full checkpoints kept per machine (default 2)
	// MinAge protects snapshots younger than this (default 10 min), so a
	// fork or merge between taking a snapshot and recording its use never
	// loses it.
	MinAge time.Duration
	// LowWaterBytes: while the state disk's free space is below the RES-4
	// reserve plus this, every machine keeps only the essentials.
	LowWaterBytes int64
}

func (p PrunePolicy) withDefaults() PrunePolicy {
	if p.KeepFS <= 0 {
		p.KeepFS = 50
	}
	if p.KeepFull <= 0 {
		p.KeepFull = 2
	}
	if p.MinAge <= 0 {
		p.MinAge = 10 * time.Minute
	}
	return p
}

func (m *Manager) clock() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

// Prune deletes the snapshots policy p no longer keeps and returns their
// IDs. Never pruned: a live machine's newest snapshot, its oldest full
// checkpoint (the warm template, REV-1) and its newest one; any snapshot a
// live machine was forked from (rollback and merge need it); and anything
// younger than MinAge. Beyond those, each live machine keeps its KeepFS
// newest file-system snapshots and KeepFull newest checkpoints; under disk
// pressure it keeps only the protected ones. A destroyed machine's
// snapshots no longer serve any rollback, so only the protections above
// keep them.
//
// Prune holds each live machine's lock while deleting its snapshots, so no
// rollback of that machine runs meanwhile; preemption does not wait for
// that lock (Preempt).
func (m *Manager) Prune(p PrunePolicy) ([]string, error) {
	p = p.withDefaults()
	pressured := false
	if p.LowWaterBytes > 0 {
		free, err := m.cfg.FreeBytes(m.cfg.StateDir)
		if err != nil {
			return nil, err
		}
		pressured = free < m.cfg.DiskReserveBytes+p.LowWaterBytes
	}

	m.mu.Lock()
	live := map[string]*machine{}
	for id, mc := range m.machines {
		live[id] = mc
	}
	byMachine := map[string][]Snapshot{}
	for _, s := range m.snaps {
		byMachine[s.Machine] = append(byMachine[s.Machine], s)
	}
	m.mu.Unlock()

	forkBases := map[string]bool{}
	for _, mc := range live {
		mc.mu.Lock()
		if mc.ForkBase != "" {
			forkBases[mc.ForkBase] = true
		}
		mc.mu.Unlock()
	}

	cutoff := m.clock().Add(-p.MinAge)
	var gone, dirs []string
	var firstErr error
	owners := make([]string, 0, len(byMachine))
	for id := range byMachine {
		owners = append(owners, id)
	}
	sort.Strings(owners)
	for _, owner := range owners {
		snaps := byMachine[owner]
		sort.Slice(snaps, func(i, j int) bool { return snaps[i].ID > snaps[j].ID }) // newest first
		mc := live[owner]
		if mc != nil {
			mc.mu.Lock()
		}
		keep := map[string]bool{}
		if mc != nil {
			keep[mc.Last] = true
			nFS, nFull := 0, 0
			var oldestFull string
			for _, s := range snaps {
				switch s.Tier {
				case FS:
					if nFS < p.KeepFS && !pressured {
						keep[s.ID] = true
					}
					nFS++
				case Full:
					if nFull == 0 || (nFull < p.KeepFull && !pressured) {
						keep[s.ID] = true
					}
					nFull++
					oldestFull = s.ID
				}
			}
			keep[oldestFull] = true
		}
		for _, s := range snaps {
			if keep[s.ID] || forkBases[s.ID] || !s.Taken.Before(cutoff) {
				continue
			}
			if err := m.unpublishSnapshot(s.ID); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			gone = append(gone, s.ID)
			dirs = append(dirs, m.snapDir(s.ID))
		}
		if mc != nil {
			mc.mu.Unlock()
		}
	}
	// The files go outside the machine's lock (L3 on #124): unpublished
	// snapshots are found by no rollback, fork, or merge.
	for _, dir := range dirs {
		if err := os.RemoveAll(dir); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	sort.Strings(gone)
	return gone, firstErr
}

// unpublishSnapshot unpublishes a snapshot: its record first, then its
// metadata, so a crash leaves a directory that load drops. The caller
// deletes the directory.
func (m *Manager) unpublishSnapshot(id string) error {
	m.mu.Lock()
	delete(m.snaps, id)
	m.mu.Unlock()
	if err := os.Remove(filepath.Join(m.snapDir(id), "meta.json")); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// RunPruner prunes by p every interval until stop is closed.
func (m *Manager) RunPruner(p PrunePolicy, interval time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if _, err := m.Prune(p); err != nil {
			log.Printf("vm: pruning snapshots: %v", err)
		}
		select {
		case <-stop:
			return
		case <-t.C:
		}
	}
}

package vm

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CheckpointAndStop puts a machine to sleep (PE7): it pauses it, takes a
// full checkpoint marked as its sleep checkpoint, stops it without letting
// it run again, and gives its memory back to admission. Only
// ResumeFromCheckpoint restores that checkpoint. The machine must be
// running, and a replay machine never sleeps.
func (m *Manager) CheckpointAndStop(ctx context.Context, id string) (Snapshot, error) {
	if strings.HasPrefix(id, EvalPrefix) {
		return Snapshot{}, fmt.Errorf("vm: replay machine %s cannot sleep", id)
	}
	mc, err := m.get(id)
	if err != nil {
		return Snapshot{}, err
	}
	mc.mu.Lock()
	if mc.State != Running {
		st := mc.State
		mc.mu.Unlock()
		return Snapshot{}, fmt.Errorf("%w: %s is %s", ErrState, id, st)
	}
	if err := m.cfg.Runtime.Pause(ctx, id); err != nil {
		mc.mu.Unlock()
		return Snapshot{}, err
	}
	prev := mc.Last
	s, err := m.captureAs(ctx, mc, Full, true)
	if err != nil {
		if s.ID != "" {
			// Published, then the machine record failed to save: an
			// error leaves no checkpoint behind (as takeLocked, #137).
			m.withdrawLocked(mc, s.ID, prev)
		}
		// Not asleep: the guest runs on.
		if rerr := m.cfg.Runtime.Resume(context.WithoutCancel(ctx), id); rerr != nil {
			err = errors.Join(err, rerr)
		}
		mc.mu.Unlock()
		return Snapshot{}, err
	}
	// Stopped while still paused, so nothing runs after the checkpoint.
	err = m.stopRuntime(ctx, mc)
	if serr := m.saveMachine(mc); err == nil {
		err = serr
	}
	if err != nil {
		// The machine is stopped, but the sleep failed: its checkpoint
		// is withdrawn, so the wake that follows resumes cold.
		m.withdrawLocked(mc, s.ID, prev)
		mc.mu.Unlock()
		return Snapshot{}, err
	}
	mc.mu.Unlock()
	m.cfg.Admit.Release(id)
	return s, nil
}

// Why a wake was cold: fixed classes for the sleeper's journal line
// (PE7 condition 12), never a path or an error's text.
const (
	ColdNotSleep = "not this machine's sleep checkpoint"
	ColdNewer    = "a newer snapshot exists"
	ColdStarted  = "the machine started since"
	ColdChanged  = "the checkpoint changed"
	ColdFailed   = "the restore failed"
)

// Wake is how ResumeFromCheckpoint woke a machine: Restored with its
// memory, or cold on its layer for the reason Cold names.
type Wake struct {
	Restored bool
	Cold     string
}

// ResumeFromCheckpoint wakes a machine CheckpointAndStop put to sleep
// (PE7). It restores memory and files from snapID only when every check
// holds:
//   - snapID is this machine's sleep checkpoint and its newest snapshot;
//   - the machine has not started since it was taken (no later layer
//     change, fork restart or merge);
//   - the checkpoint's hash matches what was written.
//
// Otherwise, or if the restore fails, the machine resumes cold on its
// layer (Resume). Either way the sleep checkpoint is deleted: it is
// restored at most once. A checkpoint the owner took, or another
// machine's, is never deleted. The label never falls (REV-5). It reports
// how the machine woke; err is the cold resume's.
func (m *Manager) ResumeFromCheckpoint(ctx context.Context, id, snapID string) (Wake, error) {
	mc, err := m.get(id)
	if err != nil {
		return Wake{}, err
	}
	mc.mu.Lock()
	st, last, starts := mc.State, mc.Last, mc.Starts
	mc.mu.Unlock()
	if st == Running {
		return Wake{}, fmt.Errorf("%w: %s is running", ErrState, id)
	}
	s, serr := m.Snapshot(snapID)
	own := serr == nil && s.Sleep && s.Machine == id
	if own {
		defer m.dropSnapshot(mc, s.ID, "")
	}
	var cold string
	switch {
	case !own || s.Tier != Full:
		cold = ColdNotSleep
	case s.ID != last:
		cold = ColdNewer
	case s.Starts != starts:
		cold = ColdStarted
	case !m.hashMatches(s):
		cold = ColdChanged
	default:
		if err := m.Rollback(ctx, id, s.ID); err == nil {
			return Wake{Restored: true}, nil
		}
		// The restore failed: whatever it left, the machine starts cold.
		cold = ColdFailed
		mc.mu.Lock()
		running := mc.State == Running
		mc.mu.Unlock()
		if running {
			return Wake{Cold: cold}, nil
		}
	}
	// The cold start gets a context of its own, bounded by ColdResumeFor:
	// a restore that ran out the caller's must still leave the machine
	// started, not wait for the keeper's next try (L3 on #149).
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ColdResumeFor)
	defer cancel()
	return Wake{Cold: cold}, m.Resume(cctx, id)
}

// ColdResumeFor bounds the cold start that follows a refused or failed
// restore in ResumeFromCheckpoint.
const ColdResumeFor = time.Minute

func (m *Manager) hashMatches(s Snapshot) bool {
	if s.Hash == "" {
		return false
	}
	h, err := treeHash(m.snapDir(s.ID))
	return err == nil && h == s.Hash
}

// treeHash is the SHA-256 over a snapshot's files and memory image: each
// entry's path, type and permissions, and a file's contents or a link's
// target, in lexical order. meta.json, which holds the hash, is left out.
func treeHash(dir string) (string, error) {
	h := sha256.New()
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		if rel == "meta.json" {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		field := func(b []byte) {
			var n [8]byte
			binary.BigEndian.PutUint64(n[:], uint64(len(b)))
			h.Write(n[:])
			h.Write(b)
		}
		field([]byte(filepath.ToSlash(rel)))
		field([]byte(fi.Mode().String()))
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			t, err := os.Readlink(p)
			if err != nil {
				return err
			}
			field([]byte(t))
		case fi.Mode().IsRegular():
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			defer f.Close()
			var n [8]byte
			binary.BigEndian.PutUint64(n[:], uint64(fi.Size()))
			h.Write(n[:])
			if _, err := io.Copy(h, f); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

package kernel

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// The security suite (HLD-3, HLD-5, EVL-3; UPD-5r-b3). §16's injection tests
// and HLD-5's minimized regression cases are log data: each case is one
// entry, and a case is never edited or reused, so the suite only grows. It
// shrinks only by an owner key (HLD-3): a drop is a widening (KEY-4), a live
// passkey's signature over SecurityDropHash, live after GrantHold, which the
// owner can cancel (KeepSecurityCase), and which a passkey revoked in the
// hold cancels with it, as it cancels the passkey's grants (D-146). The
// kernel holds a case's bytes and nothing else: what they mean is the
// grader's (broker/vm/requal), so no case parser joins the core.

// Security suite entry types.
const (
	TSecurityCase = "security.case"
	TSecurityDrop = "security.dropped"
	TSecurityKept = "security.kept"
)

// Bounds on a case, so the suite's share of the kernel's memory is bounded
// (at most MaxSecurityCases × (MaxSecurityInput + MaxSecurityExpect)) while
// a minimized case still fits. A full suite refuses a case, never drops one.
const (
	MaxSecurityCases  = 4096
	MaxSecurityID     = 128
	MaxSecurityInput  = 8 << 10
	MaxSecurityExpect = 1 << 10
)

var (
	ErrSecurityCase = errors.New("kernel: a security case is a new ID of 1 to 128 letters, digits and ._/- with a non-empty input and an expectation, within the bounds")
	ErrSecurityFull = errors.New("kernel: the security suite is full; a case is dropped only by the owner's passkey")
	ErrSecurityDrop = errors.New("kernel: a security case drop is a live passkey's signature over SecurityDropHash of a live case with no drop pending")
	ErrSecurityKeep = errors.New("kernel: no drop of that case is in its hold")
)

// SecurityCase is one case of the security suite, as the grader takes it:
// only Input reaches a sandbox; Expect stays on the host.
type SecurityCase struct {
	ID     string `json:"id"`
	Input  []byte `json:"input"`
	Expect []byte `json:"expect"`
}

type securityDrop struct {
	N  int        `json:"n"`
	ID string     `json:"id"`
	By key.Cosign `json:"by"`
}

type securityKept struct {
	ID string `json:"id"`
}

// security is the suite part of the state: every case ever added, in order,
// and each drop not cancelled, which is live from its From.
type security struct {
	cases []SecurityCase
	index map[string]int
	drops map[string]pendingDrop
	n     int // drops logged, named in each one's signature
}

type pendingDrop struct {
	From int64
	By   key.PublicKey
}

// SecurityDropHash names the n-th drop, of the case id: a signature never
// replays, even over a case whose earlier drop the owner cancelled.
func SecurityDropHash(n int, id string) [32]byte {
	b := binary.BigEndian.AppendUint64([]byte("agentos.security.drop.v1\x00"), uint64(n))
	return sha256.Sum256(append(b, id...))
}

// AddSecurityCase logs a case. It narrows, but it anchors, so a log rolled
// back to before it is caught at boot like any other (KRN-7).
func (k *Kernel) AddSecurityCase(now int64, c SecurityCase) error {
	if err := k.s.caseOK(c, now); err != nil {
		return err
	}
	return k.owner(now, TSecurityCase, c)
}

// SecurityDrop is what the owner page asks the passkey to sign to drop id:
// the drop's number; ok is false unless id is live with no drop pending.
func (s *State) SecurityDrop(id string) (n int, ok bool) {
	_, known := s.sec.index[id]
	_, dropping := s.sec.drops[id]
	return s.sec.n, known && !dropping
}

// DropSecurityCase drops id on the owner's passkey, live after GrantHold. It
// widens, so it anchors.
func (k *Kernel) DropSecurityCase(now int64, id string, by key.Cosign) error {
	n, ok := k.s.SecurityDrop(id)
	b := securityDrop{n, id, by}
	if !ok || !k.s.dropOK(b) {
		return ErrSecurityDrop
	}
	return k.owner(now, TSecurityDrop, b)
}

// KeepSecurityCase cancels a drop of id still in its hold, at the owner's
// word: it narrows.
func (k *Kernel) KeepSecurityCase(now int64, id string) error {
	if d, ok := k.s.sec.drops[id]; !ok || now >= d.From {
		return ErrSecurityKeep
	}
	_, err := k.emit(now, TSecurityKept, securityKept{id})
	return err
}

// SecuritySuite is the suite at now: its live cases, in the order added, and
// how many the owner's drops have removed. A drop in its hold leaves its case
// live.
func (s *State) SecuritySuite(now int64) (cases []SecurityCase, dropped int) {
	for _, c := range s.sec.cases {
		if d, ok := s.sec.drops[c.ID]; ok && now >= d.From {
			dropped++
			continue
		}
		cases = append(cases, SecurityCase{c.ID, slices.Clone(c.Input), slices.Clone(c.Expect)})
	}
	return cases, dropped
}

// dropped counts the cases whose drop is live at now.
func (s *State) dropped(now int64) int {
	n := 0
	for _, d := range s.sec.drops {
		if now >= d.From {
			n++
		}
	}
	return n
}

// SecurityPending lists the cases whose drop is in its hold, for the owner's
// notice (KEY-4).
func (s *State) SecurityPending(now int64) []string {
	var out []string
	for _, c := range s.sec.cases {
		if d, ok := s.sec.drops[c.ID]; ok && now < d.From {
			out = append(out, c.ID)
		}
	}
	return out
}

// caseOK checks a case as a fold must: its shape, a new ID, and room.
func (s *State) caseOK(c SecurityCase, at int64) error {
	if len(c.ID) == 0 || len(c.ID) > MaxSecurityID || len(c.Input) == 0 || len(c.Input) > MaxSecurityInput ||
		len(c.Expect) == 0 || len(c.Expect) > MaxSecurityExpect {
		return ErrSecurityCase
	}
	for _, r := range []byte(c.ID) {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '/' || r == '-') {
			return ErrSecurityCase
		}
	}
	if _, used := s.sec.index[c.ID]; used {
		return ErrSecurityCase
	}
	if len(s.sec.cases)-s.dropped(at) >= MaxSecurityCases {
		return ErrSecurityFull
	}
	return nil
}

// dropOK checks a drop as a fold must: the next drop, of a live case with
// none pending, signed by a live passkey.
func (s *State) dropOK(b securityDrop) bool {
	n, ok := s.SecurityDrop(b.ID)
	return ok && b.N == n && key.In(s.Passkeys(), b.By.By) && b.By.Over(SecurityDropHash(n, b.ID))
}

// cancelDrops cancels the drops by in their hold at at: a revoked passkey's
// last taps never go live (D-146).
func (s *State) cancelDrops(by key.PublicKey, at int64) {
	for id, d := range s.sec.drops {
		if at < d.From && d.By == by {
			delete(s.sec.drops, id)
		}
	}
}

// applySecurity folds a suite entry. One that fails its check changes nothing.
func (s *State) applySecurity(e Entry) error {
	if s.sec.index == nil {
		s.sec.index, s.sec.drops = map[string]int{}, map[string]pendingDrop{}
	}
	switch e.Type {
	case TSecurityCase:
		c, err := body[SecurityCase](e)
		if err != nil {
			return err
		}
		if s.caseOK(c, e.At) == nil {
			s.sec.index[c.ID] = len(s.sec.cases)
			s.sec.cases = append(s.sec.cases, c)
		}
	case TSecurityDrop:
		b, err := body[securityDrop](e)
		if err != nil {
			return err
		}
		if s.dropOK(b) {
			s.sec.drops[b.ID] = pendingDrop{e.At + GrantHold, b.By.By}
			s.sec.n++
		}
	case TSecurityKept:
		b, err := body[securityKept](e)
		if err != nil {
			return err
		}
		if d, ok := s.sec.drops[b.ID]; ok && e.At < d.From {
			delete(s.sec.drops, b.ID)
		}
	}
	return nil
}

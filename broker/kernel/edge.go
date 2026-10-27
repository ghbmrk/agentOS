package kernel

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Edge keys (HW-15, HW-17, REC-2; briefs/EDGE-link-core.md slice a). The
// edge is a node whose key the kernel logs: one live key at a time, bound to
// this core's head key, so a restored log, whose head key is new (BAK-1),
// carries every enrolment and revocation and trusts none of its keys. The
// first key comes in at setup only; any later one, or a replacement, is the
// latest hello the link port reported, enrolled on a hardware key's
// signature in the owner-page step, and the entry that makes it live
// revokes the key it replaces. A revoked key never comes back.

// Entry types for edge keys, all version 1.
const (
	TEdgeEnrolled  = "edge.enrolled"
	TEdgeCandidate = "edge.candidate"
	TEdgeRevoked   = "edge.revoked"
	TEdgeCut       = "edge.cut"
)

// Domains of the edge's signatures.
const (
	DomainEdgeHello  = "agentos.edge.hello.v1\x00"
	DomainEdgeEnroll = "agentos.edge.enroll.v1\x00"
)

const (
	// HelloNonce is the size of a hello's nonce, the connection's TLS exporter value.
	HelloNonce = 32
	// CandidateEvery is the least time between two logged candidates, whatever the key.
	CandidateEvery = 60_000
	// MaxSlot bounds the unlock slot an edge.cut names.
	MaxSlot = 64
)

var (
	// ErrEdgeKey refuses a key that is not an Ed25519 public key.
	ErrEdgeKey = errors.New("kernel: not an edge key")
	// ErrEdgeSig refuses an enrolment no hardware key signed over EdgeEnrollHash.
	ErrEdgeSig = errors.New("kernel: a new edge needs your hardware key's signature")
	// ErrEdgeRevoked refuses a key revoked or replaced in this log.
	ErrEdgeRevoked = errors.New("kernel: that edge key was revoked and never comes back")
	// ErrEdgeCandidate refuses enrolling a key that is not the edge on the cable now.
	ErrEdgeCandidate = errors.New("kernel: that is not the edge on the link cable")
	// ErrEdgeHello refuses a hello whose signature does not verify.
	ErrEdgeHello = errors.New("kernel: the edge's hello does not verify")
	// ErrEdgeBusy drops a hello within a minute of the last candidate, or from its key again.
	ErrEdgeBusy = errors.New("kernel: an edge hello was taken already")
	// ErrEdgeLive refuses a hello or an enrolment of the key already live.
	ErrEdgeLive = errors.New("kernel: that edge key is already live")
	// ErrEdgeSlot refuses a cut naming no unlock slot, or one out of shape.
	ErrEdgeSlot = errors.New("kernel: an edge cut names the unlock slot")
)

type (
	edgeEnrolled struct {
		Key      ed25519.PublicKey `json:"key"`
		Head     ed25519.PublicKey `json:"head"`
		First    bool              `json:"first,omitempty"`
		Replaces ed25519.PublicKey `json:"replaces,omitempty"`
		Sig      key.Cosign        `json:"sig"`
	}
	edgeCandidate struct {
		Key   ed25519.PublicKey `json:"key"`
		Nonce []byte            `json:"nonce"`
		Sig   []byte            `json:"sig"`
	}
	edgeRevoked struct {
		Key ed25519.PublicKey `json:"key"`
	}
	edgeCut struct {
		Slot string `json:"slot"`
	}
)

// edgeState is the edge keys in state.
type edgeState struct {
	setup   bool            // the log's first entry was anchors.set
	changes int             // edge.enrolled, edge.revoked and edge.cut entries
	live    *edgeEnrolled   // the last enrolment, unless revoked or cut since
	last    *edgeEnrolled   // the last enrolment, at any head, cut or not
	revoked map[string]bool // every key revoked or replaced, at any head
	cand    *edgeCandidate  // the latest candidate
	candAt  int64
}

// HelloMsg is what the edge's key signs on a connection: the domain and the
// connection's exporter value.
func HelloMsg(nonce []byte) []byte { return append([]byte(DomainEdgeHello), nonce...) }

func edgeKey(k []byte) bool { return len(k) == ed25519.PublicKeySize }

// LiveEdge is the edge key the core at head trusts: the last enrolment's,
// when it was made under head and no revoke or cut came after it.
func (s *State) LiveEdge(head ed25519.PublicKey) ed25519.PublicKey {
	if l := s.edge.live; l != nil && l.Head.Equal(head) {
		return bytes.Clone(l.Key)
	}
	return nil
}

// EdgeRevoked reports whether k was ever revoked or replaced in this log.
func (s *State) EdgeRevoked(k ed25519.PublicKey) bool { return s.edge.revoked[string(k)] }

// PendingEdge is the key the page step offers at head: the latest
// candidate's, when it is neither live nor revoked.
func (s *State) PendingEdge(head ed25519.PublicKey) ed25519.PublicKey {
	c := s.edge.cand
	if c == nil || s.EdgeRevoked(c.Key) || s.LiveEdge(head).Equal(c.Key) {
		return nil
	}
	return bytes.Clone(c.Key)
}

// EdgeReplaces is the key an enrolment of k replaces and revokes: the last
// enrolment's, if it is not revoked and not k, whatever head key it was made
// under and whether a cut came after it (HW-15). So after a restore or a
// cut, enrolling another edge still cuts the old key for good, and
// re-enrolling the same edge revokes nothing.
func (s *State) EdgeReplaces(k ed25519.PublicKey) ed25519.PublicKey {
	if l := s.edge.last; l != nil && !s.EdgeRevoked(l.Key) && !l.Key.Equal(k) {
		return bytes.Clone(l.Key)
	}
	return nil
}

// EdgeChanges is how many edge enrolments, revokes and cuts the log holds:
// an enrolment's anchor signs EdgeEnrollHash(EdgeChanges(), ...).
func (s *State) EdgeChanges() int { return s.edge.changes }

// candidateOK is the check a candidate passes, live and on replay: a hello
// that verifies, from a key never revoked, a minute after the last
// candidate and from another key. Whether the key is live is the kernel's
// check, since the fold knows no head key.
func (s *State) candidateOK(b edgeCandidate, at int64) error {
	if !edgeKey(b.Key) || len(b.Nonce) != HelloNonce || len(b.Sig) != ed25519.SignatureSize {
		return ErrEdgeKey
	}
	if !ed25519.Verify(b.Key, HelloMsg(b.Nonce), b.Sig) {
		return ErrEdgeHello
	}
	if s.EdgeRevoked(b.Key) {
		return ErrEdgeRevoked
	}
	if c := s.edge.cand; c != nil && (c.Key.Equal(b.Key) || at-s.edge.candAt < CandidateEvery) {
		return ErrEdgeBusy
	}
	return nil
}

// enrollOK is the check a later enrolment passes, live and on replay, at the
// head key it names.
func (s *State) enrollOK(b edgeEnrolled) error {
	if b.First || !edgeKey(b.Key) || !edgeKey(b.Head) || len(b.Replaces) != 0 && !edgeKey(b.Replaces) {
		return ErrEdgeKey
	}
	if s.EdgeRevoked(b.Key) {
		return ErrEdgeRevoked
	}
	if s.LiveEdge(b.Head).Equal(b.Key) {
		return ErrEdgeLive
	}
	if !s.PendingEdge(b.Head).Equal(b.Key) {
		return ErrEdgeCandidate
	}
	if !s.EdgeReplaces(b.Key).Equal(b.Replaces) || !key.In(s.Anchors, b.Sig.By) ||
		!b.Sig.Over(EdgeEnrollHash(s.edge.changes, b.Head, b.Key, b.Replaces)) {
		return ErrEdgeSig
	}
	return nil
}

// firstOK is the setup capture's place: sequence 2, right after the
// sequence-1 anchors.set, with no edge entry before it.
func (s *State) firstOK(e Entry, b edgeEnrolled) bool {
	return b.First && e.Seq == 2 && s.edge.setup && s.edge.changes == 0 && s.edge.cand == nil &&
		edgeKey(b.Key) && edgeKey(b.Head) && len(b.Replaces) == 0
}

// edgeDecision is the entry the state before e gives in e's place, when the
// kernel under head would log e at all (Rederive): an enrolment, or a
// candidate whose key is not live at head. The body is re-encoded from the
// decoded one, so a body the kernel would not have written diverges.
func (s *State) edgeDecision(e Entry, head ed25519.PublicKey) (derived, bool) {
	switch e.Type {
	case TEdgeEnrolled:
		b, err := body[edgeEnrolled](e)
		if err == nil && (s.firstOK(e, b) || s.enrollOK(b) == nil) {
			return entry(e.Type, b), true
		}
	case TEdgeCandidate:
		b, err := body[edgeCandidate](e)
		if err == nil && s.candidateOK(b, e.At) == nil && !s.LiveEdge(head).Equal(b.Key) {
			return entry(e.Type, b), true
		}
	}
	return derived{}, false
}

func (s *State) revoke(k ed25519.PublicKey) {
	if s.edge.revoked == nil {
		s.edge.revoked = map[string]bool{}
	}
	s.edge.revoked[string(k)] = true
	if s.edge.live != nil && s.edge.live.Key.Equal(k) {
		s.edge.live = nil
	}
}

// applyEdge folds an edge entry. A first key out of its place is not this
// box's log. An enrolment or candidate that fails its check, written past
// the kernel, changes nothing, so an audit trusts no writer for it.
func (s *State) applyEdge(e Entry) error {
	switch e.Type {
	case TEdgeEnrolled:
		b, err := body[edgeEnrolled](e)
		if err != nil {
			return err
		}
		if b.First {
			if !s.firstOK(e, b) {
				return fmt.Errorf("entry %d %s: a first edge key out of its place: %w", e.Seq, e.Type, ErrCorrupt)
			}
		} else if s.enrollOK(b) != nil {
			return nil
		}
		if len(b.Replaces) != 0 {
			s.revoke(b.Replaces)
		}
		s.edge.live, s.edge.last = &b, &b
		s.edge.changes++
	case TEdgeCandidate:
		b, err := body[edgeCandidate](e)
		if err != nil {
			return err
		}
		if s.candidateOK(b, e.At) == nil {
			s.edge.cand, s.edge.candAt = &b, e.At
		}
	case TEdgeRevoked:
		b, err := body[edgeRevoked](e)
		if err != nil {
			return err
		}
		if !edgeKey(b.Key) {
			return fmt.Errorf("entry %d %s: %w", e.Seq, e.Type, ErrCorrupt)
		}
		s.revoke(b.Key)
		s.edge.changes++
	case TEdgeCut:
		if _, err := body[edgeCut](e); err != nil {
			return err
		}
		s.edge.live = nil
		s.edge.changes++
	}
	return nil
}

// edgeFirst logs the key setup captured on the link port before the Owner
// Card confirm, right after anchors.set. Only Setup calls it.
func (k *Kernel) edgeFirst(now int64, edge ed25519.PublicKey) error {
	return k.owner(now, TEdgeEnrolled, edgeEnrolled{Key: edge, Head: k.Box(), First: true})
}

// LiveEdge is the edge key this core trusts now.
func (k *Kernel) LiveEdge() ed25519.PublicKey { return k.s.LiveEdge(k.log.cfg.Pub) }

// EdgeReplaces is the key enrolling edge would revoke (State.EdgeReplaces):
// the page step shows it and the hardware key signs over it.
func (k *Kernel) EdgeReplaces(edge ed25519.PublicKey) ed25519.PublicKey {
	return k.s.EdgeReplaces(edge)
}

// EdgeCandidate logs a hello the link process read on the link port: the
// edge's key, the connection's exporter value and the key's signature over
// HelloMsg. Only the link process's uid reaches it (kernel process). The
// live key's hello, a revoked key's, a bad one and any within a minute of the
// last candidate log nothing.
func (k *Kernel) EdgeCandidate(now int64, edge ed25519.PublicKey, nonce, sig []byte) error {
	if edgeKey(edge) && k.LiveEdge().Equal(edge) {
		return ErrEdgeLive
	}
	b := edgeCandidate{edge, nonce, sig}
	if err := k.s.candidateOK(b, now); err != nil {
		return err
	}
	_, err := k.emit(now, TEdgeCandidate, b)
	return err
}

// EdgeEnroll is the owner-page step: it makes edge, which must be the
// pending candidate, live on an anchor's signature c over
// EdgeEnrollHash(State.EdgeChanges(), Box(), edge, EdgeReplaces(edge)),
// revoking the last enrolled key in the same entry, after a restore or a cut
// too. It is a widening, so it anchors.
func (k *Kernel) EdgeEnroll(now int64, edge ed25519.PublicKey, c key.Cosign) error {
	b := edgeEnrolled{Key: edge, Head: k.Box(), Replaces: k.s.EdgeReplaces(edge), Sig: c}
	if err := k.s.enrollOK(b); err != nil {
		return err
	}
	return k.owner(now, TEdgeEnrolled, b)
}

// EdgeRevoke cuts edge for good with no replacement. It narrows, so it
// needs no signature.
func (k *Kernel) EdgeRevoke(now int64, edge ed25519.PublicKey) error {
	if !edgeKey(edge) {
		return ErrEdgeKey
	}
	if k.s.EdgeRevoked(edge) {
		return ErrEdgeRevoked
	}
	return k.owner(now, TEdgeRevoked, edgeRevoked{edge})
}

// EdgeCut stops trusting the live edge at a start the unlock step reports
// was not by this PC's TPM slot, naming that slot (§12.2). Only a page-step
// enrolment trusts an edge again. With nothing live it logs nothing.
func (k *Kernel) EdgeCut(now int64, slot string) error {
	if len(slot) == 0 || len(slot) > MaxSlot {
		return ErrEdgeSlot
	}
	for _, c := range []byte(slot) {
		if c < 0x21 || c > 0x7e {
			return ErrEdgeSlot
		}
	}
	if k.LiveEdge() == nil {
		return nil
	}
	return k.owner(now, TEdgeCut, edgeCut{slot})
}

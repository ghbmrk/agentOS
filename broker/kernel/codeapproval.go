package kernel

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Code approvals (CH-4, CH-10, D-226). The checker process holds the
// code-generator seed (CLK-1 exceptions); on a verified code it signs an
// approval of exact held steps with its own Ed25519 key, which the kernel
// knows from the store's pins (PinChecker), never from the owner socket. The
// approval is the owner's normal approval of each step it names, which KEY-8
// puts in place of the hold window: the step is sent at once, under every
// other check of its key, and nothing else changes. It widens no key (KEY-4):
// a step it names is already held under a key that covers it. It names no
// reveal-or-create-secret step, alone or in a batch (VRB-1).

// TCodeApproved logs a code approval.
const TCodeApproved = "code.approved"

// DomainCode is what the checker signs an approval under.
const DomainCode = "agentos.code.v1\x00"

// MaxCodeSteps bounds the steps one code approves (checker.MaxActs).
const MaxCodeSteps = 64

var (
	ErrNoChecker    = errors.New("kernel: no checker key is pinned, so no code approves a step")
	ErrCodeApproval = errors.New("kernel: a code approval is the checker's signature over distinct held steps, none a secret one")
)

// CodeStep names one step of a logged plan, and the plan by its bytes.
type CodeStep struct {
	Plan  string   `json:"plan"`
	Index int      `json:"index"`
	Hash  [32]byte `json:"hash"` // PlanHash of the plan
}

// CodeApproval is the checker's signature, By, over its steps (CodeMsg).
type CodeApproval struct {
	Steps []CodeStep        `json:"steps"`
	By    ed25519.PublicKey `json:"by"`
	Sig   []byte            `json:"sig"`
}

// CodeStepOf names step i of p.
func CodeStepOf(p Plan, i int) CodeStep { return CodeStep{p.ID, i, PlanHash(p)} }

// CodeMsg is what the checker signs to approve steps.
func CodeMsg(steps []CodeStep) []byte {
	b, _ := json.Marshal(steps)
	h := sha256.Sum256(b)
	return append([]byte(DomainCode), h[:]...)
}

// SignCode is the checker's approval of steps.
func SignCode(checker ed25519.PrivateKey, steps []CodeStep) CodeApproval {
	return CodeApproval{steps, checker.Public().(ed25519.PublicKey), ed25519.Sign(checker, CodeMsg(steps))}
}

// PinChecker sets the checker's key, handed from the store's pins at boot.
func (k *Kernel) PinChecker(pub ed25519.PublicKey) {
	k.checker = append(ed25519.PublicKey(nil), pub...)
}

// ApproveCode logs a's approval of its steps, signed by the pinned checker.
// It anchors, like every widening (KRN-7).
func (k *Kernel) ApproveCode(now int64, a CodeApproval) error {
	if len(k.checker) != ed25519.PublicKeySize {
		return ErrNoChecker
	}
	if !k.checker.Equal(a.By) || !k.s.codeOK(a) {
		return ErrCodeApproval
	}
	return k.owner(now, TCodeApproved, a)
}

// codeOK checks a against the state: each step held, named once, of an
// active plan with the bytes it names, not yet approved and not a secret
// one, and the whole signed by a.By. The fold checks it again, so a step is
// approved once.
func (s *State) codeOK(a CodeApproval) bool {
	if len(a.Steps) == 0 || len(a.Steps) > MaxCodeSteps || len(a.By) != ed25519.PublicKeySize {
		return false
	}
	seen := map[stepRef]bool{}
	for _, c := range a.Steps {
		ref := stepRef{c.Plan, c.Index}
		p, st := s.step(ref)
		if seen[ref] || st == nil || p.Status != SActive || st.Phase != PHeld || st.Approved ||
			PlanHash(p.Plan) != c.Hash || p.Plan.Step(c.Index).Verb == key.RevealOrCreateSecret {
			return false
		}
		seen[ref] = true
	}
	return ed25519.Verify(a.By, CodeMsg(a.Steps), a.Sig)
}

func (s *State) applyCode(e Entry) error {
	a, err := body[CodeApproval](e)
	if err != nil {
		return err
	}
	if s.codeOK(a) {
		for _, c := range a.Steps {
			_, st := s.step(stepRef{c.Plan, c.Index})
			st.Approved = true
		}
	}
	return nil
}

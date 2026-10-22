package run

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"sync"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// OpenExit builds the exit clerk a clerk process serves: its Secrets from
// dir, the process's own directory, durable there, and the declaration
// checked as clerk.NewExit checks it. The sealer is the software AESSealer
// until STO-2 releases the real store key; until then only tests run one.
func OpenExit(dir string, s clerk.Sealer, d clerk.Declaration, anchors []ed25519.PublicKey, roots *x509.CertPool) (*clerk.Exit, error) {
	sec, err := OpenSecrets(dir, s)
	if err != nil {
		return nil, err
	}
	return clerk.NewExit(d, anchors, sec, roots)
}

// ExitHost is the exit clerk's process around its clerk (#2643 b): the
// kernel's steps go to the clerk, and the owner's Reconnect is a
// change-account step the owner approved. clerk.Exit.Reconnect trusts its
// caller to have proved the owner; out of the kernel's process, this is that
// caller, and the proof is the step's own key: a passkey's narrowing
// (key.Verified.ByOwner), checked by clerk.Verify against the kernel's view
// like every step. The new grant is a secret, so it never enters the log:
// the owner's side stages it on this process's owner socket, and the step
// names it by its SHA-256 digest (arg "value"; "target" is the clerk). Any
// other caller, or a step the owner did not approve, or one naming another
// grant, leaves the slot unchanged.
type ExitHost struct {
	x       *clerk.Exit
	name    string
	anchors []ed25519.PublicKey
	clock   clerk.Clock

	mu     sync.Mutex
	staged []byte          // the grant the owner's side staged; nil: none
	done   map[string]bool // change-account steps done, by idempotency key
}

// NewExitHost serves x, declared as d, whose keys chain to anchors.
func NewExitHost(x *clerk.Exit, d clerk.Declaration, anchors []ed25519.PublicKey) *ExitHost {
	return &ExitHost{x: x, name: d.Name, anchors: anchors, clock: d.Clock, done: map[string]bool{}}
}

// Detail codes for a change-account step the host refuses.
const (
	DNotApproved = "not-owner-approved" // the step's key is not a passkey's narrowing
	DNotStaged   = "grant-not-staged"   // no staged grant has the step's digest
	DNotThis     = "not-this-clerk"     // the step names another clerk
)

// Do runs r: a change-account step here, any other on the clerk.
func (h *ExitHost) Do(r kernel.Request, v kernel.View) kernel.Result {
	s := r.Step()
	if s.Verb != key.ChangeAccount {
		return h.x.Do(r, v)
	}
	vk, rf := clerk.Verify(h.anchors, h.name, h.x.Facts, h.clock.Now(), r, v)
	if rf != nil {
		return kernel.Result{Outcome: "failed", Detail: rf.Code}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.done[r.Idem()] {
		return kernel.Result{Outcome: "ok", Detail: "already done"}
	}
	switch {
	case !vk.ByOwner:
		return kernel.Result{Outcome: "failed", Detail: DNotApproved}
	case s.Args["target"].Value != h.name:
		return kernel.Result{Outcome: "failed", Detail: DNotThis}
	case h.staged == nil || grantDigest(h.staged) != s.Args["value"].Value:
		return kernel.Result{Outcome: "failed", Detail: DNotStaged}
	}
	if err := h.x.Reconnect(h.staged); err != nil {
		return kernel.Result{Outcome: "failed", Detail: clerk.DCredential}
	}
	clear(h.staged)
	h.staged = nil
	h.done[r.Idem()] = true
	return kernel.Result{Outcome: "ok"}
}

// Probe asks the clerk, except for a change-account step, which acts only
// here and only on this process's memory: done once it ran, and unknown
// otherwise, since a restart forgets the staged grant as well.
func (h *ExitHost) Probe(r kernel.Request, v kernel.View) string {
	if r.Step().Verb != key.ChangeAccount {
		return h.x.Probe(r, v)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.done[r.Idem()] {
		return "done"
	}
	return "unknown"
}

func grantDigest(g []byte) string {
	d := sha256.Sum256(g)
	return hex.EncodeToString(d[:])
}

// stage keeps g for the change-account step that names its digest, in place
// of any grant staged before.
func (h *ExitHost) stage(g []byte) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	clear(h.staged)
	h.staged = append([]byte(nil), g...)
	return grantDigest(g)
}

// ListenExitOwner opens the exit clerk process's owner socket, admitting
// only the owner side's uid.
func ListenExitOwner(path string, ownerUID int) (net.Listener, error) {
	return ListenKernel(path, ownerUID)
}

// ServeExitOwner answers the owner side's one call, stage, on ln until ln
// closes. The grant crosses only this socket, never the kernel's.
func ServeExitOwner(ln net.Listener, h *ExitHost) error {
	return serveConns(ln, maxConns, func(conn net.Conn) {
		serveOne(conn, func(op string, raw json.RawMessage) (json.RawMessage, error) {
			var g []byte
			if op != "stage" || json.Unmarshal(raw, &g) != nil || len(g) == 0 {
				return nil, errors.New("run: the exit owner socket has one call, stage, with a grant")
			}
			defer clear(g)
			return json.Marshal(h.stage(g))
		})
	})
}

// ExitOwner is the owner side's caller of the exit clerk's process.
type ExitOwner struct{ Conn }

// Stage hands the clerk the grant the owner's new sign-in gave and returns
// the digest a change-account step names it by.
func (o ExitOwner) Stage(grant []byte) (digest string, err error) {
	err = o.call("stage", grant, &digest)
	return
}

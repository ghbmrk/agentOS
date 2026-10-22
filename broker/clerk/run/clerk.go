package run

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"slices"
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
// caller. The new grant is a secret, so it never enters the log: the owner's
// side stages it on this process's owner socket for one plan, and the step
// names it by its SHA-256 digest (arg "value", and content its print;
// "target" is the clerk). The
// proof is the step's own key, checked by clerk.Verify against the kernel's
// view like every step: its last link is a passkey's exact approval of that
// step (exactApproval). Any other caller, a key the owner did not give for
// this grant, another plan, or a grant not staged leaves the slot unchanged.
type ExitHost struct {
	x       *clerk.Exit
	name    string
	anchors []ed25519.PublicKey
	clock   clerk.Clock

	mu     sync.Mutex
	staged staged          // the grant the owner's side staged; zero: none
	done   map[string]bool // change-account steps done, by idempotency key
}

// staged is a grant the owner's side staged for the one plan that approves
// it. A plan the owner cancelled cannot be submitted again under its ID
// (kernel.ErrDuplicatePlan), so a cancel retires the grant with it.
type staged struct {
	plan  string
	grant []byte
}

// NewExitHost serves x, declared as d, whose keys chain to anchors.
func NewExitHost(x *clerk.Exit, d clerk.Declaration, anchors []ed25519.PublicKey) *ExitHost {
	return &ExitHost{x: x, name: d.Name, anchors: anchors, clock: d.Clock, done: map[string]bool{}}
}

// Detail codes for a change-account step the host refuses.
const (
	DNotApproved = "not-owner-approved" // the key's last link is not a passkey's exact approval of this grant
	DNotStaged   = "grant-not-staged"   // no grant is staged for this plan with the step's digest
	DNotThis     = "not-this-clerk"     // the step names another clerk
)

// MaxApproval is how long after now an exact approval may last: the
// browser's window for the owner's tap (browser.MaxApproval, CLK-3).
const MaxApproval = 15 * 60 * 1000

// grantPrint is the content a change-account step carries for the grant
// with digest d. The host's facts vouch for it from the step's own value, so
// a key whose content set is {grantPrint(d)} covers a reconnect to d alone.
func grantPrint(d string) string { return "grant:" + d }

// facts is the clerk's reading of a step's claims, with a change-account
// step's content its grant's print (KEY-2, CLK-3).
func (h *ExitHost) facts(s key.Step) (string, []string, int64) {
	if s.Verb == key.ChangeAccount {
		return grantPrint(s.Args["value"].Value), nil, 0
	}
	return h.x.Facts(s)
}

// exactApproval reports whether ver, the plan key as clerk.Verify checked
// it, is the owner's approval of exactly this reconnect (OWN-9), the way the
// browser's submit approvals are (CLK-3): its last link is one a passkey
// signed for the key's holder (key.Narrow), and that link itself allows
// only change-account, only this grant's print as content, one use, and
// expires within MaxApproval of now. So a narrowing the owner gave for
// anything else does not reconnect, and the planner, which holds the key
// but no passkey, cannot widen one. The kernel enforces the link's caveats
// on the step; a passkey cut off since is refused by Verify (kernel.Live).
func exactApproval(ver *key.Verified, digest string, now int64) bool {
	if ver == nil || !ver.ByOwner {
		return false
	}
	var verb, named, once, brief bool
	for _, c := range ver.Key.Links[len(ver.Key.Links)-1].Caveats {
		switch c.Kind {
		case key.KVerbs:
			verb = verb || slices.Equal(c.Set, []string{string(key.ChangeAccount)})
		case key.KContent:
			named = named || slices.Equal(c.Set, []string{grantPrint(digest)})
		case key.KUses:
			once = once || c.N <= 1
		case key.KExpires:
			brief = brief || c.N <= now+MaxApproval
		}
	}
	return verb && named && once && brief
}

// Do runs r: a change-account step here, any other on the clerk.
func (h *ExitHost) Do(r kernel.Request, v kernel.View) kernel.Result {
	s := r.Step()
	if s.Verb != key.ChangeAccount {
		return h.x.Do(r, v)
	}
	now := h.clock.Now()
	vk, rf := clerk.Verify(h.anchors, h.name, h.facts, now, r, v)
	if rf != nil {
		return kernel.Result{Outcome: "failed", Detail: rf.Code}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.done[r.Idem()] {
		return kernel.Result{Outcome: "ok", Detail: "already done"}
	}
	digest := s.Args["value"].Value
	switch {
	case s.Args["target"].Value != h.name:
		return kernel.Result{Outcome: "failed", Detail: DNotThis}
	case !exactApproval(vk, digest, now):
		return kernel.Result{Outcome: "failed", Detail: DNotApproved}
	case h.staged.grant == nil || h.staged.plan != r.Plan.ID || grantDigest(h.staged.grant) != digest:
		return kernel.Result{Outcome: "failed", Detail: DNotStaged}
	}
	if err := h.x.Reconnect(h.staged.grant); errors.Is(err, errUnsynced) {
		// The new grant is on disk but not surely durable: whether the
		// step took effect is unknown, and the staged grant stays for a
		// RETRY under the same key (#2742 item 7).
		return kernel.Result{Outcome: "unknown"}
	} else if err != nil {
		return kernel.Result{Outcome: "failed", Detail: clerk.DCredential}
	}
	clear(h.staged.grant)
	h.staged = staged{}
	h.done[r.Idem()] = true
	return kernel.Result{Outcome: "ok"}
}

// Probe asks the clerk, except for a change-account step, which acts only
// here and only on this process's memory: done once it ran, and unknown
// otherwise, since a restart forgets the staged grant as well.
func (h *ExitHost) Probe(r kernel.Request, v kernel.View) kernel.Result {
	if r.Step().Verb != key.ChangeAccount {
		return h.x.Probe(r, v)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.done[r.Idem()] {
		return kernel.Result{Outcome: "done"}
	}
	return kernel.Result{Outcome: "unknown"}
}

func grantDigest(g []byte) string {
	d := sha256.Sum256(g)
	return hex.EncodeToString(d[:])
}

// ErrBadGrant refuses, at stage, a grant the clerk's Reconnect could not
// take, so the owner learns it before the tap and the hold rather than
// after them as a credential failure (#2742 item 6). Its words are fixed:
// never the grant's.
var ErrBadGrant = errors.New("run: the new sign-in gave a grant this clerk cannot use; nothing was staged")

// stage keeps g for plan's change-account step, in place of any grant
// staged before, and returns its digest. A grant the clerk could not take
// is refused (ErrBadGrant) and changes nothing.
func (h *ExitHost) stage(plan string, g []byte) (string, error) {
	if h.x.CheckGrant(g) != nil {
		return "", ErrBadGrant
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	clear(h.staged.grant)
	h.staged = staged{plan, append([]byte(nil), g...)}
	return grantDigest(g), nil
}

type stageArgs struct {
	Plan  string `json:"plan"`
	Grant []byte `json:"grant"`
}

// ListenExitOwner opens the exit clerk process's owner socket, admitting
// only the owner side's uid, which is never the planner's.
func ListenExitOwner(path string, ownerUID int) (net.Listener, error) {
	return ListenKernel(path, ownerUID)
}

// ServeExitOwner answers the owner side's one call, stage, on ln until ln
// closes. The grant crosses only this socket, never the kernel's.
func ServeExitOwner(ln net.Listener, h *ExitHost) error {
	return serveConns(ln, maxConns, func(conn net.Conn) {
		serveOne(conn, func(op string, raw json.RawMessage) (json.RawMessage, error) {
			var a stageArgs
			if op != "stage" || json.Unmarshal(raw, &a) != nil || a.Plan == "" || len(a.Grant) == 0 {
				return nil, errors.New("run: the exit owner socket has one call, stage, with a plan and a grant")
			}
			defer clear(a.Grant)
			d, err := h.stage(a.Plan, a.Grant)
			if err != nil {
				return nil, err
			}
			return json.Marshal(d)
		})
	})
}

// ExitOwner is the owner side's caller of the exit clerk's process.
type ExitOwner struct{ Conn }

// Stage hands the clerk the grant the owner's new sign-in gave, for the plan
// whose change-account step the owner approves, and returns the digest that
// step names it by.
func (o ExitOwner) Stage(plan string, grant []byte) (digest string, err error) {
	err = o.call("stage", stageArgs{plan, grant}, &digest)
	return
}

// Package follow is the switch the follow clerk runs (followclerk; UPD-2,
// UPD-8, CH-10): it switches the root of trust the box takes updates from
// to the root the owner approved on the local page, and alerts the owner
// at once.
//
// The page shows a root's summary (Describe) and holds its bytes under the
// summary's digest; the owner's tier-4 approval names only that digest and
// the owner's name for the fork, so the clerk follows exactly the bytes the
// owner saw. Expiry is judged by the clock
// guard's Latest, never the wall clock (WF2). An empty name, switching
// back, is admitted only for the project's own root (WF1'): one with the
// root keys of the newest project root the box trusted (the image's, until
// the box leaves the project), or one the owner's root files chain to from
// it through TUF root rotations (update.ProjectRoot, OSS-10w-r).
package follow

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/clock"
	"github.com/ghbmrk/agentos/broker/durable"
	"github.com/ghbmrk/agentos/broker/maintain"
	"github.com/ghbmrk/agentos/broker/update"
)

// ProjectName is how the alert names the project's own chain.
const ProjectName = "the AgentOS project"

// MaxHeld bounds the roots the page holds between showing and approval.
const MaxHeld = 4

// Store is the part of update.Store the executor uses.
type Store interface {
	// FollowProject switches back, checking under the store's lock that
	// root is the project's (update.Store.FollowProject).
	FollowProject(root []byte, links [][]byte, shipped []byte, approved string, o update.Options) error
	// FollowFork follows a fork by name, refusing under the store's lock
	// a root that is the project's own (update.Store.FollowFork).
	FollowFork(root []byte, links [][]byte, shipped []byte, approved, name string, o update.Options) error
	Following() (update.Followed, error)
	TrustedRoot() ([]byte, error)
	// ProjectRoot is the newest project root the box trusted: the one it
	// trusts now while on the project chain, else the one it trusted when
	// it last left it, nil if it never recorded one.
	ProjectRoot() ([]byte, error)
}

// Clock is the HOST-1b clock guard's latest trustworthy time.
type Clock interface {
	Latest(ctx context.Context) (time.Time, clock.Status)
}

// Config is what the executor needs; New refuses a Config missing any part.
type Config struct {
	Store Store
	// Shipped is the root the image ships: the project's own root, until
	// the box records a newer one (Store.ProjectRoot).
	Shipped []byte
	Clock   Clock
	// Options are the update options; Now is always replaced by Latest.
	Options update.Options
	// Alert sends the owner a message on their channel.
	Alert func(ctx context.Context, text string) error
	// Pending is the file that holds an alert not yet sent, so a restart
	// before it goes out neither drops it nor hides it from STATUS.
	Pending string
}

// Executor follows held roots. It is safe for concurrent use.
type Executor struct {
	cfg Config

	mu    sync.Mutex
	held  map[string]held
	order []string
	// unsent is the last alert not yet sent, until it is (RetryAlert); a
	// later switch's alert replaces it. Config.Pending mirrors it.
	unsent string
}

// held is a root the page showed and the root files brought with it, the
// rotation chain a switch back may walk (OSS-10w-r).
type held struct {
	root  []byte
	chain [][]byte
}

// UnsentPrefix starts STATUS's line for an alert not yet sent (Note).
const UnsentPrefix = "Not yet texted to you: "

// New fails closed: without every part there is no executor.
func New(c Config) (*Executor, error) {
	if c.Store == nil || c.Clock == nil || c.Alert == nil || len(c.Shipped) == 0 || c.Pending == "" {
		return nil, errors.New("follow: store, shipped root, clock guard, alert and pending file are all required")
	}
	if _, err := update.RootDigest(c.Shipped); err != nil {
		return nil, fmt.Errorf("follow: shipped root: %v", err)
	}
	// An alert a previous run could not send is still owed.
	b, err := os.ReadFile(c.Pending)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("follow: pending alert: %v", err)
	}
	return &Executor{cfg: c, held: map[string]held{}, unsent: string(b)}, nil
}

// setUnsent records text as the alert owed, on disk first; "" clears it.
// The caller holds mu.
func (x *Executor) setUnsent(text string) error {
	x.unsent = text
	if text == "" {
		if err := os.Remove(x.cfg.Pending); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return durable.WriteFile(x.cfg.Pending, []byte(text), 0o600)
}

func (x *Executor) options(now time.Time) update.Options {
	o := x.cfg.Options
	o.Now = func() time.Time { return now }
	return o
}

func (x *Executor) latest(ctx context.Context) time.Time {
	t, _ := x.cfg.Clock.Latest(ctx)
	return t
}

// Describe verifies a root as the switch will, at Latest, and holds its
// bytes under the summary's digest for the owner's approval. The oldest
// held root goes once MaxHeld are held. chain is the other root files the
// owner brought with it, for a switch back across a rotation; describing
// the same root again replaces them.
func (x *Executor) Describe(ctx context.Context, root []byte, chain ...[]byte) (update.RootSummary, error) {
	if len(chain) > update.MaxRootRotations {
		return update.RootSummary{}, fmt.Errorf("%w: more than %d root files", update.ErrNotProject, update.MaxRootRotations)
	}
	sum, err := update.DescribeRoot(root, x.options(x.latest(ctx)))
	if err != nil {
		return update.RootSummary{}, err
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if _, ok := x.held[sum.Digest]; !ok {
		x.order = append(x.order, sum.Digest)
		if len(x.order) > MaxHeld {
			delete(x.held, x.order[0])
			x.order = x.order[1:]
		}
	}
	h := held{root: bytes.Clone(root)}
	for _, c := range chain {
		h.chain = append(h.chain, bytes.Clone(c))
	}
	x.held[sum.Digest] = h
	return sum, nil
}

// Project reports whether the held root with this digest is the
// project's own at Latest (WF1'): the only root a switch back (an empty
// name) is admitted for. The page asks it at describe time so it never
// offers a switch back Execute would refuse. A root no longer held is not
// the project's.
func (x *Executor) Project(ctx context.Context, digest string) bool {
	x.mu.Lock()
	h, ok := x.held[digest]
	x.mu.Unlock()
	return ok && x.project(h, x.latest(ctx)) == nil
}

// project walks from the newest project root the box trusted (the one it
// trusts now while on the project chain), or the shipped one, to h's root
// through h's chain (update.ProjectRoot).
func (x *Executor) project(h held, now time.Time) error {
	anchor, err := x.cfg.Store.ProjectRoot()
	if err != nil {
		return err
	}
	if anchor == nil {
		anchor = x.cfg.Shipped
	}
	return update.ProjectRoot(anchor, h.root, h.chain, x.options(now))
}

func (x *Executor) alert(ctx context.Context, name string, at time.Time) string {
	if name == "" {
		name = ProjectName
	}
	text := maintain.FollowAlert(name, at)
	// Saved before it is sent: a restart in between still owes it.
	x.mu.Lock()
	err := x.setUnsent(text)
	x.mu.Unlock()
	if !x.send(ctx, text) {
		if err != nil {
			return "; alert not sent yet, held for retry until restart (not saved: " + err.Error() + ")"
		}
		return "; alert not sent yet, held for retry"
	}
	return "; owner alerted"
}

// send sends text and, once it is sent, clears it as the unsent alert
// unless a later alert replaced it. A crash between sending and clearing
// sends it again after the restart: at least once, never dropped.
func (x *Executor) send(ctx context.Context, text string) bool {
	if err := x.cfg.Alert(ctx, text); err != nil {
		return false
	}
	x.mu.Lock()
	if x.unsent == text {
		// A file left behind is sent again after a restart: a duplicate,
		// not a loss.
		_ = x.setUnsent("")
	}
	x.mu.Unlock()
	return true
}

// RetryAlert sends the unsent alert, if any, and reports whether it went.
// agentosd calls it each minute.
func (x *Executor) RetryAlert(ctx context.Context) bool {
	x.mu.Lock()
	text := x.unsent
	x.mu.Unlock()
	return text != "" && x.send(ctx, text)
}

// Note is STATUS's line while an alert is unsent (control.Handler.Notes),
// so the owner learns of the switch on the page or by STATUS even while
// the text cannot go out.
func (x *Executor) Note() string {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.unsent == "" {
		return ""
	}
	return UnsentPrefix + x.unsent
}

// Switched is how a switch ended.
type Switched int

const (
	NotSwitched     Switched = iota // nothing changed
	SwitchedOK                      // the box follows the root under the name
	SwitchedUnknown                 // the root may be in place with the switch unfinished
)

// Switch switches to the held root digest names, under name ("" switches
// back to the project's own root), judging expiry at Latest. The text is
// the plain-words evidence either way.
func (x *Executor) Switch(ctx context.Context, digest, name string) (Switched, string) {
	x.mu.Lock()
	h, ok := x.held[digest]
	x.mu.Unlock()
	if !ok {
		return NotSwitched, "the page no longer holds the root that was approved; show it again"
	}
	root := h.root
	now := x.latest(ctx)
	var err error
	if name == "" {
		// Checked under the store's lock, against the anchor at the
		// moment of the switch (security 4a on #667).
		err = x.cfg.Store.FollowProject(root, h.chain, x.cfg.Shipped, digest, x.options(now))
		if errors.Is(err, update.ErrNotProject) {
			return NotSwitched, "switching back needs the project's own root: its root keys, or the root files that rotate to it from the last project root I trusted (" + err.Error() + ")"
		}
	} else {
		err = x.cfg.Store.FollowFork(root, h.chain, x.cfg.Shipped, digest, name, x.options(now))
		if errors.Is(err, update.ErrIsProject) {
			return NotSwitched, "this is the project's own root: switch back to the project instead of following it under a name"
		}
	}
	if err != nil {
		if cur, rerr := x.cfg.Store.TrustedRoot(); rerr != nil || bytes.Equal(cur, root) {
			return SwitchedUnknown, err.Error()
		}
		return NotSwitched, err.Error()
	}
	return SwitchedOK, "now following root " + digest + x.alert(ctx, name, now)
}

// Settled reads the box's own trusted root, not the held one (after a
// restart nothing is held): SwitchedOK when the box trusts digest under
// name. TrustedRoot first completes or forgets a switch a crash
// interrupted, so when the box trusts neither the root nor the source,
// this switch is not in place now: the journal's broker-account fence
// holds every other switch while one is unresolved, and a root rotation
// keeps the source (#1372). The kernel has no such fence, so the follow
// clerk judges "not in place" against its own record of the step
// (followclerk). When only one of them matches, it cannot tell.
func (x *Executor) Settled(digest, name string) (Switched, string) {
	cur, err := x.cfg.Store.TrustedRoot()
	if err != nil {
		return SwitchedUnknown, err.Error()
	}
	d, err := update.RootDigest(cur)
	if err != nil {
		return SwitchedUnknown, err.Error()
	}
	src, err := x.cfg.Store.Following()
	if err != nil {
		return SwitchedUnknown, err.Error()
	}
	switch {
	case d == digest && src.Name == name:
		return SwitchedOK, "now following root " + digest
	case d != digest && src.Name != name:
		return NotSwitched, "I trust neither that root nor that source now"
	}
	return SwitchedUnknown, "I do not trust that root under that name"
}

// Realert sends the owner the switch's alert again, at Latest (at least
// once, OWN-4), and says whether it went.
func (x *Executor) Realert(ctx context.Context, name string) string {
	return x.alert(ctx, name, x.latest(ctx))
}

// Latest is the clock guard's latest trustworthy time, the follow clerk's
// own clock (WF2).
func (x *Executor) Latest(ctx context.Context) time.Time { return x.latest(ctx) }

// Current is the root digest the box trusts and the name of the source it
// follows ("" for the project's own root).
func (x *Executor) Current() (digest, name string, err error) {
	cur, err := x.cfg.Store.TrustedRoot()
	if err != nil {
		return "", "", err
	}
	if digest, err = update.RootDigest(cur); err != nil {
		return "", "", err
	}
	src, err := x.cfg.Store.Following()
	if err != nil {
		return "", "", err
	}
	return digest, src.Name, nil
}

// Package follow is the executor for meta.update.follow (OSS-10, GR26): it
// switches the root of trust the box takes updates from to the root the
// owner approved on the local page, and alerts the owner at once.
//
// The page shows a root's summary (Describe) and holds its bytes under the
// summary's digest; the owner's tier-4 intent names only that digest and
// the owner's name for the fork (grants.FollowIntent), so the executor
// follows exactly the bytes the owner saw. Expiry is judged by the clock
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
	"path/filepath"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/clock"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
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
	return writeAtomic(x.cfg.Pending, []byte(text))
}

// writeAtomic replaces path with b so a crash leaves the old or the new
// file, never part of one.
func writeAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pending-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
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

// parse reads what an intent asks for: the digest and the name. why is set
// when the intent is not a well-formed follow.
func parse(in journal.Intent) (digest, name, why string) {
	if in.Action != journal.ActionUpdateFollow {
		return "", "", "not a request to change where updates come from"
	}
	digest, name, ok := grants.FollowOf(in.ID)
	if !ok {
		return "", "", "malformed request to change where updates come from"
	}
	return digest, name, ""
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

// Execute switches to the held root the intent's digest names.
func (x *Executor) Execute(ctx context.Context, in journal.Intent, _ int) journal.Outcome {
	digest, name, why := parse(in)
	if why != "" {
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: why}
	}
	x.mu.Lock()
	h, ok := x.held[digest]
	x.mu.Unlock()
	if !ok {
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "the page no longer holds the root that was approved; show it again"}
	}
	root := h.root
	now := x.latest(ctx)
	var err error
	if name == "" {
		// Checked under the store's lock, against the anchor at the
		// moment of the switch (security 4a on #667).
		err = x.cfg.Store.FollowProject(root, h.chain, x.cfg.Shipped, digest, x.options(now))
		if errors.Is(err, update.ErrNotProject) {
			return journal.Outcome{Result: journal.ResultNotApplied,
				Evidence: "switching back needs the project's own root: its root keys, or the root files that rotate to it from the last project root I trusted (" + err.Error() + ")"}
		}
	} else {
		err = x.cfg.Store.FollowFork(root, h.chain, x.cfg.Shipped, digest, name, x.options(now))
		if errors.Is(err, update.ErrIsProject) {
			return journal.Outcome{Result: journal.ResultNotApplied,
				Evidence: "this is the project's own root: switch back to the project instead of following it under a name"}
		}
	}
	if err != nil {
		if cur, rerr := x.cfg.Store.TrustedRoot(); rerr != nil || bytes.Equal(cur, root) {
			// The root may be in place with the switch unfinished:
			// Reconcile decides.
			return journal.Outcome{Result: journal.ResultUnknown, Evidence: err.Error()}
		}
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: err.Error()}
	}
	return journal.Outcome{Result: journal.ResultSucceeded, Evidence: "now following root " + digest + x.alert(ctx, name, now)}
}

// Reconcile reports a switch done when the box trusts the root the intent
// approved, under the intent's name, and alerts again (at least once). It
// reads the box's own trusted root, not the held one: after a restart
// nothing is held.
func (x *Executor) Reconcile(ctx context.Context, in journal.Intent, _ int) journal.Outcome {
	digest, name, why := parse(in)
	if why != "" {
		return journal.Outcome{Result: journal.ResultUnknown, Evidence: why}
	}
	cur, err := x.cfg.Store.TrustedRoot()
	if err != nil {
		return journal.Outcome{Result: journal.ResultUnknown, Evidence: err.Error()}
	}
	d, err := update.RootDigest(cur)
	if err != nil {
		return journal.Outcome{Result: journal.ResultUnknown, Evidence: err.Error()}
	}
	src, err := x.cfg.Store.Following()
	if err != nil || d != digest || src.Name != name {
		return journal.Outcome{Result: journal.ResultUnknown, Evidence: "I do not trust that root under that name"}
	}
	return journal.Outcome{Result: journal.ResultSucceeded, Evidence: "now following root " + digest + x.alert(ctx, name, x.latest(ctx))}
}

// Route shares the "update" executor name between following and release
// activation (apply): follows go to f, everything else to other. Without
// other, nothing but a follow runs.
func Route(f *Executor, other journal.Executor) journal.Executor {
	return router{f, other}
}

type router struct {
	f     *Executor
	other journal.Executor
}

func (r router) pick(in journal.Intent) journal.Executor {
	if in.Action == journal.ActionUpdateFollow {
		return r.f
	}
	return r.other
}

func (r router) Execute(ctx context.Context, in journal.Intent, attempt int) journal.Outcome {
	x := r.pick(in)
	if x == nil {
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "no executor for " + in.Action}
	}
	return x.Execute(ctx, in, attempt)
}

func (r router) Reconcile(ctx context.Context, in journal.Intent, attempt int) journal.Outcome {
	x := r.pick(in)
	if x == nil {
		return journal.Outcome{Result: journal.ResultUnknown, Evidence: "no executor for " + in.Action}
	}
	return x.Reconcile(ctx, in, attempt)
}

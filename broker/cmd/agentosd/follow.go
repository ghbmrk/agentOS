package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/clock"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/follow"
	"github.com/ghbmrk/agentos/broker/follow/followclerk"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
	"github.com/ghbmrk/agentos/broker/localapi"
	ownerch "github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/update"
)

// followSetting is changing where updates come from (OSS-10, GR26): the
// follow executor over the box's update store and the root the image
// ships, on the HOST-1b clock guard's Latest (WF2), alerting the owner on
// their channel. The page describes the root (WF3), so it is wired only
// when agentosd serves the page. The switch is the follow clerk's
// (followclerk, CH-10, KRN-4), which agentosd hosts for the kernel over
// the same executor, so it switches only to a root the page holds; the
// journal's update executor is retired (#3430).
type followSetting struct {
	x     *follow.Executor
	guard func() *clock.Guard
	owner atomic.Pointer[ownerch.Channel]
	// post, in tests only, takes the owner's alert in place of the channel.
	post func(text string) error
}

// pendingAlert names the file in the update store dir that holds a follow
// alert not yet sent, so a restart still owes it (OSS-10w2 L3).
const pendingAlert = "follow-alert-pending"

// alertRetry is how often an alert that could not be sent is tried again.
const alertRetry = time.Minute

// newFollowSetting is nil, with no error, when neither the store nor the
// shipped root is named: nothing is followed and the page's follow ops
// are refused. One without the other, or a store not yet initialised from
// the shipped root, is an error.
func newFollowSetting(storeDir, shippedPath string, guard func() *clock.Guard) (*followSetting, error) {
	switch {
	case storeDir == "" && shippedPath == "":
		return nil, nil
	case storeDir == "" || shippedPath == "":
		return nil, errors.New("-update-store and -shipped-root go together")
	}
	shipped, err := os.ReadFile(shippedPath)
	if err != nil {
		return nil, err
	}
	st := &update.Store{Dir: storeDir}
	if _, err := st.TrustedRoot(); err != nil {
		return nil, fmt.Errorf("update store %s: %v", storeDir, err)
	}
	s := &followSetting{guard: guard}
	s.x, err = follow.New(follow.Config{Store: st, Shipped: shipped, Clock: guardClock{guard}, Alert: s.alert,
		Pending: filepath.Join(storeDir, pendingAlert)})
	if err != nil {
		return nil, err
	}
	return s, nil
}

// wire serves the page's describe op and the RETRY line of a parked
// follow step. It reports whether it wired anything.
func (s *followSetting) wire(cfg *daemon.Config) bool {
	if s == nil || cfg.PageSocket == nil {
		return false
	}
	cfg.PageSocket.DescribeRoot = s.describe
	if cfg.KernelRetryLines == nil {
		cfg.KernelRetryLines = map[string]func() (string, string){}
	}
	cfg.KernelRetryLines[followclerk.Name] = s.retryLine
	// An alert not yet sent shows on STATUS until it is (OSS-10w L3).
	cfg.Notes = append(cfg.Notes, s.x.Note)
	return true
}

// retryLine is a parked follow step's RETRY line: what the box follows at
// this ask, read from its own store, and that RETRY would replace it. A
// step parked before a later follow approval would undo that approval if
// retried (#3444's reviews), and the owner reads that here.
func (s *followSetting) retryLine() (object, detail string) {
	const replaces = "RETRY replaces it"
	name, digest, err := s.x.Following()
	if err != nil {
		return "updates, source unread", "RETRY replaces what I follow now"
	}
	if name == "" {
		name = "the project"
	}
	return "updates, now from " + name, "root " + digest[:12] + "; " + replaces
}

// followClerkFlags checks -follow-clerk and -follow-anchors: both or
// neither, as absolute paths, and only beside the follow setting and the
// kernel's uid, the one peer the clerk's socket admits.
func followClerkFlags(sock, anchors string, kernelUID int, s *followSetting) error {
	switch {
	case sock == "" && anchors == "":
		return nil
	case sock == "" || anchors == "":
		return errors.New("-follow-clerk and -follow-anchors go together")
	case !filepath.IsAbs(sock) || !filepath.IsAbs(anchors):
		return errors.New("-follow-clerk and -follow-anchors must be absolute paths")
	case s == nil:
		return errors.New("-follow-clerk needs -update-store and -shipped-root")
	case kernelUID <= 0:
		return errors.New("-follow-clerk needs -kernel-uid, the only peer it admits")
	}
	return nil
}

// serveClerk hosts the follow clerk for the kernel on sock, admitting only
// kernelUID, under the owner's anchors read from anchorsPath, a file only
// owner (root on a box) writes (D-146). proc.ServeClerk serves one call at
// a time, so Do and Probe never overlap. The socket is open when it
// returns; it serves until ctx ends.
func (s *followSetting) serveClerk(ctx context.Context, sock, anchorsPath string, owner, kernelUID int, logf func(string, ...any)) error {
	anchors, err := readAnchors(anchorsPath, owner)
	if err != nil {
		return err
	}
	ln, err := proc.ListenClerk(sock, kernelUID)
	if err != nil {
		return fmt.Errorf("follow clerk: %v", err)
	}
	c := followclerk.New(s.x, anchors)
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	go func() {
		if err := proc.ServeClerk(ln, c, anchors); err != nil && ctx.Err() == nil {
			logf("follow clerk: %v", err)
		}
	}()
	return nil
}

// maxAnchorsFile bounds the anchors file, as the mail clerk's.
const maxAnchorsFile = 16 << 10

// readAnchors reads the owner's anchors from path, which must be a regular
// file, not a link, owned by owner and writable by no one else, in a
// directory the same holds for: so neither the kernel's uid nor any other
// can put anchors of its own there (D-146, as agentos-clerk-mail's).
func readAnchors(path string, owner int) ([]key.PublicKey, error) {
	refuse := func(why string) error {
		return fmt.Errorf("follow clerk: the owner's anchors at %s: %s", path, why)
	}
	rootOnly := func(fi os.FileInfo, dir bool) bool {
		st, ok := fi.Sys().(*syscall.Stat_t)
		return ok && fi.IsDir() == dir && (dir || fi.Mode().IsRegular()) && int(st.Uid) == owner && fi.Mode().Perm()&0o022 == 0
	}
	fi, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return nil, refuse(err.Error())
	}
	if !rootOnly(fi, true) {
		return nil, refuse("its directory is not root's alone")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, refuse(err.Error())
	}
	defer f.Close()
	if fi, err = f.Stat(); err != nil {
		return nil, refuse(err.Error())
	}
	if !rootOnly(fi, false) {
		return nil, refuse("not a file root alone writes")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxAnchorsFile+1))
	if err != nil {
		return nil, refuse(err.Error())
	}
	if len(b) > maxAnchorsFile {
		return nil, refuse("too long")
	}
	anchors, err := handoff.ParseAnchors(b)
	if err != nil {
		return nil, refuse("does not read as the owner's anchors")
	}
	return anchors, nil
}

// attach gives the alert the owner channel and retries an unsent alert
// until ctx is done.
func (s *followSetting) attach(ctx context.Context, d *daemon.Daemon) {
	if s == nil {
		return
	}
	if ch := d.Owner(); ch != nil {
		s.owner.Store(ch)
	}
	go func() {
		t := time.NewTicker(alertRetry)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.x.RetryAlert(ctx)
			}
		}
	}()
}

// alert is fixed broker wording (maintain.FollowAlert), so it goes as the
// broker's own text, not as an agent reply. It asks the owner to act if
// the switch was not theirs, so it is security class: never held
// (W5-Dc-r1b QH-9).
func (s *followSetting) alert(_ context.Context, text string) error {
	if s.post != nil {
		return s.post(text)
	}
	ch := s.owner.Load()
	if ch == nil {
		return errors.New("no owner channel")
	}
	return ch.Post(ownerch.ClassSecurity, text)
}

// errNoGuard: the clock guard has not started (or could not), so no root
// is described; the switch itself fails closed on guardClock.
var errNoGuard = errors.New("follow: the clock check is not running")

func (s *followSetting) describe(ctx context.Context, root []byte, chain [][]byte) (localapi.RootSummary, error) {
	if s.guard() == nil {
		return localapi.RootSummary{}, errNoGuard
	}
	sum, err := pageSummary(s.x.Describe(ctx, root, chain...))
	if err == nil {
		sum.Project = s.x.Project(ctx, sum.Digest)
	}
	return sum, err
}

// pageSummary is the summary as the page shows it. A refused root carries
// only its coarse cause, never the verifier's text (OSS-10w L3).
func pageSummary(sum update.RootSummary, err error) (localapi.RootSummary, error) {
	if err != nil {
		return localapi.RootSummary{Reason: rootReason(err)}, err
	}
	return localapi.RootSummary{Version: sum.Version, Keys: sum.Keys, Thresholds: sum.Thresholds,
		Expires: sum.Expires, Digest: sum.Digest}, nil
}

func rootReason(err error) string {
	switch {
	case errors.Is(err, update.ErrExpired):
		return localapi.RootExpired
	case errors.Is(err, update.ErrWeakThreshold):
		return localapi.RootThreshold
	case errors.Is(err, update.ErrSignatures):
		return localapi.RootSignatures
	}
	return ""
}

// guardClock is the guard's Latest. Before the guard runs it answers the
// far future, the stricter answer: every root reads as expired, so
// nothing is followed on an unchecked clock (WF2).
type guardClock struct{ g func() *clock.Guard }

var farFuture = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)

func (c guardClock) Latest(ctx context.Context) (time.Time, clock.Status) {
	if g := c.g(); g != nil {
		return g.Latest(ctx)
	}
	return farFuture, clock.Status{State: clock.Unchecked}
}

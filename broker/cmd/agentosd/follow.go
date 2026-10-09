package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/ghbmrk/agentos/broker/clock"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/follow"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/localapi"
	ownerch "github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/update"
)

// followSetting is changing where updates come from (OSS-10, GR26): the
// follow executor over the box's update store and the root the image
// ships, on the HOST-1b clock guard's Latest (WF2), alerting the owner on
// their channel. The page asks for it and confirms it (WF3), so it is
// wired only when agentosd serves the page.
type followSetting struct {
	x     *follow.Executor
	guard func() *clock.Guard
	owner atomic.Pointer[ownerch.Channel]
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

// wire serves the page's follow ops and registers the executor; release
// activation has no executor in this build, so only follows run under
// "update" (follow.Route). It reports whether it wired anything.
func (s *followSetting) wire(cfg *daemon.Config) bool {
	if s == nil || cfg.PageSocket == nil {
		return false
	}
	cfg.PageSocket.DescribeRoot = s.describe
	if cfg.BrokerExecutors == nil {
		cfg.BrokerExecutors = map[string]journal.Executor{}
	}
	cfg.BrokerExecutors[grants.FollowExecutor] = follow.Route(s.x, nil)
	// An alert not yet sent shows on STATUS until it is (OSS-10w L3).
	cfg.Notes = append(cfg.Notes, s.x.Note)
	return true
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
	ch := s.owner.Load()
	if ch == nil {
		return errors.New("no owner channel")
	}
	return ch.Post(ownerch.ClassSecurity, text)
}

// errNoGuard: the clock guard has not started (or could not), so no root
// is described; the switch itself fails closed on guardClock.
var errNoGuard = errors.New("follow: the box clock check is not running")

func (s *followSetting) describe(ctx context.Context, root []byte) (localapi.RootSummary, error) {
	if s.guard() == nil {
		return localapi.RootSummary{}, errNoGuard
	}
	sum, err := pageSummary(s.x.Describe(ctx, root))
	if err == nil {
		sum.Project = s.x.Project(sum.Digest)
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

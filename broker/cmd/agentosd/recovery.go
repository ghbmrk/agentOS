package main

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/backup"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/owner/kernelsock"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// The Recovery key page's ops (REC-4, BAK-1; MIG-4-recovery-r4a, route A
// of D-201; localsrv.Recovery). The page makes the new card and takes its
// confirm (agentosd links no card code), and only then asks Begin for the
// challenge; nothing reaches the kernel or the keeper before that. Rotate
// runs brief decision 6's order: the hardware key's tap (found among the
// kernel's anchors, as the Backups page's), the kernel's approval
// (recoveryrotate), the keeper's root one-shot over its socket, which
// opens the store with the owner's factor and writes the new slot and
// recipient in one commit, then the kernel's switch (recipient). The
// factor and the new key go to the keeper alone: the kernel sees recipient
// IDs and the approval, and no log line carries either.

// keeperRotateSock is the keeper's rotation socket
// (agentos-keeper-rotate.socket): root's one-shot, one connection each.
const keeperRotateSock = "/run/agentos-keeper/rotate.sock"

// recoveryApprovalFor is how long a route-A approval verifies (brief
// decision 3): the switch is retried with it until then.
const recoveryApprovalFor = 15 * time.Minute

// recoveryKernel is the owner seam the page's ops call (kernelsock.Owner).
type recoveryKernel interface {
	keyReader
	Backups(ctx context.Context) (kernelsock.BackupsView, error)
	RecoveryRotate(ctx context.Context, next string, c key.Cosign) ([]byte, error)
	SwitchRecipient(ctx context.Context, recipient, approval []byte) error
}

// rotationKeeper is the keeper's rotation one-shot: one request, one word
// (kernelsock.Keeper).
type rotationKeeper interface {
	Rotate(ctx context.Context, factor string, secret, next, approval []byte) (string, error)
}

// recoveryFlow serves the page's ops. A switch the kernel did not take
// after the keeper's write is kept, as the new recipient's wire form and
// the approval (neither secret), and retried by run until the approval
// lapses; the kernel's next start reads the recipient from the store too.
type recoveryFlow struct {
	K      recoveryKernel
	S      *backupSchedule
	Keeper rotationKeeper
	Now    func() time.Time

	mu      sync.Mutex
	pending *pendingSwitch
}

type pendingSwitch struct {
	wire, approval []byte
	until          time.Time
}

func newRecoveryFlow(k recoveryKernel, s *backupSchedule) *recoveryFlow {
	return &recoveryFlow{K: k, S: s, Keeper: kernelsock.Keeper{Socket: keeperRotateSock}, Now: time.Now}
}

// The log lines: fixed words, never a factor, a key or an approval.
const (
	LogRecoveryReplaced = "recovery key: replaced; the store holds the new key and backup recipient"
	LogRecoverySwitched = "recovery key: the kernel seals backups to the new key's recipient"
	LogRecoveryRetry    = "recovery key: the kernel has not taken the new recipient yet; I retry with the same approval"
	LogRecoveryLapsed   = "recovery key: the kernel did not take the new recipient before the approval lapsed; its next start reads it from the store"
)

// recoveryCode maps a kernel answer to the page's fixed codes.
func recoveryCode(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, kernelsock.ErrSetupOnly):
		return sockets.Code(localapi.ErrRecoverySetup)
	case errors.Is(err, kernelsock.ErrRotateSig), errors.Is(err, kernelsock.ErrApprovalStale), errors.Is(err, kernelsock.ErrApprovalExpired):
		// A tap that verified here over a recipient the kernel has moved
		// past, or an approval used or lapsed.
		return sockets.Code(localapi.ErrRecoveryStale)
	}
	return sockets.Code(localapi.ErrRecoveryUnavailable)
}

// keeperCode maps the keeper's word to the page's fixed codes; "ok" is nil.
func keeperCode(word string) error {
	switch word {
	case "ok":
		return nil
	case "factor":
		return sockets.Code(localapi.ErrRecoveryFactor)
	case "stale", "approval":
		return sockets.Code(localapi.ErrRecoveryStale)
	case "busy":
		return sockets.Code(localapi.ErrRecoveryBusy)
	}
	return sockets.Code(localapi.ErrRecoveryUnavailable)
}

// recoveryTapCode is tapper's passkey code as the recovery ops' own.
func recoveryTapCode(err error) error {
	var c sockets.Code
	errors.As(err, &c)
	switch string(c) {
	case localapi.ErrPasskeyNotAnchor:
		return sockets.Code(localapi.ErrRecoveryNotAnchor)
	case localapi.ErrPasskeyBadAssertion:
		return sockets.Code(localapi.ErrRecoveryBadAssertion)
	}
	return sockets.Code(localapi.ErrRecoveryUnavailable)
}

// change is the recipient IDs a rotation to next names: the one the
// kernel holds now (fresh), and next's.
func (f *recoveryFlow) change(ctx context.Context, next []byte) (old string, r backup.Recipient, err error) {
	if len(next) != localapi.RecoveryKeyLen {
		return "", backup.Recipient{}, sockets.Code(localapi.ErrBadArgs)
	}
	if r, err = backup.RecipientFor(next); err != nil {
		return "", backup.Recipient{}, sockets.Code(localapi.ErrRecoveryUnavailable)
	}
	if err := f.S.read(ctx); err != nil {
		return "", backup.Recipient{}, recoveryCode(err)
	}
	v, _ := f.S.snapshot()
	if v.Recipient == r.ID() {
		return "", backup.Recipient{}, sockets.Code(localapi.ErrBadArgs)
	}
	return v.Recipient, r, nil
}

// Begin returns the challenge over changing the kernel's recipient to
// next's. It asks the kernel for a read only.
func (f *recoveryFlow) Begin(ctx context.Context, next []byte) (localapi.RecoveryBegun, error) {
	old, r, err := f.change(ctx, next)
	if err != nil {
		return localapi.RecoveryBegun{}, err
	}
	ch := key.Challenge(kernelsock.RotateMsg(old, r.ID()))
	return localapi.RecoveryBegun{Old: old, Next: r.ID(), Challenge: ch[:]}, nil
}

// Rotate makes next the recovery key in brief decision 6's order; each
// refusal before the keeper's ok changed nothing.
func (f *recoveryFlow) Rotate(ctx context.Context, factor string, secret, next, authData, clientData, sig []byte) (localapi.RecoveryDone, error) {
	if factor != localapi.RecoveryFactorPassphrase && factor != localapi.RecoveryFactorRecovery {
		return localapi.RecoveryDone{}, sockets.Code(localapi.ErrBadArgs)
	}
	old, r, err := f.change(ctx, next)
	if err != nil {
		return localapi.RecoveryDone{}, err
	}
	anchors, live, _, err := ownerKeys(ctx, f.K)
	if err != nil {
		return localapi.RecoveryDone{}, recoveryCode(err)
	}
	by, canon, err := tapper(kernelsock.RotateMsg(old, r.ID()), anchors, live, authData, clientData, sig)
	if err != nil {
		return localapi.RecoveryDone{}, recoveryTapCode(err)
	}
	approval, err := f.K.RecoveryRotate(ctx, r.ID(), key.Cosign{By: by, Sig: canon})
	if err != nil {
		return localapi.RecoveryDone{}, recoveryCode(err)
	}
	word, err := f.Keeper.Rotate(ctx, factor, secret, next, approval)
	if err != nil {
		log.Printf("recovery key: the keeper did not answer: %v", err)
		return localapi.RecoveryDone{}, sockets.Code(localapi.ErrRecoveryUnavailable)
	}
	if err := keeperCode(word); err != nil {
		return localapi.RecoveryDone{}, err
	}
	log.Print(LogRecoveryReplaced)
	wire := append(append([]byte{}, r.X...), r.EK...)
	f.mu.Lock()
	f.pending = &pendingSwitch{wire: wire, approval: approval, until: f.Now().Add(recoveryApprovalFor)}
	f.mu.Unlock()
	switched := f.retry(ctx)
	// The schedule's next tick sees no backup that counts under the new
	// recipient, and takes one at once (e decision 6).
	f.S.read(ctx)
	return localapi.RecoveryDone{Switched: switched}, nil
}

// retry asks the kernel to switch to the kept recipient, and reports
// whether no switch is still owed. A refusal that names the approval
// (used for another recipient, or lapsed) or a lapsed wait drops it.
func (f *recoveryFlow) retry(ctx context.Context) bool {
	f.mu.Lock()
	p := f.pending
	f.mu.Unlock()
	if p == nil {
		return true
	}
	if !f.Now().Before(p.until) {
		f.drop(p, LogRecoveryLapsed)
		return false
	}
	err := f.K.SwitchRecipient(ctx, p.wire, p.approval)
	switch {
	case err == nil:
		f.drop(p, LogRecoverySwitched)
		return true
	case errors.Is(err, kernelsock.ErrApprovalStale), errors.Is(err, kernelsock.ErrApprovalExpired):
		f.drop(p, LogRecoveryLapsed)
		return false
	}
	log.Print(LogRecoveryRetry)
	return false
}

func (f *recoveryFlow) drop(p *pendingSwitch, line string) {
	f.mu.Lock()
	if f.pending == p {
		f.pending = nil
	}
	f.mu.Unlock()
	log.Print(line)
}

// run retries a kept switch every interval until ctx ends.
func (f *recoveryFlow) run(ctx context.Context, every time.Duration) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
		f.retry(ctx)
	}
}

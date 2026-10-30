package main

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/owner/kernelsock"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// The Recovery key page's lost-card ops (REC-4; MIG-4-recovery-r4b, route B
// of D-201). With no card factor the running box cannot open the store, so
// a hardware key's tap over RotateMsg(old, "") gets the kernel's route-B
// approval, which agentosd writes whole to the request file the unlock
// step reads at the next boot (agentos-keeper-kernel.service's
// -recovery-request). That step makes the new key, replaces the slot and
// recipient in one write and hands the card's bits to the kernel, which
// holds them until the page's confirm. agentosd keeps nothing: the request
// file is the approval (its integrity is the head key's signature), and
// the card's bits pass through to the page that prints them.

// lostRequest is the unlock step's request file, in agentosd's root-only
// state directory.
const lostRequest = "/var/lib/agentos/recovery-request"

// The log lines: fixed words, never an approval or a card.
const (
	LogLostFiled     = "recovery key: a lost-card request is filed for the next restart"
	LogLostWithdrawn = "recovery key: the lost-card request is withdrawn"
	LogLostRestart   = "recovery key: restarting for the lost-card request"
	LogLostDone      = "recovery key: the new card is confirmed; the kernel wiped its copy"
)

// recoveryOps is the Recovery key page's ops on agentosd: route A's and
// the lost card's (localsrv.Recovery).
type recoveryOps struct {
	*recoveryFlow
	*lostCard
}

// lostKernel is the owner seam the lost-card ops call (kernelsock.Owner).
type lostKernel interface {
	keyReader
	Backups(ctx context.Context) (kernelsock.BackupsView, error)
	RecoveryRotate(ctx context.Context, next string, c key.Cosign) ([]byte, error)
	RecoveryCard(ctx context.Context) ([]byte, error)
	RecoveryCardDone(ctx context.Context) error
}

// lostCard serves the lost-card ops. Request is the request file; Reboot
// restarts the box; Booted is when this boot began.
type lostCard struct {
	K       lostKernel
	S       *backupSchedule
	Request string
	Reboot  func(context.Context) error
	Booted  func() time.Time
}

func newLostCard(k lostKernel, s *backupSchedule) *lostCard {
	return &lostCard{K: k, S: s, Request: lostRequest, Reboot: startReboot, Booted: bootedAt}
}

// restartTrigger is the file agentos-recovery-restart.path watches: it
// starts the weekly reboot's unit. /run is emptied at every boot.
const restartTrigger = "/run/agentos-recovery-restart"

// startReboot writes the restart's trigger; agentosd starts no process.
func startReboot(context.Context) error {
	return privfile.WriteAtomic(filepath.Dir(restartTrigger), filepath.Base(restartTrigger), nil, nil)
}

// bootedAt is when this boot began, by the wall clock now; the zero time
// when /proc/uptime does not read.
func bootedAt() time.Time {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return time.Time{}
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return time.Time{}
	}
	up, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return time.Time{}
	}
	return time.Now().Add(-time.Duration(up * float64(time.Second)))
}

// old is the backup recipient the kernel holds now, fresh.
func (l *lostCard) old(ctx context.Context) (string, error) {
	if err := l.S.read(ctx); err != nil {
		return "", recoveryCode(err)
	}
	v, _ := l.S.snapshot()
	return v.Recipient, nil
}

// LostBegin returns the challenge over replacing old with a key made at
// the next restart. It asks the kernel for a read only.
func (l *lostCard) LostBegin(ctx context.Context) (localapi.RecoveryLostBegun, error) {
	old, err := l.old(ctx)
	if err != nil {
		return localapi.RecoveryLostBegun{}, err
	}
	ch := key.Challenge(kernelsock.RotateMsg(old, ""))
	return localapi.RecoveryLostBegun{Old: old, Challenge: ch[:]}, nil
}

// Lost files the kernel's route-B approval on a hardware key's tap; a
// phone passkey's is refused before the kernel is asked. A filed request
// is replaced: the newest tap is the one the next restart carries out.
func (l *lostCard) Lost(ctx context.Context, authData, clientData, sig []byte) error {
	old, err := l.old(ctx)
	if err != nil {
		return err
	}
	anchors, live, _, err := ownerKeys(ctx, l.K)
	if err != nil {
		return recoveryCode(err)
	}
	by, canon, err := tapper(kernelsock.RotateMsg(old, ""), anchors, live, authData, clientData, sig)
	if err != nil {
		return recoveryTapCode(err)
	}
	approval, err := l.K.RecoveryRotate(ctx, "", key.Cosign{By: by, Sig: canon})
	if err != nil {
		return recoveryCode(err)
	}
	if err := privfile.WriteAtomic(filepath.Dir(l.Request), filepath.Base(l.Request), approval, nil); err != nil {
		log.Printf("recovery key: file the lost-card request: %v", err)
		return sockets.Code(localapi.ErrRecoveryUnavailable)
	}
	log.Print(LogLostFiled)
	return nil
}

// LostState reports a filed request, one the last restart left (the unlock
// step removes each it carries out), and a card the kernel holds.
func (l *lostCard) LostState(ctx context.Context) (localapi.RecoveryLostState, error) {
	var st localapi.RecoveryLostState
	fi, err := os.Lstat(l.Request)
	switch {
	case err == nil:
		st.Filed = true
		st.Ignored = fi.ModTime().Before(l.Booted())
	case !errors.Is(err, os.ErrNotExist):
		return st, sockets.Code(localapi.ErrRecoveryUnavailable)
	}
	b, err := l.K.RecoveryCard(ctx)
	clear(b)
	switch {
	case err == nil:
		st.Ready = true
	case !errors.Is(err, kernelsock.ErrNoRecoveryCard):
		return st, recoveryCode(err)
	}
	return st, nil
}

// LostWithdraw removes a filed request; none is not an error.
func (l *lostCard) LostWithdraw(context.Context) error {
	if err := os.Remove(l.Request); err != nil && !errors.Is(err, os.ErrNotExist) {
		return sockets.Code(localapi.ErrRecoveryUnavailable)
	}
	log.Print(LogLostWithdrawn)
	return nil
}

// Restart restarts the box for a filed request; with none it refuses, so
// the page restarts the box only for this.
func (l *lostCard) Restart(ctx context.Context) error {
	st, err := l.LostState(ctx)
	if err != nil {
		return err
	}
	if !st.Filed || st.Ignored {
		return sockets.Code(localapi.ErrRecoveryStale)
	}
	if err := l.Reboot(ctx); err != nil {
		log.Printf("recovery key: restart: %v", err)
		return sockets.Code(localapi.ErrRecoveryUnavailable)
	}
	log.Print(LogLostRestart)
	return nil
}

// LostCard is the new card's bits the kernel holds, for the page to print.
func (l *lostCard) LostCard(ctx context.Context) ([]byte, error) {
	b, err := l.K.RecoveryCard(ctx)
	if errors.Is(err, kernelsock.ErrNoRecoveryCard) {
		return nil, sockets.Code(localapi.ErrRecoveryNoCard)
	}
	if err != nil {
		return nil, recoveryCode(err)
	}
	return b, nil
}

// LostDone has the kernel wipe the card once the owner confirmed it.
func (l *lostCard) LostDone(ctx context.Context) error {
	if err := l.K.RecoveryCardDone(ctx); err != nil {
		return recoveryCode(err)
	}
	log.Print(LogLostDone)
	return nil
}

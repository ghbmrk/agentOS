package main

import (
	"context"
	"encoding/json"
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
// holds them until the page's confirm. The kernel shows them only on a
// hardware key's tap over the card's ID, its backup recipient's, which the
// page prints on the card as its mark (#4128, #4160). agentosd keeps no
// secret: the request file is the approval (its integrity is the head
// key's signature), the card's bits pass through to the page that prints
// them, and the shown file keeps the ID of the last card a page showed,
// and whether it was confirmed, so the page can name the card in effect
// after the kernel has let it go.

// lostRequest is the unlock step's request file, in agentosd's root-only
// state directory.
const lostRequest = "/var/lib/agentos/recovery-request"

// lostShown is the shown file, beside it.
const lostShown = "/var/lib/agentos/recovery-card-shown"

// The log lines: fixed words, never an approval or a card.
const (
	LogLostFiled     = "recovery key: a lost-card request is filed for the next restart"
	LogLostWithdrawn = "recovery key: the lost-card request is withdrawn"
	LogLostRestart   = "recovery key: restarting for the lost-card request"
	LogLostShown     = "recovery key: the new card is shown on a hardware key's tap"
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
	RecoveryCardID(ctx context.Context) (string, error)
	RecoveryCard(ctx context.Context, c key.Cosign) ([]byte, error)
	RecoveryCardDone(ctx context.Context) error
}

// lostCard serves the lost-card ops. Request is the request file, Shown
// the shown file; Reboot restarts the box; Booted is when this boot began.
type lostCard struct {
	K       lostKernel
	S       *backupSchedule
	Request string
	Shown   string
	Reboot  func(context.Context) error
	Booted  func() time.Time
}

func newLostCard(k lostKernel, s *backupSchedule) *lostCard {
	return &lostCard{K: k, S: s, Request: lostRequest, Shown: lostShown, Reboot: startReboot, Booted: bootedAt}
}

// shown is the shown file's record: the ID of the last card a page showed
// and whether the owner confirmed it.
type shown struct {
	ID        string `json:"id"`
	Confirmed bool   `json:"confirmed"`
}

// readShown is the shown file's record; the zero record when there is
// none or it does not read as one.
func (l *lostCard) readShown() shown {
	var r shown
	b, err := os.ReadFile(l.Shown)
	if err != nil || json.Unmarshal(b, &r) != nil || len(r.ID) != localapi.RecoveryIDLen || strings.Trim(r.ID, "0123456789abcdef") != "" {
		return shown{}
	}
	return r
}

// writeShown records r; a failure is logged only, since it costs the page
// no more than naming the card in effect later.
func (l *lostCard) writeShown(r shown) {
	b, _ := json.Marshal(r)
	if err := privfile.WriteAtomic(filepath.Dir(l.Shown), filepath.Base(l.Shown), b, nil); err != nil {
		log.Printf("recovery key: record the card shown: %v", err)
	}
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
// step removes each it carries out), a card the kernel holds, and the last
// card a page showed: whether it was confirmed and is in effect.
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
	_, err = l.K.RecoveryCardID(ctx)
	switch {
	case err == nil:
		st.Ready = true
	case !errors.Is(err, kernelsock.ErrNoRecoveryCard):
		return st, recoveryCode(err)
	}
	if r := l.readShown(); r.ID != "" {
		old, err := l.old(ctx)
		if err != nil {
			return st, err
		}
		st.Shown, st.Confirmed, st.InEffect = r.ID, r.Confirmed, r.ID == old
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

// cardID is the ID of the card the kernel holds, or ErrRecoveryNoCard.
func (l *lostCard) cardID(ctx context.Context) (string, error) {
	id, err := l.K.RecoveryCardID(ctx)
	if errors.Is(err, kernelsock.ErrNoRecoveryCard) {
		return "", sockets.Code(localapi.ErrRecoveryNoCard)
	}
	if err != nil {
		return "", recoveryCode(err)
	}
	return id, nil
}

// LostCardBegin returns the challenge over seeing the card the kernel
// holds, and its ID. It reads no bits.
func (l *lostCard) LostCardBegin(ctx context.Context) (localapi.RecoveryLostCardBegun, error) {
	id, err := l.cardID(ctx)
	if err != nil {
		return localapi.RecoveryLostCardBegun{}, err
	}
	ch := key.Challenge(kernelsock.CardMsg(id))
	return localapi.RecoveryLostCardBegun{ID: id, Challenge: ch[:]}, nil
}

// LostCard is the new card's bits the kernel holds, for the page to print,
// on a hardware key's tap over CardMsg of its ID (#4128): a phone
// passkey's is refused before the kernel is asked, and the kernel checks
// the tap again. The shown file then names the card.
func (l *lostCard) LostCard(ctx context.Context, authData, clientData, sig []byte) (localapi.RecoveryLostCard, error) {
	id, err := l.cardID(ctx)
	if err != nil {
		return localapi.RecoveryLostCard{}, err
	}
	anchors, live, _, err := ownerKeys(ctx, l.K)
	if err != nil {
		return localapi.RecoveryLostCard{}, recoveryCode(err)
	}
	by, canon, err := tapper(kernelsock.CardMsg(id), anchors, live, authData, clientData, sig)
	if err != nil {
		return localapi.RecoveryLostCard{}, recoveryTapCode(err)
	}
	b, err := l.K.RecoveryCard(ctx, key.Cosign{By: by, Sig: canon})
	if errors.Is(err, kernelsock.ErrNoRecoveryCard) {
		return localapi.RecoveryLostCard{}, sockets.Code(localapi.ErrRecoveryNoCard)
	}
	if err != nil {
		return localapi.RecoveryLostCard{}, recoveryCode(err)
	}
	l.writeShown(shown{ID: id})
	log.Print(LogLostShown)
	return localapi.RecoveryLostCard{Card: b, ID: id}, nil
}

// LostDone has the kernel wipe the card once the owner confirmed it.
func (l *lostCard) LostDone(ctx context.Context) error {
	if err := l.K.RecoveryCardDone(ctx); err != nil {
		return recoveryCode(err)
	}
	if r := l.readShown(); r.ID != "" && !r.Confirmed {
		r.Confirmed = true
		l.writeShown(r)
	}
	log.Print(LogLostDone)
	return nil
}

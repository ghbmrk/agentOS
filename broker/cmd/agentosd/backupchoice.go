package main

import (
	"context"
	"errors"
	"log"

	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/owner/kernelsock"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// The Backups page's ops (BAK-1, BAK-2; MIG-4-recovery-e4b, #3390;
// localsrv.Backups). A destination is authority the kernel holds (where
// the box may connect), so adding one is a widening a hardware key signs:
// the page gathers the tap over key.CosignMsg(kernel.BackupTargetHash(n,
// t)) (kernelsock.TargetMsg), n the destinations the kernel has added so far, and the kernel
// checks it against its own anchors. Removing one narrows, so it needs no
// tap. agentosd signs nothing and keeps nothing; its checks only make the
// page's reply exact.

// backupChoiceKernel is the owner seam the page's ops call
// (kernelsock.Owner).
type backupChoiceKernel interface {
	keyReader
	Backups(ctx context.Context) (kernelsock.BackupsView, error)
	BackupTarget(ctx context.Context, t kernelsock.Target, c key.Cosign) error
	Untarget(ctx context.Context, name string) error
}

// backupChoice serves the Backups page from the kernel and the schedule's
// lines; S is re-read after each change, so STATUS and the page agree and
// the schedule's next tick takes a new destination's first backup.
type backupChoice struct {
	K backupChoiceKernel
	S *backupSchedule
}

// backupCode maps the kernel's answer to the page's fixed codes; no kernel
// text passes.
func backupCode(err error) error {
	var r kernelsock.Refused
	switch {
	case err == nil:
		return nil
	case errors.Is(err, kernelsock.ErrSetupOnly):
		return sockets.Code(localapi.ErrBackupSetup)
	case errors.Is(err, kernelsock.ErrTargetExists):
		return sockets.Code(localapi.ErrBackupNameTaken)
	case errors.Is(err, kernelsock.ErrTargetSig), errors.Is(err, kernelsock.ErrNoTarget):
		// A signature that verified here over a count the kernel has
		// moved past, or a removal another page made first.
		return sockets.Code(localapi.ErrBackupStale)
	case errors.As(err, &r):
		// The kernel's other refusals of an add are of the place: out
		// of shape, not a directory it reaches, inside its own data, or
		// no backups kept (kernel.ErrTarget, kernel/proc).
		return sockets.Code(localapi.ErrBackupPlace)
	}
	return sockets.Code(localapi.ErrBackupUnavailable)
}

// readCode is a failed read's code: a read refuses nothing of the place.
func readCode(err error) error {
	if errors.Is(err, kernelsock.ErrSetupOnly) {
		return sockets.Code(localapi.ErrBackupSetup)
	}
	return sockets.Code(localapi.ErrBackupUnavailable)
}

// tapCode is tapper's passkey code as the backup ops' own.
func tapCode(err error) error {
	var c sockets.Code
	errors.As(err, &c)
	switch string(c) {
	case localapi.ErrPasskeyNotAnchor:
		return sockets.Code(localapi.ErrBackupNotAnchor)
	case localapi.ErrPasskeyBadAssertion:
		return sockets.Code(localapi.ErrBackupBadAssertion)
	}
	return sockets.Code(localapi.ErrBackupUnavailable)
}

func target(p localapi.BackupPlace) (kernelsock.Target, bool) {
	t := kernelsock.Target{Name: p.Name, Kind: p.Kind, Locator: p.Locator, AppendOnly: p.AppendOnly}
	return t, p.Kind == kernelsock.KindDir && p.Newest == 0
}

// read is a fresh view, kept by the schedule too.
func (c *backupChoice) read(ctx context.Context) (kernelsock.BackupsView, error) {
	if err := c.S.read(ctx); err != nil {
		return kernelsock.BackupsView{}, readCode(err)
	}
	v, _ := c.S.snapshot()
	return v, nil
}

func (c *backupChoice) List(ctx context.Context) (localapi.BackupChoice, error) {
	v, err := c.read(ctx)
	if err != nil {
		return localapi.BackupChoice{}, err
	}
	out := localapi.BackupChoice{Lines: c.S.lines(), Places: []localapi.BackupPlace{}, Wipeable: c.S.wipeable(), NoKey: v.Recipient == ""}
	if out.Lines == nil {
		out.Lines = []string{}
	}
	if out.Wipeable == nil {
		out.Wipeable = []string{}
	}
	for _, t := range current(v) {
		p := localapi.BackupPlace{Name: t.Name, Kind: t.Kind, Locator: t.Locator, AppendOnly: t.AppendOnly}
		if at, ok := newest(v, t.Name); ok {
			p.Newest = at
		}
		out.Places = append(out.Places, p)
	}
	return out, nil
}

// Begin returns the challenge over adding p as the next destination. The
// kernel is asked to add it unsigned first: it checks the place before the
// signature, so its refusal for want of one says the place is good, and
// any other refusal names what is wrong before the owner taps.
func (c *backupChoice) Begin(ctx context.Context, p localapi.BackupPlace) (localapi.BackupBegun, error) {
	t, ok := target(p)
	if !ok {
		return localapi.BackupBegun{}, sockets.Code(localapi.ErrBadArgs)
	}
	v, err := c.read(ctx)
	if err != nil {
		return localapi.BackupBegun{}, err
	}
	for _, kt := range v.Targets {
		if kt.Name == t.Name {
			return localapi.BackupBegun{}, sockets.Code(localapi.ErrBackupNameTaken)
		}
	}
	err = c.K.BackupTarget(ctx, t, key.Cosign{})
	if err == nil {
		// The kernel took an unsigned widening: never expected, so say
		// so and offer no tap.
		log.Print(LogBackupUnsigned)
		return localapi.BackupBegun{}, sockets.Code(localapi.ErrBackupUnavailable)
	}
	if !errors.Is(err, kernelsock.ErrTargetSig) {
		return localapi.BackupBegun{}, backupCode(err)
	}
	n := len(v.Targets)
	ch := key.Challenge(kernelsock.TargetMsg(n, t))
	return localapi.BackupBegun{N: n, Challenge: ch[:]}, nil
}

// LogBackupUnsigned is logged when the kernel took Begin's unsigned add.
const LogBackupUnsigned = "backups: the kernel added a destination with no hardware key's signature"

// Add adds p as destination n on the hardware key whose assertion over
// Begin's challenge this is, found by tapper among the kernel's anchors.
// A count other than the kernel's is ErrBackupStale: the challenge was
// over another add.
func (c *backupChoice) Add(ctx context.Context, p localapi.BackupPlace, n int, authData, clientData, sig []byte) error {
	t, ok := target(p)
	if !ok {
		return sockets.Code(localapi.ErrBadArgs)
	}
	v, err := c.read(ctx)
	if err != nil {
		return err
	}
	if n != len(v.Targets) {
		return sockets.Code(localapi.ErrBackupStale)
	}
	anchors, live, _, err := ownerKeys(ctx, c.K)
	if err != nil {
		return readCode(err)
	}
	by, canon, err := tapper(kernelsock.TargetMsg(n, t), anchors, live, authData, clientData, sig)
	if err != nil {
		return tapCode(err)
	}
	err = backupCode(c.K.BackupTarget(ctx, t, key.Cosign{By: by, Sig: canon}))
	c.S.read(ctx)
	return err
}

// Remove stops new backups to the current destination name; one removed
// already is done, and one never listed is ErrBackupStale.
func (c *backupChoice) Remove(ctx context.Context, name string) error {
	v, err := c.read(ctx)
	if err != nil {
		return err
	}
	for _, t := range v.Targets {
		if t.Name != name {
			continue
		}
		if t.Removed {
			return nil
		}
		err := backupCode(c.K.Untarget(ctx, name))
		c.S.read(ctx)
		return err
	}
	return sockets.Code(localapi.ErrBackupStale)
}

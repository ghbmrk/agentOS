package main

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/ghbmrk/agentos/broker/owner/kernelsock"
)

// kernelFlags checks -kernel-owner, -kernel-uid and -kernel-owner-uid
// (MIG-4-run start-up slice, #2682): all three or none. Neither uid is
// root, and the owner side's uid is the kernel's peer alone, distinct from
// the kernel's and from every uid in others (the local UI's, the modem
// bridge's, the mail clerk's), so no other process the broker serves runs
// as the seam's caller. None set is no kernel to call.
func kernelFlags(sock string, kernelUID, ownerUID int, others ...int) (*kernelsock.Owner, error) {
	if sock == "" && kernelUID < 0 && ownerUID < 0 {
		return nil, nil
	}
	switch {
	case sock == "" || kernelUID < 0 || ownerUID < 0:
		return nil, errors.New("-kernel-owner, -kernel-uid and -kernel-owner-uid go together")
	case !filepath.IsAbs(sock):
		return nil, errors.New("-kernel-owner must be an absolute path")
	case kernelUID == 0 || ownerUID == 0:
		return nil, errors.New("-kernel-uid and -kernel-owner-uid never name root")
	case kernelUID == ownerUID:
		return nil, errors.New("-kernel-owner-uid must differ from -kernel-uid")
	}
	for _, u := range others {
		if u >= 0 && (u == ownerUID || u == kernelUID) {
			return nil, errors.New("-kernel-uid and -kernel-owner-uid must differ from the local UI's, the modem bridge's and the mail clerk's uids")
		}
	}
	return &kernelsock.Owner{Socket: sock, UID: kernelUID, As: ownerUID}, nil
}

// setupReader is the one kernel call the start-up probe makes.
type setupReader interface {
	SetupOpen(context.Context) (bool, error)
}

// reachKernel says, at start, whether the kernel answers on its owner
// socket: once that it is not reached yet (the kernel's unit starts beside
// the broker's, and on a box with no sealed store it never starts), then
// once whether it is waiting for setup or running. It tries every `every`
// until then, and stops at the first answer or refusal; it holds nothing
// up. A setup-only kernel serves this call too.
func reachKernel(ctx context.Context, k setupReader, every time.Duration, logf func(string, ...any)) {
	said := false
	for {
		open, err := k.SetupOpen(ctx)
		switch {
		case err == nil && open:
			logf("kernel: reached; it is waiting for setup")
			return
		case err == nil:
			logf("kernel: reached; it is running")
			return
		case !errors.Is(err, kernelsock.ErrUnreachable) && !errors.Is(err, kernelsock.ErrLost):
			logf("kernel: reached, but it refused me: %v", err)
			return
		case !said:
			logf("kernel: not reached yet; I keep trying (%v)", err)
			said = true
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// storedKernel is the owner commands' kernel (daemon.Config.Kernel,
// #2783). With no sealed store the kernel's unit does not start and no
// kernel can open a log or run a plan, so it reads as waiting for setup:
// STOP and RESUME have nothing to reach there, and do not fail for it.
type storedKernel struct {
	kernelsock.Owner
	store string
}

func (k storedKernel) SetupOpen(ctx context.Context) (bool, error) {
	if _, err := os.Lstat(k.store); errors.Is(err, fs.ErrNotExist) {
		return true, nil
	}
	return k.Owner.SetupOpen(ctx)
}

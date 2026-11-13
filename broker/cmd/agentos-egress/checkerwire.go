package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/ghbmrk/agentos/broker/checker"
	"github.com/ghbmrk/agentos/broker/checker/checkersock"
	"github.com/ghbmrk/agentos/broker/holder"
)

// With -checker (SIM-split-wire part 3, CH-4) the code-generator seed would
// be the checker's to check against: the unlock step hands it there while the
// vault is open and takes it back at a lock, as it does each API key with
// its holder. The broker's code checks go to the checker's verify socket,
// and the unlock step's own code goes to the checker's hand socket, so the
// last spent step is the checker's one store: a code the broker spent
// cannot then unlock the vault, nor the other way round. This process
// keeps only the unlock proof (owner.UnlockProofPrefix) on its verify
// socket. Without -checker nothing changes.
//
// Since D-244 no process serves the hand socket (agentos-checker serves
// only verify.sock, through clerk/codecheck), so with -checker set every
// hand fails and the unlock and every tier-4 approval are refused, and
// checkerFlagOK refuses a directory where another uid could listen.

// errOnChecker refuses a code-generator code on this process's verify
// socket while the checker checks them.
var errOnChecker = errors.New("code-generator codes are checked by the checker (-checker)")

// checkerFlagOK checks serve's -checker: empty, or an absolute directory
// that only root or this uid could plant a listener in (#5649). The client
// hands the seed to whatever listens at dir/hand.sock with no peer-uid
// check (W-3), so a directory another uid could write, replace or relink
// is refused at start rather than warned about.
func checkerFlagOK(dir string) error { return checkerFlagAs(dir, uint32(os.Geteuid())) }

// checkerFlagAs is checkerFlagOK trusting uid euid besides root; tests name
// another uid to reach the owner case.
func checkerFlagAs(dir string, euid uint32) error {
	if dir == "" {
		return nil
	}
	if !filepath.IsAbs(dir) {
		return errors.New("-checker needs the checker's absolute socket directory")
	}
	abs := filepath.Clean(dir)
	for p := abs; ; p = filepath.Dir(p) {
		if err := ownedDir(p, euid, p == abs); err != nil {
			return fmt.Errorf("-checker %s: %w", dir, err)
		}
		if filepath.Dir(p) == p {
			return nil
		}
	}
}

// ownedDir refuses p unless it is a real directory, not a link, owned by
// root or euid and writable by no other uid. A sticky parent such as /tmp
// may be writable by all, since no other uid may rename what it does not
// own; the socket directory itself (last) may not.
func ownedDir(p string, euid uint32, last bool) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.IsDir():
		return fmt.Errorf("%s is not a directory", p)
	case !ok || st.Uid != 0 && st.Uid != euid:
		return fmt.Errorf("%s is not owned by root or uid %d", p, euid)
	case fi.Mode().Perm()&0o022 != 0 && (last || fi.Mode()&os.ModeSticky == 0):
		return fmt.Errorf("%s is writable by other uids", p)
	}
	return nil
}

// seedKeeper hands the checker the channel's seed from the open vault, and
// again whenever the vault's values change, so a replaced seed (REC-3's
// re-enrollment, setup's confirmed enrollment) reaches it.
func (c *custody) seedKeeper() *holder.Keeper {
	return &holder.Keeper{
		Socket: filepath.Join(c.checker, checker.HandSocket),
		Every:  c.keepEvery,
		Version: func() uint64 {
			if v := c.keys.Load(); v != nil {
				return v.Gen()
			}
			return 0
		},
		Secret: func() ([]byte, error) {
			v := c.keys.Load()
			if v == nil {
				return nil, errNoKey
			}
			s, ok := v.Secret(SeedName)
			if !ok {
				return nil, errNoKey
			}
			return []byte(s.Reveal()), nil
		},
	}
}

// matchOnChecker hands the checker seed and checks code there after the
// durable last step. Caller holds mu; a pending vault's seed is taken back
// before it returns, so only an open vault leaves one in the checker.
func (c *custody) matchOnChecker(seed []byte, code string) (int64, bool, error) {
	k := &holder.Keeper{
		Socket:  filepath.Join(c.checker, checker.HandSocket),
		Version: func() uint64 { return 1 }, // a new keeper always hands
		Secret:  func() ([]byte, error) { return bytes.Clone(seed), nil },
	}
	if c.ph != open {
		defer c.dropSeed(k)
	}
	ctx, cancel := context.WithTimeout(context.Background(), dropTimeout)
	defer cancel()
	if _, err := k.Check(ctx); err != nil {
		return 0, false, err
	}
	return checkersock.VerifyClient(k.Socket).VerifyTOTP(code, c.st.LastStep, true)
}

// handChannelSeed puts the vault's channel seed back in the checker, for
// a confirmEnroll that handed it a pending seed it then did not make the
// channel's; with no channel seed it takes the checker's back. Caller
// holds mu and has c.v.
func (c *custody) handChannelSeed() {
	k := &holder.Keeper{
		Socket:  filepath.Join(c.checker, checker.HandSocket),
		Version: func() uint64 { return 1 }, // a new keeper always hands
		Secret: func() ([]byte, error) {
			s, ok := c.v.Secret(SeedName)
			if !ok {
				return nil, errNoKey
			}
			return []byte(s.Reveal()), nil
		},
	}
	if _, ok := c.v.Secret(SeedName); !ok {
		c.dropSeed(k)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), dropTimeout)
	defer cancel()
	if _, err := k.Check(ctx); err != nil {
		// Never leave the pending seed checking the broker's codes.
		c.dropSeed(k)
	}
}

// dropSeed takes the checker's seed back through k and tells the owner if
// a running checker refused.
func (c *custody) dropSeed(k *holder.Keeper) {
	ctx, cancel := context.WithTimeout(context.Background(), dropTimeout)
	defer cancel()
	if err := k.Drop(ctx); err != nil && !errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ECONNREFUSED) {
		c.notify(fmt.Sprintf("checker at %s: seed not taken back: %v", c.checker, err))
	}
}

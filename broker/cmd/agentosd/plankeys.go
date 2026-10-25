package main

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"syscall"

	"github.com/ghbmrk/agentos/broker/guest"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
)

// maxPlanGrant bounds the clerk-key grant's file: a key of key.MaxLinks
// links is a few kilobytes.
const maxPlanGrant = 64 << 10

// loadPlanHolder returns the key that holds the owner's clerk-key grant to
// agentosd and signs its guests' plans (KEY-3, KEY-4). It lives at path in
// agentosd's state dir, root's alone (0600), and is kept across reboots
// (Mark, #3087 comment 6397118211). The first start, finding no file, makes
// one. A file that is there but open to another uid, not a plain file, or
// not one seed is an error and is never replaced: a new key would orphan
// the owner's grant without a word.
func loadPlanHolder(path string) (ed25519.PrivateKey, error) {
	seed, err := readPrivate(path, ed25519.SeedSize)
	if errors.Is(err, os.ErrNotExist) {
		seed = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		if err := privfile.WriteAtomic(filepath.Dir(path), filepath.Base(path), seed, nil); err != nil {
			return nil, err
		}
		return ed25519.NewKeyFromSeed(seed), nil
	}
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("plan holder %s: %d bytes, not one %d-byte seed", path, len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// openPlanKeys is the guest plane's Keys from the -plan-holder and
// -plan-grant flags, or nil, refusing every plan, when holderPath is empty
// or the holder key cannot be read or made; it logs which.
func openPlanKeys(holderPath, grantPath string) guest.Keys {
	if holderPath == "" {
		log.Printf("plan keys: no -plan-holder; every guest plan is refused")
		return nil
	}
	holder, err := loadPlanHolder(holderPath)
	if err != nil {
		log.Printf("plan keys: %v; every guest plan is refused", err)
		return nil
	}
	log.Printf("plan keys: holder %x", holder.Public())
	return planKeys(holder, grantPath, log.Printf)
}

// readPrivate reads path, which must be this uid's alone and at most max
// bytes, without following a symlink.
func readPrivate(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := privfile.CheckFile(f); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, max)
	}
	return b, nil
}

// planKeys is the guest plane's Keys (PLN-5 (b)): the owner's clerk-key
// grant to holder, read from grantPath at each plan, narrowed to the
// machine with key.Derive and handed to that machine's own key, which
// agentosd derives from holder and never gives the guest (KEY-3). No grant
// file, or one not granted to holder, gives no key, so the plan is refused.
// The kernel, not this file, says whether the grant is live: a revoked or
// lapsed grant reaches it and is rejected there.
func planKeys(holder ed25519.PrivateKey, grantPath string, logf func(string, ...any)) guest.Keys {
	return func(machine string) (key.Key, ed25519.PrivateKey, bool) {
		b, err := readPrivate(grantPath, maxPlanGrant)
		if errors.Is(err, os.ErrNotExist) {
			return key.Key{}, nil, false
		}
		var grant key.Key
		if err == nil {
			err = json.Unmarshal(b, &grant)
		}
		if err == nil && len(grant.Links) == 0 {
			err = errors.New("a bare root, not a clerk key")
		}
		if err != nil {
			logf("plan keys: grant %s: %v", grantPath, err)
			return key.Key{}, nil, false
		}
		m := machineHolder(holder, machine)
		k, err := key.Derive(grant, holder, m.Public().(ed25519.PublicKey))
		if err != nil {
			logf("plan keys: grant %s: %v", grantPath, err)
			return key.Key{}, nil, false
		}
		return k, m, true
	}
}

// machineHolder is machine's own key: derived from holder's seed, so it
// needs no file of its own and is the same at every start, and distinct per
// machine, so each machine's plans cite a key of their own.
func machineHolder(holder ed25519.PrivateKey, machine string) ed25519.PrivateKey {
	mac := hmac.New(sha256.New, holder.Seed())
	mac.Write([]byte("agentos guest plan holder\x00"))
	mac.Write([]byte(machine))
	return ed25519.NewKeyFromSeed(mac.Sum(nil))
}

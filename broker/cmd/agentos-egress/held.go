package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/holder"
	"github.com/ghbmrk/agentos/broker/netguard"
	"github.com/ghbmrk/agentos/broker/vault"
)

// holderDirs collects -holder adapter=dir flags: the socket directory of
// the holder that keeps each adapter's API key (ARC-1, SIM-split-wire).
// With holders the proxy adds no key itself: it sends each call to the
// adapter's holder, and the unlock step hands the holder its key.
type holderDirs map[string]string

func (h holderDirs) String() string { return "" }
func (h holderDirs) Set(v string) error {
	name, dir, ok := strings.Cut(v, "=")
	if !ok || !adapterName(name) || !filepath.IsAbs(dir) {
		return errors.New("want adapter=/absolute/socket/dir, for a built-in adapter")
	}
	if _, dup := h[name]; dup {
		return fmt.Errorf("-holder %s given twice", name)
	}
	h[name] = filepath.Clean(dir)
	return nil
}

// check refuses holders for some adapters only: a key with no holder would
// stay in this process, and one holder per account is the point.
func (h holderDirs) check() error {
	if len(h) == 0 {
		return nil
	}
	for _, a := range adapters() {
		if _, ok := h[a.Name]; !ok {
			return fmt.Errorf("-holder: adapter %s has no holder; give one for every adapter or none", a.Name)
		}
	}
	return nil
}

func adapterName(name string) bool {
	for _, a := range adapters() {
		if a.Name == name {
			return true
		}
	}
	return false
}

// newHeldProxy is newGrantedProxy over holders: no vault, so no key to
// inject; each adapter's calls go to its holder's request socket, and the
// responses are redacted by keyed hashes of every vault value (CRED-7).
func newHeldProxy(v *vault.Vault, g map[string][]string, dirs holderDirs, guard *netguard.Policy, stored func(machine, adapter string) bool) (*egress.Proxy, error) {
	rts := map[string]http.RoundTripper{}
	for _, a := range adapters() {
		rts[a.Credential] = holder.Client(filepath.Join(dirs[a.Name], holder.RequestSocket))
	}
	return egress.New(egress.Config{
		Granted:  stored,
		Guard:    guard,
		Adapters: adapters(),
		Grants:   g,
		Holders:  rts,
		Redaction: func() (egress.Redactor, error) {
			r, err := v.HashRedactor()
			if err != nil {
				return nil, err
			}
			return r, nil
		},
		Audit: noAudit{},
	})
}

// keepers are the unlock step's holder keepers, one per adapter, running
// while the vault is open.
type keepers struct {
	list []*holder.Keeper
	stop context.CancelFunc
	wg   sync.WaitGroup
}

var errNoKey = errors.New("no key to hand")

// startKeepersLocked starts a keeper per holder over v. Caller holds mu.
func (c *custody) startKeepersLocked(v *vault.Vault) {
	c.stopKeepersLocked()
	if len(c.holders) == 0 {
		return
	}
	c.keys.Store(v)
	ctx, stop := context.WithCancel(context.Background())
	ks := &keepers{stop: stop}
	for _, a := range adapters() {
		cred := a.Credential
		k := &holder.Keeper{
			Socket:  filepath.Join(c.holders[a.Name], holder.HandSocket),
			Every:   c.keepEvery,
			Version: c.keyVer.Load,
			// The keeper reads the key from the open vault without mu,
			// so a lock (which holds mu) can wait for its round.
			Secret: func() ([]byte, error) {
				v := c.keys.Load()
				if v == nil {
					return nil, errNoKey
				}
				s, ok := apiKeysOnly{v}.Secret(cred)
				if !ok {
					return nil, errNoKey
				}
				return []byte(s.Reveal()), nil
			},
		}
		ks.list = append(ks.list, k)
		ks.wg.Add(1)
		go func() { defer ks.wg.Done(); k.Run(ctx) }()
	}
	c.keep = ks
}

// dropTimeout bounds each holder's drop at a lock.
const dropTimeout = 2 * time.Second

// stopKeepersLocked stops the keepers, waits for any hand in flight, and
// takes each holder's key back, so a locked vault leaves none in a holder
// (CRED-1). A holder that is down holds none. Caller holds mu.
func (c *custody) stopKeepersLocked() {
	c.keys.Store(nil)
	ks := c.keep
	if ks == nil {
		return
	}
	c.keep = nil
	ks.stop()
	ks.wg.Wait()
	errs := make([]error, len(ks.list))
	var wg sync.WaitGroup
	for i, k := range ks.list {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), dropTimeout)
			defer cancel()
			errs[i] = k.Drop(ctx)
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil && !errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ECONNREFUSED) {
			c.notify(fmt.Sprintf("holder at %s: key not taken back at lock: %v", filepath.Dir(ks.list[i].Socket), err))
		}
	}
}

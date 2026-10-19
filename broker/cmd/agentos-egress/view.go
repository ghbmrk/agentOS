package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/holder"
	"github.com/ghbmrk/agentos/broker/netguard"
	"github.com/ghbmrk/agentos/broker/vault"
)

// The keyless proxy process (SIM-split-wire, ARC-1, CRED-1): with -proxy,
// the model and routing sockets are served by `agentos-egress proxy`, a
// process that never opens the vault. The vault process hands it a view
// of the open vault over a hand socket, as the keepers hand each holder
// its key: which providers have a stored key or the owner's private-data
// marker, whether a key is stored while locked, and the keyed-hash
// redactor (CRED-7). The view holds no vault value and no vault key, so
// the process that parses the agent's requests holds nothing to leak.

// modelSource is what the model and routing paths ask: custody in the
// vault process, or proxyView in the proxy process.
type modelSource interface {
	model() *egress.Proxy
	modelGrantedNow() bool
	privateGrantedNow() bool
	storedGrant(machine, provider string) bool
	privateAllowed(provider string) bool
}

// sourceBox lets privateHook hold either source in one atomic pointer.
type sourceBox struct{ modelSource }

// modelView is the view the vault process hands the proxy process. Keys
// and Private name providers, Keyed is the state file's mark while locked,
// and Redactor is a vault.HashRedactor's encoding: a random key and keyed
// hashes, never a value.
type modelView struct {
	Open     bool     `json:"open"`
	Keys     []string `json:"keys,omitempty"`
	Private  []string `json:"private,omitempty"`
	Keyed    bool     `json:"keyed"`
	Redactor []byte   `json:"redactor,omitempty"`
}

// maxView bounds a handed view: the redactor's hashes grow with the vault.
const maxView = 4 << 20

// viewSnapshot is the view of the vault as the keepers see it (keys). It
// never takes mu, so a lock that holds mu can wait for a round.
func (c *custody) viewSnapshot() ([]byte, error) {
	m := modelView{Keyed: c.keyed.Load()}
	if v := c.keys.Load(); v != nil {
		m.Open = true
		for _, a := range adapters() {
			if hasKind(v, a.Credential, vault.KindAPIKey) {
				m.Keys = append(m.Keys, a.Name)
			}
			if hasKind(v, PrivateOKPrefix+a.Name, KindPrivateOK) {
				m.Private = append(m.Private, a.Name)
			}
		}
		r, err := v.HashRedactor()
		if err != nil {
			return nil, err
		}
		if m.Redactor, err = r.MarshalBinary(); err != nil {
			return nil, err
		}
	}
	return json.Marshal(m)
}

// viewVersion names the view now: the unlock epoch, which moves at every
// unlock and lock, and the vault's change count while open.
func (c *custody) viewVersion() uint64 {
	var gen uint64
	if v := c.keys.Load(); v != nil {
		gen = v.Gen() & 0xffffffff
	}
	return c.epoch.Load()<<32 | gen
}

// viewKeeper hands the proxy process the view. Its rounds run one at a
// time, so the round a lock runs lands after any round in flight.
type viewKeeper struct {
	k     *holder.Keeper
	turn  chan struct{}
	nudge chan struct{}
}

func newViewKeeper(c *custody, dir string) *viewKeeper {
	return &viewKeeper{
		k: &holder.Keeper{
			Socket:  filepath.Join(dir, holder.HandSocket),
			Secret:  c.viewSnapshot,
			Version: c.viewVersion,
			Every:   c.keepEvery,
		},
		turn:  make(chan struct{}, 1),
		nudge: make(chan struct{}, 1),
	}
}

// check runs one round.
func (vk *viewKeeper) check(ctx context.Context) error {
	select {
	case vk.turn <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-vk.turn }()
	_, err := vk.k.Check(ctx)
	return err
}

// run checks every round, and at once when poked, until ctx ends.
func (vk *viewKeeper) run(ctx context.Context) {
	every := vk.k.Every
	if every <= 0 {
		every = 2 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		vk.check(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-vk.nudge:
		}
	}
}

// poke asks for a round now.
func (vk *viewKeeper) poke() {
	select {
	case vk.nudge <- struct{}{}:
	default:
	}
}

// handView hands the proxy the view now, before the change that called
// it returns: a lock, and every value stored or deleted while open (the
// vault's OnChange), so a narrowing such as a withdrawn private-data
// answer, and the keyed hash of a new value, reach the proxy before the
// next call does (CRED-1, CRED-7). A proxy that is not running holds no
// view. It never takes mu, so callers may hold it.
func (c *custody) handView() {
	if c.view == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), dropTimeout)
	defer cancel()
	if err := c.view.check(ctx); err != nil && !errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ECONNREFUSED) {
		c.handFails.Add(1)
		c.notify(fmt.Sprintf("proxy at %s: not handed the vault's change: %v", filepath.Dir(c.view.k.Socket), err))
	}
}

// proxyView is the proxy process's model source: the last view handed,
// and the flags' grants, which both processes are started with.
type proxyView struct {
	agent        string
	granted      bool
	flagGrants   map[string]bool
	privateFlags map[string]bool
	proxy        *egress.Proxy

	mu      sync.Mutex
	handed  bool
	open    bool
	keyed   bool
	keys    map[string]bool
	private map[string]bool
	red     *vault.HashRedactor
}

var errViewLocked = errors.New("vault locked")

// newProxyView builds the view's proxy over holders: every call goes to
// its adapter's holder, and responses are redacted by the handed keyed
// hashes.
func newProxyView(g grants, agent string, pok map[string]bool, dirs holderDirs, guard *netguard.Policy) (*proxyView, error) {
	if len(dirs) == 0 {
		return nil, errors.New("the proxy process needs -holder for every adapter")
	}
	if err := dirs.check(); err != nil {
		return nil, err
	}
	pv := &proxyView{agent: agent, granted: modelGranted(g), flagGrants: flagGrantsOf(g), privateFlags: pok}
	p, err := egress.New(egress.Config{
		Granted:   pv.storedGrant,
		Guard:     guard,
		Adapters:  adapters(),
		Grants:    g,
		Holders:   holderTransports(dirs),
		Redaction: pv.redactor,
		Audit:     noAudit{},
	})
	if err != nil {
		return nil, err
	}
	pv.proxy = p
	return pv, nil
}

func (pv *proxyView) redactor() (egress.Redactor, error) {
	pv.mu.Lock()
	defer pv.mu.Unlock()
	if !pv.open || pv.red == nil {
		return nil, errViewLocked
	}
	return pv.red, nil
}

// Hand takes a view. One that does not parse leaves the proxy locked.
func (pv *proxyView) Hand(b []byte) {
	var m modelView
	err := json.Unmarshal(b, &m)
	var red *vault.HashRedactor
	if err == nil && m.Open {
		red = new(vault.HashRedactor)
		err = red.UnmarshalBinary(m.Redactor)
	}
	clear(m.Redactor)
	pv.mu.Lock()
	defer pv.mu.Unlock()
	pv.handed = true
	if err != nil {
		pv.open, pv.keyed, pv.keys, pv.private, pv.red = false, false, nil, nil, nil
		return
	}
	pv.open, pv.keyed, pv.red = m.Open, m.Keyed, red
	pv.keys, pv.private = set(m.Keys), set(m.Private)
}

// Drop forgets the view: locked, with no stored key known.
func (pv *proxyView) Drop() {
	pv.mu.Lock()
	defer pv.mu.Unlock()
	pv.handed, pv.open, pv.keyed, pv.keys, pv.private, pv.red = false, false, false, nil, nil, nil
}

func (pv *proxyView) Held() bool {
	pv.mu.Lock()
	defer pv.mu.Unlock()
	return pv.handed
}

func set(names []string) map[string]bool {
	out := map[string]bool{}
	for _, n := range names {
		out[n] = true
	}
	return out
}

// The answers below mirror custody's (storedGrant, privateAllowed,
// modelGrantedNow, privateGrantedNow) over the view.

func (pv *proxyView) model() *egress.Proxy {
	pv.mu.Lock()
	defer pv.mu.Unlock()
	if !pv.open {
		return nil
	}
	return pv.proxy
}

func (pv *proxyView) storedGrant(machine, provider string) bool {
	pv.mu.Lock()
	defer pv.mu.Unlock()
	if pv.agent == "" || machine != pv.agent || !pv.open {
		return false
	}
	_, known := adapterNamed(provider)
	return known && pv.keys[provider]
}

func (pv *proxyView) privateAllowed(provider string) bool {
	pv.mu.Lock()
	defer pv.mu.Unlock()
	if !pv.open {
		return false
	}
	_, known := adapterNamed(provider)
	return known && pv.private[provider]
}

func (pv *proxyView) modelGrantedNow() bool {
	pv.mu.Lock()
	defer pv.mu.Unlock()
	if pv.granted {
		return true
	}
	if pv.agent == "" {
		return false
	}
	if pv.open {
		return len(pv.keys) > 0
	}
	return pv.keyed
}

func (pv *proxyView) privateGrantedNow() bool {
	pv.mu.Lock()
	defer pv.mu.Unlock()
	if !pv.open {
		return false
	}
	for _, p := range modelProviders() {
		n := p.Name()
		_, known := adapterNamed(n)
		granted := pv.flagGrants[n] || pv.agent != "" && known && pv.keys[n]
		allowed := pv.privateFlags[n] || known && pv.private[n]
		if granted && allowed {
			return true
		}
	}
	return false
}

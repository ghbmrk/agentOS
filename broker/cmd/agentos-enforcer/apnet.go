package main

// The Wi-Fi access points (briefs/ENF-l-b2.md part a, #3670, #4569): the
// Wi-Fi passwords (ap.Keys) kept in the state directory, one push.Pusher
// per access point for the process's lifetime (ap ASSUMPTIONS ENF-g-8),
// each driven by its own push.Watch whose every report reaches the page,
// and enrolment's hand-over from the setup network to the Owner,
// Household and Guests networks (enrol.Network). Its assumptions are
// ASSUMPTIONS.md ENF-l-ap-1 to ENF-l-ap-6.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	"github.com/ghbmrk/agentos/broker/enforcer/ap"
	"github.com/ghbmrk/agentos/broker/enforcer/ap/push"
	"github.com/ghbmrk/agentos/broker/enforcer/enrol"
	"github.com/ghbmrk/agentos/broker/enforcer/page"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

const (
	fileAPKeys = "ap-keys.json" // the Wi-Fi passwords (ap.Keys) and whether the setup network is gone
	fileAPSSH  = "ap-ssh.key"   // the enforcer's Ed25519 key for the access points' SSH
)

// apEvery is how often each access point is pushed its whole
// configuration again, so a file changed on it is put back within it
// (ENF-g-8). A policy that changes the configuration, and enrolment, push
// at once (nudge).
const apEvery = time.Minute

// apReplaceWait bounds how long enrolment waits for every access point to
// hold the four networks: one push's own bound (push.Pusher.Timeout's
// default) and a margin for the push a nudge cut short.
const apReplaceWait = 45 * time.Second

// watcher is an access point's pusher as the daemon drives it:
// *push.Pusher in production, a fake access point in the lifecycle test.
type watcher interface {
	Watch(ctx context.Context, every time.Duration, cfg func() ([]ap.File, error), report func(push.Result, error))
}

// newPusher is the production watcher for one access point: its address,
// its pinned host key, the enforcer's key, and a dialer bound to the
// access point's admin interface (ENF-g-8: Dial has no default).
func newPusher(iface string) func(addr string, host ssh.PublicKey, signer ssh.Signer) watcher {
	return func(addr string, host ssh.PublicKey, signer ssh.Signer) watcher {
		d := net.Dialer{Timeout: 10 * time.Second, Control: func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) { serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface) }); err != nil {
				return err
			}
			return serr
		}}
		return &push.Pusher{Addr: addr, HostKey: host, Signer: signer, Dial: d.DialContext}
	}
}

// apState is the access points' state file.
type apState struct {
	Keys ap.Keys `json:"keys"`
	// Replaced is set once every access point held the four networks
	// after enrolment: from then on the setup network is gone for good
	// (enrol.Network.Replaced), across restarts and factory resets.
	Replaced bool `json:"replaced"`
}

// provisionAP stores the setup network's password, the sticker's, at
// first boot (HW-10): the one Wi-Fi secret made before enrolment. It
// refuses a state directory that already holds Wi-Fi passwords.
func provisionAP(dir fileStore, setup string) error {
	if b, err := dir.Load(); err != nil || b != nil {
		return errors.Join(err, errors.New("access point: already provisioned"))
	}
	k := ap.Keys{Setup: setup}
	// Config checks the password as the access point will take it.
	if _, err := ap.Config(policy.Document{}, placeholderLayout(), k); err != nil {
		return fmt.Errorf("access point: setup password: %w", err)
	}
	b, err := json.Marshal(apState{Keys: k})
	if err != nil {
		return err
	}
	return dir.Save(b)
}

// placeholderLayout is a layout that passes ap.Layout.Check, for checking
// a password alone.
func placeholderLayout() ap.Layout {
	return ap.Layout{Uplink: "lan1", DeviceUplink: "lan1", Owner: 10, Household: 20, Guests: 30, Admin: 70,
		Addr:   netip.MustParsePrefix("10.70.0.2/24"),
		Radios: []ap.Radio{{Name: "radio0", Path: "p", Band: "2g", HTMode: "HE20", Channel: "1", Country: "GB"}},
		SSID:   ap.SSIDs{Setup: "s", Owner: "o", Household: "h", Guests: "g", Devices: "d"}, EnforcerKey: "ssh-ed25519 AAAA"}
}

// apSSHKey is the enforcer's SSH key for the access points: made on first
// start and kept in the state directory (mode 0600), as the channel key
// is. Its public half is the only login the access points accept
// (ap.Layout.EnforcerKey); -ap-pub prints it for setup.
func apSSHKey(store fileStore, r io.Reader) (ssh.Signer, error) {
	priv, err := channelKey(store, r)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}

// authorizedKey is s's public half in authorized_keys form, with no
// newline.
func authorizedKey(s ssh.Signer) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey())))
}

// apPoint is one access point: its pusher for the process's lifetime, and
// its last report.
type apPoint struct {
	addr string
	w    watcher
	kick chan struct{}

	// Under apNet.mu: the generation of the files the last report's push
	// carried, and that report.
	gen      uint64
	reported bool
	res      push.Result
	err      error
	logged   string
}

// apNet is the access points as enrolment, the page and the daemon's
// clock reach them.
type apNet struct {
	d      *Enforcer
	layout ap.Layout
	points []*apPoint
	store  fileStore
	every  time.Duration
	wait   time.Duration

	mu   sync.Mutex
	cond *sync.Cond
	st   apState
	// replacing is enrolment's hand-over in progress: the access points
	// are pushed the four networks, not yet the saved state's setup one.
	replacing bool
	// gen counts each change of what the access points must hold that a
	// waiter needs reported: enrolment's hand-over and its undoing.
	gen uint64
	// hash is the policy the device passwords were last synced to.
	hash string

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// openAP reads the Wi-Fi passwords and builds one pusher per access
// point; start runs them. With no access point configured enrolment
// refuses, as before this slice, so the sticker never outlives an
// enrolment that pushed nothing.
func (d *Enforcer) openAP() (*apNet, error) {
	n := &apNet{d: d, layout: d.cfg.AP.Layout, store: d.store(fileAPKeys), every: apEvery, wait: apReplaceWait}
	n.cond = sync.NewCond(&n.mu)
	if d.dp.APWait != 0 {
		n.wait = d.dp.APWait
	}
	if len(d.cfg.AP.Points) == 0 {
		return n, nil
	}
	b, err := n.store.Load()
	if err != nil {
		return nil, fmt.Errorf("access point: %w", err)
	}
	if b == nil {
		return nil, errors.New("access point: no setup password provisioned (-provision with -ap-setup)")
	}
	if err := json.Unmarshal(b, &n.st); err != nil {
		return nil, fmt.Errorf("access point: %w", err)
	}
	signer, err := apSSHKey(d.store(fileAPSSH), d.dp.Rand)
	if err != nil {
		return nil, fmt.Errorf("access point key: %w", err)
	}
	n.layout.EnforcerKey = authorizedKey(signer)
	for _, p := range d.cfg.AP.Points {
		host, _, _, _, err := ssh.ParseAuthorizedKey([]byte(p.HostKey))
		if err != nil {
			return nil, fmt.Errorf("access point %s: host key: %w", p.Addr, err)
		}
		n.points = append(n.points, &apPoint{addr: p.Addr.String(), w: d.dp.AP(p.Addr.String(), host, signer), kick: make(chan struct{}, 1)})
	}
	return n, nil
}

// start runs each access point's Watch until close. A nudge ends the
// running Watch and starts another on the same pusher, which pushes at
// once: the pusher, and so its count of abandoned opens, lives as long
// as the process (ENF-g-8, #4569).
func (n *apNet) start() {
	ctx, cancel := context.WithCancel(context.Background())
	n.cancel = cancel
	for _, p := range n.points {
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			for {
				wctx, stop := context.WithCancel(ctx)
				done := make(chan struct{})
				var gen uint64 // written by cfg, read by report: one goroutine, in turn
				go func() {
					defer close(done)
					p.w.Watch(wctx, n.every, func() ([]ap.File, error) {
						g, files, err := n.files()
						gen = g
						return files, err
					}, func(res push.Result, err error) { n.report(p, gen, res, err) })
				}()
				select {
				case <-ctx.Done():
					stop()
					<-done
					return
				case <-p.kick:
					stop()
					<-done
				}
			}
		}()
	}
}

func (n *apNet) close() {
	if n.cancel != nil {
		n.cancel()
		n.wg.Wait()
	}
	n.mu.Lock()
	n.cond.Broadcast()
	n.mu.Unlock()
}

// nudge has every access point pushed now.
func (n *apNet) nudge() {
	for _, p := range n.points {
		select {
		case p.kick <- struct{}{}:
		default:
		}
	}
}

// files is what every access point must hold now, and its generation.
// Until enrolment's hand-over it is the setup network alone. After it,
// each Devices-network device of the policy in force has its own
// password, saved before any access point is sent it, so a restart never
// forgets a password a device was given.
func (n *apNet) files() (uint64, []ap.File, error) {
	n.d.mu.Lock()
	doc, h := n.d.engine.CurrentHash()
	n.d.mu.Unlock()
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.st.Replaced {
		// The factory policy has no device, and no device has a password
		// before the hand-over (ap.Keys.Sync refuses one).
		k := ap.Keys{Setup: n.st.Keys.Setup}
		if n.replacing {
			k = n.st.Keys
		}
		files, err := ap.Config(policy.Document{}, n.layout, k)
		return n.gen, files, err
	}
	if h != n.hash {
		next := apState{Keys: cloneKeys(n.st.Keys), Replaced: true}
		if _, err := next.Keys.Sync(doc); err != nil {
			return n.gen, nil, err
		}
		if !keysEqual(next.Keys, n.st.Keys) {
			if err := n.save(next); err != nil {
				return n.gen, nil, fmt.Errorf("device Wi-Fi passwords not saved, so not pushed: %w", err)
			}
			n.st = next
		}
		n.hash = h
	}
	files, err := ap.Config(doc, n.layout, n.st.Keys)
	return n.gen, files, err
}

// report takes one Watch report: kept for the page, logged when it
// changes, and handed to an enrolment waiting on it.
func (n *apNet) report(p *apPoint, gen uint64, res push.Result, err error) {
	if errors.Is(err, context.Canceled) {
		return // a nudge cut this push short; the next Watch pushes again
	}
	n.mu.Lock()
	p.gen, p.reported, p.res, p.err = gen, true, res, err
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	changed := msg != p.logged
	p.logged = msg
	n.cond.Broadcast()
	n.mu.Unlock()
	if changed {
		switch {
		case errors.Is(err, push.ErrStalled):
			n.d.dp.Logf(fmt.Sprintf("access point %s: stalled, %d session opens waiting: %v", p.addr, res.Abandoned, err))
		case err != nil:
			n.d.dp.Logf(fmt.Sprintf("access point %s: push failed: %v", p.addr, err))
		default:
			n.d.dp.Logf(fmt.Sprintf("access point %s: pushed", p.addr))
		}
	}
}

func (n *apNet) save(st apState) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return n.store.Save(b)
}

// Replaced reports whether enrolment's hand-over finished: every access
// point held the four networks and that was saved.
func (n *apNet) Replaced() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.st.Replaced
}

// Replace makes the four networks' passwords, saved before any is pushed,
// has every access point pushed them at once, and waits until each has
// reported holding them. Only then is the hand-over saved and the Owner
// network's card returned. A push that fails or does not finish in time
// undoes it: the access points are pushed the setup network again, the
// passwords are kept for the next try, and enrolment enrols nothing.
func (n *apNet) Replace() (enrol.Card, error) {
	n.mu.Lock()
	if n.st.Replaced {
		defer n.mu.Unlock()
		return n.ownerCard(), nil
	}
	if len(n.points) == 0 {
		n.mu.Unlock()
		return enrol.Card{}, errors.New("no access point configured")
	}
	if n.replacing {
		n.mu.Unlock()
		return enrol.Card{}, errors.New("a hand-over to the Owner network is already running")
	}
	if !n.st.Keys.Enrolled() {
		next := apState{Keys: cloneKeys(n.st.Keys)}
		if err := next.Keys.Enrol(); err != nil {
			n.mu.Unlock()
			return enrol.Card{}, err
		}
		if err := n.save(next); err != nil {
			n.mu.Unlock()
			return enrol.Card{}, fmt.Errorf("Wi-Fi passwords not saved: %w", err)
		}
		n.st = next
	}
	n.replacing = true
	n.gen++
	g := n.gen
	n.mu.Unlock()
	n.nudge()

	err := n.await(g)
	n.mu.Lock()
	n.replacing = false
	if err == nil {
		next := n.st
		next.Replaced = true
		if err = n.save(next); err == nil {
			n.st = next
			card := n.ownerCard()
			n.mu.Unlock()
			return card, nil
		}
	}
	n.gen++
	n.mu.Unlock()
	n.nudge() // the setup network again, wherever the four reached
	return enrol.Card{}, err
}

// await waits until every access point reported a push of generation g
// or later: nil when each succeeded, the first failure otherwise, or a
// timeout after wait.
func (n *apNet) await(g uint64) error {
	timeout := false
	t := time.AfterFunc(n.wait, func() {
		n.mu.Lock()
		timeout = true
		n.cond.Broadcast()
		n.mu.Unlock()
	})
	defer t.Stop()
	n.mu.Lock()
	defer n.mu.Unlock()
	for {
		done := true
		for _, p := range n.points {
			switch {
			case !p.reported || p.gen < g:
				done = false
			case p.err != nil:
				return fmt.Errorf("access point %s: %w", p.addr, p.err)
			}
		}
		if done {
			return nil
		}
		if timeout {
			return fmt.Errorf("the access points did not take the new networks within %v", n.wait)
		}
		n.cond.Wait()
	}
}

func (n *apNet) ownerCard() enrol.Card {
	c, _ := n.st.Keys.NetworkCard(n.layout, policy.NetOwner)
	return enrol.Card{SSID: c.SSID, Shown: c.Shown, QR: c.QR}
}

// tick pushes at once when the policy in force changed since the device
// passwords were last synced, so a device's new password, or the removal
// of one, reaches the access points without waiting for apEvery.
func (n *apNet) tick() {
	if len(n.points) == 0 {
		return
	}
	n.d.mu.Lock()
	_, h := n.d.engine.CurrentHash()
	n.d.mu.Unlock()
	n.mu.Lock()
	stale := n.st.Replaced && h != n.hash
	n.mu.Unlock()
	if stale {
		n.nudge()
	}
}

// pageAPs is the access points as the page shows them.
type pageAPs struct{ n *apNet }

func (p pageAPs) Points() []page.APState {
	p.n.mu.Lock()
	defer p.n.mu.Unlock()
	out := make([]page.APState, 0, len(p.n.points))
	for _, x := range p.n.points {
		out = append(out, page.APState{Addr: x.addr, Stalled: errors.Is(x.err, push.ErrStalled), Abandoned: x.res.Abandoned})
	}
	return out
}

// Cards is the four networks' cards once enrolment handed over, then one
// for each Devices-network device by id, with the band devices join on
// (ENF-g-7). Before the hand-over home is not served (the page sends the
// owner to /enrol), and the setup network's password is the sticker's.
func (p pageAPs) Cards() []page.WiFiCard {
	n := p.n
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.st.Replaced {
		return nil
	}
	var out []page.WiFiCard
	for _, net := range []string{policy.NetOwner, policy.NetHousehold, policy.NetGuests} {
		if c, ok := n.st.Keys.NetworkCard(n.layout, net); ok {
			out = append(out, page.WiFiCard{Network: net, SSID: c.SSID, Shown: c.Shown, Note: c.Note, QR: c.QR})
		}
	}
	ids := make([]string, 0, len(n.st.Keys.Device))
	for id := range n.st.Keys.Device {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		if c, ok := n.st.Keys.DeviceCard(n.layout, id); ok {
			out = append(out, page.WiFiCard{Device: id, SSID: c.SSID, Shown: c.Shown, Note: c.Note, QR: c.QR})
		}
	}
	return out
}

func cloneKeys(k ap.Keys) ap.Keys {
	k.Device = maps.Clone(k.Device)
	return k
}

func keysEqual(a, b ap.Keys) bool {
	if a.Setup != b.Setup || a.Owner != b.Owner || a.Household != b.Household || a.Guests != b.Guests || a.Devices != b.Devices || len(a.Device) != len(b.Device) {
		return false
	}
	for id, k := range a.Device {
		if b.Device[id] != k {
			return false
		}
	}
	return true
}

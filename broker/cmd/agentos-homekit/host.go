package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/homekit"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// stateName is the paired devices' file in the clerk's directory (design
// point 4): each Device's name, address, pin, AID, bounds and off, never a
// HomeKit code or a key but the accessory's public key.
const stateName = "homekit.json"

// maxState bounds the file read; maxDevices is the number of thermostats
// the clerk holds (a bridge counts each of its thermostats); maxListed
// bounds one listing from the enforcer.
const (
	maxState   = 64 << 10
	maxDevices = 16
	maxListed  = 64
)

// The host's errors: fixed text naming nothing an accessory sent and no
// part of a HomeKit code. agentosd maps them to the page's codes (b2b).
var (
	errArgs        = errors.New("homekit: the call's arguments are refused")
	errNotListed   = errors.New("homekit: the enforcer does not list that accessory")
	errPaired      = errors.New("homekit: that accessory is paired; reset HomeKit on it first")
	errExists      = errors.New("homekit: a device with that name is connected")
	errUnknown     = errors.New("homekit: no device with that name is connected")
	errCode        = errors.New("homekit: the accessory refused the HomeKit code")
	errMaxTries    = errors.New("homekit: the accessory takes no more tries until HomeKit is reset on it")
	errBusy        = errors.New("homekit: the accessory refused pairing now; try again later")
	errUnreachable = errors.New("homekit: the accessory could not be reached")
	errNotOpen     = errors.New("homekit: the device is not open now")
	errBounds      = errors.New("homekit: those bounds are refused")
	errStopped     = errors.New("homekit: stopped (STOP); only status and resume are served")
	errAdmission   = errors.New("homekit: no room for another device")
	errState       = errors.New("homekit: the devices file does not load")
	errSave        = errors.New("homekit: the devices file was not written")
)

// nameRE is the owner's name for a device; a bridge's further thermostats
// are named name-2 and on (homekit.Clerk.Resolve).
var nameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// recordNameRE admits the -N suffix past the owner's 32 characters.
var recordNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)

// bounds are the owner's confirmed bounds for one setpoint, in °C.
type bounds struct {
	Min float64 `json:"min"`
	Max float64 `json:"max"`
}

// record is one paired thermostat as the file holds it.
type record struct {
	Name        string `json:"name"`
	Addr        string `json:"addr"`
	AccessoryID string `json:"accessory_id"`
	// Key is the accessory's Ed25519 long-term public key (AccessoryLTPK),
	// hex: the pin (DEV-3).
	Key    string            `json:"key"`
	AID    uint64            `json:"aid,omitempty"`
	Bounds map[string]bounds `json:"bounds,omitempty"`
	Off    bool              `json:"off,omitempty"`
}

// state is the file's form.
type state struct {
	Devices []record `json:"devices"`
	// Stopped is the last STOP the owner side relayed (KRN-7), kept so a
	// restart during a STOP opens no link.
	Stopped bool `json:"stopped,omitempty"`
}

// setpoints are the characteristics that take bounds: the rows with an
// in-bounds verb (target temperature and the two thresholds).
func setpoint(char string) bool {
	return homekit.ClassFor(homekit.ServiceThermostat, char).InBounds != ""
}

func toRecord(d homekit.Device) record {
	r := record{Name: d.Name, Addr: d.Addr, AccessoryID: d.Pin.AccessoryID, Key: hex.EncodeToString(d.Pin.LTPK), AID: d.AID, Off: d.Off}
	for c, b := range d.Bounds {
		if b.Confirmed {
			if r.Bounds == nil {
				r.Bounds = map[string]bounds{}
			}
			r.Bounds[c] = bounds{b.Min, b.Max}
		}
	}
	return r
}

// device reads and checks a record: the clerk's Device, pin included.
func (r record) device() (homekit.Device, error) {
	k, err := hex.DecodeString(r.Key)
	if err != nil || len(k) != ed25519.PublicKeySize || !recordNameRE.MatchString(r.Name) || checkAddr(r.Addr) != nil {
		return homekit.Device{}, errState
	}
	d := homekit.Device{Name: r.Name, Addr: r.Addr, Pin: homekit.Pin{AccessoryID: r.AccessoryID, LTPK: k}, AID: r.AID, Off: r.Off}
	if !d.Pin.Valid() {
		return homekit.Device{}, errState
	}
	for c, b := range r.Bounds {
		if !setpoint(c) || !finite(b.Min, b.Max) || b.Min > b.Max {
			return homekit.Device{}, errState
		}
		if d.Bounds == nil {
			d.Bounds = map[string]homekit.Bounds{}
		}
		d.Bounds[c] = homekit.Bounds{Min: b.Min, Max: b.Max, Confirmed: true}
	}
	return d, nil
}

func finite(v ...float64) bool {
	for _, f := range v {
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return false
		}
	}
	return true
}

// checkAddr admits an "ip:port" on the home network only: a private or
// link-local address with no zone and a port (DEV-2, NET-2).
func checkAddr(s string) error {
	ap, err := netip.ParseAddrPort(s)
	a := ap.Addr()
	if err != nil || ap.Port() == 0 || a.Zone() != "" || !(a.IsPrivate() || a.IsLinkLocalUnicast()) || ap.String() != s {
		return errArgs
	}
	return nil
}

// listed is one HAP accessory the enforcer's channel lists (design point
// 3): its device ID in the enforcer, address, HAP port and the TXT record's
// id, c# and sf. Only a listed accessory can be connected.
type listed struct {
	Device string `json:"device"`
	Addr   string `json:"addr"`
	Port   uint16 `json:"port"`
	ID     string `json:"id"`
	C      uint32 `json:"c#"`
	SF     uint8  `json:"sf"`
}

// unpaired says the TXT sf flag's bit 0 is set: the accessory is not paired.
func (l listed) unpaired() bool { return l.SF&1 != 0 }

func (l listed) hostport() string {
	return netip.AddrPortFrom(netip.MustParseAddr(l.Addr), l.Port).String()
}

var (
	deviceIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)
	hapIDRE    = regexp.MustCompile(`^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$`)
)

// check puts a listed entry in canonical form, so no text the enforcer's
// channel sent reaches a STATUS line or the page unchecked.
func (l listed) check() (listed, error) {
	a, err := netip.ParseAddr(l.Addr)
	if err != nil || l.Port == 0 || !deviceIDRE.MatchString(l.Device) || !hapIDRE.MatchString(l.ID) || l.C == 0 {
		return listed{}, errArgs
	}
	l.Addr, l.ID = a.String(), strings.ToUpper(l.ID)
	if checkAddr(l.hostport()) != nil {
		return listed{}, errArgs
	}
	return l, nil
}

// entry is one paired thermostat in the host: its Device and, while a
// runner holds one, its open link.
type entry struct {
	dev homekit.Device
	// link is the open link and ld the runner's copy of dev it was opened
	// with; both under host.mu, and ld's Bounds only under host.op.
	link   link
	ld     *homekit.Device
	cancel context.CancelFunc
	done   chan struct{}
	drops  int
}

// host is the HomeKit clerk's process state: the clerk, the address
// guard, the devices file, the enforcer's listing and one runner per
// device that is not off.
type host struct {
	dir      string
	p        pairer
	guard    *netguard.Policy
	events   *limiter
	log      func(string)
	setupKey [32]byte
	pairing  string // the box's controller pairing ID (public)

	// op serializes the owner's steps, which may each take a dial; mu
	// guards the state below for short sections only.
	op      sync.Mutex
	mu      sync.Mutex
	devs    []*entry
	stopped bool
	listed  []listed
	configs map[string]uint32 // last c# seen per accessory ID
	pinned  []netguard.Pin    // the guard's pins as last set
	ctx     context.Context
	wg      sync.WaitGroup
	started bool
}

// load reads the devices file: missing is no device; any malformed record
// refuses the whole file (design point 4).
func load(dir string) (state, []homekit.Device, error) {
	f, err := os.OpenFile(filepath.Join(dir, stateName), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return state{}, nil, nil
	}
	if err != nil {
		return state{}, nil, errState
	}
	defer f.Close()
	if privfile.CheckFile(f) != nil {
		return state{}, nil, errState
	}
	b, err := io.ReadAll(io.LimitReader(f, maxState+1))
	if err != nil || len(b) > maxState {
		return state{}, nil, errState
	}
	var st state
	if json.Unmarshal(b, &st) != nil || len(st.Devices) > maxDevices {
		return state{}, nil, errState
	}
	seen := map[string]bool{}
	var devs []homekit.Device
	for _, r := range st.Devices {
		d, err := r.device()
		if err != nil || seen[r.Name] {
			return state{}, nil, errState
		}
		seen[r.Name] = true
		devs = append(devs, d)
	}
	return st, devs, nil
}

// save writes the devices whole (privfile.WriteAtomic); held under h.mu.
func (h *host) save() error {
	st := state{Stopped: h.stopped, Devices: []record{}}
	for _, e := range h.devs {
		st.Devices = append(st.Devices, toRecord(e.dev))
	}
	b, err := json.Marshal(st)
	if err != nil {
		return errSave
	}
	if privfile.WriteAtomic(h.dir, stateName, b, nil) != nil {
		return errSave
	}
	return nil
}

// start loads the devices file and opens every device that is not off,
// unless a STOP holds. A malformed file refuses the start before any dial.
func (h *host) start(ctx context.Context) error {
	st, devs, err := load(h.dir)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ctx, h.stopped, h.configs = ctx, st.Stopped, map[string]uint32{}
	for _, d := range devs {
		h.devs = append(h.devs, &entry{dev: d})
	}
	h.pins(nil)
	h.started = true
	for _, e := range h.devs {
		h.run(e)
	}
	return nil
}

// pins hands the guard every paired device's GuardPin and, during a
// connect, the setup pin for the listed address (HK-21); held under h.mu.
func (h *host) pins(setup *netip.AddrPort) {
	var ps []netguard.Pin
	for _, e := range h.devs {
		if p, err := e.dev.GuardPin(); err == nil && !slices.Contains(ps, p) {
			ps = append(ps, p)
		}
	}
	if setup != nil {
		ps = append(ps, netguard.Pin{Kind: netguard.PinDevice, Addr: *setup, Key: h.setupKey})
	}
	if err := h.guard.SetPins(ps); err != nil {
		h.log("homekit: the address guard refused the devices' pins: " + err.Error())
		return
	}
	h.pinned = ps
}

// run starts e's runner when it is not off and no STOP holds; held under
// h.mu.
func (h *host) run(e *entry) {
	if !h.started || h.stopped || e.dev.Off || e.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(h.ctx)
	e.cancel, e.done = cancel, make(chan struct{})
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		defer close(e.done)
		h.loop(ctx, e)
	}()
}

// halt ends e's runner and closes its link, so a blocked step ends at
// once; held under h.mu. It returns the channel that closes when the
// runner has returned.
func (h *host) halt(e *entry) <-chan struct{} {
	done := e.done
	if e.cancel != nil {
		e.cancel()
		e.cancel = nil
	}
	if e.link != nil {
		e.link.Close()
	}
	if done == nil {
		done = make(chan struct{})
		close(done)
	}
	return done
}

// sleep waits d or until ctx ends.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// loop is one device's runner: open by pair-verify, poll every pollEvery,
// and redial a dropped link with a capped backoff, raising one counted
// line per drop. An identity mismatch turns the device off (HK-18) and the
// runner ends; only a re-pin brings it back.
func (h *host) loop(ctx context.Context, e *entry) {
	wait := backoff.Min
	for ctx.Err() == nil {
		h.mu.Lock()
		d := e.dev
		d.Bounds = maps.Clone(d.Bounds)
		h.mu.Unlock()
		if d.AID == 0 {
			if h.resolve(ctx, e, &d) {
				return
			}
		} else if l, err := h.p.Open(ctx, &d); err == nil {
			wait = backoff.Min
			if !h.hold(ctx, e, l, &d) {
				return
			}
		} else if d.Off {
			h.turnOff(e)
			return
		}
		if ctx.Err() != nil {
			return
		}
		h.mu.Lock()
		e.drops++
		n := e.drops
		h.mu.Unlock()
		h.log(fmt.Sprintf("homekit %s: link down, redialing (%d drops)", d.Name, n))
		if !sleep(ctx, wait) {
			return
		}
		wait = min(2*wait, backoff.Max)
	}
}

// hold keeps an open link, polling it until it fails or ctx ends; it
// reports whether the runner goes on.
func (h *host) hold(ctx context.Context, e *entry, l link, d *homekit.Device) bool {
	h.mu.Lock()
	if ctx.Err() != nil {
		h.mu.Unlock()
		l.Close()
		return false
	}
	e.link, e.ld = l, d
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		e.link, e.ld = nil, nil
		h.mu.Unlock()
		l.Close()
	}()
	for {
		if _, err := l.Poll(); err != nil {
			return ctx.Err() == nil
		}
		if !sleep(ctx, pollEvery) {
			return false
		}
	}
}

// turnOff records a device turned off by an identity mismatch (HK-18):
// a KRN-7 line, and the file, so a restart does not dial it again.
func (h *host) turnOff(e *entry) {
	h.mu.Lock()
	defer h.mu.Unlock()
	e.dev.Off = true
	if err := h.save(); err != nil {
		h.log("homekit " + e.dev.Name + ": off not saved: " + err.Error())
	}
	h.log("homekit " + e.dev.Name + ": KRN-7 off: the accessory did not prove its pinned key; re-pin it on the local page")
}

// resolve finds the thermostats behind a device paired before its
// accessories were read (ErrUnresolved at connect) and replaces it with
// one device per thermostat; it reports whether the runner is done.
func (h *host) resolve(ctx context.Context, e *entry, d *homekit.Device) bool {
	out, err := h.p.Resolve(ctx, d)
	if d.Off {
		h.turnOff(e)
		return true
	}
	if err != nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if ctx.Err() != nil {
		return true
	}
	i := slices.Index(h.devs, e)
	if i < 0 || len(h.devs)-1+len(out) > maxDevices || slices.ContainsFunc(out, func(o homekit.Device) bool {
		return slices.ContainsFunc(h.devs, func(x *entry) bool { return x != e && x.dev.Name == o.Name })
	}) {
		h.log("homekit " + d.Name + ": its thermostats were found, but their names or number are refused; disconnect it and connect it again")
		return false
	}
	old := slices.Clone(h.devs)
	var add []*entry
	for _, o := range out {
		add = append(add, &entry{dev: o})
	}
	h.devs = slices.Insert(slices.Delete(h.devs, i, i+1), i, add...)
	if err := h.save(); err != nil {
		h.devs = old
		return false
	}
	e.cancel = nil
	for _, n := range add {
		h.run(n)
	}
	return true
}

func (h *host) find(name string) *entry {
	for _, e := range h.devs {
		if e.dev.Name == name {
			return e
		}
	}
	return nil
}

// group is every device on e's accessory (a bridge's thermostats share one
// pairing); held under h.mu.
func (h *host) group(e *entry) []*entry {
	var out []*entry
	for _, x := range h.devs {
		if x.dev.Pin.AccessoryID == e.dev.Pin.AccessoryID && x.dev.Addr == e.dev.Addr {
			out = append(out, x)
		}
	}
	return out
}

// nameFree says no device but those in skip is name or a bridge sibling
// of it (name-2 and on); held under h.mu.
func (h *host) nameFree(name string, skip []*entry) bool {
	return !slices.ContainsFunc(h.devs, func(x *entry) bool {
		return !slices.Contains(skip, x) && (x.dev.Name == name || strings.HasPrefix(x.dev.Name, name+"-") || strings.HasPrefix(name, x.dev.Name+"-"))
	})
}

// listedBy returns the listed accessory with the enforcer's device ID;
// held under h.mu.
func (h *host) listedBy(device string) (listed, bool) {
	for _, l := range h.listed {
		if l.Device == device {
			return l, true
		}
	}
	return listed{}, false
}

// pairErr maps a pairing failure to the host's fixed errors.
func pairErr(err error) error {
	switch {
	case errors.Is(err, homekit.ErrAuthentication):
		return errCode
	case errors.Is(err, homekit.ErrMaxTries):
		return errMaxTries
	case errors.Is(err, homekit.ErrUnavailable):
		return errPaired
	case errors.Is(err, homekit.ErrBackoff), errors.Is(err, homekit.ErrBusy), errors.Is(err, homekit.ErrMaxPeers):
		return errBusy
	case errors.Is(err, homekit.ErrRefused):
		return errArgs
	}
	return errUnreachable
}

// pair runs one pair-setup by code with the listed accessory l (design
// point 3): the guard holds the setup pin for l's address only for the
// step, then the paired devices' GuardPins. It makes one attempt.
func (h *host) pair(name string, l listed, code string, skip []*entry) ([]homekit.Device, error) {
	addr := l.hostport()
	ap := netip.MustParseAddrPort(addr)
	h.mu.Lock()
	h.pins(&ap)
	ctx := h.ctx
	h.mu.Unlock()
	devs, err := h.p.Connect(ctx, name, addr, code)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pins(nil)
	if err != nil && !(errors.Is(err, homekit.ErrUnresolved) && len(devs) == 1) {
		h.log("homekit " + name + ": pair-setup with " + l.Device + " failed")
		return nil, pairErr(err)
	}
	if len(devs) == 0 || len(h.devs)-len(skip)+len(devs) > maxDevices {
		return nil, errAdmission
	}
	for _, d := range devs {
		if !h.nameFree(d.Name, skip) {
			return nil, errExists
		}
	}
	return devs, nil
}

// stepAllowed refuses every owner step but status and resume during a
// STOP; held under h.op.
func (h *host) stepAllowed() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.stopped {
		return errStopped
	}
	return nil
}

// connect is the owner's tier-4 connect (DEV-10, CH-6): the listed,
// unpaired accessory is paired by its HomeKit code, its thermostats are
// saved, and each opens by pair-verify. The code is used once and kept
// nowhere.
func (h *host) connect(name, device, code string) error {
	h.op.Lock()
	defer h.op.Unlock()
	if err := h.stepAllowed(); err != nil {
		return err
	}
	if !nameRE.MatchString(name) {
		return errArgs
	}
	h.mu.Lock()
	l, ok := h.listedBy(device)
	free, full := h.nameFree(name, nil), len(h.devs) >= maxDevices
	h.mu.Unlock()
	switch {
	case !ok:
		return errNotListed
	case !l.unpaired():
		return errPaired
	case !free:
		return errExists
	case full:
		return errAdmission
	}
	devs, err := h.pair(name, l, code, nil)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	var add []*entry
	for _, d := range devs {
		add = append(add, &entry{dev: d})
	}
	h.devs = append(h.devs, add...)
	if err := h.save(); err != nil {
		h.devs = h.devs[:len(h.devs)-len(add)]
		h.pins(nil)
		h.log("homekit " + name + ": paired but not saved; reset HomeKit on the thermostat and connect it again")
		return err
	}
	h.pins(nil)
	h.configs[devs[0].Pin.AccessoryID] = l.C
	h.log(fmt.Sprintf("homekit %s: connected by the owner, %d thermostats", name, len(devs)))
	for _, e := range add {
		h.run(e)
	}
	return nil
}

// repin is the owner's tier-4 re-pin (design point 5): after the owner
// resets HomeKit on the thermostat, pair-setup again by code with the
// listed accessory replaces every device on the old pairing. The new key
// is pinned and the old one refused.
func (h *host) repin(name, device, code string) error {
	h.op.Lock()
	defer h.op.Unlock()
	if err := h.stepAllowed(); err != nil {
		return err
	}
	h.mu.Lock()
	e := h.find(name)
	l, ok := h.listedBy(device)
	var grp []*entry
	if e != nil {
		grp = h.group(e)
	}
	h.mu.Unlock()
	switch {
	case e == nil:
		return errUnknown
	case !ok:
		return errNotListed
	case !l.unpaired():
		return errPaired
	}
	base := grp[0].dev.Name
	devs, err := h.pair(base, l, code, grp)
	if err != nil {
		return err
	}
	var dones []<-chan struct{}
	h.mu.Lock()
	old := slices.Clone(h.devs)
	for _, x := range grp {
		dones = append(dones, h.halt(x))
	}
	h.devs = slices.DeleteFunc(h.devs, func(x *entry) bool { return slices.Contains(grp, x) })
	var add []*entry
	for _, d := range devs {
		add = append(add, &entry{dev: d})
	}
	h.devs = append(h.devs, add...)
	if err := h.save(); err != nil {
		h.devs = old
		h.pins(nil)
		for _, x := range grp {
			h.run(x)
		}
		h.mu.Unlock()
		return err
	}
	h.pins(nil)
	h.configs[devs[0].Pin.AccessoryID] = l.C
	h.mu.Unlock()
	for _, d := range dones {
		<-d
	}
	h.mu.Lock()
	for _, x := range grp {
		h.events.forget(x.dev.Name)
	}
	for _, x := range add {
		h.run(x)
	}
	h.mu.Unlock()
	h.log("homekit " + base + ": re-pinned by the owner")
	return nil
}

// disconnect is the owner's disconnect (design point 5): remove-pairing
// for the box's own pairing over a pinned session, then every device on
// that pairing leaves the file, then its runner and counts go. With the
// accessory off or unreachable the devices still go; the answer says the
// accessory kept the pairing, so the owner resets HomeKit on it.
func (h *host) disconnect(name string) (bool, error) {
	h.op.Lock()
	defer h.op.Unlock()
	if err := h.stepAllowed(); err != nil {
		return false, err
	}
	h.mu.Lock()
	e := h.find(name)
	if e == nil {
		h.mu.Unlock()
		return false, errUnknown
	}
	grp := h.group(e)
	var dones []<-chan struct{}
	for _, x := range grp {
		dones = append(dones, h.halt(x))
	}
	d := e.dev
	ctx := h.ctx
	h.mu.Unlock()
	for _, c := range dones {
		<-c
	}
	removed := false
	// An accessory that did not prove its key is not dialed again (HK-18).
	if !d.Off && d.AID != 0 {
		if l, err := h.p.Open(ctx, &d); err == nil {
			removed = l.RemovePairing() == nil
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	old := slices.Clone(h.devs)
	h.devs = slices.DeleteFunc(h.devs, func(x *entry) bool { return slices.Contains(grp, x) })
	if err := h.save(); err != nil {
		h.devs = old
		for _, x := range grp {
			h.run(x)
		}
		return false, err
	}
	h.pins(nil)
	delete(h.configs, d.Pin.AccessoryID)
	for _, x := range grp {
		h.events.forget(x.dev.Name)
	}
	if removed {
		h.log("homekit " + name + ": disconnected by the owner; the accessory removed my pairing")
	} else {
		h.log("homekit " + name + ": disconnected by the owner here only; reset HomeKit on the thermostat")
	}
	return removed, nil
}

// bounds is the owner's tier-4 bounds confirmation (design point 6): the
// link checks them against the characteristic's declared range, and they
// are kept in the file. Until then every setpoint write is
// `actuate-physical`.
func (h *host) bounds(name, char string, lo, hi float64) error {
	h.op.Lock()
	defer h.op.Unlock()
	if err := h.stepAllowed(); err != nil {
		return err
	}
	if !setpoint(char) || !finite(lo, hi) || lo > hi {
		return errBounds
	}
	h.mu.Lock()
	e := h.find(name)
	if e == nil {
		h.mu.Unlock()
		return errUnknown
	}
	l, ld := e.link, e.ld
	h.mu.Unlock()
	if l == nil {
		return errNotOpen
	}
	prior := maps.Clone(ld.Bounds)
	if err := l.ConfirmBounds(char, lo, hi); err != nil {
		return errBounds
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	old := e.dev.Bounds
	e.dev.Bounds = maps.Clone(ld.Bounds)
	if err := h.save(); err != nil {
		e.dev.Bounds = old
		ld.Bounds = prior
		return err
	}
	h.log("homekit " + name + ": bounds confirmed by the owner for " + homekit.ClassFor(homekit.ServiceThermostat, char).Name)
	return nil
}

// stop is the owner side's STOP relay (KRN-7): every link closes and every
// step but status and resume is refused until resume. It is saved first,
// so a restart during a STOP opens nothing.
func (h *host) stop() error {
	h.mu.Lock()
	h.stopped = true
	err := h.save()
	var dones []<-chan struct{}
	for _, e := range h.devs {
		dones = append(dones, h.halt(e))
	}
	h.mu.Unlock()
	for _, d := range dones {
		<-d
	}
	h.log("homekit: every link closed (STOP)")
	return err
}

func (h *host) resume() error {
	h.op.Lock()
	defer h.op.Unlock()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stopped = false
	if err := h.save(); err != nil {
		h.stopped = true
		return err
	}
	for _, e := range h.devs {
		h.run(e)
	}
	h.log("homekit: links resumed")
	return nil
}

// setListed replaces the accessories the enforcer lists (design point 3).
// A listed accessory is never dialed until the owner connects it. A paired
// accessory listed with a new c# re-resolves its open links (Link.Config).
func (h *host) setListed(ls []listed) error {
	if err := h.stepAllowed(); err != nil {
		return err
	}
	if len(ls) > maxListed {
		return errArgs
	}
	out := make([]listed, 0, len(ls))
	seen := map[string]bool{}
	for _, l := range ls {
		c, err := l.check()
		if err != nil || seen[c.Device] {
			return errArgs
		}
		seen[c.Device] = true
		out = append(out, c)
	}
	type reconf struct {
		l    link
		c    uint32
		name string
	}
	var rs []reconf
	h.mu.Lock()
	h.listed = out
	for _, l := range out {
		last, known := h.configs[l.ID]
		h.configs[l.ID] = l.C
		if !known || last == l.C {
			continue
		}
		for _, e := range h.devs {
			if strings.EqualFold(e.dev.Pin.AccessoryID, l.ID) && e.link != nil {
				rs = append(rs, reconf{e.link, l.C, e.dev.Name})
			}
		}
	}
	h.mu.Unlock()
	for _, r := range rs {
		if err := r.l.Config(int(r.c)); err != nil {
			// The runner sees the failed link and redials, which resolves
			// afresh.
			r.l.Close()
			h.log("homekit " + r.name + ": re-resolve after a configuration change failed")
		}
	}
	return nil
}

// statusAnswer is STATUS: fixed lines, the devices and the listed
// accessories, for the page (b2b). It names a device by the owner's name,
// its type and its key's fingerprint, and a listed accessory by the
// enforcer's device ID; nothing an accessory sent appears.
type statusAnswer struct {
	Lines    []string       `json:"lines"`
	Stopped  bool           `json:"stopped"`
	Devices  []deviceStatus `json:"devices"`
	Listed   []listedStatus `json:"listed"`
	Pairing  string         `json:"pairing"` // the box's controller pairing ID
	MaxCount int            `json:"max_devices"`
}

type deviceStatus struct {
	Name string `json:"name"`
	Type string `json:"type"`
	// Key is the first 8 characters of the hex SHA-256 of the pinned
	// accessory key.
	Key    string            `json:"key"`
	State  string            `json:"state"` // "open", "connecting", "off", "stopped"
	Bounds map[string]bounds `json:"bounds,omitempty"`
}

type listedStatus struct {
	Device   string `json:"device"`
	Addr     string `json:"addr"`
	Unpaired bool   `json:"unpaired"`
}

// fingerprint is the first 8 characters of the pinned key's SHA-256.
func fingerprint(k ed25519.PublicKey) string {
	s := sha256.Sum256(k)
	return hex.EncodeToString(s[:4])
}

func (h *host) status() statusAnswer {
	h.mu.Lock()
	defer h.mu.Unlock()
	a := statusAnswer{Stopped: h.stopped, Devices: []deviceStatus{}, Listed: []listedStatus{}, MaxCount: maxDevices}
	a.Pairing = h.pairing
	if h.stopped {
		a.Lines = append(a.Lines, "homekit: stopped (STOP); no link opens until RESUME")
	}
	for _, e := range h.devs {
		st := "connecting"
		switch {
		case e.dev.Off:
			st = "off"
		case h.stopped:
			st = "stopped"
		case e.link != nil:
			st = "open"
		}
		fp := fingerprint(e.dev.Pin.LTPK)
		ds := deviceStatus{Name: e.dev.Name, Type: "thermostat", Key: fp, State: st}
		for c, b := range e.dev.Bounds {
			if b.Confirmed {
				if ds.Bounds == nil {
					ds.Bounds = map[string]bounds{}
				}
				ds.Bounds[c] = bounds{b.Min, b.Max}
			}
		}
		a.Devices = append(a.Devices, ds)
		c := h.events.stats(e.dev.Name)
		line := fmt.Sprintf("homekit %s: thermostat, key %s, %s; %d values counted, %d limited", e.dev.Name, fp, st, c.sent, c.limited)
		if e.drops > 0 {
			line += fmt.Sprintf(", %d drops", e.drops)
		}
		if e.dev.Off {
			line += "; the accessory did not prove its pinned key: reset HomeKit on it and re-pin it on the local page"
		}
		a.Lines = append(a.Lines, line)
	}
	for _, l := range h.listed {
		if slices.ContainsFunc(h.devs, func(e *entry) bool { return strings.EqualFold(e.dev.Pin.AccessoryID, l.ID) }) {
			continue
		}
		a.Listed = append(a.Listed, listedStatus{Device: l.Device, Addr: l.hostport(), Unpaired: l.unpaired()})
		if l.unpaired() {
			a.Lines = append(a.Lines, "homekit accessory "+l.Device+": listed by the enforcer, unpaired; connect it on the local page")
		} else {
			a.Lines = append(a.Lines, "homekit accessory "+l.Device+": listed by the enforcer, paired elsewhere; reset HomeKit on it to connect it")
		}
	}
	return a
}

// tick ends the DEV-8 windows every interval until ctx ends; then it stops
// every runner.
func (h *host) tick(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			h.mu.Lock()
			for _, e := range h.devs {
				h.halt(e)
			}
			h.mu.Unlock()
			h.wg.Wait()
			return
		case <-t.C:
			h.events.Flush()
		}
	}
}

package devsecret

// REQ: STO-4, STO-3

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/pairseal"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

const rp = "enforcer.home.arpa"

var canary = []byte("SYNTHETIC-LOCK-SECRET-CANARY-1")

type owner struct{ priv *ecdsa.PrivateKey }

func (o owner) public() key.PublicKey {
	point, _ := o.priv.PublicKey.Bytes()
	pk, err := key.ES256(rp, point)
	if err != nil {
		panic(err)
	}
	return pk
}

// sign is the owner's phone answering get() for msg's challenge on the
// enforcer's page.
func (o owner) sign(msg []byte) []byte {
	c := key.Challenge(msg)
	cd, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": base64.RawURLEncoding.EncodeToString(c[:]),
		"origin": "https://" + rp, "crossOrigin": false})
	h := sha256.Sum256([]byte(rp))
	ad := append(h[:], 0x01|0x04, 0, 0, 0, 0)
	cdh := sha256.Sum256(cd)
	m := sha256.Sum256(append(slices.Clone(ad), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, o.priv, m[:])
	if err != nil {
		panic(err)
	}
	b, err := key.AssertionSig(key.Assertion{AuthenticatorData: ad, ClientDataJSON: cd, Signature: sig})
	if err != nil {
		panic(err)
	}
	return b
}

type mem struct{ b []byte }

func (m *mem) Load() ([]byte, error) { return m.b, nil }
func (m *mem) Save(b []byte) error   { m.b = slices.Clone(b); return nil }

// box is the test's state sealing: AES-GCM under a key only the box holds.
type box struct{ aead cipher.AEAD }

func newBox() box {
	k := make([]byte, 32)
	rand.Read(k)
	b, _ := aes.NewCipher(k)
	g, _ := cipher.NewGCM(b)
	return box{g}
}

func (b box) Seal(p []byte) ([]byte, error) {
	n := make([]byte, b.aead.NonceSize())
	rand.Read(n)
	return b.aead.Seal(n, n, p, nil), nil
}

func (b box) Open(s []byte) ([]byte, error) {
	if len(s) < b.aead.NonceSize() {
		return nil, errors.New("short")
	}
	return b.aead.Open(nil, s[:b.aead.NonceSize()], s[b.aead.NonceSize():], nil)
}

// The processes of the test enforcer: one radio stack per lock, the page
// and the channel.
var (
	frontProc   = Peer{UID: 2001}
	sideProc    = Peer{UID: 2002}
	pageProc    = Peer{UID: 1001}
	channelProc = Peer{UID: 1002}
	drivers     = map[string]Peer{"front-lock": frontProc, "side-lock": sideProc, "back-lock": sideProc, "back-door": sideProc}
)

type rig struct {
	t     *testing.T
	o     owner
	eng   *policy.Engine
	key   *pairseal.Key
	disk  *mem
	box   box
	store *Store
	now   time.Time
	ver   uint64
}

// newRig is a home whose signed policy holds an everyday lamp and a back
// lock, and an empty secret store.
func newRig(t *testing.T) *rig {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	r := &rig{t: t, o: owner{priv}, disk: &mem{}, box: newBox(), now: time.Unix(1_800_000_000, 0), ver: 1}
	var err error
	if r.eng, err = policy.Open(r.o.public(), &mem{}); err != nil {
		t.Fatal(err)
	}
	if r.key, err = pairseal.NewKey(); err != nil {
		t.Fatal(err)
	}
	r.store = r.open()
	base := policy.Document{Devices: []policy.Device{
		{ID: "lamp", Network: policy.NetDevices, Everyday: true},
		{ID: "back-lock", Network: policy.NetDevices, Class: policy.ClassLock, Secure: "lock"},
	}}
	r.propose(base, "set up\n")
	r.land()
	return r
}

func (r *rig) open() *Store {
	r.t.Helper()
	s, err := Open(Config{Owner: r.o.public(), Key: r.key, Policy: r.eng, Box: r.box, Disk: r.disk,
		Process: func(d string) (Peer, bool) { p, ok := drivers[d]; return p, ok }})
	if err != nil {
		r.t.Fatal(err)
	}
	return s
}

// signed is the owner's approval of next with diff, at the next version.
func (r *rig) signed(next policy.Document, diff string) (policy.Proposal, []byte) {
	r.ver++
	next.Version = r.ver
	prop := policy.Proposal{Doc: next, Diff: []byte(diff)}
	root, err := prop.Root(r.o.public())
	if err != nil {
		r.t.Fatal(err)
	}
	return prop, r.o.sign(key.RootMsg(root))
}

func (r *rig) propose(next policy.Document, diff string) (policy.Proposal, []byte) {
	r.t.Helper()
	prop, sig := r.signed(next, diff)
	if _, err := r.eng.Propose(prop, sig, r.now.UnixMilli()); err != nil {
		r.t.Fatal(err)
	}
	return prop, sig
}

func (r *rig) land() {
	r.t.Helper()
	r.now = r.now.Add(time.Hour)
	if _, err := r.eng.Tick(r.now.UnixMilli()); err != nil {
		r.t.Fatal(err)
	}
}

func lock(id string) policy.Device {
	return policy.Device{ID: id, Network: policy.NetDevices, Class: policy.ClassLock, Secure: "lock"}
}

func with(d policy.Document, devs ...policy.Device) policy.Document {
	d.Devices = append(slices.Clone(d.Devices), devs...)
	return d
}

// addDiff is an add-device diff naming env's hash for device, as the page
// draws it.
func addDiff(device string, env []byte) string {
	return "This opens something.\nAdd the device " + device + ".\n" + pairseal.Statement(device, pairseal.HashHex(env)) + "\n"
}

func (r *rig) seal(device string) []byte {
	env, err := pairseal.Seal(r.key.Recipient(), device, canary)
	if err != nil {
		r.t.Fatal(err)
	}
	return env
}

// TestOpensOnlyAfterAssertion: a sealed secret opens only with the owner's
// assertion over a waiting diff that adds its device and names its hash;
// the same envelope offered for another device, replayed, with no or
// another assertion, or over a diff that names another hash or adds no
// device is refused, and nothing is held.
func TestOpensOnlyAfterAssertion(t *testing.T) {
	t.Run("approved", func(t *testing.T) {
		r := newRig(t)
		env := r.seal("front-lock")
		prop, sig := r.propose(with(r.eng.Current(), lock("front-lock")), addDiff("front-lock", env))
		if err := r.store.Admit("front-lock", env, prop, sig); err != nil {
			t.Fatal(err)
		}
		if fp, ok := r.store.Fingerprint("front-lock"); !ok || fp != pairseal.Hash(env) {
			t.Errorf("fingerprint %x %v", fp, ok)
		}
		if err := r.store.Admit("front-lock", env, prop, sig); !errors.Is(err, policy.ErrNotRising) {
			t.Errorf("replayed admission: %v", err)
		}
		r.land()
		if got, err := r.store.Release("front-lock", frontProc); err != nil || !bytes.Equal(got, canary) {
			t.Errorf("release after landing: %q %v", got, err)
		}
	})

	cases := []struct {
		name string
		do   func(r *rig) error
		want error
	}{
		{"no assertion", func(r *rig) error {
			env := r.seal("front-lock")
			prop, _ := r.propose(with(r.eng.Current(), lock("front-lock")), addDiff("front-lock", env))
			return r.store.Admit("front-lock", env, prop, nil)
		}, policy.ErrBadSig},
		{"another passkey", func(r *rig) error {
			env := r.seal("front-lock")
			prop, _ := r.propose(with(r.eng.Current(), lock("front-lock")), addDiff("front-lock", env))
			priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			root, _ := prop.Root(r.o.public())
			return r.store.Admit("front-lock", env, prop, owner{priv}.sign(key.RootMsg(root)))
		}, policy.ErrBadSig},
		{"assertion over another diff", func(r *rig) error {
			env := r.seal("front-lock")
			prop, sig := r.propose(with(r.eng.Current(), lock("front-lock")), addDiff("front-lock", env))
			prop.Diff = []byte("This opens something.\n")
			return r.store.Admit("front-lock", env, prop, sig)
		}, policy.ErrBadSig},
		{"diff names no secret", func(r *rig) error {
			env := r.seal("front-lock")
			prop, sig := r.propose(with(r.eng.Current(), lock("front-lock")), "This opens something.\nAdd the device front-lock.\n")
			return r.store.Admit("front-lock", env, prop, sig)
		}, ErrUnnamed},
		{"diff names another envelope", func(r *rig) error {
			env, planted := r.seal("front-lock"), r.seal("front-lock")
			prop, sig := r.propose(with(r.eng.Current(), lock("front-lock")), addDiff("front-lock", env))
			return r.store.Admit("front-lock", planted, prop, sig)
		}, ErrUnnamed},
		{"envelope for another device", func(r *rig) error {
			env := r.seal("front-lock")
			prop, sig := r.propose(with(r.eng.Current(), lock("side-lock")), addDiff("side-lock", env))
			return r.store.Admit("side-lock", env, prop, sig)
		}, pairseal.ErrOpen},
		{"change adds another device", func(r *rig) error {
			env := r.seal("front-lock")
			prop, sig := r.propose(with(r.eng.Current(), lock("side-lock")), addDiff("front-lock", env))
			return r.store.Admit("front-lock", env, prop, sig)
		}, ErrNotAdd},
		{"device already in the policy (a swap)", func(r *rig) error {
			env := r.seal("back-lock")
			prop, sig := r.propose(with(r.eng.Current(), lock("side-lock")), addDiff("back-lock", env))
			return r.store.Admit("back-lock", env, prop, sig)
		}, ErrNotAdd},
		{"everyday device", func(r *rig) error {
			env := r.seal("plug")
			prop, sig := r.propose(with(r.eng.Current(), policy.Device{ID: "plug", Network: policy.NetDevices, Everyday: true}), addDiff("plug", env))
			return r.store.Admit("plug", env, prop, sig)
		}, ErrNotAdd},
		{"signed but not waiting", func(r *rig) error {
			env := r.seal("front-lock")
			prop, sig := r.signed(with(r.eng.Current(), lock("front-lock")), addDiff("front-lock", env))
			return r.store.Admit("front-lock", env, prop, sig)
		}, ErrNotLive},
		{"replayed after cancel", func(r *rig) error {
			env := r.seal("front-lock")
			prop, sig := r.propose(with(r.eng.Current(), lock("front-lock")), addDiff("front-lock", env))
			if err := r.store.Admit("front-lock", env, prop, sig); err != nil {
				return err
			}
			r.eng.Cancel(r.eng.Pending()[0].ID)
			if err := r.store.Prune(); err != nil {
				return err
			}
			return r.store.Admit("front-lock", env, prop, sig)
		}, policy.ErrNotRising},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			if err := c.do(r); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			for _, d := range []string{"front-lock", "side-lock", "back-lock", "plug"} {
				if _, ok := r.store.Fingerprint(d); ok {
					t.Errorf("%s: a secret is held", d)
				}
			}
			r.land()
			for _, d := range []string{"front-lock", "side-lock", "back-lock", "plug"} {
				if _, err := r.store.Release(d, drivers[d]); err == nil {
					t.Errorf("%s: a secret is released", d)
				}
			}
		})
	}
}

// admit adds device with a sealed secret and lands the change.
func (r *rig) admit(device string) []byte {
	r.t.Helper()
	env := r.seal(device)
	prop, sig := r.propose(with(r.eng.Current(), lock(device)), addDiff(device, env))
	if err := r.store.Admit(device, env, prop, sig); err != nil {
		r.t.Fatal(err)
	}
	if _, err := r.store.Release(device, drivers[device]); !errors.Is(err, ErrNoSecret) {
		r.t.Errorf("%s released before its change landed: %v", device, err)
	}
	r.land()
	return env
}

// TestReleasedOnlyToOwnDevice: each secret goes only to the process that
// drives its device; another device's process, the page's and the
// channel's get none, and neither the page nor the channel links the
// store, so they hold no path to a secret at all.
func TestReleasedOnlyToOwnDevice(t *testing.T) {
	r := newRig(t)
	r.admit("front-lock")
	r.admit("side-lock")
	for _, c := range []struct {
		device string
		p      Peer
		ok     bool
	}{
		{"front-lock", frontProc, true},
		{"side-lock", sideProc, true},
		{"front-lock", sideProc, false},
		{"side-lock", frontProc, false},
		{"front-lock", pageProc, false},
		{"side-lock", pageProc, false},
		{"front-lock", channelProc, false},
		{"side-lock", channelProc, false},
		{"back-lock", sideProc, false}, // driven by side's stack, but holds no secret here
	} {
		got, err := r.store.Release(c.device, c.p)
		if c.ok != (err == nil) || c.ok != bytes.Equal(got, canary) {
			t.Errorf("%s to uid %d: %q %v", c.device, c.p.UID, got, err)
		}
	}
	got, _ := r.store.Release("front-lock", frontProc)
	clear(got)
	if again, err := r.store.Release("front-lock", frontProc); err != nil || !bytes.Equal(again, canary) {
		t.Error("a caller's copy aliases the store")
	}

	out, err := exec.Command("go", "list", "-deps", "../page", "../channel").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		if strings.HasSuffix(dep, "/enforcer/devsecret") {
			t.Errorf("the page or the channel links %s", dep)
		}
	}
}

// TestSealedAtRestAndErased: the store's saved state is sealed (no secret
// bytes on disk), survives a restart, and a secret is erased when its
// device is removed from the policy or its add-device change is
// cancelled.
func TestSealedAtRestAndErased(t *testing.T) {
	r := newRig(t)
	env := r.admit("front-lock")
	if bytes.Contains(r.disk.b, canary) {
		t.Fatal("the secret is on disk unsealed")
	}
	r.store = r.open()
	if fp, ok := r.store.Fingerprint("front-lock"); !ok || fp != pairseal.Hash(env) {
		t.Fatal("restart lost the secret")
	}
	if got, err := r.store.Release("front-lock", frontProc); err != nil || !bytes.Equal(got, canary) {
		t.Fatalf("release after restart: %v", err)
	}
	if _, err := Open(Config{Owner: r.o.public(), Key: r.key, Policy: r.eng, Box: newBox(), Disk: r.disk,
		Process: func(string) (Peer, bool) { return Peer{}, false }}); !errors.Is(err, ErrCorrupt) {
		t.Errorf("another box opened the state: %v", err)
	}

	// Removing a safety-list device is an asserted tightening: it applies
	// at once on the owner's assertion.
	cur := r.eng.Current()
	cur.Devices = slices.DeleteFunc(cur.Devices, func(d policy.Device) bool { return d.ID == "front-lock" })
	r.propose(cur, "This closes something on a safety-list device.\nRemove the device front-lock.\n")
	if err := r.store.Prune(); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.store.Fingerprint("front-lock"); ok {
		t.Error("removed device's secret still held")
	}

	// Cancelled: erased at once, so a later add of the same name without a
	// secret finds none.
	env = r.seal("side-lock")
	prop, sig := r.propose(with(r.eng.Current(), lock("side-lock")), addDiff("side-lock", env))
	if err := r.store.Admit("side-lock", env, prop, sig); err != nil {
		t.Fatal(err)
	}
	if err := r.store.Prune(); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.store.Fingerprint("side-lock"); !ok {
		t.Fatal("prune erased a waiting secret")
	}
	if err := r.eng.Cancel(r.eng.Pending()[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := r.store.Prune(); err != nil {
		t.Fatal(err)
	}
	r.propose(with(r.eng.Current(), lock("side-lock")), "This opens something.\nAdd the device side-lock.\n")
	r.land()
	if _, err := r.store.Release("side-lock", sideProc); !errors.Is(err, ErrNoSecret) {
		t.Errorf("cancelled secret released: %v", err)
	}
	if bytes.Contains(r.disk.b, canary) {
		t.Error("the secret is on disk unsealed")
	}
}

// failDisk refuses every save once fail is set.
type failDisk struct {
	mem
	fail bool
}

func (f *failDisk) Save(b []byte) error {
	if f.fail {
		return errors.New("disk full")
	}
	return f.mem.Save(b)
}

// TestSaveFailureFailsClosed: when the sealed state cannot be saved,
// Admit reports it and holds nothing, and Prune reports it but erases in
// memory all the same, so a cancelled secret is never released to a
// device re-added under its name without one (Security on #4073).
func TestSaveFailureFailsClosed(t *testing.T) {
	r := newRig(t)
	disk := &failDisk{}
	r.disk = &disk.mem
	var err error
	r.store, err = Open(Config{Owner: r.o.public(), Key: r.key, Policy: r.eng, Box: r.box, Disk: disk,
		Process: func(d string) (Peer, bool) { p, ok := drivers[d]; return p, ok }})
	if err != nil {
		t.Fatal(err)
	}
	r.admit("front-lock")

	disk.fail = true
	next := r.seal("side-lock")
	prop, sig := r.propose(with(r.eng.Current(), lock("side-lock")), addDiff("side-lock", next))
	if err := r.store.Admit("side-lock", next, prop, sig); err == nil {
		t.Error("Admit did not report the failed save")
	}
	if _, ok := r.store.Fingerprint("side-lock"); ok {
		t.Error("a secret is held that was never saved")
	}
	r.land()

	// Removed while the disk refuses: erased in memory, error reported.
	cur := r.eng.Current()
	cur.Devices = slices.DeleteFunc(cur.Devices, func(d policy.Device) bool { return d.ID == "front-lock" })
	r.propose(cur, "This closes something on a safety-list device.\nRemove the device front-lock.\n")
	if err := r.store.Prune(); err == nil {
		t.Error("Prune did not report the failed save")
	}
	if _, ok := r.store.Fingerprint("front-lock"); ok {
		t.Error("a removed device's secret is still held after a failed save")
	}

	// Cancelled while the disk refuses, then the name re-added with no
	// secret: nothing is released.
	disk.fail = false
	env := r.seal("back-door")
	prop, sig = r.propose(with(r.eng.Current(), lock("back-door")), addDiff("back-door", env))
	if err := r.store.Admit("back-door", env, prop, sig); err != nil {
		t.Fatal(err)
	}
	disk.fail = true
	if err := r.eng.Cancel(r.eng.Pending()[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := r.store.Prune(); err == nil {
		t.Error("Prune did not report the failed save")
	}
	r.propose(with(r.eng.Current(), lock("back-door")), "This opens something.\nAdd the device back-door.\n")
	r.store.Prune()
	r.land()
	if _, err := r.store.Release("back-door", sideProc); !errors.Is(err, ErrNoSecret) {
		t.Errorf("a cancelled secret was released after failed saves: %v", err)
	}
	disk.fail = false
	if err := r.store.Prune(); err != nil {
		t.Fatal(err)
	}
}

// TestPruneRetriesFailedSave: after a Prune whose save failed, the next
// Prune saves the erase even though nothing is left to erase in memory,
// so the erased secret is gone on disk too, not only at the next Admit or
// restart (L3 on #4073).
// REQ: STO-4
func TestPruneRetriesFailedSave(t *testing.T) {
	r := newRig(t)
	disk := &failDisk{}
	r.disk = &disk.mem
	open := func() *Store {
		t.Helper()
		s, err := Open(Config{Owner: r.o.public(), Key: r.key, Policy: r.eng, Box: r.box, Disk: disk,
			Process: func(d string) (Peer, bool) { p, ok := drivers[d]; return p, ok }})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	r.store = open()
	r.admit("front-lock")

	disk.fail = true
	cur := r.eng.Current()
	cur.Devices = slices.DeleteFunc(cur.Devices, func(d policy.Device) bool { return d.ID == "front-lock" })
	r.propose(cur, "This closes something on a safety-list device.\nRemove the device front-lock.\n")
	if err := r.store.Prune(); err == nil {
		t.Fatal("Prune did not report the failed save")
	}
	if _, ok := open().Fingerprint("front-lock"); !ok {
		t.Fatal("the failed save reached the disk")
	}
	if err := r.store.Prune(); err == nil {
		t.Error("a second Prune on a refusing disk did not retry the save")
	}

	disk.fail = false
	if err := r.store.Prune(); err != nil {
		t.Fatal(err)
	}
	if _, ok := open().Fingerprint("front-lock"); ok {
		t.Error("the erased secret is still on disk after a later Prune")
	}
	saved := slices.Clone(disk.b)
	if err := r.store.Prune(); err != nil || !bytes.Equal(disk.b, saved) {
		t.Errorf("a Prune with nothing owed saved again: %v", err)
	}
}

// TestEverydayLosesSecret: a safety-list device a later signed change
// makes everyday gets no secret and Prune erases it, as for a removed
// device (L3 on #4073).
// REQ: STO-4, NET-2
func TestEverydayLosesSecret(t *testing.T) {
	r := newRig(t)
	r.admit("front-lock")
	r.admit("side-lock")
	cur := r.eng.Current()
	for i, d := range cur.Devices {
		if d.ID == "front-lock" {
			cur.Devices[i] = policy.Device{ID: d.ID, Network: d.Network, Everyday: true}
		}
	}
	r.propose(cur, "This opens something.\nMove the device front-lock off the safety list.\n")
	r.land()
	if _, err := r.store.Release("front-lock", frontProc); !errors.Is(err, ErrNoSecret) {
		t.Errorf("an everyday device's secret released: %v", err)
	}
	if err := r.store.Prune(); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.store.Fingerprint("front-lock"); ok {
		t.Error("an everyday device's secret still held")
	}
	if got, err := r.store.Release("side-lock", sideProc); err != nil || !bytes.Equal(got, canary) {
		t.Errorf("the other lock lost its secret: %v", err)
	}
}

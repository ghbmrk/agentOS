package channel

// REQ: NET-2, STO-4

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/devsecret"
	"github.com/ghbmrk/agentos/broker/enforcer/pairseal"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/enforcer/wire"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

var lockCanary = []byte("SYNTHETIC-CHANNEL-LOCK-SECRET-CANARY")

type gcmBox struct{ aead cipher.AEAD }

func (b gcmBox) Seal(p []byte) ([]byte, error) {
	n := make([]byte, b.aead.NonceSize())
	rand.Read(n)
	return b.aead.Seal(n, n, p, nil), nil
}

func (b gcmBox) Open(s []byte) ([]byte, error) {
	if len(s) < b.aead.NonceSize() {
		return nil, errors.New("short")
	}
	return b.aead.Open(nil, s[:b.aead.NonceSize()], s[b.aead.NonceSize():], nil)
}

// heldLock is a device-secret store holding the lock's secret, admitted
// as the page admits it, and the envelope it came in.
func heldLock(t *testing.T) (*devsecret.Store, []byte) {
	t.Helper()
	p, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	o := owner{p}
	eng, err := policy.Open(o.public(), &memStore{})
	if err != nil {
		t.Fatal(err)
	}
	propose := func(d policy.Document, diff string) (policy.Proposal, []byte) {
		prop := policy.Proposal{Doc: d, Diff: []byte(diff)}
		root, _ := prop.Root(o.public())
		sig := o.sign(key.RootMsg(root))
		if _, err := eng.Propose(prop, sig, 0); err != nil {
			t.Fatal(err)
		}
		return prop, sig
	}
	propose(policy.Document{Version: 1}, "empty\n")
	if _, err := eng.Tick(policy.Wait); err != nil {
		t.Fatal(err)
	}
	k, _ := pairseal.NewKey()
	k2 := make([]byte, 32)
	rand.Read(k2)
	blk, _ := aes.NewCipher(k2)
	g, _ := cipher.NewGCM(blk)
	st, err := devsecret.Open(devsecret.Config{Owner: o.public(), Key: k, Policy: eng, Box: gcmBox{g}, Disk: &memStore{},
		Process: func(string) (devsecret.Peer, bool) { return devsecret.Peer{UID: 2001}, true }})
	if err != nil {
		t.Fatal(err)
	}
	env, err := pairseal.Seal(k.Recipient(), "lock", lockCanary)
	if err != nil {
		t.Fatal(err)
	}
	next := policy.Document{Version: 2, Devices: []policy.Device{{ID: "lock", Network: policy.NetDevices, Class: policy.ClassLock, Secure: SecureLock}}}
	prop, sig := propose(next, "Add the device lock.\n"+pairseal.Statement("lock", pairseal.HashHex(env))+"\n")
	if err := st.Admit("lock", env, prop, sig); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Tick(2 * policy.Wait); err != nil {
		t.Fatal(err)
	}
	if got, err := st.Release("lock", devsecret.Peer{UID: 2001}); err != nil || !bytes.Equal(got, lockCanary) {
		t.Fatalf("the store does not hold the secret: %v", err)
	}
	return st, env
}

// TestNoSecretOnChannel: with the enforcer's real device-secret store wired
// in, no read of any kind, for any device, and no reply to any other kind
// carries the secret's bytes; the fingerprint read answers exactly the
// envelope's hash, and only for a device whose secret is held. The channel
// links no path to a secret: its one hook is Fingerprint, whose type holds
// a hash.
func TestNoSecretOnChannel(t *testing.T) {
	st, env := heldLock(t)
	r := newRig(t, func(c *Config) {
		c.Fingerprint = st.Fingerprint
		// Every refusal below is expected; none is a burst.
		c.Limits = map[Kind]Limit{KindRefused: {Burst: 1000, Every: time.Millisecond}}
	})
	cl := r.dial()
	var replies []wire.Msg
	devices := []string{""}
	for _, d := range home().Devices {
		devices = append(devices, d.ID)
	}
	id := uint64(1)
	for _, d := range devices {
		for _, what := range []wire.ReadWhat{wire.ReadState, wire.ReadExport, wire.ReadFingerprint, wire.ReadTraffic} {
			if what == wire.ReadExport && d != "" || what != wire.ReadExport && d == "" {
				continue
			}
			m := cl.do(wire.Read{ID: id, What: what, Device: d})
			id++
			replies = append(replies, m)
			rep, ok := m.(wire.ReadReply)
			switch {
			case what == wire.ReadFingerprint && d == "lock":
				if want := pairseal.Hash(env); !ok || !bytes.Equal(rep.Body, want[:]) {
					t.Errorf("lock's fingerprint is %+v, want the envelope's hash", m)
				}
			case what == wire.ReadFingerprint && ok:
				t.Errorf("%s: a fingerprint for a secret not held: %+v", d, m)
			}
		}
	}
	// The other two kinds, aimed at the device whose secret is held.
	replies = append(replies,
		cl.do(wire.Command{ID: id, Device: "lock", Verb: wire.VerbLock}),
		cl.do(wire.Command{ID: id + 1, Device: "lock", Verb: wire.VerbOn}),
		cl.do(wire.Tighten{ID: id + 2, Kind: wire.IsolateDevice, Device: "lock"}),
	)
	all := fmt.Sprintf("%#v %#v", replies, r.events())
	if bytes.Contains([]byte(all), lockCanary) {
		t.Fatal("a channel reply or log line carries the secret")
	}
	for _, m := range replies {
		if rep, ok := m.(wire.ReadReply); ok && bytes.Contains(rep.Body, lockCanary) {
			t.Fatalf("read reply %d carries the secret", rep.ID)
		}
	}
}

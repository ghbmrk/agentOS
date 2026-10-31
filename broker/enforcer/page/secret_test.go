package page

// REQ: STO-4, STO-3

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/devsecret"
	"github.com/ghbmrk/agentos/broker/enforcer/pairseal"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

var lockSecret = []byte("SYNTHETIC-FRONT-LOCK-SECRET")

type gcmBox struct{ aead cipher.AEAD }

func newGCMBox() gcmBox {
	k := make([]byte, 32)
	rand.Read(k)
	b, _ := aes.NewCipher(k)
	g, _ := cipher.NewGCM(b)
	return gcmBox{g}
}

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

var frontStack = devsecret.Peer{UID: 2001}

// secretRig is newRig's page with the enforcer's device-secret store wired
// in, as the daemon wires it.
func secretRig(t *testing.T) (*rig, *devsecret.Store, *pairseal.Key) {
	t.Helper()
	g := newRig(t)
	k, err := pairseal.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	st, err := devsecret.Open(devsecret.Config{Owner: g.a.Public(), Key: k, Policy: g.e, Box: newGCMBox(), Disk: &memStore{},
		Process: func(d string) (devsecret.Peer, bool) { return frontStack, d == "front" }})
	if err != nil {
		t.Fatal(err)
	}
	g.s, err = New(Config{
		Name: rp, Owner: g.a.Public(),
		Addrs:  []netip.AddrPort{netip.AddrPortFrom(ownerAddr, 443)},
		Allow:  []netip.Prefix{netip.PrefixFrom(ownerAddr, 32)},
		Policy: g.e, Channel: g.ch, Cert: g.cert.Leaf, Secrets: st,
		Now: func() time.Time { return g.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return g, st, k
}

var addFront = edit(2, func(d *policy.Document) {
	d.Devices = append(d.Devices, policy.Device{ID: "front", Network: policy.NetDevices, Class: policy.ClassLock, Secure: "lock"})
})

// sealedLink is the add-device link the core's helper draws: the device
// and hash in the query, the envelope in the fragment, which the browser
// does not send, so it is returned apart.
func sealedLink(next policy.Document, device, hash string) string {
	return linkFor(next, "") + "&" + pairseal.ParamDevice + "=" + url.QueryEscape(device) + "&" + pairseal.ParamHash + "=" + hash
}

func (g *rig) openSealed(link string) (string, string, string) {
	g.t.Helper()
	w := g.do(http.MethodGet, link, nil)
	if w.Code != http.StatusOK {
		g.t.Fatalf("open: %d %s", w.Code, w.Body)
	}
	body := w.Body.String()
	id, ch := reID.FindStringSubmatch(body), reChal.FindStringSubmatch(body)
	if id == nil || ch == nil {
		g.t.Fatalf("no challenge on the screen:\n%s", body)
	}
	return body, id[1], ch[1]
}

type sealedTap struct {
	assertion
	Sealed string `json:"sealed"`
}

func (g *rig) approveSealed(id string, a assertion, env []byte) *httptest.ResponseRecorder {
	a.ID = id
	return g.do(http.MethodPost, "/approve", sealedTap{a, base64.RawURLEncoding.EncodeToString(env)})
}

// TestAddDeviceHandsOverSealedSecret: an add-device link that names a
// sealed secret draws a diff with pairseal.Statement's line for that
// device and hash, and the owner's one tap, with the envelope from the
// fragment, both adds the device (a loosening, waiting) and has the store
// hold the secret; it is released to the device's process once the change
// lands. Cancelling the change erases the secret.
func TestAddDeviceHandsOverSealedSecret(t *testing.T) {
	g, st, k := secretRig(t)
	env, _ := pairseal.Seal(k.Recipient(), "front", lockSecret)
	h := pairseal.HashHex(env)
	body, id, ch := g.openSealed(sealedLink(addFront, "front", h))
	if !strings.Contains(body, template_escape(pairseal.Statement("front", h[:pairseal.ShortHash]+"…"))) ||
		!strings.Contains(body, "<code>"+h+"</code>") || !strings.Contains(body, `data-sealed="1"`) {
		t.Fatalf("the screen does not name the sealed secret, hash short and in full:\n%s", body)
	}
	if strings.Contains(body, string(lockSecret)) {
		t.Fatal("the screen shows the secret")
	}
	if w := g.approveSealed(id, g.a.get(ch), env); w.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	if fp, ok := st.Fingerprint("front"); !ok || fp != pairseal.Hash(env) || len(g.e.Pending()) != 1 {
		t.Fatalf("not held: %v, pending %d", ok, len(g.e.Pending()))
	}
	if _, err := st.Release("front", frontStack); err == nil {
		t.Error("released before the change landed")
	}
	// The owner signed the whole line; the home page shows it short too.
	if diff := string(g.e.Pending()[0].Diff); !strings.Contains(diff, "\n"+pairseal.Statement("front", h)+"\n") {
		t.Errorf("the signed diff lacks the whole line:\n%s", diff)
	}
	if home := g.do(http.MethodGet, "/", nil).Body.String(); !strings.Contains(home, template_escape(pairseal.Statement("front", h[:pairseal.ShortHash]+"…"))) ||
		!strings.Contains(home, "<code>"+h+"</code>") {
		t.Errorf("the home page does not show the waiting line short:\n%s", home)
	}

	// Cancel on the page: the secret goes with the change.
	pid := g.e.Pending()[0].ID
	w := g.do(http.MethodPost, "/challenge", map[string]string{"action": ActCancel, "target": pid})
	var c struct{ ID, Challenge string }
	json.Unmarshal(w.Body.Bytes(), &c)
	a := g.a.get(c.Challenge)
	a.ID = c.ID
	if w := g.do(http.MethodPost, "/act", struct {
		assertion
		Action string `json:"action"`
	}{a, ActCancel}); w.Code != http.StatusOK {
		t.Fatalf("cancel: %d %s", w.Code, w.Body)
	}
	if _, ok := st.Fingerprint("front"); ok {
		t.Fatal("a cancelled change's secret is still held")
	}

	// Again, and let it land.
	env, _ = pairseal.Seal(k.Recipient(), "front", lockSecret)
	_, id, ch = g.openSealed(sealedLink(addFront, "front", pairseal.HashHex(env)))
	if w := g.approveSealed(id, g.a.get(ch), env); w.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	if _, err := g.e.Tick(g.now.Add(time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if got, err := st.Release("front", frontStack); err != nil || string(got) != string(lockSecret) {
		t.Fatalf("release after landing: %v", err)
	}
}

// TestSealedLinkRefusals: a link whose secret names no added safety-list
// device, an ill-formed hash, a page with no store, a tap without the
// envelope or with another one, and an envelope the store cannot open for
// the device are all refused, and nothing is added or held.
func TestSealedLinkRefusals(t *testing.T) {
	g, st, k := secretRig(t)
	env, _ := pairseal.Seal(k.Recipient(), "front", lockSecret)
	h := pairseal.HashHex(env)
	tv := edit(2, func(d *policy.Document) {
		d.Devices = append(d.Devices, policy.Device{ID: "front", Network: policy.NetDevices, Everyday: true})
	})
	for name, link := range map[string]string{
		"existing device":     sealedLink(edit(2, func(d *policy.Document) { dev(d, "lock").Allow = nil }), "lock", h),
		"device not added":    sealedLink(addFront, "back", h),
		"everyday device":     sealedLink(tv, "front", h),
		"upper-case hash":     sealedLink(addFront, "front", strings.ToUpper(h)),
		"short hash":          sealedLink(addFront, "front", h[:62]),
		"device without hash": linkFor(addFront, "") + "&" + pairseal.ParamDevice + "=front",
		"two devices":         sealedLink(addFront, "front", h) + "&" + pairseal.ParamDevice + "=front&" + pairseal.ParamHash + "=" + h,
	} {
		if w := g.do(http.MethodGet, link, nil); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", name, w.Code)
		}
	}

	noStore := newRig(t)
	if w := noStore.do(http.MethodGet, sealedLink(addFront, "front", h), nil); w.Code != http.StatusBadRequest {
		t.Errorf("page with no store: %d", w.Code)
	}

	other, _ := pairseal.Seal(k.Recipient(), "front", lockSecret)
	forBack, _ := pairseal.Seal(k.Recipient(), "back", lockSecret)
	for name, c := range map[string]struct {
		hash string
		env  []byte
		code int
	}{
		"no envelope":          {h, nil, http.StatusBadRequest},
		"another envelope":     {h, other, http.StatusBadRequest},
		"envelope for another": {pairseal.HashHex(forBack), forBack, http.StatusConflict},
	} {
		g.now = g.now.Add(LinkWindow) // past the link limit
		_, id, ch := g.openSealed(sealedLink(addFront, "front", c.hash))
		w := g.approveSealed(id, g.a.get(ch), c.env)
		if w.Code != c.code {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
		if c.env != nil && !strings.Contains(w.Body.String(), "pair the device again") {
			t.Errorf("%s: the refusal names no next step: %s", name, w.Body)
		}
		if _, ok := st.Fingerprint("front"); ok || len(g.e.Pending()) != 0 || g.e.Current().Device("front") != nil {
			t.Errorf("%s: something was added or held", name)
		}
	}

	// An envelope posted with a change that names none.
	_, id, ch := g.open(addFront, "")
	if w := g.approveSealed(id, g.a.get(ch), env); w.Code != http.StatusBadRequest || len(g.e.Pending()) != 0 {
		t.Errorf("unasked envelope: %d", w.Code)
	}
}

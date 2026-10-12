package main

// The owner pin command (DEV-net-e 2b, A14 acceptance 2): a tier-4
// command writes, replaces and removes netpin:<label> entries, and the
// guard follows at once. Addresses and names are synthetic.
// REQ: DEV-2, BAK-1, CAP-13, DEV-net-e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/netguard"
)

// pinRig is an open vault with a guard, on the fast unlock path.
func pinRig(t *testing.T) (*fastRig, *netguard.Policy) {
	t.Helper()
	r := newFastRig(t, true)
	g := netguard.New(netguard.Config{})
	r.c.guard = g
	tk := r.unlock(t)
	if err := r.c.confirm(tk, r.code()); err != nil {
		t.Fatal(err)
	}
	return r, g
}

// next moves to the next 30 s step and returns its code: a code works once.
func (r *fastRig) next() string {
	r.clk.add(30 * time.Second)
	return r.code()
}

// endpoint is a TLS server identity with its pin.
type endpoint struct {
	cert tls.Certificate
	key  [32]byte
}

func newEndpoint(t *testing.T, name string) endpoint {
	t.Helper()
	c := selfSignedFor(t, name)
	return endpoint{c, netguard.KeyHash(c.Leaf)}
}

// handshake runs the guard's TLS client against e over a pipe, with
// serverName as the name the caller dials ("" for an address-only pin).
func handshake(g *netguard.Policy, e endpoint, serverName string) error {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go tls.Server(b, &tls.Config{Certificates: []tls.Certificate{e.cert}}).Handshake()
	cfg := g.TLSConfig(nil)
	cfg.ServerName = serverName
	a.SetDeadline(time.Now().Add(5 * time.Second))
	return tls.Client(a, cfg).Handshake()
}

func pinEntries(t *testing.T, r *fastRig) map[string]string {
	t.Helper()
	out := map[string]string{}
	r.c.mu.Lock()
	defer r.c.mu.Unlock()
	for _, e := range r.c.v.List() {
		if strings.HasPrefix(e.Name, pinEntryPrefix) {
			out[e.Name] = e.Kind
		}
	}
	return out
}

// A pin change needs the vault open and an approval code, used once; a
// wrong code writes nothing and tells the owner. No TPM is needed: a pin
// is not a trusted-host change.
func TestPinNeedsAnApprovalCode(t *testing.T) {
	r := newFastRig(t, true)
	k := newEndpoint(t, "backup.home.example").key
	rec := pinRecord{Kind: "backup", Addr: "192.168.1.40:8443", Key: hex.EncodeToString(k[:])}
	if _, err := r.c.pin(r.code(), "nas", rec); err != errLocked {
		t.Fatalf("pin while locked: %v", err)
	}
	tk := r.unlock(t)
	if err := r.c.confirm(tk, r.code()); err != nil {
		t.Fatal(err)
	}
	r.notes = nil
	if _, err := r.c.pin("000000", "nas", rec); err == nil || !strings.HasPrefix(err.Error(), "wrong code") {
		t.Fatalf("wrong code: %v", err)
	}
	if _, err := r.c.pin("", "nas", rec); err == nil {
		t.Fatal("no code accepted")
	}
	if len(pinEntries(t, r)) != 0 {
		t.Fatal("a pin was written without a valid code")
	}
	if !hasNote(r.notes, "wrong code for an owner pin change") {
		t.Fatalf("notes: %q", r.notes)
	}
	c := r.next()
	if _, err := r.c.pin(c, "nas", rec); err != nil {
		t.Fatal(err)
	}
	if _, err := r.c.pin(c, "nas", rec); err == nil {
		t.Fatal("the same code worked twice")
	}
	if got := pinEntries(t, r); got["netpin:nas"] != pinEntryKind || len(got) != 1 {
		t.Fatalf("entries: %v", got)
	}
}

// Acceptance 2: after the owner pins them, a backup endpoint (by address)
// and a hosted endpoint (by name) are reachable for their purpose with
// their keys; a compute host presenting a key other than its pin is
// refused at the handshake.
func TestPinnedBackupAndHostedReachableComputeWrongKeyRefused(t *testing.T) {
	r, g := pinRig(t)
	call := handlerCall(t, r.c)
	nas, models, gpu, rogue := newEndpoint(t, "nas.home.example"), newEndpoint(t, "models.home.example"),
		newEndpoint(t, "gpu.home.example"), newEndpoint(t, "gpu.home.example")
	for _, p := range []map[string]string{
		{"label": "nas", "kind": "backup", "addr": "192.168.1.40:8443", "key": hex.EncodeToString(nas.key[:])},
		{"label": "models", "kind": "hosted", "name": "models.home.example", "addr": "192.168.1.50:443", "key": hex.EncodeToString(models.key[:])},
		{"label": "gpu", "kind": "compute", "name": "gpu.home.example", "addr": "192.168.1.60:8443", "key": hex.EncodeToString(gpu.key[:])},
	} {
		p["code"] = r.next()
		if code, out := call("POST", "/pin", p); code != http.StatusOK || out["label"] != p["label"] || out["replaced"] != false {
			t.Fatalf("pin %s: %d %v", p["label"], code, out)
		}
	}
	backup := netguard.WithPurpose(context.Background(), netguard.PurposeBackup)
	model := netguard.WithPurpose(context.Background(), netguard.PurposeModelCall)
	if err := g.Check(backup, netip.MustParseAddr("192.168.1.40"), 8443, "tcp"); err != nil {
		t.Fatalf("pinned backup address: %v", err)
	}
	if err := handshake(g, nas, ""); err != nil {
		t.Fatalf("pinned backup key: %v", err)
	}
	if err := g.Check(model, netip.MustParseAddr("192.168.1.50"), 443, "tcp"); err != nil {
		t.Fatalf("pinned hosted address: %v", err)
	}
	if err := handshake(g, models, "models.home.example"); err != nil {
		t.Fatalf("pinned hosted key: %v", err)
	}
	if err := handshake(g, gpu, "gpu.home.example"); err != nil {
		t.Fatalf("pinned compute key: %v", err)
	}
	if err := handshake(g, rogue, "gpu.home.example"); !errors.Is(err, netguard.ErrDenied) {
		t.Fatalf("a compute host with a wrong key: %v", err)
	}
	// The pins are listed for the owner by label, kind and endpoint.
	code, out := call("GET", "/pins", nil)
	list, _ := out["pins"].([]any)
	if code != http.StatusOK || len(list) != 3 {
		t.Fatalf("pins: %d %v", code, out)
	}
	first, _ := list[0].(map[string]any)
	if first["label"] != "gpu" || first["kind"] != "compute" || first["name"] != "gpu.home.example" ||
		first["addr"] != "192.168.1.60:8443" || first["key"] != hex.EncodeToString(gpu.key[:]) {
		t.Fatalf("first pin: %v", first)
	}
}

// Re-pin: the endpoint's key changed (a new certificate on the NAS), so the
// old pin refuses it. Pinning the same label again replaces the entry: the
// new key works, the old key is refused, and the owner is told it was a
// replacement. Removing the pin ends it.
func TestRepinReplacesAndUnpinRemoves(t *testing.T) {
	r, g := pinRig(t)
	old, renewed := newEndpoint(t, "nas.home.example"), newEndpoint(t, "nas.home.example")
	rec := func(k [32]byte) pinRecord {
		return pinRecord{Kind: "backup", Name: "nas.home.example", Addr: "192.168.1.40:8443", Key: hex.EncodeToString(k[:])}
	}
	if replaced, err := r.c.pin(r.next(), "nas", rec(old.key)); err != nil || replaced {
		t.Fatalf("first pin: %v %v", replaced, err)
	}
	if err := handshake(g, renewed, "nas.home.example"); !errors.Is(err, netguard.ErrDenied) {
		t.Fatalf("a new key before the re-pin: %v", err)
	}
	r.notes = nil
	if replaced, err := r.c.pin(r.next(), "nas", rec(renewed.key)); err != nil || !replaced {
		t.Fatalf("re-pin: %v %v", replaced, err)
	}
	if err := handshake(g, renewed, "nas.home.example"); err != nil {
		t.Fatalf("the new key after the re-pin: %v", err)
	}
	if err := handshake(g, old, "nas.home.example"); !errors.Is(err, netguard.ErrDenied) {
		t.Fatalf("the old key after the re-pin: %v", err)
	}
	if len(pinEntries(t, r)) != 1 || !hasNote(r.notes, "owner pin replaced: nas (backup)") {
		t.Fatalf("entries %v, notes %q", pinEntries(t, r), r.notes)
	}
	if err := r.c.unpin("000000", "nas"); err == nil {
		t.Fatal("unpin with a wrong code")
	}
	if err := r.c.unpin(r.next(), "nas"); err != nil {
		t.Fatal(err)
	}
	if err := r.c.unpin(r.next(), "nas"); err != errNoSuchPin {
		t.Fatalf("unpin twice: %v", err)
	}
	backup := netguard.WithPurpose(context.Background(), netguard.PurposeBackup)
	if err := g.Check(backup, netip.MustParseAddr("192.168.1.40"), 8443, "tcp"); !errors.Is(err, netguard.ErrDenied) {
		t.Fatalf("the endpoint after unpin: %v", err)
	}
	if len(pinEntries(t, r)) != 0 {
		t.Fatalf("entries after unpin: %v", pinEntries(t, r))
	}
}

// A bad label or record is refused before the code is spent, and writes
// nothing; the refusal names the problem, never the value. The local
// page's credential write still refuses pin entries (N12).
func TestPinRefusals(t *testing.T) {
	r, _ := pinRig(t)
	k := pinKey
	good := pinRecord{Kind: "backup", Addr: "192.168.1.40:8443", Key: hex.EncodeToString(k[:])}
	for name, tc := range map[string]struct {
		label string
		rec   pinRecord
	}{
		"empty label":    {"", good},
		"label with ':'": {"a:b", good},
		"upper case":     {"NAS", good},
		"long label":     {strings.Repeat("a", 33), good},
		"unknown kind":   {"x", pinRecord{Kind: "router", Addr: good.Addr, Key: good.Key}},
		"device kind":    {"x", pinRecord{Kind: "device", Addr: good.Addr, Key: good.Key}},
		"no key":         {"x", pinRecord{Kind: "backup", Addr: good.Addr}},
		"short key":      {"x", pinRecord{Kind: "backup", Addr: good.Addr, Key: "abcd"}},
		"no endpoint":    {"x", pinRecord{Kind: "backup", Key: good.Key}},
		"bad address":    {"x", pinRecord{Kind: "backup", Addr: "192.168.1.40", Key: good.Key}},
		"bad name":       {"x", pinRecord{Kind: "hosted", Name: "has space.example", Key: good.Key}},
	} {
		t.Run(name, func(t *testing.T) {
			c := r.next()
			_, err := r.c.pin(c, tc.label, tc.rec)
			var ue *unlockErr
			if !errors.As(err, &ue) || ue.status != http.StatusBadRequest {
				t.Fatalf("refused with %v", err)
			}
			if strings.Contains(err.Error(), "192.168") || strings.Contains(err.Error(), good.Key) {
				t.Fatalf("the refusal carries a value: %v", err)
			}
			if _, err := r.c.pin(c, "ok", good); err != nil {
				t.Fatalf("the code was spent by a refused pin: %v", err)
			}
			if err := r.c.unpin(r.next(), "ok"); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := r.c.put("netpin:x", pinJSON("backup", "", "192.168.1.40:8443", pinKey)); err != errBadCredential {
		t.Fatalf("custody.put wrote a pin: %v", err)
	}
	if len(pinEntries(t, r)) != 0 {
		t.Fatalf("entries: %v", pinEntries(t, r))
	}
}

// The owner command line: pin reads the code and prints what happened in
// owner words, a second pin of the same label says it replaced the old
// key, pins lists them, unpin removes.
func TestPinCLI(t *testing.T) {
	r, _ := pinRig(t)
	run := filepath.Join(t.TempDir(), "run")
	os.Mkdir(run, 0o700)
	ln, err := net.Listen("unix", filepath.Join(run, UnlockSocket))
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: unlockHandler(r.c)}
	go srv.Serve(ln)
	defer srv.Close()
	k1, k2 := newEndpoint(t, "nas.home.example").key, newEndpoint(t, "nas.home.example").key
	args := func(k [32]byte) []string {
		return []string{"-run", run, "-label", "nas", "-kind", "backup", "-addr", "192.168.1.40:8443", "-key", hex.EncodeToString(k[:])}
	}
	var out bytes.Buffer
	if err := pinCmd(args(k1), strings.NewReader(r.next()+"\n"), &out); err != nil {
		t.Fatalf("pin: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "Pinned nas: backups may reach 192.168.1.40:8443 with key "+hex.EncodeToString(k1[:8])) {
		t.Fatalf("pin output: %s", out.String())
	}
	out.Reset()
	if err := pinCmd(args(k2), strings.NewReader(r.next()+"\n"), &out); err != nil {
		t.Fatalf("re-pin: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "Re-pinned nas") || !strings.Contains(out.String(), "the old key no longer works") {
		t.Fatalf("re-pin output: %s", out.String())
	}
	out.Reset()
	if err := pinsCmd([]string{"-run", run}, &out); err != nil || !strings.Contains(out.String(), "nas") ||
		!strings.Contains(out.String(), hex.EncodeToString(k2[:8])) {
		t.Fatalf("pins: %v\n%s", err, out.String())
	}
	if err := pinCmd(args(k1), strings.NewReader("000000\n"), io.Discard); err == nil || !strings.Contains(err.Error(), "wrong code") {
		t.Fatalf("pin with a wrong code: %v", err)
	}
	if err := unpinCmd([]string{"-run", run, "-label", "nas"}, strings.NewReader(r.next()+"\n")); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := pinsCmd([]string{"-run", run}, &out); err != nil || !strings.Contains(out.String(), "No pinned endpoints") {
		t.Fatalf("pins after unpin: %v\n%s", err, out.String())
	}
}

func hasNote(notes []string, want string) bool {
	for _, n := range notes {
		if n == want {
			return true
		}
	}
	return false
}

func handlerCall(t *testing.T, c *custody) func(method, path string, body any) (int, map[string]any) {
	return func(method, path string, body any) (int, map[string]any) {
		t.Helper()
		var rd io.Reader
		if body != nil {
			raw, _ := json.Marshal(body)
			rd = bytes.NewReader(raw)
		}
		w := httptest.NewRecorder()
		unlockHandler(c).ServeHTTP(w, httptest.NewRequest(method, path, rd))
		out := map[string]any{}
		json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
}

// selfSignedFor is a throwaway endpoint certificate for name, with Leaf set.
func selfSignedFor(t *testing.T, name string) tls.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k, Leaf: leaf}
}

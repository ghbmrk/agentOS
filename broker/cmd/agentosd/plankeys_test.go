package main

// REQ: KEY-3, KEY-4, PLN-5

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

func seedKey(b byte) ed25519.PrivateKey {
	s := make([]byte, ed25519.SeedSize)
	s[0] = b
	return ed25519.NewKeyFromSeed(s)
}

func pubOf(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

// #3087: the first start makes the holder key, root's alone (0600); every
// later start reads the same key back.
func TestPlanHolderIsMadeOnceAndKept(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plan-holder.key")
	h1, err := loadPlanHolder(path)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 || fi.Size() != ed25519.SeedSize {
		t.Fatalf("holder file %v, %d bytes", fi.Mode(), fi.Size())
	}
	h2, err := loadPlanHolder(path)
	if err != nil {
		t.Fatal(err)
	}
	if !h1.Equal(h2) {
		t.Fatal("a second start made a new holder key")
	}
}

// #3087: a holder file another uid can read, a symlink, or one that is not
// one seed is refused and left as it was: replacing it would orphan the
// owner's grant without a word.
func TestPlanHolderRefusesAFileItCannotTrust(t *testing.T) {
	dir := t.TempDir()
	other := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(other, make([]byte, ed25519.SeedSize), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, mk := range map[string]func(string) error{
		"open to others": func(p string) error { return os.WriteFile(p, make([]byte, ed25519.SeedSize), 0o644) },
		"short":          func(p string) error { return os.WriteFile(p, []byte("seed"), 0o600) },
		"long":           func(p string) error { return os.WriteFile(p, make([]byte, ed25519.PrivateKeySize), 0o600) },
		"symlink":        func(p string) error { return os.Symlink(other, p) },
		"directory":      func(p string) error { return os.Mkdir(p, 0o700) },
	} {
		p := filepath.Join(dir, name)
		if err := mk(p); err != nil {
			t.Fatal(err)
		}
		before, _ := os.Lstat(p)
		if _, err := loadPlanHolder(p); err == nil {
			t.Errorf("%s: loaded", name)
		}
		after, err := os.Lstat(p)
		if err != nil || after.Size() != before.Size() || after.Mode() != before.Mode() || !after.ModTime().Equal(before.ModTime()) {
			t.Errorf("%s: the file was changed (%v)", name, err)
		}
	}
}

// grantRig is the real kernel holding the owner's grant of a mail clerk key
// to agentosd's holder, which planKeys reads from its state dir.
type grantRig struct {
	k      *kernel.Kernel
	owner  ed25519.PrivateKey
	holder ed25519.PrivateKey
	root   key.Key
	clerk  key.Key
	path   string
	at     int64
	logs   []string
}

func newGrantRig(t *testing.T) *grantRig {
	t.Helper()
	owner, second, head := seedKey(1), seedKey(2), seedKey(3)
	dir := t.TempDir()
	holder, err := loadPlanHolder(filepath.Join(dir, "plan-holder.key"))
	if err != nil {
		t.Fatal(err)
	}
	r := &grantRig{owner: owner, holder: holder, path: filepath.Join(dir, "plan-grant.json"),
		at: time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC).UnixMilli()}
	l, err := kernel.Open(kernel.Config{Store: &kernel.MemStore{}, Anchor: &kernel.MemAnchor{},
		Pub: pubOf(head), Sign: head, Rand: rand.NewChaCha8([32]byte{1})})
	if err != nil {
		t.Fatal(err)
	}
	if r.k, err = kernel.Boot(l, []ed25519.PublicKey{pubOf(owner), pubOf(second)}, nil, r.at); err != nil {
		t.Fatal(err)
	}
	r.root = key.Issue(owner, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Organize}, Serial: "guest-1"})
	setup := r.at - kernel.GrantHold
	if r.clerk, err = key.ClerkKey(r.root, owner, pubOf(holder), setup, 0); err != nil {
		t.Fatal(err)
	}
	h := kernel.BatchHash(r.root, r.clerk)
	if err := r.k.Issue(setup, []key.Cosign{key.Approve(owner, h), key.Approve(second, h)}, r.root, r.clerk); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *grantRig) write(t *testing.T, k key.Key, mode os.FileMode) {
	t.Helper()
	b, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(r.path)
	if err := os.WriteFile(r.path, b, mode); err != nil {
		t.Fatal(err)
	}
}

func (r *grantRig) keys() func(string) (key.Key, ed25519.PrivateKey, bool) {
	return planKeys(r.holder, r.path, func(f string, a ...any) { r.logs = append(r.logs, fmt.Sprintf(f, a...)) })
}

func (r *grantRig) plan(id string, k key.Key, h ed25519.PrivateKey) kernel.Plan {
	return kernel.SignPlan(kernel.Plan{ID: id, Key: k, Steps: []kernel.PlanStep{{Verb: key.Organize, Clerk: "mail",
		Args: map[string]string{"target": "t", "label": "l"}, Labels: []string{"private"}}}}, h)
}

// #3087: with the owner's grant in the state dir, each machine gets its own
// key narrowed from it (KEY-3), and the real kernel admits a plan signed
// with it; the machines' keys and signers differ, and are the same after a
// restart.
func TestPlanKeysNarrowTheGrantPerMachine(t *testing.T) {
	r := newGrantRig(t)
	r.write(t, r.clerk, 0o600)
	keys := r.keys()
	ka, ha, ok := keys("a")
	kb, hb, okb := keys("b")
	if !ok || !okb {
		t.Fatalf("no key: %v", r.logs)
	}
	if ha.Equal(hb) || ka.Tip() == kb.Tip() || ha.Equal(r.holder) {
		t.Fatal("two machines share a key or a signer, or a machine signs as agentosd's holder")
	}
	if len(ka.Links) != 2 || ka.Links[0].Holder.Equal(ka.Links[1].Holder) || !bytes.Equal(ka.Links[1].Holder, pubOf(ha)) {
		t.Fatalf("machine a's key is not the grant handed on to its own signer: %+v", ka.Links)
	}
	if _, _, rf := kernel.Admit(r.k.State(), r.plan("a/1", ka, ha), r.at+1); rf != nil {
		t.Fatalf("the kernel refused machine a's plan: %+v", rf)
	}
	if _, _, rf := kernel.Admit(r.k.State(), r.plan("b/1", ka, hb), r.at+1); rf == nil {
		t.Fatal("the kernel admitted machine a's key signed by machine b")
	}
	again, ha2, _ := planKeys(r.holder, r.path, t.Logf)("a")
	if again.Tip() != ka.Tip() || !ha2.Equal(ha) {
		t.Fatal("machine a's key changed with a fresh planKeys")
	}
}

// #3087: no grant, a grant to another holder, a bare root, a malformed or
// open file: no key, so the plane refuses the plan before signing it.
func TestPlanKeysGiveNoKeyWithoutAGrantToTheHolder(t *testing.T) {
	r := newGrantRig(t)
	keys := r.keys()
	if _, _, ok := keys("a"); ok || len(r.logs) != 0 {
		t.Fatalf("a key with no grant file (logs %v)", r.logs)
	}
	toOther, err := key.ClerkKey(r.root, r.owner, pubOf(seedKey(9)), r.at, 0)
	if err != nil {
		t.Fatal(err)
	}
	for name, write := range map[string]func(){
		"another holder": func() { r.write(t, toOther, 0o600) },
		"bare root":      func() { r.write(t, r.root, 0o600) },
		"open to others": func() { r.write(t, r.clerk, 0o644) },
		"not json": func() {
			os.Remove(r.path)
			if err := os.WriteFile(r.path, []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		write()
		r.logs = nil
		if _, h, ok := keys("a"); ok || h != nil {
			t.Errorf("%s: a key", name)
		}
		if len(r.logs) != 1 {
			t.Errorf("%s: logs %v", name, r.logs)
		}
	}
}

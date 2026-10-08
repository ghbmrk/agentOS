package recovery

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/vault"
)

// testGen stands in for card.Generate (P2-2): same field formats, a short
// test word list for the passphrase.
func testGen(r io.Reader) (*Card, error) {
	if r == nil {
		r = rand.Reader
	}
	sym := func(n int) string {
		b := make([]byte, n)
		io.ReadFull(r, b)
		for i := range b {
			b[i] = Alphabet[b[i]&31]
		}
		return groupFour(string(b))
	}
	rk, err := NewRecoveryKey(r)
	if err != nil {
		return nil, err
	}
	words := []string{"tulip", "orbit", "mosaic", "ember", "quartz", "lantern", "harbor", "velvet"}
	var ws []string
	for i := 0; i < 7; i++ {
		var x [1]byte
		io.ReadFull(r, x[:])
		ws = append(ws, words[x[0]&7])
	}
	seed := make([]byte, 32)
	io.ReadFull(r, seed)
	return &Card{WiFiName: "AgentOS-" + sym(4), WiFiPassword: sym(16), SetupSecret: sym(26), SetupCode: sym(8),
		VaultPassphrase: strings.Join(ws, " "), GridSeed: seed, RecoveryKey: rk.Text()}, nil
}

func groupFour(s string) string {
	var parts []string
	for len(s) > 4 {
		parts, s = append(parts, s[:4]), s[4:]
	}
	return strings.Join(append(parts, s), "-")
}

// fakeTPM is a TPM factor whose seal is a plain blob. Tests only.
type fakeTPM struct{ blob []byte }

func (fakeTPM) Kind() string { return vault.SlotTPM }
func (f fakeTPM) Enroll() (vault.Slot, []byte, error) {
	s := vault.Slot{Kind: vault.SlotTPM, Sealed: f.blob}
	k, err := f.KEK(s)
	return s, k, err
}
func (f fakeTPM) KEK(s vault.Slot) ([]byte, error) { return hkdf(s.Sealed, nil, "test-tpm", 32), nil }

// box is a drive as provisioned at setup: the vault process's directory
// (vault, key slots with a recovery slot and a TPM slot) and the broker's
// state directory (journal, owner state, a machine layer).
type box struct {
	t      *testing.T
	dir    string
	b      *Box
	card   Card
	rk     RecoveryKey
	seed   []byte
	apiKey []byte
}

const ownerNum = "+15550000001"

var lay = Layout{Vault: "egress/vault", Keys: "egress/vault.keys", Owner: "broker/owner.json",
	Layers: []string{"broker/machines/m1/upper"}, ForgetLog: "broker/forget-log.json"}

func newBox(t *testing.T) *box {
	t.Helper()
	x := &box{t: t, dir: t.TempDir()}
	eg := filepath.Join(x.dir, "egress")
	must(t, os.Mkdir(eg, 0o700))
	c, err := testGen(nil)
	must(t, err)
	x.card = *c
	x.rk, err = ParseRecoveryKey(c.RecoveryKey)
	must(t, err)
	x.b = &Box{VaultPath: filepath.Join(eg, "vault"), KeysPath: filepath.Join(eg, "vault.keys")}
	// The passphrase slot costs a full Argon2id run, so the rig's vault
	// starts from the recovery slot; tests that need the passphrase slot
	// add it (withPassphrase).
	x.b.V, err = vault.CreateSealed(x.b.VaultPath, x.b.KeysPath, Factor(x.rk))
	must(t, err)
	t.Cleanup(func() { x.b.V.Close() })
	must(t, Provision(x.b, x.card, Factor(x.rk)))
	must(t, x.b.V.Rekey(Factor(x.rk), fakeTPM{[]byte("sealed-to-host-a-tpm")}))
	x.seed, _ = random(nil, TOTPSeedBytes)
	must(t, x.b.V.Put(SeedName, vault.KindTOTPSeed, x.seed))
	x.apiKey = []byte(fmt.Sprintf("sk-synthetic-%x", x.seed[:12]))
	must(t, x.b.V.Put("openai", vault.KindAPIKey, x.apiKey))

	br := filepath.Join(x.dir, "broker")
	must(t, os.MkdirAll(filepath.Join(br, "journal"), 0o700))
	must(t, os.WriteFile(filepath.Join(br, "journal", "000001.log"), []byte(`{"id":"G1","action":"meta.grant"}`+"\n"), 0o600))
	must(t, owner.FileStore{Path: filepath.Join(br, "owner.json")}.Save(owner.State{UnlockedUntil: t0.Add(24 * time.Hour), GridUsed: []string{"A1"}}))
	layer := filepath.Join(br, "machines", "m1", "upper")
	must(t, os.MkdirAll(filepath.Join(layer, "etc"), 0o755))
	must(t, os.WriteFile(filepath.Join(layer, "etc", "hostname"), []byte("m1\n"), 0o644))
	must(t, os.Symlink("etc/hostname", filepath.Join(layer, "hostname-link")))
	must(t, os.WriteFile(filepath.Join(layer, "tool"), []byte("#!/bin/sh\n"), 0o755))
	if os.Geteuid() == 0 {
		// A guest user's file: setgid is kept only for a group other than
		// root's. In a user namespace (the A9 sandbox) uid 1000 may be
		// unmapped; the file then stays root's, which no test with kept
		// owners runs under.
		_ = os.Chown(filepath.Join(layer, "tool"), 1000, 1000)
	}
	must(t, os.Chmod(filepath.Join(layer, "tool"), 0o755|os.ModeSetgid))
	big := make([]byte, 3*chunkSize+123) // spans several sealed chunks
	rand.Read(big)
	must(t, os.WriteFile(filepath.Join(br, "machines", "m1", "disk.img"), big, 0o600))
	return x
}

// withPassphrase adds the card's passphrase slot (one Argon2id run).
func (x *box) withPassphrase() {
	must(x.t, x.b.V.Rekey(Factor(x.rk), vault.Passphrase(x.card.VaultPassphrase)))
}

func (x *box) roots() []Root {
	return []Root{{"egress", filepath.Join(x.dir, "egress")}, {"broker", filepath.Join(x.dir, "broker")}}
}

func (x *box) backup() []byte {
	x.t.Helper()
	var buf bytes.Buffer
	must(x.t, Backup(x.b, x.roots(), &buf, t0))
	return buf.Bytes()
}

// restore restores bk to a new directory and opens it with the recovery
// key.
func (x *box) restore(bk []byte, rk RecoveryKey, at time.Time) (*Box, string, error) {
	dst := filepath.Join(x.t.TempDir(), "new-drive")
	if _, err := Restore(bytes.NewReader(bk), rk, dst, lay, Options{}, at); err != nil {
		return nil, dst, err
	}
	return openAt(x.t, dst, rk), dst, nil
}

func openAt(t *testing.T, dst string, rk RecoveryKey) *Box {
	t.Helper()
	b := &Box{VaultPath: filepath.Join(dst, lay.Vault), KeysPath: filepath.Join(dst, lay.Keys)}
	var err error
	b.V, err = vault.OpenSealed(b.VaultPath, b.KeysPath, Factor(rk))
	must(t, err)
	t.Cleanup(func() { b.V.Close() })
	return b
}

// rotate generates and commits a rotation, typing back the prompted value.
func (x *box) rotate(parts []Part, auth Auth, proof Proof) (Done, error) {
	p, err := BeginRotate(x.b, parts, auth, proof, testGen, nil, t0)
	if err != nil {
		return Done{}, err
	}
	return p.Commit(x.b, p.answer, t0)
}

// dataKey unwraps the recovery slot from the file format alone, for the
// A8 scan's canary.
func dataKey(t *testing.T, keysPath string, rk RecoveryKey) []byte {
	t.Helper()
	raw, err := os.ReadFile(keysPath)
	must(t, err)
	k, err := unwrapRecovery(raw, rk)
	must(t, err)
	return k
}

var t0 = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustKey(t *testing.T) RecoveryKey {
	k, err := NewRecoveryKey(nil)
	must(t, err)
	return k
}

// totp is RFC 6238 (SHA-1, 30 s, 6 digits), written out independently of
// the owner package so a shared bug cannot hide.
func totp(seed []byte, at time.Time) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(at.Unix()/30))
	m := hmac.New(sha1.New, seed)
	m.Write(msg[:])
	s := m.Sum(nil)
	off := s[len(s)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(s[off:off+4])&0x7fffffff)%1_000_000)
}

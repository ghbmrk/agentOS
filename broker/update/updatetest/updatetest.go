// Package updatetest makes verified releases for other packages' tests:
// a throwaway TUF repository signed by synthetic keys, checked by a box
// store, so a test gets the same *update.Verified a real check returns.
package updatetest

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/attest"
	"github.com/ghbmrk/agentos/broker/update"
)

// Release publishes release version with the given image files (paths
// under host-image/ or guest-image/) in a 2-of-2 repository and returns
// the box's check of it. A security release also gets one passing
// attestation from the box's allow-listed attestor, so its Security() holds (UPD-8, D6).
func Release(t testing.TB, version int64, security bool, images map[string][]byte) *update.Verified {
	t.Helper()
	v, _ := Box(t, version, security, images)
	return v
}

// Box is Release, also returning the box store that checked it (installed
// release 0), for tests that stage and commit it.
func Box(t testing.TB, version int64, security bool, images map[string][]byte) (*update.Verified, *update.Store) {
	t.Helper()
	d := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	key := func() (ed25519.PublicKey, ed25519.PrivateKey) {
		pub, pk, err := ed25519.GenerateKey(rand.Reader)
		must(err)
		return pub, pk
	}
	p1, k1 := key()
	p2, k2 := key()
	sp, sk := key()
	tp, tk := key()
	repo, err := update.Init(filepath.Join(d, "repo"), update.RootConfig{
		Root: []ed25519.PublicKey{p1, p2}, Targets: []ed25519.PublicKey{p1, p2},
		Snapshot: []ed25519.PublicKey{sp}, Timestamp: []ed25519.PublicKey{tp},
		RootThreshold: 2, TargetsThreshold: 2})
	must(err)
	publish := func() {
		for _, k := range []ed25519.PrivateKey{k1, k2} {
			must(repo.Sign("targets", k))
		}
		must(repo.Publish(sk, tk))
	}
	for _, k := range []ed25519.PrivateKey{k1, k2} {
		must(repo.Sign("root", k))
	}
	publish()
	rel := update.Manifest{Version: version, Channel: update.ChannelStable, Security: security, UsrRootHash: strings.Repeat("0f", 32)}
	local := map[string]string{}
	for p, b := range images {
		f := filepath.Join(d, fmt.Sprintf("img%d", len(local)))
		must(os.WriteFile(f, b, 0o600))
		rel.Files = append(rel.Files, p)
		local[p] = f
	}
	must(repo.AddRelease(rel, local))
	publish()
	root, err := os.ReadFile(filepath.Join(repo.Dir, "metadata", "1.root.json"))
	must(err)
	st, err := update.InitStore(filepath.Join(d, "box"), root, 0)
	must(err)
	ap, ak := key() // the box's allow-listed attestor (D6)
	res, err := st.Check(update.DirSource(repo.Dir), update.Options{Attestors: []ed25519.PublicKey{ap}})
	must(err)
	if res.Release == nil {
		t.Fatal("updatetest: no release")
	}
	if !security {
		return res.Release, st
	}
	att, err := update.Attest(ak, res.Release, update.Statement{Result: update.ResultPass, Channel: update.ChannelFast, Hardware: attest.Hardware{Vendor: attest.Unlisted, Model: attest.Unlisted, Firmware: attest.Unlisted}})
	must(err)
	return res.Release.WithAttestations([][]byte{att}, nil), st
}

// Mirror is a throwaway 2-of-2 release repository a test publishes
// releases to one at a time, read through Source by box stores made with
// Box, as a box reads its update mirror.
type Mirror struct {
	t      testing.TB
	repo   update.Repo
	dir    string
	signer []ed25519.PrivateKey
	snap   ed25519.PrivateKey
	stamp  ed25519.PrivateKey
}

// NewMirror makes an empty mirror.
func NewMirror(t testing.TB) *Mirror {
	t.Helper()
	m := &Mirror{t: t, dir: t.TempDir()}
	key := func() (ed25519.PublicKey, ed25519.PrivateKey) {
		pub, pk, err := ed25519.GenerateKey(rand.Reader)
		m.must(err)
		return pub, pk
	}
	p1, k1 := key()
	p2, k2 := key()
	sp, sk := key()
	tp, tk := key()
	m.signer, m.snap, m.stamp = []ed25519.PrivateKey{k1, k2}, sk, tk
	var err error
	m.repo, err = update.Init(filepath.Join(m.dir, "repo"), update.RootConfig{
		Root: []ed25519.PublicKey{p1, p2}, Targets: []ed25519.PublicKey{p1, p2},
		Snapshot: []ed25519.PublicKey{sp}, Timestamp: []ed25519.PublicKey{tp},
		RootThreshold: 2, TargetsThreshold: 2})
	m.must(err)
	for _, k := range m.signer {
		m.must(m.repo.Sign("root", k))
	}
	m.publish()
	return m
}

func (m *Mirror) must(err error) {
	m.t.Helper()
	if err != nil {
		m.t.Fatal(err)
	}
}

func (m *Mirror) publish() {
	m.t.Helper()
	for _, k := range m.signer {
		m.must(m.repo.Sign("targets", k))
	}
	m.must(m.repo.Publish(m.snap, m.stamp))
}

// Add publishes release version on channel with one host image file; its
// /usr root hash is UsrHash(version).
func (m *Mirror) Add(version int64, channel string, security bool) {
	m.t.Helper()
	f := filepath.Join(m.dir, fmt.Sprintf("usr%d", version))
	m.must(os.WriteFile(f, []byte(fmt.Sprint("usr ", version)), 0o600))
	rel := update.Manifest{Version: version, Channel: channel, Security: security, UsrRootHash: UsrHash(version),
		Files: []string{"host-image/usr.img"}}
	m.must(m.repo.AddRelease(rel, map[string]string{"host-image/usr.img": f}))
	m.publish()
}

// UsrHash is the /usr root hash Mirror gives release version.
func UsrHash(version int64) string { return fmt.Sprintf("%064x", version) }

// Source is the mirror as a box reads it.
func (m *Mirror) Source() update.Source { return update.DirSource(m.repo.Dir) }

// Box is a new box store trusting the mirror's first root, with release
// installed preloaded.
func (m *Mirror) Box(installed int64) *update.Store {
	m.t.Helper()
	root, err := os.ReadFile(filepath.Join(m.repo.Dir, "metadata", "1.root.json"))
	m.must(err)
	st, err := update.InitStore(filepath.Join(m.t.TempDir(), "box"), root, installed)
	m.must(err)
	return st
}

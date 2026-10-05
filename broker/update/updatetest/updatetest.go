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

	"github.com/ghbmrk/agentos/broker/update"
)

// Release publishes release version with the given image files (paths
// under host-image/ or guest-image/) in a 2-of-2 repository and returns
// the box's check of it. A security release also gets one passing
// attestation from the box's allow-listed attestor, so its Security() holds (UPD-8, D6).
func Release(t testing.TB, version int64, security bool, images map[string][]byte) *update.Verified {
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
		return res.Release
	}
	att, err := update.Attest(ak, res.Release, update.Statement{Result: update.ResultPass, Channel: update.ChannelFast, HardwareClass: "test"})
	must(err)
	return res.Release.WithAttestations([][]byte{att}, nil)
}

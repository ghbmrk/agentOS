package maintain

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/update"
)

// clock is a settable test clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// proposer stands in for the change pipeline.
type proposer struct {
	mu    sync.Mutex
	got   []update.Verified
	state change.State
	err   error
}

func (p *proposer) ProposeRelease(_ context.Context, v update.Verified) (change.Report, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return change.Report{}, p.err
	}
	p.got = append(p.got, v)
	st := p.state
	if st == "" {
		st = change.StateAwaitingOwner
	}
	return change.Report{ID: fmt.Sprintf("c%d", len(p.got)), State: st}, nil
}

func (p *proposer) proposed() []update.Verified {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]update.Verified(nil), p.got...)
}

// failSource is a mirror that cannot be reached.
type failSource struct{}

func (failSource) Open(string) (io.ReadCloser, error) { return nil, errors.New("connection refused") }

// rig is a release repository with 2-of-3 root and targets keys, a box
// with release 1 installed, and Loop 3 in front of it.
type rig struct {
	t        *testing.T
	dir      string
	clk      *clock
	repo     update.Repo
	tgt      []ed25519.PrivateKey
	snap, ts ed25519.PrivateKey
	rootJSON []byte
	store    *update.Store
	state    *change.MemStore
	p        *proposer
	online   bool
	channel  string
	atts     [][]byte
	own      ed25519.PrivateKey
	mirrors  []update.Source
	l        *Loop3
}

func keys(t *testing.T, dir, prefix string, n int) ([]ed25519.PrivateKey, []ed25519.PublicKey) {
	var privs []ed25519.PrivateKey
	var pubs []ed25519.PublicKey
	for i := 0; i < n; i++ {
		base := filepath.Join(dir, fmt.Sprintf("%s%d", prefix, i))
		pub, err := update.Keygen(base)
		if err != nil {
			t.Fatal(err)
		}
		priv, err := update.LoadPrivateKey(base + ".key")
		if err != nil {
			t.Fatal(err)
		}
		privs, pubs = append(privs, priv), append(pubs, pub)
	}
	return privs, pubs
}

func newRig(t *testing.T) *rig {
	t.Helper()
	dir := t.TempDir()
	kdir := filepath.Join(dir, "keys")
	os.Mkdir(kdir, 0o700)
	r := &rig{t: t, dir: dir, clk: &clock{t: time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)},
		state: &change.MemStore{}, p: &proposer{}, online: true, channel: update.ChannelStable}
	root, rp := keys(t, kdir, "root", 3)
	var tp, sp, tsp []ed25519.PublicKey
	r.tgt, tp = keys(t, kdir, "targets", 3)
	s, sp := keys(t, kdir, "snapshot", 1)
	ts, tsp := keys(t, kdir, "timestamp", 1)
	r.snap, r.ts = s[0], ts[0]
	repo, err := update.Init(filepath.Join(dir, "repo"), update.RootConfig{
		Root: rp, Targets: tp, Snapshot: sp, Timestamp: tsp, RootThreshold: 2, TargetsThreshold: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	repo.Now = r.clk.now
	r.repo = repo
	r.must(repo.Sign("root", root[0]))
	r.must(repo.Sign("root", root[1]))
	r.must(repo.Sign("targets", r.tgt[0]))
	r.must(repo.Sign("targets", r.tgt[1]))
	r.must(repo.Publish(r.snap, r.ts))
	r.rootJSON, err = os.ReadFile(filepath.Join(repo.Dir, "metadata", "1.root.json"))
	if err != nil {
		t.Fatal(err)
	}
	r.store, err = update.InitStore(filepath.Join(dir, "box"), r.rootJSON, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, r.own, _ = ed25519.GenerateKey(rand.Reader)
	r.mirrors = []update.Source{update.DirSource(repo.Dir)}
	r.l = r.newLoop()
	return r
}

func (r *rig) newLoop() *Loop3 {
	r.t.Helper()
	l, err := New(Config{
		Store:   r.store,
		Mirrors: func() []update.Source { return r.mirrors },
		Online:  func() bool { return r.online },
		Channel: func() string { return r.channel },
		Attestations: func(context.Context, string) ([][]byte, error) {
			return r.atts, nil
		},
		OwnKey:   r.own.Public().(ed25519.PublicKey),
		Pipeline: r.p,
		State:    r.state,
		Now:      r.clk.now,
	})
	if err != nil {
		r.t.Fatal(err)
	}
	return l
}

func (r *rig) must(err error) {
	r.t.Helper()
	if err != nil {
		r.t.Fatal(err)
	}
}

// release publishes release v (stable unless mod changes it), signed by
// two targets keys.
func (r *rig) release(v int64, mod func(*update.Manifest)) {
	r.t.Helper()
	files := map[string]string{}
	rel := update.Manifest{Version: v, Channel: update.ChannelStable, UsrRootHash: strings.Repeat("ab", 32)}
	for _, name := range []string{"entry.conf", "usr.img"} {
		p := fmt.Sprintf("host-image/%d/%s", v, name)
		local := filepath.Join(r.dir, fmt.Sprintf("%d-%s", v, name))
		r.must(os.WriteFile(local, []byte(fmt.Sprintf("%s of release %d", name, v)), 0o644))
		files[p] = local
		rel.Files = append(rel.Files, p)
	}
	if mod != nil {
		mod(&rel)
	}
	r.must(r.repo.AddRelease(rel, files))
	r.must(r.repo.Sign("targets", r.tgt[0]))
	r.must(r.repo.Sign("targets", r.tgt[2]))
	r.must(r.repo.Publish(r.snap, r.ts))
}

// refresh re-signs snapshot and timestamp, as the repository's daily job.
func (r *rig) refresh() { r.must(r.repo.Refresh(r.snap, r.ts)) }

// attest adds a passing fast-channel attestation for the newest release
// from an independent installation.
func (r *rig) attest() {
	r.t.Helper()
	other, err := update.InitStore(filepath.Join(r.t.TempDir(), "other"), r.rootJSON, 1)
	r.must(err)
	res, err := other.Check(update.DirSource(r.repo.Dir), update.Options{Channel: update.ChannelFast, Now: r.clk.now})
	r.must(err)
	if res.Release == nil {
		r.t.Fatal("no release to attest")
	}
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	b, err := update.Attest(k, res.Release, update.Statement{Result: update.ResultPass, Channel: update.ChannelFast, HardwareClass: "n95-8g"})
	r.must(err)
	r.atts = append(r.atts, b)
}

// tick offers and runs Loop 3's next job, as the scheduler would. It
// reports whether there was one and its value.
func (r *rig) tick() (bool, float64) {
	r.t.Helper()
	job, ok := r.l.Next(context.Background(), true)
	if !ok {
		return false, 0
	}
	if job.UsesModel {
		r.t.Fatal("update checks make no model calls")
	}
	res := job.Run(context.Background())
	if res.Err != nil {
		r.t.Logf("job error: %v", res.Err)
	}
	return true, res.Value
}

func (r *rig) digest() string { return strings.Join(r.l.Digest(), "\n") }

package run

// REQ: CLK-1, CH-3, OWN-9

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

var phonePub, phonePriv = gen(8)

// exitRig is the kernel's process and an OAuth exit clerk's process, with
// the owner's phone enrolled and the clerk's owner socket.
type exitRig struct {
	*box
	sec   *clerk.Secrets
	owner ExitOwner
	host  *ExitHost
	last  *seenCall
}

// seenCall keeps the last call the kernel made to the host, to replay it.
type seenCall struct {
	h    *ExitHost
	mu   sync.Mutex
	req  kernel.Request
	view kernel.View
}

func (c *seenCall) Do(r kernel.Request, v kernel.View) kernel.Result {
	c.mu.Lock()
	c.req, c.view = r, v
	c.mu.Unlock()
	return c.h.Do(r, v)
}

func (c *seenCall) Probe(r kernel.Request, v kernel.View) string { return c.h.Probe(r, v) }

func newExitRig(t *testing.T) *exitRig {
	t.Helper()
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := sec.Put("web", clerk.KindGrant, []byte(`{"refresh_token":"canary-refresh-old","client_id":"agentos-test"}`)); err != nil {
		t.Fatal(err)
	}
	d := clerk.Declaration{Name: "web", Ops: ops("https://example.com:1"), Guard: guard("127.0.0.1:1"), Refresh: "https://example.com/token"}
	x, err := clerk.NewExit(d, anchors, sec, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := NewExitHost(x, d, anchors)
	sock := filepath.Join(shortDir(t), "x.sock")
	ln, err := ListenClerk(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	last := &seenCall{h: h}
	go ServeClerk(ln, last, anchors)
	osock := filepath.Join(shortDir(t), "o.sock")
	oln, err := ListenExitOwner(osock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { oln.Close() })
	go ServeExitOwner(oln, h)
	b := newBoxFor(t, sock, "web", key.Post, key.ChangeAccount)
	if err := b.h.With(func(k *kernel.Kernel) error { return k.Enroll(b.now, key.Enroll(ownerPriv, phonePub)) }); err != nil {
		t.Fatal(err)
	}
	return &exitRig{box: b, sec: sec, host: h, last: last, owner: ExitOwner{Conn{Socket: osock, UID: os.Getuid(), Timeout: 20 * time.Second}}}
}

// approve is the owner's phone narrowing the clerk key for one use: each a
// new link, since a link's use is counted once.
func (r *exitRig) approve() key.Key {
	r.t.Helper()
	k, err := key.Narrow(r.key, phonePriv, key.LimitUses(1), key.LimitExpires(r.now+10*key.DayMS))
	if err != nil {
		r.t.Fatal(err)
	}
	return k
}

// reconnect runs a change-account step for grant digest under k, and
// returns its state and whether the store changed.
func (r *exitRig) reconnect(k key.Key, target, digest string) (kernel.StepState, bool) {
	r.t.Helper()
	before, _ := r.sec.MarshalBinary()
	r.plans++
	id := "c" + string(rune('0'+r.plans))
	p := kernel.SignPlan(kernel.Plan{ID: id, Key: k, Steps: []kernel.PlanStep{{Verb: key.ChangeAccount, Clerk: "web", Args: map[string]string{"target": target, "value": digest}}}}, holderPriv)
	if err := r.h.With(func(k *kernel.Kernel) error { return k.Submit(r.now, p) }); err != nil {
		r.t.Fatal(err)
	}
	r.now += 2 * key.DayMS
	r.tick(r.now)
	after, _ := r.sec.MarshalBinary()
	var st kernel.StepState
	r.box.h.With(func(k *kernel.Kernel) error {
		if p := k.State().Plans[id]; p != nil && len(p.Steps) == 1 {
			st = p.Steps[0]
		}
		return nil
	})
	return st, !bytes.Equal(before, after)
}

// The owner's Reconnect, out of the kernel's process, is a change-account
// step under a key the owner's passkey narrowed, naming the grant the
// owner's side staged on the clerk's own socket by its digest. Without the
// passkey's approval, for another clerk, or for a grant not staged, the
// slot is unchanged; with all three it is replaced once, and the staged
// grant is spent (#2643 b).
func TestReconnectNeedsTheOwnersApprovalAndTheStagedGrant(t *testing.T) {
	r := newExitRig(t)
	grant := []byte(`{"refresh_token":"canary-refresh-new","client_id":"agentos-test"}`)
	digest, err := r.owner.Stage(grant)
	if err != nil || digest != grantDigest(grant) {
		t.Fatalf("staging: %q, %v", digest, err)
	}
	other := grantDigest([]byte(`{"refresh_token":"canary-refresh-other","client_id":"agentos-test"}`))
	for _, c := range []struct {
		name           string
		approved       bool
		target, digest string
		detail         string
	}{
		{"the clerk's own key", false, "web", digest, DNotApproved},
		{"another grant", true, "web", other, DNotStaged},
		{"another clerk", true, "mail", digest, DNotThis},
	} {
		k := r.key
		if c.approved {
			k = r.approve()
		}
		st, changed := r.reconnect(k, c.target, c.digest)
		if changed || st.Detail != c.detail {
			t.Errorf("%s: step %s %q, store changed %v", c.name, st.Phase, st.Detail, changed)
		}
	}
	st, changed := r.reconnect(r.approve(), "web", digest)
	if !changed || st.Phase != kernel.PDone {
		t.Fatalf("the approved reconnect: step %s %q, store changed %v", st.Phase, st.Detail, changed)
	}
	r.now += key.DayMS // past the kernel's own duplicate guard (KRN-8)
	if st, changed := r.reconnect(r.approve(), "web", digest); changed || st.Detail != DNotStaged {
		t.Fatalf("a spent staged grant was used again: step %s %q, store changed %v", st.Phase, st.Detail, changed)
	}
}

// The owner socket has one call, and the grant never reaches the kernel's
// log: only its digest does.
func TestTheStagedGrantNeverReachesTheLog(t *testing.T) {
	r := newExitRig(t)
	grant := []byte(`{"refresh_token":"canary-refresh-log","client_id":"agentos-test"}`)
	if err := r.owner.call("reconnect", grant, nil); err == nil {
		t.Fatal("the exit owner socket answered a call other than stage")
	}
	digest, err := r.owner.Stage(grant)
	if err != nil {
		t.Fatal(err)
	}
	if _, changed := r.reconnect(r.approve(), "web", digest); !changed {
		t.Fatal("the approved reconnect changed nothing")
	}
	log := plainLog(t, r.cfg.Log, r.cfg.Key)
	if bytes.Contains(log, []byte("canary-refresh-log")) || !bytes.Contains(log, []byte(digest)) {
		t.Fatal("the log carries the grant, or not its digest")
	}
}

// plainLog is every entry of the kernel's log at path, opened under its key:
// frames of a 4-byte length, a nonce and the sealed entry (kernel/log.go).
func plainLog(t *testing.T, path string, k [32]byte) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := aes.NewCipher(k[:])
	if err != nil {
		t.Fatal(err)
	}
	a, err := cipher.NewGCM(b)
	if err != nil {
		t.Fatal(err)
	}
	var out []byte
	for seq := uint64(1); len(raw) > 0; seq++ {
		n := int(binary.BigEndian.Uint32(raw))
		fr := raw[4 : 4+n]
		pt, err := a.Open(nil, fr[:a.NonceSize()], fr[a.NonceSize():], binary.BigEndian.AppendUint64(nil, seq))
		if err != nil {
			t.Fatalf("log entry %d: %v", seq, err)
		}
		out = append(out, pt...)
		raw = raw[4+n:]
	}
	if len(out) == 0 {
		t.Fatal("the log is empty")
	}
	return out
}

// A change-account step acts once, and only as the kernel sent it: the same
// step sent again after it ran, or one the kernel never sent, leaves the slot
// as it is, however the owner approved it; the host answers the kernel's
// probe from what it did (#2643 b).
func TestReconnectActsOnceAndOnlyAsTheKernelSentIt(t *testing.T) {
	r := newExitRig(t)
	grant := []byte(`{"refresh_token":"canary-refresh-once","client_id":"agentos-test"}`)
	digest, err := r.owner.Stage(grant)
	if err != nil {
		t.Fatal(err)
	}
	if st, changed := r.reconnect(r.approve(), "web", digest); !changed || st.Phase != kernel.PDone {
		t.Fatalf("the approved reconnect: step %s %q, store changed %v", st.Phase, st.Detail, changed)
	}
	r.last.mu.Lock()
	sent, sentView := r.last.req, r.last.view
	r.last.mu.Unlock()
	if got := r.host.Probe(sent, sentView); got != "done" {
		t.Errorf("probe of the step that ran: %q", got)
	}
	if _, err := r.owner.Stage(grant); err != nil {
		t.Fatal(err)
	}
	before, _ := r.sec.MarshalBinary()
	if res := r.host.Do(sent, sentView); res.Outcome != "ok" {
		t.Errorf("the step sent again: %+v", res)
	}
	// One the kernel never sent: an approved plan, verified against the
	// kernel's view, but not dispatched.
	p := kernel.SignPlan(kernel.Plan{ID: "never", Key: r.approve(), Steps: []kernel.PlanStep{{Verb: key.ChangeAccount, Clerk: "web", Args: map[string]string{"target": "web", "value": digest}}}}, holderPriv)
	req := kernel.Request{Plan: p}
	var v snapshot
	r.h.With(func(k *kernel.Kernel) error { v = view(k.State(), anchors, req, r.now); return nil })
	if res := r.host.Do(req, &v); res.Outcome != "failed" {
		t.Errorf("a step the kernel never sent: %+v", res)
	}
	if got := r.host.Probe(req, &v); got != "unknown" {
		t.Errorf("probe of a step that never ran: %q", got)
	}
	if after, _ := r.sec.MarshalBinary(); !bytes.Equal(before, after) {
		t.Fatal("a step sent again, or never sent, changed the slot")
	}
}

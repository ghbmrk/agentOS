package run

// REQ: CLK-1, CH-3, OWN-9, KRN-8

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	dir   string // the clerk's Secrets directory
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

func (c *seenCall) Probe(r kernel.Request, v kernel.View) kernel.Result { return c.h.Probe(r, v) }

func newExitRig(t *testing.T) *exitRig {
	t.Helper()
	return newExitRigFor(t, "https://example.com/token")
}

// newExitRigFor is newExitRig for a clerk whose token endpoint is refresh;
// with none, its slot holds a static secret.
func newExitRigFor(t *testing.T, refresh string) *exitRig {
	t.Helper()
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	kind, secret := clerk.KindGrant, []byte(`{"refresh_token":"canary-refresh-old","client_id":"agentos-test"}`)
	if refresh == "" {
		kind, secret = clerk.KindStatic, []byte("canary-static-secret")
	}
	if err := sec.Put("web", kind, secret); err != nil {
		t.Fatal(err)
	}
	// The clerk reads the rig's clock, as the kernel does.
	var b *box
	d := clerk.Declaration{Name: "web", Ops: ops("https://example.com:1"), Guard: guard("127.0.0.1:1"), Refresh: refresh, Clock: func() int64 { return b.now }}
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
	b = newBoxFor(t, sock, "web", key.Post, key.ChangeAccount)
	if err := b.h.With(func(k *kernel.Kernel) error { return k.Enroll(b.now, key.Enroll(ownerPriv, phonePub)) }); err != nil {
		t.Fatal(err)
	}
	return &exitRig{box: b, sec: sec, host: h, last: last, dir: dir, owner: ExitOwner{Conn{Socket: osock, UID: os.Getuid(), Timeout: 20 * time.Second}}}
}

// approve is the owner's phone approving exactly a reconnect to the grant
// with digest d: change-account only, that value only, one use, for
// MaxApproval. Time moves on a second each call, so each is a new link.
func (r *exitRig) approve(d string) key.Key {
	r.t.Helper()
	r.now += 1000
	return r.narrow(key.LimitVerbs(key.ChangeAccount), key.LimitContent(grantPrint(d)), key.LimitUses(1), key.LimitExpires(r.now+MaxApproval))
}

func (r *exitRig) narrow(cs ...key.Caveat) key.Key {
	r.t.Helper()
	return r.narrowBy(phonePriv, cs...)
}

func (r *exitRig) narrowBy(by ed25519.PrivateKey, cs ...key.Caveat) key.Key {
	r.t.Helper()
	k, err := key.Narrow(r.key, by, cs...)
	if err != nil {
		r.t.Fatal(err)
	}
	return k
}

// reconnect runs plan id, a change-account step for grant digest under k,
// and returns its state and whether the store changed.
func (r *exitRig) reconnect(id string, k key.Key, target, digest string) (kernel.StepState, bool) {
	r.t.Helper()
	return r.reconnectClaiming(id, k, target, digest, grantPrint(digest))
}

// reconnectClaiming is reconnect with the step's content claimed as content.
func (r *exitRig) reconnectClaiming(id string, k key.Key, target, digest, content string) (kernel.StepState, bool) {
	r.t.Helper()
	before, _ := r.sec.MarshalBinary()
	p := kernel.SignPlan(kernel.Plan{ID: id, Key: k, Steps: []kernel.PlanStep{{Verb: key.ChangeAccount, Clerk: "web", Args: map[string]string{"target": target, "value": digest}, Content: content}}}, holderPriv)
	if err := r.h.With(func(k *kernel.Kernel) error { return k.Submit(r.now, p) }); err != nil {
		r.t.Fatal(err)
	}
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

func (r *exitRig) stage(plan string, grant []byte) string {
	r.t.Helper()
	d, err := r.owner.Stage(plan, grant)
	if err != nil || d != grantDigest(grant) {
		r.t.Fatalf("staging: %q, %v", d, err)
	}
	return d
}

// The owner's Reconnect, out of the kernel's process, is a change-account
// step under the owner's exact approval, naming by digest the grant the
// owner's side staged for that plan on the clerk's own socket. The clerk
// key alone, a narrowing the owner gave for anything else, another clerk,
// another plan, or a grant not staged leaves the slot unchanged; with all
// of it the slot is replaced once and the staged grant is spent (#2643 b).
func TestReconnectNeedsTheOwnersExactApprovalAndTheStagedGrant(t *testing.T) {
	r := newExitRig(t)
	grant := []byte(`{"refresh_token":"canary-refresh-new","client_id":"agentos-test"}`)
	digest := grantDigest(grant)
	other := grantDigest([]byte(`{"refresh_token":"canary-refresh-other","client_id":"agentos-test"}`))
	for i, c := range []struct {
		name           string
		k              key.Key
		target, digest string
		otherPlan      bool
		detail         string
	}{
		{"the clerk's own key", r.key, "web", digest, false, DNotApproved},
		{"a narrowing for anything else", r.narrow(key.LimitUses(1), key.LimitExpires(r.now+MaxApproval)), "web", digest, false, DNotApproved},
		{"the planner's own exact narrowing", r.narrowBy(holderPriv, key.LimitVerbs(key.ChangeAccount), key.LimitContent(grantPrint(digest)), key.LimitUses(1), key.LimitExpires(r.now+MaxApproval)), "web", digest, false, DNotApproved},
		{"an approval of any verb", r.narrow(key.LimitContent(grantPrint(digest)), key.LimitUses(1), key.LimitExpires(r.now+MaxApproval)), "web", digest, false, DNotApproved},
		{"an approval of change-account and more", r.narrow(key.LimitVerbs(key.ChangeAccount, key.Post), key.LimitContent(grantPrint(digest)), key.LimitUses(1), key.LimitExpires(r.now+MaxApproval)), "web", digest, false, DNotApproved},
		{"an approval of this grant and another", r.narrow(key.LimitVerbs(key.ChangeAccount), key.LimitContent(grantPrint(digest), grantPrint(other)), key.LimitUses(1), key.LimitExpires(r.now+MaxApproval)), "web", digest, false, DNotApproved},
		{"an approval naming no grant", r.narrow(key.LimitVerbs(key.ChangeAccount), key.LimitUses(1), key.LimitExpires(r.now+MaxApproval)), "web", digest, false, DNotApproved},
		{"an approval of more than one use", r.narrow(key.LimitVerbs(key.ChangeAccount), key.LimitContent(grantPrint(digest)), key.LimitUses(2), key.LimitExpires(r.now+MaxApproval)), "web", digest, false, DNotApproved},
		{"a lasting approval", r.narrow(key.LimitVerbs(key.ChangeAccount), key.LimitContent(grantPrint(digest)), key.LimitUses(1), key.LimitExpires(r.now+MaxApproval+60000)), "web", digest, false, DNotApproved},
		{"another grant", r.approve(other), "web", other, false, DNotStaged},
		{"another clerk", r.approve(digest), "mail", digest, false, DNotThis},
		{"another plan", r.approve(digest), "web", digest, true, DNotStaged},
	} {
		id := "case" + string(rune('a'+i))
		staged := id
		if c.otherPlan {
			staged = "someone-else"
		}
		r.stage(staged, grant)
		st, changed := r.reconnect(id, c.k, c.target, c.digest)
		if changed || st.Detail != c.detail {
			t.Errorf("%s: step %s %q, store changed %v", c.name, st.Phase, st.Detail, changed)
		}
	}
	r.stage("ok", grant)
	st, changed := r.reconnect("ok", r.approve(digest), "web", digest)
	if !changed || st.Phase != kernel.PDone {
		t.Fatalf("the approved reconnect: step %s %q, store changed %v", st.Phase, st.Detail, changed)
	}
	if r.host.staged.grant != nil || r.host.staged.plan != "" {
		t.Fatal("the reconnect left its staged grant in memory")
	}
	r.now += key.DayMS // past the kernel's own duplicate guard (KRN-8)
	if st, changed := r.reconnect("again", r.approve(digest), "web", digest); changed || st.Detail != DNotStaged {
		t.Fatalf("a spent staged grant was used again: step %s %q, store changed %v", st.Phase, st.Detail, changed)
	}
}

// A reconnect the clerk cannot make (a grant that does not read, or one
// that would take the Secrets file past what the next open reads) fails,
// is not done to a probe, and leaves the slot and the file as they were.
func TestAReconnectThatFailsChangesNothing(t *testing.T) {
	r := newExitRig(t)
	for _, c := range []struct {
		name  string
		grant []byte
	}{
		{"a grant past the file's bound", []byte(`{"refresh_token":"` + strings.Repeat("r", maxSecrets) + `"}`)},
	} {
		r.plans++
		id := "f" + string(rune('0'+r.plans))
		d := r.stage(id, c.grant)
		st, changed := r.reconnect(id, r.approve(d), "web", d)
		if changed || st.Detail != clerk.DCredential {
			t.Errorf("%s: step %s %q, store changed %v", c.name, st.Phase, st.Detail, changed)
		}
		r.last.mu.Lock()
		req, v := r.last.req, r.last.view
		r.last.mu.Unlock()
		if got := r.host.Probe(req, v).Outcome; got != "unknown" {
			t.Errorf("%s: probe %q", c.name, got)
		}
	}
	if _, err := OpenSecrets(r.dir, testSealer()); err != nil {
		t.Fatalf("the Secrets file no longer opens: %v", err)
	}
}

// A grant Reconnect could not take is refused when the owner's side stages
// it, before the tap and the hold, in fixed words that never carry the
// grant; the grant staged before it stays, and its step still runs (#2742
// item 6).
func TestAGrantTheClerkCannotTakeIsRefusedAtStage(t *testing.T) {
	r := newExitRig(t)
	good := []byte(`{"refresh_token":"canary-refresh-new","client_id":"agentos-test"}`)
	d := r.stage("s1", good)
	for _, bad := range [][]byte{
		[]byte(`{"token":"canary-refresh-bad"}`),
		[]byte(`not json canary-refresh-bad`),
	} {
		got, err := r.owner.Stage("s1", bad)
		if !errors.Is(err, ErrBadGrant) || got != "" { // the owner side tells it by errors.Is
			t.Fatalf("staging %q: %q, %v; want ErrBadGrant", bad, got, err)
		}
	}
	if st, changed := r.reconnect("s1", r.approve(d), "web", d); st.Phase != kernel.PDone || !changed {
		t.Fatalf("the grant staged before a refused one: step %s %q, store changed %v", st.Phase, st.Detail, changed)
	}
}

// A clerk with no token endpoint takes no grant at all: staging one through
// the owner socket is refused as ErrNoReconnect, which the owner side tells
// by errors.Is, and never as ErrBadGrant, whose words send the owner to sign
// in again, which cannot help (#2771 review).
func TestAClerkWithNoRefreshGrantRefusesEveryStage(t *testing.T) {
	r := newExitRigFor(t, "")
	got, err := r.owner.Stage("s1", []byte(`{"refresh_token":"canary-refresh-new","client_id":"agentos-test"}`))
	if !errors.Is(err, ErrNoReconnect) || errors.Is(err, ErrBadGrant) || got != "" {
		t.Fatalf("staging for a clerk with no refresh grant: %q, %v; want ErrNoReconnect", got, err)
	}
	if strings.Contains(err.Error(), "sign in again") {
		t.Fatalf("the refusal sends the owner to sign in again: %q", err)
	}
}

// A reconnect whose new grant is renamed into place but whose directory sync
// fails is unknown, not failed: the grant is on disk, and may or may not
// survive a crash (#2742 item 7).
func TestAReconnectWrittenButNotSyncedIsUnknown(t *testing.T) {
	r := newExitRig(t)
	grant := []byte(`{"refresh_token":"canary-refresh-unsynced","client_id":"agentos-test"}`)
	d := r.stage("u", grant)
	file := filepath.Join(r.dir, secretsName)
	before, _ := os.ReadFile(file)
	sync := syncDir
	t.Cleanup(func() { syncDir = sync })
	syncDir = func(string) error { return errors.New("synthetic sync failure") }
	st, _ := r.reconnect("u", r.approve(d), "web", d)
	syncDir = sync
	if after, _ := os.ReadFile(file); bytes.Equal(before, after) {
		t.Fatal("the new grant was not renamed into place")
	}
	if st.Phase != kernel.PUnknown {
		t.Fatalf("a reconnect written but not synced: %s %q", st.Phase, st.Detail)
	}
	r.last.mu.Lock()
	req, v := r.last.req, r.last.view
	r.last.mu.Unlock()
	if got := r.host.Probe(req, v).Outcome; got != "unknown" {
		t.Fatalf("a probe of the unsynced reconnect: %q", got)
	}
	// The staged grant is kept, so the same step sent again (a RETRY)
	// makes the reconnect, and only then is it done.
	if res := r.host.Do(req, v); res.Outcome != "ok" {
		t.Fatalf("the reconnect sent again: %+v", res)
	}
	if got := r.host.Probe(req, v).Outcome; got != "done" {
		t.Fatalf("a probe after the reconnect sent again: %q", got)
	}
}

// The owner socket has one call, and the grant never reaches the kernel's
// log: only its digest does.
func TestTheStagedGrantNeverReachesTheLog(t *testing.T) {
	r := newExitRig(t)
	grant := []byte(`{"refresh_token":"canary-refresh-log","client_id":"agentos-test"}`)
	if err := r.owner.call("reconnect", stageArgs{"log", grant}, nil); err == nil {
		t.Fatal("the exit owner socket answered a call other than stage")
	}
	for _, a := range []stageArgs{{"", grant}, {"log", nil}} {
		if err := r.owner.call("stage", a, nil); err == nil {
			t.Fatalf("staging %+v was taken", a)
		}
	}
	digest := r.stage("log", grant)
	if _, changed := r.reconnect("log", r.approve(digest), "web", digest); !changed {
		t.Fatal("the approved reconnect changed nothing")
	}
	log := plainLog(t, r.cfg.Log, r.cfg.Key)
	if bytes.Contains(log, []byte("canary-refresh-log")) || !bytes.Contains(log, []byte(digest)) {
		t.Fatal("the log carries the grant, or not its digest")
	}
}

// A change-account step acts once, and only as the kernel sent it: the same
// step sent again after it ran, or one the kernel never sent, leaves the slot
// as it is, however the owner approved it; the host answers the kernel's
// probe from what it did (#2643 b).
func TestReconnectActsOnceAndOnlyAsTheKernelSentIt(t *testing.T) {
	r := newExitRig(t)
	grant := []byte(`{"refresh_token":"canary-refresh-once","client_id":"agentos-test"}`)
	digest := r.stage("once", grant)
	if st, changed := r.reconnect("once", r.approve(digest), "web", digest); !changed || st.Phase != kernel.PDone {
		t.Fatalf("the approved reconnect: step %s %q, store changed %v", st.Phase, st.Detail, changed)
	}
	r.last.mu.Lock()
	sent, sentView := r.last.req, r.last.view
	r.last.mu.Unlock()
	if got := r.host.Probe(sent, sentView).Outcome; got != "done" {
		t.Errorf("probe of the step that ran: %q", got)
	}
	r.stage("once", grant)
	before, _ := r.sec.MarshalBinary()
	if res := r.host.Do(sent, sentView); res.Outcome != "ok" {
		t.Errorf("the step sent again: %+v", res)
	}
	// One the kernel never sent: an approved plan, verified against the
	// kernel's view, but not dispatched.
	r.stage("never", grant)
	p := kernel.SignPlan(kernel.Plan{ID: "never", Key: r.approve(digest), Steps: []kernel.PlanStep{{Verb: key.ChangeAccount, Clerk: "web", Args: map[string]string{"target": "web", "value": digest}, Content: grantPrint(digest)}}}, holderPriv)
	req := kernel.Request{Plan: p}
	var v snapshot
	r.h.With(func(k *kernel.Kernel) error { v = view(k.State(), anchors, req, r.now); return nil })
	if res := r.host.Do(req, &v); res.Outcome != "failed" {
		t.Errorf("a step the kernel never sent: %+v", res)
	}
	if got := r.host.Probe(req, &v).Outcome; got != "unknown" {
		t.Errorf("probe of a step that never ran: %q", got)
	}
	if after, _ := r.sec.MarshalBinary(); !bytes.Equal(before, after) {
		t.Fatal("a step sent again, or never sent, changed the slot")
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

// The exact approval lasts MaxApproval, so under a key that holds a novel
// step for less, the reconnect is held and then made; under a key that holds
// it for longer, the approval has expired when the hold ends and the slot is
// left as it was. Each reconnect names a new grant, so each is novel (row u).
func TestAReconnectOutlastsOnlyAHoldShorterThanItsApproval(t *testing.T) {
	for _, c := range []struct {
		name string
		hold int64
		done bool
	}{
		{"a 10-minute novelty window", 10 * 60 * 1000, true},
		{"a 30-minute novelty window", 30 * 60 * 1000, false},
	} {
		r := newExitRig(t)
		grant := []byte(`{"refresh_token":"canary-refresh-held","client_id":"agentos-test"}`)
		d := r.stage("held", grant)
		r.now += 1000
		k := r.narrow(key.LimitVerbs(key.ChangeAccount), key.LimitContent(grantPrint(d)), key.LimitUses(1), key.LimitExpires(r.now+MaxApproval), key.LimitHold(0, c.hold))
		before, _ := r.sec.MarshalBinary()
		if st, _ := r.reconnect("held", k, "web", d); st.Phase != kernel.PHeld {
			t.Fatalf("%s: the reconnect was not held: %s %q", c.name, st.Phase, st.Detail)
		}
		r.now += c.hold + 1000
		r.tick(r.now)
		after, _ := r.sec.MarshalBinary()
		if changed := !bytes.Equal(before, after); changed != c.done {
			t.Errorf("%s: store changed %v, want %v (step %+v)", c.name, changed, c.done, r.step("held"))
		}
		// Undone means ended: the approval ran out, not a hold that never ends.
		if st := r.step("held"); !c.done && st.Phase != kernel.PCancelled {
			t.Errorf("%s: the expired reconnect is %s %q, want cancelled", c.name, st.Phase, st.Detail)
		}
	}
}

// The clerk judges a reconnect's content by its own facts, the print of the
// grant the step's value names: a step claiming the approved grant while its
// value names another staged one is refused, and the slot is unchanged.
func TestAReconnectClaimingAnotherGrantIsRefused(t *testing.T) {
	r := newExitRig(t)
	grant := []byte(`{"refresh_token":"canary-refresh-new","client_id":"agentos-test"}`)
	approved := grantDigest([]byte(`{"refresh_token":"canary-refresh-other","client_id":"agentos-test"}`))
	digest := r.stage("claim", grant)
	st, changed := r.reconnectClaiming("claim", r.approve(approved), "web", digest, grantPrint(approved))
	if changed || st.Detail != clerk.RClaim {
		t.Fatalf("step %s %q, store changed %v", st.Phase, st.Detail, changed)
	}
}

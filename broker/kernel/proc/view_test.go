package proc

// REQ: CLK-2, KRN-8, A4

import (
	"cmp"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// fakeView is a log's answers for one in-flight request, every one set to a
// value the check reads.
type fakeView struct {
	grants   map[key.ID]int64
	enrolled []key.Enrollment
	cut      []ed25519.PublicKey
	changes  key.Changes
	ledger   map[key.ID][]key.Use
	dispatch kernel.Dispatch
	line     int64
	task     kernel.Task
}

func (f *fakeView) Granted(id key.ID) (int64, bool) { from, ok := f.grants[id]; return from, ok }
func (f *fakeView) Enrollments() ([]key.Enrollment, []ed25519.PublicKey) {
	return f.enrolled, f.cut
}
func (f *fakeView) ChangesView() *key.Changes { return &f.changes }
func (f *fakeView) LedgerBefore(seq uint64) key.Ledger {
	if seq != f.dispatch.Seq {
		return uses(nil)
	}
	return uses(f.ledger)
}
func (f *fakeView) Dispatched(kernel.Request) (kernel.Dispatch, bool) { return f.dispatch, true }
func (f *fakeView) OneOffLine(key.ID, int64) int64                    { return f.line }
func (f *fakeView) Task(id string, now int64) (kernel.Task, bool) {
	return f.task, id == f.task.ID && now < f.task.Until
}

// Every answer the clerk's check reads crosses the wire as the log gave it:
// revocations, pauses and STOP, the enrollments and the cut-off passkeys, the
// hold and its start, the ledger, the one-off line and the task (#2700 item
// 5). A view that drops or forces any of them would let the clerk act on a
// state the log does not hold; today the kernel refuses those states before
// it dispatches, so only this test pins the wire.
func TestViewCarriesWhatTheCheckReads(t *testing.T) {
	now := time.Now().UnixMilli()
	root := key.Issue(ownerPriv, key.Root{Clerk: "web", Verbs: []key.Verb{key.Post}, Serial: "r1"})
	ck, err := key.ClerkKey(root, ownerPriv, holderPub, now, 1<<40)
	if err != nil {
		t.Fatal(err)
	}
	ps := kernel.PlanStep{Verb: key.Post, Clerk: "web", Args: map[string]string{"to": "alice", "msg": "hi"}, Content: "text", Labels: []string{"public"}}
	p := kernel.SignPlan(kernel.Plan{ID: "p1", Key: ck, Steps: []kernel.PlanStep{ps}}, holderPriv)
	r := kernel.Request{Plan: p, Index: 0}
	ver, err := kernel.VerifyPlan(p, anchors)
	if err != nil {
		t.Fatal(err)
	}
	phone, _ := gen(8)
	lost, _ := gen(9)
	f := &fakeView{
		grants:   map[key.ID]int64{},
		enrolled: []key.Enrollment{key.Enroll(ownerPriv, phone)},
		cut:      []ed25519.PublicKey{lost},
		changes:  key.Changes{Revoked: map[key.ID]bool{ver.ID(): true}, Paused: map[key.ID]bool{ver.Root(): true}, Stopped: true},
		ledger:   map[key.ID][]key.Use{},
		line:     42,
		task:     kernel.Task{ID: ver.Limits.Task, At: now - 10, Until: now + 60_000},
	}
	for i, id := range ver.IDs {
		f.grants[id] = now - int64(i) - 1
	}
	for i, id := range ver.Scopes() {
		f.ledger[id] = []key.Use{{At: now - 1000*int64(i+1), Amount: int64(i + 3), Recipient: "alice", Task: "p0"}}
	}

	// A held step and an unheld one, so the wire can neither drop nor force
	// the hold.
	for _, d := range []kernel.Dispatch{{Seq: 7, Held: true, HeldAt: now - 5, Novel: true}, {Seq: 8}} {
		f.dispatch = d
		roundTrip(t, f, ver, r, now)
	}
}

func roundTrip(t *testing.T, f *fakeView, ver *key.Verified, r kernel.Request, now int64) {
	t.Helper()
	b, err := json.Marshal(view(f, anchors, r, now))
	if err != nil {
		t.Fatal(err)
	}
	var s snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	same := func(what string, got, want any) {
		t.Helper()
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: the clerk reads %+v, the log says %+v", what, got, want)
		}
	}
	for _, id := range ver.IDs {
		gf, gok := s.Granted(id)
		wf, wok := f.Granted(id)
		same("grant "+fmt.Sprint(id), []any{gf, gok}, []any{wf, wok})
	}
	ge, gc := s.Enrollments()
	same("enrollments", ge, f.enrolled)
	same("cut-off passkeys", gc, f.cut)
	same("changes", *s.ChangesView(), f.changes)
	gd, gok := s.Dispatched(r)
	same("dispatch", []any{gd, gok}, []any{f.dispatch, true})
	for _, id := range ver.Scopes() {
		// as far as the chain's caps count it (TestViewLedgerIsBoundedByTheCaps)
		same("ledger "+fmt.Sprint(id), s.LedgerBefore(f.dispatch.Seq).Uses(id), needed(f.ledger[id], ver.Limits.Caps, id, r.Step().Task, now))
	}
	same("one-off line", s.OneOffLine(ver.Root(), now), f.line)
	gt, tok := s.Task(ver.Limits.Task, now)
	same("task", []any{gt, tok}, []any{f.task, true})
}

// count is what a cap counts over us at now, as key.Verified's caps do.
func count(cp key.Cap, us []key.Use, task, recipient string, now int64) int64 {
	var n int64
	for _, u := range us {
		switch cp.Kind {
		case key.KSpendDay:
			if u.At > now-key.DayMS {
				n += u.Amount
			}
		case key.KRateDay:
			if u.At > now-key.DayMS {
				n++
			}
		case key.KRateRecipient:
			if u.At > now-key.DayMS && u.Recipient == recipient {
				n++
			}
		case key.KSpendTask:
			if u.Task == task {
				n += u.Amount
			}
		case key.KUses:
			n++
		}
	}
	return n
}

// The view carries a scope's uses only as far as its caps can count them
// (#2700 item 3): every cap counts the same on the bounded list as on the
// whole ledger, at the kernel's time and on a clerk clock behind it by up to
// viewSkew, as far as the cap's own limit. A ledger of a year of daily uses
// shrinks to the day's and the task's.
func TestViewLedgerIsBoundedByTheCaps(t *testing.T) {
	now := int64(400 * key.DayMS)
	s1, s2, s3 := key.ID{1}, key.ID{2}, key.ID{3}
	var all []key.Use
	for d := int64(365); d >= 0; d-- {
		for h := int64(0); h < 24; h += 6 {
			all = append(all, key.Use{At: now - d*key.DayMS - h*3_600_000, Amount: 1 + h, Recipient: fmt.Sprint("r", h%12), Task: fmt.Sprint("t", d%7)})
		}
	}
	// One just outside the kernel's day but inside a lagging clerk's.
	all = append(all, key.Use{At: now - key.DayMS - viewSkew/2, Amount: 5, Recipient: "r0", Task: "t9"})
	slices.SortFunc(all, func(a, b key.Use) int { return cmp.Compare(a.At, b.At) }) // the log's order
	caps := []key.Cap{
		{Scope: s1, Kind: key.KSpendDay, N: 1 << 40}, {Scope: s1, Kind: key.KRateDay, N: 1 << 40},
		{Scope: s1, Kind: key.KRateRecipient, N: 1 << 40}, {Scope: s1, Kind: key.KSpendTask, N: 1 << 40},
		{Scope: s1, Kind: key.KUses, N: 3},
		{Scope: s2, Kind: key.KUses, N: 1 << 40},
		{Scope: s3, Kind: key.KUses, N: 10},
	}
	got := needed(all, caps, s1, "t3", now)
	if len(got) >= len(all)/3 {
		t.Fatalf("the bounded list keeps %d of %d uses", len(got), len(all))
	}
	for _, cp := range caps[:5] {
		for _, at := range []int64{now, now - viewSkew} {
			whole := count(cp, all, "t3", "r0", at)
			part := count(cp, got, "t3", "r0", at)
			if cp.Kind == key.KUses {
				whole, part = min(whole, cp.N), min(part, cp.N)
			}
			if whole != part {
				t.Errorf("%s at now-%d: %d on the bounded list, %d on the whole ledger", cp.Kind, now-at, part, whole)
			}
		}
	}
	if got := needed(all, caps, s2, "t3", now); len(got) != len(all) {
		t.Fatalf("a use cap over the ledger's size keeps %d of %d uses", len(got), len(all))
	}
	if got := needed(all, caps, s3, "t3", now); !reflect.DeepEqual(got, all[len(all)-10:]) {
		t.Fatalf("a use cap of 10 keeps %d uses, want the newest 10", len(got))
	}
	if got := needed(all, caps, key.ID{4}, "t3", now); got == nil || len(got) != 0 {
		t.Fatalf("a scope with no cap: %v, want an empty list that still covers it", got)
	}
}

// A call the kernel began writing is unknown when the write fails, never
// unsent: part of it may have reached the clerk, which may act on it (KRN-8,
// #2700 item 6). The clerk here reads one byte of a large call and hangs up.
func TestAFailedWriteIsUnknown(t *testing.T) {
	sock := filepath.Join(shortDir(t), "c.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			io.ReadFull(c, make([]byte, 1))
			c.Close()
		}
	}()
	ps := kernel.PlanStep{Verb: key.Post, Clerk: "web", Args: map[string]string{"to": "alice", "msg": strings.Repeat("x", 2<<20)}}
	r := kernel.Request{Plan: kernel.Plan{ID: "big", Steps: []kernel.PlanStep{ps}}}
	c := remote{Remote{Socket: sock, UID: os.Getuid(), Timeout: 20 * time.Second}, anchors}
	if res := c.do(r, snapshot{}); res.Outcome != "unknown" || res.Detail != DLost {
		t.Fatalf("a call cut off mid-write: %+v, want unknown %s", res, DLost)
	}
	if got := c.probe(r, snapshot{}).Outcome; got != "unknown" {
		t.Fatalf("a probe cut off mid-write: %q, want unknown", got)
	}
}

// A call past what the clerk reads is never sent: the step fails as
// too-large, not unknown, so it does not park with a false warning that it
// may have happened, and a probe counts no check (#2708 item 1). One just
// under the bound is sent.
func TestACallPastTheBoundIsNeverSent(t *testing.T) {
	sock := filepath.Join(shortDir(t), "c.sock")
	ln, err := ListenClerk(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan int, 1)
	go func() {
		n := 0
		for {
			conn, err := ln.Accept()
			if err != nil {
				got <- n
				return
			}
			n++
			// The clerk's own read (serve): the call at the bound is read whole.
			var in call
			detail := "whole"
			if json.NewDecoder(io.LimitReader(conn, maxCall)).Decode(&in) != nil {
				detail = "cut"
			}
			conn.Write([]byte(`{"outcome":"failed","detail":"` + detail + `"}` + "\n"))
			conn.Close()
		}
	}()
	c := remote{Remote: Remote{Socket: sock, UID: os.Getuid(), Timeout: 20 * time.Second}}
	// sized is a request whose call is n bytes with its newline.
	sized := func(n int) kernel.Request {
		b, _ := json.Marshal(call{opDo, kernel.Request{}, snapshot{}})
		return kernel.Request{Plan: kernel.Plan{ID: strings.Repeat("p", n-len(b)-1)}}
	}
	big, fits := sized(maxCall+1), sized(maxCall)
	if b, _ := json.Marshal(call{opDo, fits, snapshot{}}); len(b)+1 != maxCall {
		t.Fatalf("the call that fits is %d bytes with its newline, want %d", len(b)+1, maxCall)
	}
	if res := c.do(big, snapshot{}); res.Outcome != "failed" || res.Detail != DTooLarge {
		t.Errorf("a call past the bound: %+v", res)
	}
	// A probe that can never be sent counts a check, so the step parks
	// rather than probing forever (#2742 item 8).
	if got := c.probe(big, snapshot{}).Outcome; got != "unknown" {
		t.Errorf("a probe past the bound: %q", got)
	}
	if res := c.do(fits, snapshot{}); res.Detail != "whole" {
		t.Errorf("a call at the bound: %+v", res)
	}
	ln.Close()
	if n := <-got; n != 1 {
		t.Fatalf("%d calls reached the clerk, want only the one at the bound", n)
	}
}

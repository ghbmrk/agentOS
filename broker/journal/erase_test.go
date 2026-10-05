package journal

// REQ: CAP-3, OP-1, OP-5

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func canaryIntent(id, origin string) Intent {
	in := intent(id, "acct-"+id)
	in.Origin = origin
	in.Params = map[string]any{"body": "quoting zebracorn-" + id}
	in.Preconditions = []string{"zebracorn-" + id + " still unanswered"}
	return in
}

// Erasing a deleted source's intents removes their content from memory and
// the file, keeps the audit trail and OP-1, never lets an erased intent run,
// and holds an intent whose outcome is still open.
func TestEraseRemovesContentAndKeepsAudit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.log")
	st, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	svc := newService()
	svc.mode = func(key string) execMode {
		if strings.HasPrefix(key, "d") {
			return modeDropAck
		}
		return modeOK
	}
	e := mustOpen(t, st, newPolicy(), svc)
	t0 := time.Now().UTC()
	must(e.Submit(canaryIntent("old", "guest:other")))
	for _, id := range []string{"a", "b", "c", "d"} {
		must(e.Submit(canaryIntent(id, "guest:L")))
	}
	must(e.Authorize(ctx, "a"))
	must(e.Dispatch(ctx, "a"))  // succeeded
	must(e.Authorize(ctx, "b")) // authorized, not run
	must(e.Authorize(ctx, "d"))
	must(e.Dispatch(ctx, "d")) // outcome unknown
	ids := e.Since("guest:L", t0)
	if strings.Join(ids, ",") != "a,b,c,d" {
		t.Fatalf("since: %v", ids)
	}
	erased, held, err := e.Erase(ids)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(erased, ",") != "a,b,c" || strings.Join(held, ",") != "d" {
		t.Fatalf("erased %v held %v", erased, held)
	}
	for id, want := range map[string]State{"a": Succeeded, "b": Denied, "c": Denied} {
		s := must(e.Get(id))
		if s.State != want || s.Intent.Params != nil || len(s.Intent.Recipients) != 1 || s.Intent.Account != "acct-"+id {
			t.Fatalf("%s: %+v", id, s)
		}
		if want == Denied && s.Permission.Reason != ErasedReason {
			t.Fatalf("%s: reason %q", id, s.Permission.Reason)
		}
	}
	if _, err := e.Dispatch(ctx, "b"); err == nil {
		t.Fatal("an erased intent was dispatched")
	}
	data, _ := os.ReadFile(path)
	for _, id := range []string{"a", "b", "c"} {
		if strings.Contains(string(data), "zebracorn-"+id) {
			t.Fatalf("content of %s remains in the journal file", id)
		}
	}
	if !strings.Contains(string(data), "zebracorn-old") || !strings.Contains(string(data), "zebracorn-d") {
		t.Fatal("content outside the erase was removed")
	}
	// OP-1: the same request again is recognised, a different one refused.
	if s, err := e.Submit(canaryIntent("a", "guest:L")); err != nil || s.State != Succeeded {
		t.Fatalf("resubmit after erase: %+v %v", s, err)
	}
	// The rewritten journal replays to the same state, and appends still
	// land in it (the lock moved with it).
	if _, err := OpenFile(path); !errors.Is(err, ErrLocked) {
		t.Fatalf("rewritten journal not locked: %v", err)
	}
	must(e.Submit(canaryIntent("e", "guest:L")))
	st.Close()
	st2, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	e2 := mustOpen(t, st2, newPolicy(), svc)
	if s := must(e2.Get("a")); s.State != Succeeded || s.Intent.Params != nil {
		t.Fatalf("after reopen: %+v", s)
	}
	if _, err := e2.Submit(canaryIntent("a", "guest:L")); err != nil {
		t.Fatalf("OP-1 after reopen: %v", err)
	}
	in := canaryIntent("a", "guest:L")
	in.Params["body"] = "other"
	if _, err := e2.Submit(in); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed params after erase: %v", err)
	}
	if _, err := e2.Get("e"); err != nil {
		t.Fatal("append after the rewrite was lost")
	}
	if strings.Join(e2.Erased(), ",") != "a,b,c" {
		t.Fatalf("erased after reopen: %v", e2.Erased())
	}
}

// An erase whose rewrite a crash cut off is finished when the journal
// reopens.
func TestEraseFinishedOnOpen(t *testing.T) {
	st := &failingRewrite{}
	e := mustOpen(t, st, newPolicy(), newService())
	must(e.Submit(canaryIntent("a", "guest:L")))
	st.fail = true
	if _, _, err := e.Erase([]string{"a"}); err == nil {
		t.Fatal("failed rewrite not reported")
	}
	st.fail = false
	data, _ := st.ReadAll()
	if !strings.Contains(string(data), "zebracorn-a") {
		t.Fatal("test needs the content left behind")
	}
	e2 := mustOpen(t, st, newPolicy(), newService())
	data, _ = st.ReadAll()
	if strings.Contains(string(data), "zebracorn-a") || len(e2.Erased()) != 1 {
		t.Fatal("open did not finish the erase")
	}
}

type failingRewrite struct {
	MemStore
	fail bool
}

func (f *failingRewrite) Rewrite(data []byte) error {
	if f.fail {
		return errors.New("disk full")
	}
	return f.MemStore.Rewrite(data)
}

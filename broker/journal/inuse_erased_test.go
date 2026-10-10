package journal

import (
	"path/filepath"
	"testing"
	"time"
)

// REQ: CAP-3, ADP-9, A12

// erasedUses maps each intent holding a place in the window ending now
// to whether it was erased.
func erasedUses(e *Engine, c *clock) map[string]bool {
	out := map[string]bool{}
	for _, u := range e.InUse("acct", "send", c.now().Add(-24*time.Hour)) {
		out[u.Intent.ID] = u.Erased
	}
	return out
}

// TestInUseMarksErasedUses (SR3-2-f3): an intent erased under CAP-3 keeps
// its place under the bound and is marked Erased, so the gate can count it
// against every record once its record key is gone. The mark survives
// replay of the rewritten journal.
func TestInUseMarksErasedUses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.log")
	st, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{t: time.Date(2026, 10, 9, 9, 0, 0, 0, time.UTC)}
	e := openAt(t, st, c, newService())
	for _, id := range []string{"a", "b"} {
		in := intent(id, "acct")
		in.Params = map[string]any{"record": "inv-1042"}
		must(e.Submit(in))
		must(e.Authorize(ctx, id))
		must(e.Dispatch(ctx, id))
	}
	if _, _, err := e.Erase([]string{"a"}); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"a": true, "b": false}
	check := func(when string, e *Engine) {
		t.Helper()
		got := erasedUses(e, c)
		if len(got) != len(want) || got["a"] != want["a"] || got["b"] != want["b"] {
			t.Fatalf("%s: erased marks %v, want %v", when, got, want)
		}
	}
	check("after erase", e)
	st.Close()
	st2, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	check("after replay", openAt(t, st2, c, newService()))
}

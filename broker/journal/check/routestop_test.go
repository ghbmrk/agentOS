package check

import "testing"

// REQ: OP-5, CRED-RS-1

// CRED-RS-1: a route stop and its reopening are note records, so a journal
// holding them stays clean; they must not read as an unknown record type
// and turn STATUS into a standing "Journal check failed".
func TestRouteStopRecordsAreClean(t *testing.T) {
	w := newWorld(t, 7, honest)
	for i := 0; i < 20; i++ {
		w.step()
	}
	if err := w.eng.StopRoute("codex", "login-refused"); err != nil {
		t.Fatal(err)
	}
	if err := w.eng.ReopenRoute("codex", "login-refused"); err != nil {
		t.Fatal(err)
	}
	if v := mustEngine(t, w.eng, true); len(v) != 0 {
		t.Fatalf("route stop records judged violations: %+v", v)
	}
	if n := Note(w.eng)(); n != "" {
		t.Fatalf("clean journal with route stops noted %q", n)
	}
}

package main

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/e2e/boxe2e/codexstub"
)

// REQ: HW-10

// updatingBox is a fakeBox whose step 6 still waits for the first-boot
// update: /setup shows only the wait message, never aiOpen. Every other
// path is the embedded fakeBox's.
type updatingBox struct{ *fakeBox }

func (u updatingBox) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/setup" {
		w.Write([]byte(`<h2>6. Connect AI</h2><p class="muted">Updating this box. This can take a few minutes.</p>`))
		return
	}
	u.fakeBox.ServeHTTP(w, r)
}

// A step 6 that never lists providers, as while the first-boot update
// runs, fails as "step 6 did not open" after the step's two minutes on the
// driver's clock: a product failure, so FAIL and not the not-driven text
// (#1890 item 5, ASSUMPTIONS E11). The clock is the driver's now and
// sleep, so the wait takes no real time.
func TestStep6ThatNeverOpensFails(t *testing.T) {
	f := &fakeBox{stub: codexstub.New(), offer: true, host: "auth.openai.com"}
	d := fakeDriver(f)
	d.phone.Transport = handlerRT{updatingBox{f}}
	at := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return at }
	d.sleep = func(t time.Duration) { at = at.Add(t) }
	start := at
	err := d.guestTask()
	if err == nil || !strings.HasPrefix(err.Error(), "step 6 did not open: after 2m0s") || !strings.Contains(err.Error(), `"6. Connect AI"`) {
		t.Fatalf("%v, want step 6 did not open", err)
	}
	if waited := at.Sub(start); waited < 2*time.Minute || waited > 2*time.Minute+2*time.Second {
		t.Fatalf("waited %s on the driver's clock, want 2m", waited)
	}
	if f.stub.Hits()["usercode"] != 0 {
		t.Fatalf("signed in on a page that never opened: %v", f.stub.Hits())
	}
}

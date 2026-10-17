package owner

import (
	"testing"
	"time"
)

// REQ: CH-10

// The expiry guard (APPROVAL-expiry-guard, #1923): answerLocked refuses a
// request past its expiry by itself, so a caller that skips expireLocked
// cannot approve with a code that has expired. Both answer paths are
// checked: a texted code and the local page's code-generator code.
func TestAnswerRefusesAnExpiredRequestWithoutCallerExpiry(t *testing.T) {
	for _, page := range []bool{false, true} {
		r := newRig(t, nil)
		r.unlock()
		r.ch.Request([]Item{lowItem("late")}, 0)
		m := lowCodeRe.FindStringSubmatch(r.inbox())
		if m == nil {
			t.Fatal("no texted code")
		}
		r.advance(DefaultCodeTTL + time.Minute)
		code := m[2]
		if page {
			code = r.totp()
		}
		now := r.clock()
		var decided []Decision
		r.ch.mu.Lock()
		out, accepted, _ := r.ch.answerLocked(reply{word: "YES", id: m[1], code: code}, now, &decided, page)
		_, open := r.ch.open[m[1]]
		r.ch.mu.Unlock()
		if accepted || open {
			t.Fatalf("page=%v: an expired request was answered: %q (accepted=%v, open=%v)", page, out, accepted, open)
		}
		if len(decided) != 1 || decided[0].Approved || decided[0].Why != "expired" {
			t.Fatalf("page=%v: decisions %+v, want one expired denial", page, decided)
		}
	}
}

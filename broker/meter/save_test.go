package meter

import (
	"os"
	"strings"
	"sync"
	"testing"
)

// REQ: RES-4
//
// Security review 2, finding 3 (SR2-3): a settled call whose charge cannot
// be saved (a full disk) is reported, not dropped silently.

func TestASettleThatCannotBeSavedIsReported(t *testing.T) {
	var mu sync.Mutex
	var got []error
	m, _, _ := open(t, Config{
		MachineCap: Limits{Calls: 100, Tokens: 1 << 20}, OverallCap: Limits{Calls: 100, Tokens: 1 << 20},
		SaveError: func(err error) { mu.Lock(); got = append(got, err); mu.Unlock() },
	})
	c, err := m.Start("m1", 10, 100)
	if err != nil {
		t.Fatal(err)
	}
	// The state can no longer be written.
	if err := os.Mkdir(m.cfg.Path+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	c.Done(500)
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || !strings.Contains(got[0].Error(), "meter") {
		t.Fatalf("save failure reported %v", got)
	}
	if u := m.Usage("m1"); u.Tokens != 500 {
		t.Fatalf("charge not kept in memory: %+v", u)
	}
}

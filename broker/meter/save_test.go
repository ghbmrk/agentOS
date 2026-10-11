package meter

import (
	"os"
	"path/filepath"
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
	// The state can no longer be written: a directory holds its name.
	if err := os.Remove(m.cfg.Path); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(m.cfg.Path, "x"), 0o700); err != nil {
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

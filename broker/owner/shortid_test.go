package owner

// REQ: CH-12, CH-3

import (
	"strings"
	"testing"
	"time"
)

// only limits the ID space to a few IDs: Reserved reports every other ID.
// Three-character IDs, since the allocator's last pass scans all of those
// in order, while its first pass tries two-character ones at random.
func only(ids ...string) func(string) bool {
	return func(id string) bool {
		for _, x := range ids {
			if x == id {
				return false
			}
		}
		return true
	}
}

// C11 (change): IDs the change pipeline still answers to are never given
// to an approval request, so "UNDO K3" or "YES K3" names one thing.
func TestRequestsSkipReservedIDs(t *testing.T) {
	r := newRigEdit(t, func(c *Config) { c.Reserved = only("B04") })
	id, err := r.ch.Request([]Item{lowItem("i1")}, 10*time.Minute)
	if err != nil || id != "B04" {
		t.Fatalf("request ID %q %v", id, err)
	}
	if id, err := r.ch.Request([]Item{lowItem("i2")}, 10*time.Minute); err == nil {
		t.Fatalf("a request took a reserved ID: %q", id)
	}
}

// ShortID lends the pipeline an ID clear of open requests and of the
// pipeline's own, and the channel keeps it from its requests at once,
// before the pipeline has saved the adoption that uses it.
func TestShortIDClearOfRequestsAndLentAtOnce(t *testing.T) {
	r := newRigEdit(t, func(c *Config) { c.Reserved = only("B04", "C05", "D06") })
	req, err := r.ch.Request([]Item{lowItem("i1")}, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var asked []string
	lent, err := r.ch.ShortID(func(id string) bool {
		asked = append(asked, id)
		return false
	})
	if err != nil || lent == req || !strings.Contains("B04 C05 D06", lent) {
		t.Fatalf("lent %q (request %q) %v", lent, req, err)
	}
	if len(asked) == 0 {
		t.Fatal("ShortID did not ask the pipeline which IDs it uses")
	}
	req2, err := r.ch.Request([]Item{lowItem("i2")}, 10*time.Minute)
	if err != nil || req2 == lent || req2 == req {
		t.Fatalf("second request %q (lent %q, first %q) %v", req2, lent, req, err)
	}
	if id, err := r.ch.ShortID(func(string) bool { return false }); err == nil {
		t.Fatalf("lent %q with every ID in use", id)
	}
	// The pipeline's own IDs are skipped too.
	r2 := newRigEdit(t, func(c *Config) { c.Reserved = only("B04", "C05") })
	if id, err := r2.ch.ShortID(func(id string) bool { return id == "B04" }); err != nil || id != "C05" {
		t.Fatalf("lent %q %v, want C05", id, err)
	}
}

// A lent ID survives a channel restart: the pipeline may not have saved
// its adoption yet when the box goes down.
func TestShortIDLentAcrossRestart(t *testing.T) {
	store := &MemStore{}
	r := newRigEditStore(t, store, func(c *Config) { c.Reserved = only("B04", "C05") })
	lent, err := r.ch.ShortID(func(string) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	r.ch = r.open()
	id, err := r.ch.Request([]Item{lowItem("i1")}, 10*time.Minute)
	if err != nil || id == lent {
		t.Fatalf("request after restart took lent ID %q: %q %v", lent, id, err)
	}
}

func newRigEdit(t *testing.T, edit func(*Config)) *rig { return newRigEditStore(t, nil, edit) }

func newRigEditStore(t *testing.T, store Store, edit func(*Config)) *rig {
	r := newRig(t, store)
	r.edit = edit
	r.ch = r.open()
	return r
}

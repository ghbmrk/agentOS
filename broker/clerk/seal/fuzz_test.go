package seal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// REQ: STO-2, A8

// The unlock step parses the store file before any key exists, from a drive
// an attacker may have written. Corrupt bytes must not panic, and whatever
// parses must hold to every bound and read back the same.
func FuzzParse(f *testing.F) {
	path := filepath.Join(f.TempDir(), "store")
	s, err := Create(path, Recovery{Key: make([]byte, RecoveryLen)})
	if err != nil {
		f.Fatal(err)
	}
	s.Close()
	good, err := os.ReadFile(path)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add(good[:len(good)/2])
	f.Add([]byte{})
	f.Add([]byte(`{"v":1}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		fl, err := parse(b)
		if err != nil {
			return
		}
		if len(fl.Slots) == 0 || len(fl.Slots) > MaxSlots || len(fl.ID) != idLen {
			t.Fatalf("parsed past a bound: %d slots", len(fl.Slots))
		}
		again, err := json.Marshal(fl)
		if err != nil {
			t.Fatal(err)
		}
		fl2, err := parse(again)
		if err != nil {
			t.Fatalf("a parsed file does not parse again: %v", err)
		}
		if b2, _ := json.Marshal(fl2); string(b2) != string(again) {
			t.Fatal("a parsed file reads back differently")
		}
	})
}

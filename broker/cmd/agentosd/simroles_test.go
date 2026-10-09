package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ghbmrk/agentos/broker/localsrv"
	"github.com/ghbmrk/agentos/broker/modemlink"
)

// REQ: CH-1, CH-19

// P2-2w d2b: agentosd records an adopted SIM in agentos-modem's roles
// file, which the bridge only reads (its unit binds the directory
// read-only, L3 on #170). The file is replaced whole, keeps any other
// line's role, and stays readable by the bridge's user.
func TestAdoptedSIMIsRecordedInTheRolesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roles.json")
	rec := recordOwnerSIM(path)
	if err := rec("89012600000000012345"); err != nil {
		t.Fatal(err)
	}
	if got := readRoles(t, path); !reflect.DeepEqual(got, map[string]any{"owner_iccid": "89012600000000012345"}) {
		t.Fatalf("roles %v", got)
	}
	os.WriteFile(path, []byte(`{"owner_iccid":"8901","second_iccid":"8902"}`), 0o644)
	if err := rec("89012600000000099999"); err != nil {
		t.Fatal(err)
	}
	if got := readRoles(t, path); !reflect.DeepEqual(got, map[string]any{"owner_iccid": "89012600000000099999", "second_iccid": "8902"}) {
		t.Fatalf("roles %v", got)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v %v", fi.Mode(), err)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".roles-*")); len(left) != 0 {
		t.Fatalf("temp files left: %v", left)
	}
	// A roles file that is not JSON is not overwritten blind.
	os.WriteFile(path, []byte("garbage"), 0o644)
	if err := rec("89012600000000012345"); err == nil {
		t.Fatal("a corrupt roles file was overwritten")
	}
	// No directory: an error, not a panic.
	if err := recordOwnerSIM(filepath.Join(t.TempDir(), "none", "roles.json"))("8901"); err == nil {
		t.Fatal("no directory: recorded")
	}
}

func readRoles(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// P2-2w d2b: the page's line carries the SIM the owner may adopt, by tag
// and last four digits.
func TestPageLineOffersTheSIM(t *testing.T) {
	got := pageLine(fakeLine{note: "n", sim: "0123456789abcdef", ends: "2345"})()
	if got.SIM != "0123456789abcdef" || got.SIMEnds != "2345" {
		t.Fatalf("%+v", got)
	}
}

// The link's refusal of a SIM no longer offered reaches the page as
// localsrv's stale refusal; other errors pass as they are.
func TestAStaleSIMIsLocalsrvsRefusal(t *testing.T) {
	boom := errors.New("boom")
	for in, want := range map[error]error{nil: nil, modemlink.ErrStale: localsrv.ErrStaleSIM, boom: boom} {
		if got := adoptSIM(func(string) error { return in })("t"); !errors.Is(got, want) || (want == nil) != (got == nil) {
			t.Errorf("%v: got %v, want %v", in, got, want)
		}
	}
}

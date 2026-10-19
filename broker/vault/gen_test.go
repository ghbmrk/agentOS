package vault

import (
	"fmt"
	"path/filepath"
	"testing"
)

// REQ: CRED-7

// TestGenMovesOnEveryChange: the keyless proxy (SIM-split-wire) is handed
// a fresh redactor whenever the vault's values change, so every stored or
// deleted value moves Gen, and a failed or empty change does not.
func TestGenMovesOnEveryChange(t *testing.T) {
	v, err := Create(filepath.Join(t.TempDir(), "vault"), testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	g0 := v.Gen()
	if err := v.Put("a", KindAPIKey, canary(t)); err != nil {
		t.Fatal(err)
	}
	g1 := v.Gen()
	if g1 == g0 {
		t.Fatal("Gen did not move on Put")
	}
	if err := v.Delete("missing"); err != nil {
		t.Fatal(err)
	}
	if v.Gen() != g1 {
		t.Fatal("Gen moved on a delete that changed nothing")
	}
	if err := v.Put("a", KindAPIKey, []byte("short")); err == nil {
		t.Fatal("short value stored")
	}
	if v.Gen() != g1 {
		t.Fatal("Gen moved on a refused Put")
	}
	if err := v.Delete("a"); err != nil {
		t.Fatal(err)
	}
	if v.Gen() == g1 {
		t.Fatal("Gen did not move on Delete")
	}
}

// TestOnChangeRunsAfterEveryChange: the hook runs once after each stored
// or deleted value, through Put, PutMany and Delete, outside the vault's
// lock (it reads the vault here), and not for a refused or empty change;
// nil clears it.
func TestOnChangeRunsAfterEveryChange(t *testing.T) {
	v, err := Create(filepath.Join(t.TempDir(), "vault"), testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	var seen []int
	v.OnChange(func() { seen = append(seen, len(v.List())) })
	if err := v.Put("a", KindAPIKey, canary(t)); err != nil {
		t.Fatal(err)
	}
	if err := v.PutMany([]Item{{Name: "b", Kind: KindAPIKey, Value: canary(t)}, {Name: "c", Kind: KindAPIKey, Value: canary(t)}}); err != nil {
		t.Fatal(err)
	}
	if err := v.Put("a", KindAPIKey, []byte("short")); err == nil {
		t.Fatal("short value stored")
	}
	if err := v.Delete("missing"); err != nil {
		t.Fatal(err)
	}
	if err := v.Delete("b"); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(seen) != "[1 3 2]" {
		t.Fatalf("hook saw %v, want [1 3 2]: once per change, after it", seen)
	}
	v.OnChange(nil)
	if err := v.Delete("c"); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 3 {
		t.Fatal("a cleared hook ran")
	}
}

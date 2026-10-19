package vault

import (
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

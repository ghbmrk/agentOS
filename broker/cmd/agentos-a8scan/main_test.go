package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/recovery"
	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: CRED-8
// Acceptance: A8 (the scan tool for the owner session)

func TestScanFindsPlantedKeyMaterialAndPassesACleanDrive(t *testing.T) {
	dir := t.TempDir()
	vp, kp := filepath.Join(dir, "vault"), filepath.Join(dir, "vault.keys")
	rk, err := recovery.NewRecoveryKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.CreateSealed(vp, kp, recovery.Factor(rk))
	if err != nil {
		t.Fatal(err)
	}
	seed := []byte("synthetic-seed-0123456789")
	if err := v.Put("owner-totp-seed", vault.KindTOTPSeed, seed); err != nil {
		t.Fatal(err)
	}
	v.Close()
	esp := filepath.Join(dir, "esp")
	os.Mkdir(esp, 0o700)
	os.WriteFile(filepath.Join(esp, "loader.conf"), []byte("timeout 0\n"), 0o600)

	var out bytes.Buffer
	n, err := run(vp, kp, rk, []string{dir}, &out)
	if err != nil || n != 0 {
		t.Fatalf("clean drive: %d findings, %v\n%s", n, err, out.String())
	}
	// A seed left in a plaintext file is found and named, not printed.
	os.WriteFile(filepath.Join(esp, "leak.txt"), []byte("x"+string(seed)+"y"), 0o600)
	out.Reset()
	n, err = run(vp, kp, rk, []string{esp}, &out)
	if err != nil || n == 0 || !strings.Contains(out.String(), "vault entry owner-totp-seed") || strings.Contains(out.String(), string(seed)) {
		t.Fatalf("leak: %d, %v\n%s", n, err, out.String())
	}
	// A key-slot file carrying anything else fails.
	raw, _ := os.ReadFile(kp)
	os.WriteFile(kp, []byte(strings.Replace(string(raw), `"slots":`, `"verifier":"x","slots":`, 1)), 0o600)
	out.Reset()
	if n, _ := run(vp, kp, rk, []string{esp}, &out); n == 0 {
		t.Fatalf("extra field passed:\n%s", out.String())
	}
}

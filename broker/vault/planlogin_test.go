package vault

// REQ: CRED-8, A14, CRED-7

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A plan login (egress.PlanLogins) is a "plan-login" vault entry holding a
// token set as JSON. Its canaries are on the drive only as ciphertext, and
// the redactor removes the entry's whole value from any text.
func TestPlanLoginEntryIsCiphertextAtRestAndRedacted(t *testing.T) {
	dir := t.TempDir()
	v, err := Create(filepath.Join(dir, "vault"), bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	access, refresh := string(canary(t)), string(canary(t))
	val, _ := json.Marshal(map[string]string{"access_token": access, "refresh_token": refresh, "account_id": "acct-x"})
	if err := v.Put("plan-login-codex", "plan-login", val); err != nil {
		t.Fatal(err)
	}
	filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(p)
		for _, s := range []string{access, refresh} {
			if bytes.Contains(b, []byte(s)) {
				t.Fatalf("%s holds a plan-login canary in the clear", p)
			}
		}
		return nil
	})
	r, err := v.Redactor()
	if err != nil {
		t.Fatal(err)
	}
	out := r.Redact([]byte("echo: " + string(val)))
	if bytes.Contains(out, []byte(access)) || bytes.Contains(out, []byte(refresh)) {
		t.Fatalf("redactor left a token: %s", out)
	}
}

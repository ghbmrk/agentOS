package inbox

// REQ: VRB-2

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const evalDir = "../../../evals/slice-inbox"

type fixtureMail struct {
	ID     string `json:"id"`
	File   string `json:"file"`
	Class  string `json:"class"`
	Reason string `json:"reason"`
}

// loadFixture reads the eval set's world, key records and mail (read only).
func loadFixture(t testing.TB) (World, []fixtureMail, map[string][]byte) {
	t.Helper()
	var w World
	var meta struct {
		Mails []fixtureMail `json:"mails"`
	}
	read := func(name string, v any) {
		b, err := os.ReadFile(filepath.Join(evalDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, v); err != nil {
			t.Fatal(err)
		}
	}
	read("world.json", &w)
	read("world.json", &meta)
	read("keys.json", &w.DKIMKeys)
	raw := map[string][]byte{}
	for _, m := range meta.Mails {
		b, err := os.ReadFile(filepath.Join(evalDir, m.File))
		if err != nil {
			t.Fatal(err)
		}
		raw[m.ID] = b
	}
	return w, meta.Mails, raw
}

func TestEvaluateMatchesFixtureReasons(t *testing.T) {
	w, mails, raw := loadFixture(t)
	for _, m := range mails {
		if got, _ := Evaluate(raw[m.ID], w); got != m.Reason {
			t.Errorf("%s: reason %q, want %q", m.ID, got, m.Reason)
		}
	}
}

func TestEvaluateURLOfEligibleMail(t *testing.T) {
	w, _, raw := loadFixture(t)
	if r, u := Evaluate(raw["M01"], w); r != ROK || !strings.HasPrefix(u, "https://") {
		t.Fatalf("M01: %q %q", r, u)
	}
}

func TestDKIMTamperedBodyFails(t *testing.T) {
	w, _, raw := loadFixture(t)
	good := VerifyDKIM(raw["M01"], w.DKIMKeys)
	if len(good) == 0 || !good[0].Pass {
		t.Fatalf("M01 signature should verify: %+v", good)
	}
	bad := append([]byte{}, raw["M01"]...)
	bad = append(bad, []byte("x\r\n")...)
	if s := VerifyDKIM(bad, w.DKIMKeys); len(s) == 0 || s[0].Pass {
		t.Fatalf("appended body must fail: %+v", s)
	}
}

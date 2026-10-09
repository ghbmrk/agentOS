package browseract

import (
	"encoding/json"
	"strings"
	"testing"
)

// REQ: CRED-4, CRED-4b, CRED-10

const canary = "CANARY-SESSION-COOKIE-NOT-REAL"

func TestCRED4bFixtureExecutorHidesVaultSession(t *testing.T) {
	store := &MemorySessions{}
	ex := &Executor{
		Sessions:     store,
		Origins:      []string{"http://127.0.0.1:9"},
		CanaryCookie: canary,
	}
	raw, _ := json.Marshal(map[string]any{"v": 0, "verb": "snapshot"})
	res, err := ex.Run("acct-1", raw)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || strings.Contains(res.Snapshot, canary) {
		t.Fatalf("result leaked canary: %+v", res)
	}
	state, ok := store.Get("acct-1")
	if !ok || !strings.Contains(string(state), canary) {
		t.Fatal("vault seam did not hold the canary session")
	}
	if strings.Contains(res.Snapshot, "secret") {
		t.Fatalf("password value visible: %q", res.Snapshot)
	}
	raw, _ = json.Marshal(map[string]any{"v": 0, "verb": "navigate", "url": "https://evil.example/"})
	res, err = ex.Run("acct-1", raw)
	if err != nil || res.Error == "" || !strings.Contains(res.Error, "off-origin") {
		t.Fatalf("off-origin: %+v %v", res, err)
	}
}

func TestCRED4bNoLiveSitesInPackage(t *testing.T) {
	for _, host := range []string{"accounts.google.com", "login.microsoftonline.com", "github.com", "login.live.com", "appleid.apple.com"} {
		raw, _ := json.Marshal(map[string]any{"v": 0, "verb": "navigate", "url": "https://" + host + "/"})
		ex := &Executor{Origins: []string{"http://127.0.0.1"}, CanaryCookie: canary, Sessions: &MemorySessions{}}
		res, err := ex.Run("a", raw)
		if err != nil {
			t.Fatal(err)
		}
		if res.Error == "" {
			t.Fatalf("live site %s was not refused", host)
		}
	}
}

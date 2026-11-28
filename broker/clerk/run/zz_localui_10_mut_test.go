package run

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/model"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// REQ: CLK-1, TN-account-plan-6
// MUT-kill-localui-10 (#6774): the serveKeyCall cases and the accountPlan
// branch that mutgate left alive on #6434, each pinned by a test that
// fails without it.

// mut10APIs is a key store over the shipped declarations.
func mut10APIs(t *testing.T) *model.APIs {
	t.Helper()
	k := make([]byte, 32)
	rand.Read(k)
	sealer, err := clerk.NewAESSealer(k)
	if err != nil {
		t.Fatal(err)
	}
	apis, err := model.NewAPIs(model.Shipped, model.NewKeys(sealer, nil), netguard.New(netguard.Config{}), nil)
	if err != nil {
		t.Fatal(err)
	}
	return apis
}

// mut10Key is provider's state in apis.
func mut10Key(t *testing.T, apis *model.APIs, provider string) model.KeyState {
	t.Helper()
	st, err := apis.State()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range st {
		if s.Provider == provider {
			return s
		}
	}
	t.Fatalf("no state for %s in %+v", provider, st)
	return model.KeyState{}
}

// Each key call does its own change to the store: set, relabel, remove.
func TestMut10KeyCallsChangeTheStore(t *testing.T) {
	apis := mut10APIs(t)
	p := model.Shipped[0].Provider
	call := func(op string, k keyArgs) {
		t.Helper()
		raw, _ := json.Marshal(k)
		if out, err := serveKeyCall(apis, op, raw); err != nil || out != nil {
			t.Fatalf("%s: %s %v", op, out, err)
		}
	}
	call("apikeyset", keyArgs{Provider: p, Key: "canary-key-0001", Private: true})
	if s := mut10Key(t, apis, p); !s.Set || !s.Private {
		t.Fatalf("after apikeyset: %+v", s)
	}
	call("apikeyprivate", keyArgs{Provider: p, Private: false})
	if s := mut10Key(t, apis, p); !s.Set || s.Private {
		t.Fatalf("after apikeyprivate: %+v", s)
	}
	call("apikeyremove", keyArgs{Provider: p})
	if s := mut10Key(t, apis, p); s.Set {
		t.Fatalf("after apikeyremove: %+v", s)
	}
}

// Mail settings that do not load make the plan an error, never a plan
// read as if no account were set up.
func TestMut10AccountPlanWithUnreadableSettingsIsAnError(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	f := filepath.Join(dir, mailSettings)
	if err := os.WriteFile(f, []byte("{not json"), 0); err != nil {
		t.Fatal(err)
	}
	h := NewMailHost(context.Background(), dir, sec, planConfig(srv))
	if p, err := h.accountPlan(); !errors.Is(err, errMailUnreadable) {
		t.Fatalf("unreadable settings: %+v, %v; want errMailUnreadable", p, err)
	}
}

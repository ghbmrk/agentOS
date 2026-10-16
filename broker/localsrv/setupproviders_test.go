package localsrv

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// REQ: CRED-5, CAP-9, CRED-1, ONB-3

// A synthetic key: not one any provider issued.
const canaryKey = "sk-CANARY-localsrv-key-7f3"

// fakeProviders stands in for the vault process's provider ops.
type fakeProviders struct {
	keys    map[string]string
	private map[string]bool
	err     error
	privErr error // SetPrivateOK's answer when set; nothing is recorded
	calls   int
	sets    int // SetPrivateOK calls
	// setHook, when set, runs first in each SetPrivateOK; an error it
	// returns is the answer, and nothing is recorded.
	setHook func(provider string, ok bool) error
	owedLie bool // Providers claims every provider is owed a yes
	plan    bool // Providers also lists "codex", signed in by device code
}

func (f *fakeProviders) Providers() ([]localapi.SetupProvider, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	var out []localapi.SetupProvider
	for _, id := range []string{"anthropic", "openai"} {
		p := localapi.SetupProvider{ID: id, Name: id, APIKey: true, Connected: f.keys[id] != "", PrivateOK: f.private[id]}
		if f.owedLie {
			yes := true
			p.Owed = &yes
		}
		out = append(out, p)
	}
	if f.plan {
		out = append(out, localapi.SetupProvider{ID: "codex", Name: "ChatGPT plan", DeviceCode: true, Connected: f.keys["codex"] != "", PrivateOK: f.private["codex"]})
	}
	return out, nil
}

func (f *fakeProviders) PutAPIKey(provider, key string) error {
	f.calls++
	if f.err != nil {
		return f.err
	}
	if provider != "openai" && provider != "anthropic" {
		return ProviderRefused
	}
	f.keys[provider] = key
	return nil
}

func (f *fakeProviders) SetPrivateOK(provider string, ok bool) error {
	f.calls++
	f.sets++
	if f.setHook != nil {
		if err := f.setHook(provider, ok); err != nil {
			return err
		}
	}
	if f.err != nil {
		return f.err
	}
	if f.privErr != nil {
		return f.privErr
	}
	if provider != "openai" && provider != "anthropic" {
		return ProviderRefused
	}
	f.private[provider] = ok
	return nil
}

func providersRig(t *testing.T) (*setupRig, *fakeProviders) {
	r := newSetupRig(t)
	f := &fakeProviders{keys: map[string]string{}, private: map[string]bool{}}
	r.s.cfg.Providers = f
	return r, f
}

// P2-2w c4e: setup lists the vault's providers, passes a key to the vault
// and records the private-data answer, keeping nothing (CRED-1).
func TestSetupServesTheVaultsProviders(t *testing.T) {
	r, f := providersRig(t)
	var l localapi.SetupProviders
	if err := r.call(localapi.OpSetupProviders, nil, &l); err != nil || len(l.Providers) != 2 || l.Providers[1].Connected {
		t.Fatalf("list %v %+v", err, l)
	}
	if err := r.call(localapi.OpSetupAPIKey, localapi.APIKey{Provider: "openai", Key: canaryKey}, nil); err != nil {
		t.Fatal(err)
	}
	if err := r.call(localapi.OpSetupPrivateOK, localapi.PrivateOK{Provider: "openai", OK: true}, nil); err != nil {
		t.Fatal(err)
	}
	if f.keys["openai"] != canaryKey || !f.private["openai"] {
		t.Fatalf("vault %+v", f)
	}
	if err := r.call(localapi.OpSetupProviders, nil, &l); err != nil || !l.Providers[1].Connected || !l.Providers[1].PrivateOK {
		t.Fatalf("after %v %+v", err, l)
	}
	if strings.Contains(localapi.APIKey{Provider: "openai", Key: canaryKey}.String(), "CANARY") ||
		strings.Contains(localapi.APIKey{Key: canaryKey}.GoString(), "CANARY") {
		t.Fatal("APIKey prints its key")
	}
	r.enrollAndConfirm()
	if err := r.call(localapi.OpSetupFinish, localapi.Finish{Owner: "+15550100100"}, nil); err != nil {
		t.Fatal(err)
	}
	n := f.calls
	for _, c := range []struct {
		op   string
		args any
	}{
		{localapi.OpSetupProviders, nil},
		{localapi.OpSetupAPIKey, localapi.APIKey{Provider: "openai", Key: canaryKey + "2"}},
		{localapi.OpSetupPrivateOK, localapi.PrivateOK{Provider: "openai"}},
	} {
		if err := r.call(c.op, c.args, nil); code(err) != localapi.ErrSetupClosed {
			t.Fatalf("%s after finish: %v", c.op, err)
		}
	}
	if f.calls != n {
		t.Fatal("a closed setup reached the vault")
	}
}

// A key that the proxy could not send is bad args and never reaches the
// vault; the vault's refusals are fixed codes that carry no key.
func TestSetupKeysAreCheckedAndRefusalsFixed(t *testing.T) {
	r, f := providersRig(t)
	for _, k := range []string{"", "sk CANARY", "sk-CANARY\r\nX: 1", "sk-CANARY-\x7f", strings.Repeat("k", localapi.MaxAPIKey+1)} {
		if err := r.call(localapi.OpSetupAPIKey, localapi.APIKey{Provider: "openai", Key: k}, nil); code(err) != localapi.ErrBadArgs {
			t.Fatalf("key %.20q: %v", k, err)
		}
	}
	if err := r.call(localapi.OpSetupAPIKey, localapi.APIKey{Key: canaryKey}, nil); code(err) != localapi.ErrBadArgs {
		t.Fatalf("no provider: %v", err)
	}
	if f.calls != 0 {
		t.Fatal("a malformed key reached the vault")
	}
	if err := r.call(localapi.OpSetupAPIKey, localapi.APIKey{Provider: "other", Key: canaryKey}, nil); code(err) != localapi.ErrBadArgs {
		t.Fatalf("refused: %v", err)
	}
	for _, c := range []struct {
		err  error
		want string
	}{
		{EnrollClosed, localapi.ErrEnrollUnavailable},
		{EnrollNotOpen, localapi.ErrEnrollUnavailable},
		{KeyRefused, localapi.ErrKeyRefused},     // ONB-3: the provider said no
		{KeyUnchecked, localapi.ErrKeyUnchecked}, // the provider could not be asked
		{errors.New("vault: " + canaryKey), localapi.ErrFailed},
	} {
		f.err = c.err
		r.now = r.now.Add(time.Minute)
		err := r.call(localapi.OpSetupAPIKey, localapi.APIKey{Provider: "openai", Key: canaryKey}, nil)
		if code(err) != c.want || strings.Contains(err.Error(), "CANARY") {
			t.Fatalf("%v: %v", c.err, err)
		}
		if err := r.call(localapi.OpSetupProviders, nil, nil); code(err) != c.want {
			t.Fatalf("list %v: %v", c.err, err)
		}
	}
}

// Each key is a vault write: a compromised page cannot have agentosd make
// more than APIKeysPerMinute.
func TestSetupKeysAreBounded(t *testing.T) {
	r, _ := providersRig(t)
	for i := 0; i < localapi.APIKeysPerMinute; i++ {
		if err := r.call(localapi.OpSetupAPIKey, localapi.APIKey{Provider: "openai", Key: canaryKey}, nil); err != nil {
			t.Fatal(i, err)
		}
	}
	if err := r.call(localapi.OpSetupAPIKey, localapi.APIKey{Provider: "openai", Key: canaryKey}, nil); code(err) != localapi.ErrLimited {
		t.Fatalf("over the bound: %v", err)
	}
	r.now = r.now.Add(time.Minute)
	if err := r.call(localapi.OpSetupAPIKey, localapi.APIKey{Provider: "openai", Key: canaryKey}, nil); err != nil {
		t.Fatal(err)
	}
}

// With no vault provider ops configured, setup lists none and refuses
// every key and answer.
func TestSetupWithoutProvidersListsNone(t *testing.T) {
	r := newSetupRig(t)
	var l localapi.SetupProviders
	if err := r.call(localapi.OpSetupProviders, nil, &l); err != nil || len(l.Providers) != 0 {
		t.Fatalf("list %v %+v", err, l)
	}
	if err := r.call(localapi.OpSetupAPIKey, localapi.APIKey{Provider: "openai", Key: canaryKey}, nil); code(err) != localapi.ErrBadArgs {
		t.Fatalf("key: %v", err)
	}
	if err := r.call(localapi.OpSetupPrivateOK, localapi.PrivateOK{Provider: "openai", OK: true}, nil); code(err) != localapi.ErrBadArgs {
		t.Fatalf("private: %v", err)
	}
}

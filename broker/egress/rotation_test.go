package egress

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: CRED-7

// rotatingVault replaces the credential the moment the proxy fetches it,
// so the rotation lands after the request's redactor was built and before
// the key is injected.
type rotatingVault struct {
	*vault.Vault
	t      *testing.T
	name   string
	newKey string
}

func (v *rotatingVault) Secret(name string) (vault.Secret, bool) {
	if name == v.name && v.newKey != "" {
		if err := v.Vault.Put(name, vault.KindAPIKey, []byte(v.newKey)); err != nil {
			v.t.Fatal(err)
		}
	}
	return v.Vault.Secret(name)
}

// CRED-7: a key rotated between the start of a request and its injection
// is still redacted when the provider echoes it back.
func TestRotatedKeyIsRedactedWhenEchoed(t *testing.T) {
	r := newRig(t, nil)
	rv := &rotatingVault{Vault: r.vault, t: t, name: "openai-key", newKey: synthetic(t, "sk-rotated-")}
	p, err := New(Config{
		Adapters:  []Adapter{OpenAI("openai-key")},
		Grants:    map[string][]string{"m1": {"openai"}},
		Vault:     rv,
		Transport: r.transport,
		Audit:     r.audit,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.provider.reply = func(w http.ResponseWriter, req *http.Request) {
		auth := req.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Echo", auth)
		io.WriteString(w, `{"echo":"`+auth+`"}`)
	}
	w := httptest.NewRecorder()
	p.Handler("m1").ServeHTTP(w, chat("/openai/v1/chat/completions"))
	if w.Code != 200 {
		t.Fatalf("got %d", w.Code)
	}
	if got := r.provider.seen[0].Header.Get("Authorization"); got != "Bearer "+rv.newKey {
		t.Fatalf("rotation did not land before injection: %q", got)
	}
	dump := w.Body.String()
	for k, vs := range w.Header() {
		dump += k + ": " + strings.Join(vs, ",") + "\n"
	}
	if strings.Contains(dump, rv.newKey) {
		t.Fatalf("rotated key reached the guest:\n%s", dump)
	}
	if !strings.Contains(w.Body.String(), vault.Placeholder) {
		t.Fatalf("echo not redacted: %q", w.Body.String())
	}
}

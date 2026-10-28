package model_test

// REQ: CLK-3, CLK-14, CLK-1, LOG-7

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/model"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/netguard"
)

type resolver netip.Addr

func (r resolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.Addr(r)}, nil
}

// ledger admits everything, recording the amounts it admits and meters.
type ledger struct{ admitted, metered []int64 }

func (l *ledger) AdmitSpend(_ int64, plan string, amount int64) (kernel.Admitted, *key.Refusal) {
	l.admitted = append(l.admitted, amount)
	return kernel.Admitted{Plan: plan}, nil
}
func (l *ledger) Meter(_ int64, _ kernel.Admitted, _ string, amount int64, _ string) error {
	l.metered = append(l.metered, amount)
	return nil
}
func (*ledger) Hold(int64, string, *key.Refusal) error     { return nil }
func (*ledger) AdmitPool(int64, string) *key.Refusal       { return nil }
func (*ledger) ReadPool(int64, string, int64, int64) error { return nil }

func newSealer(t *testing.T) clerk.Sealer {
	t.Helper()
	k := make([]byte, 32)
	rand.Read(k)
	s, err := clerk.NewAESSealer(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// apiRig is one declared provider on a local TLS server, at one token a
// minor unit, with its key set and allowed private data.
func apiRig(t *testing.T, h http.HandlerFunc, connect func(context.Context, string, string) (net.Conn, error)) (*model.APIs, *model.Clerk, *ledger) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	if connect == nil {
		connect = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
		}
	}
	guard := netguard.New(netguard.Config{Resolver: resolver(netip.MustParseAddr("8.8.8.8")), Connect: connect})
	d := model.Shipped[0]
	d.Host = "api.example.com"
	d.Models = []model.APIModel{{Route: "r", Model: "m", InPerM: 1_000_000, OutPerM: 1_000_000, Context: 5000, MaxOut: 100}}
	a, err := model.NewAPIs([]model.APIDeclaration{d}, model.NewKeys(newSealer(t), nil), guard, roots)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.SetKey(d.Provider, "sk-test-0123456789", true); err != nil {
		t.Fatal(err)
	}
	l := &ledger{}
	return a, &model.Clerk{Routes: a.Prices(), Ledger: l}, l
}

func ok(usage string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"content":[],"usage":%s}`, usage)
	}
}

// The shipped declarations validate, and no declared provider's name or
// host appears in this package's code: the providers are data (CLK-14).
func TestShippedProvidersAreDataNotCode(t *testing.T) {
	if _, err := model.NewAPIs(model.Shipped, model.NewKeys(newSealer(t), nil), netguard.New(netguard.Config{}), nil); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range model.Shipped {
			for _, w := range []string{d.Provider, d.Host} {
				if bytes.Contains(bytes.ToLower(src), []byte(w)) {
					t.Errorf("%s names %q", f, w)
				}
			}
		}
	}
}

// A declaration that would inject the key elsewhere, let the provider act
// for the caller, set a credential header or repeat a route is refused at
// start (CLK-3).
func TestABadDeclarationIsRefused(t *testing.T) {
	for name, edit := range map[string]func(d *model.APIDeclaration){
		"a key header outside the list": func(d *model.APIDeclaration) { d.Header = "X-Goog-Api-Key" },
		"a credential header":           func(d *model.APIDeclaration) { d.Headers = map[string]string{"X-Session-Token": "x"} },
		"a streamed body":               func(d *model.APIDeclaration) { d.Body.Keys = append(d.Body.Keys, "stream") },
		"a server-side tool source":     func(d *model.APIDeclaration) { d.Body.Keys = append(d.Body.Keys, "mcp_servers") },
		"a host with a path":            func(d *model.APIDeclaration) { d.Host = "api.example.com/v1" },
		"an opaque content key":         func(d *model.APIDeclaration) { d.Body.BlockOpaque = map[string][]string{"tool_result": {"content"}} },
		"an opaque source key":          func(d *model.APIDeclaration) { d.Body.ToolOpaque = []string{"source"} },
		"a path with an escape":         func(d *model.APIDeclaration) { d.Ops = []model.APIOp{{Name: "x", Path: "/v1/%2e%2e"}} },
		"a repeated route":              func(d *model.APIDeclaration) { d.Models = append(d.Models, d.Models[0]) },
		"a negative price": func(d *model.APIDeclaration) {
			d.Models = []model.APIModel{{Route: "r", Model: "m", InPerM: -1, Context: 1, MaxOut: 1}}
		},
	} {
		d := model.Shipped[0]
		d.Body.Keys = append([]string(nil), d.Body.Keys...)
		edit(&d)
		if _, err := model.NewAPIs([]model.APIDeclaration{d}, model.NewKeys(newSealer(t), nil), netguard.New(netguard.Config{}), nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The keys are written only sealed, open again only under their sealer, and
// a value that does not open leaves the store empty (CLK-1, STO-2).
func TestTheKeysAreSealedInTheirSlot(t *testing.T) {
	s := newSealer(t)
	var atRest []byte
	keys := model.NewKeys(s, func(b []byte) error { atRest = append([]byte(nil), b...); return nil })
	a, err := model.NewAPIs(model.Shipped, keys, netguard.New(netguard.Config{}), nil)
	if err != nil {
		t.Fatal(err)
	}
	const canary = "sk-test-CANARY-sealed-42"
	if err := a.SetKey(model.Shipped[0].Provider, canary, false); err != nil {
		t.Fatal(err)
	}
	if len(atRest) == 0 || bytes.Contains(atRest, []byte(canary)) {
		t.Fatalf("at rest: %q", atRest)
	}
	if err := a.SetKey("no-such-provider", canary, false); !errors.Is(err, model.ErrKeyForm) {
		t.Fatalf("an undeclared provider: %v", err)
	}
	if err := a.SetKey(model.Shipped[0].Provider, "has space in it", false); !errors.Is(err, model.ErrKeyForm) {
		t.Fatalf("a key out of form: %v", err)
	}
	again := model.NewKeys(s, nil)
	if err := again.Load(atRest); err != nil {
		t.Fatal(err)
	}
	b, _ := model.NewAPIs(model.Shipped, again, netguard.New(netguard.Config{}), nil)
	if st, err := b.State(); err != nil || !st[0].Set || st[0].Private {
		t.Fatalf("reloaded state %+v, %v", st, err)
	}
	other := model.NewKeys(newSealer(t), nil)
	if err := other.Load(atRest); !errors.Is(err, model.ErrKeysOpen) {
		t.Fatalf("another sealer's value: %v", err)
	}
	if blob, _ := other.MarshalBinary(); len(blob) != 0 {
		t.Fatal("a value that does not open was kept")
	}
	if err := a.RemoveKey(model.Shipped[0].Provider); err != nil || len(atRest) != 0 {
		t.Fatalf("removing the last key: %v, %q left", err, atRest)
	}
}

// A call is admitted at its worst case before it is sent: its body's bytes
// and its output cap, or the whole context window when it carries content
// by source, whose tokens its bytes do not bound. Cache writes are metered
// at their declared weight (LOG-7).
func TestAnAPICallIsAdmittedAtItsWorstCase(t *testing.T) {
	a, c, l := apiRig(t, ok(`{"input_tokens":3,"output_tokens":4,"cache_creation_input_tokens":10,"cache_read_input_tokens":1}`), nil)
	plain := []byte(`{"model":"m","max_tokens":20,"messages":[{"role":"user","content":"hi"}]}`)
	if _, err := a.Call(c, 0, "t", "r", "messages", plain); err != nil {
		t.Fatal(err)
	}
	image := []byte(`{"model":"m","max_tokens":20,"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AAAA"}}]}]}`)
	if _, err := a.Call(c, 0, "t", "r", "messages", image); err != nil {
		t.Fatal(err)
	}
	if len(l.admitted) != 2 || l.admitted[0] != int64(len(plain))+20 || l.admitted[1] != 5000+20 {
		t.Fatalf("admitted %v", l.admitted)
	}
	// 3 + 2*10 + 1 in, 4 out.
	if l.metered[0] != 28 || l.metered[1] != 28 {
		t.Fatalf("metered %v, want 28 each", l.metered)
	}
}

// A request refused before it left costs nothing; one cut after it was
// sent is charged the admitted worst case (LOG-7).
func TestAnAPICallIsChargedByWhetherItLeft(t *testing.T) {
	body := []byte(`{"model":"m","max_tokens":20,"messages":[]}`)
	a, c, l := apiRig(t, ok(`{}`), func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("refused") })
	if _, err := a.Call(c, 0, "t", "r", "messages", body); !errors.Is(err, model.ErrNotSent) || len(l.metered) != 1 || l.metered[0] != 0 {
		t.Fatalf("never sent: %v, metered %v", err, l.metered)
	}
	a, c, l = apiRig(t, func(w http.ResponseWriter, _ *http.Request) {
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Close()
	}, nil)
	if _, err := a.Call(c, 0, "t", "r", "messages", body); err == nil || len(l.metered) != 1 || l.metered[0] != l.admitted[0] {
		t.Fatalf("cut after sending: %v, metered %v of %v", err, l.metered, l.admitted)
	}
	// An answer that reports no usage is charged its whole output cap,
	// which its bytes do not bound (#3705 L3 3).
	a, c, l = apiRig(t, ok(`{"output_tokens":1}`), nil)
	if _, err := a.Call(c, 0, "t", "r", "messages", body); err != nil || l.metered[0] != l.admitted[0] {
		t.Fatalf("no usage reported: %v, metered %v of %v", err, l.metered, l.admitted)
	}
}

// A content block's source must be inline, wherever the block sits, but a
// key named source in a tool's input schema or a tool call's arguments is
// the caller's own data, not a source (#3705 UX 6).
func TestOnlyContentBlocksHaveSources(t *testing.T) {
	a, c, _ := apiRig(t, ok(`{"input_tokens":1,"output_tokens":1}`), nil)
	for name, body := range map[string]string{
		"a tool schema with a source property": `{"model":"m","max_tokens":8,"messages":[],"tools":[{"name":"f","input_schema":{"type":"object","properties":{"source":{"type":"string"}}}}]}`,
		"a tool call whose input has a source": `{"model":"m","max_tokens":8,"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"x","name":"f","input":{"source":{"type":"url","url":"https://x.test"}}}]}]}`,
	} {
		if _, err := a.Call(c, 0, "t", "r", "messages", []byte(body)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Every object's source is checked, and an opaque key is skipped only
	// on its declared parent (#3705 L3 7): never by its name alone.
	for name, body := range map[string]string{
		"an image by address inside a tool result":     `{"model":"m","max_tokens":8,"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"x","content":[{"type":"image","source":{"type":"url","url":"https://x.test/a.png"}}]}]}]}`,
		"a source in an object with no type":           `{"model":"m","max_tokens":8,"messages":[{"role":"user","content":[{"source":{"type":"url","url":"https://x.test"}}]}]}`,
		"an input key on a block that is no tool call": `{"model":"m","max_tokens":8,"messages":[{"role":"user","content":[{"type":"text","text":"x","input":{"type":"image","source":{"type":"url","url":"https://x.test"}}}]}]}`,
		"an input_schema key outside a tools entry":    `{"model":"m","max_tokens":8,"messages":[{"role":"user","content":[{"type":"text","text":"x","input_schema":{"type":"image","source":{"type":"url","url":"https://x.test"}}}]}]}`,
		"a system block by address":                    `{"model":"m","max_tokens":8,"system":[{"type":"image","source":{"type":"url","url":"https://x.test"}}],"messages":[]}`,
		"a stored file inside a document's content":    `{"model":"m","max_tokens":8,"messages":[{"role":"user","content":[{"type":"document","source":{"type":"content","content":[{"type":"image","source":{"type":"file","file_id":"f"}}]}}]}]}`,
		"a tools entry's own source":                   `{"model":"m","max_tokens":8,"messages":[],"tools":[{"name":"f","input_schema":{"type":"object"},"source":{"type":"url","url":"https://x.test"}}]}`,
	} {
		if _, err := a.Call(c, 0, "t", "r", "messages", []byte(body)); err == nil || err.Error() != "model: body source" {
			t.Errorf("%s: %v, want a source refusal", name, err)
		}
	}
}

// An answer under the read bound that its re-encoding grows past it (HTML
// escaping spells each < in six bytes) is refused, not sent on to read as
// lost on the planner's side, and is metered at the usage it reported
// (#3705 L3 8).
func TestAnAnswerGrownPastTheBoundIsRefused(t *testing.T) {
	a, c, l := apiRig(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"t":"%s","usage":{"input_tokens":2,"output_tokens":3}}`, strings.Repeat("<", 1<<20))
	}, nil)
	_, err := a.Call(c, 0, "t", "r", "messages", []byte(`{"model":"m","max_tokens":8,"messages":[]}`))
	if err == nil || err.Error() != "model: "+model.DAnswer || len(l.metered) != 1 || l.metered[0] != 5 {
		t.Fatalf("a grown answer: %v, metered %v", err, l.metered)
	}
}

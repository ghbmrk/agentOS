package model

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/netguard"
)

// API-key routes (MIG-4-exit m1, CLK-7, CLK-3). The model clerk holds each
// provider's API key sealed in its one slot (Keys) and injects it into that
// provider's declared inference operations only. A call names a declared
// operation and carries its JSON body; the clerk holds the body to the
// declaration's schema, sends its own re-encoding with the key added, and
// gives back the answer with the key stripped. The providers are data
// (apikeys.json, CLK-14): no provider is named in this code.

//go:embed apikeys.json
var apiKeysJSON []byte

// Shipped are the built-in providers' declarations.
var Shipped = mustDeclarations(apiKeysJSON)

func mustDeclarations(b []byte) []APIDeclaration {
	d, err := ParseDeclarations(b)
	if err != nil {
		panic(err)
	}
	return d
}

// ParseDeclarations reads a JSON list of declarations, refusing unknown
// fields.
func ParseDeclarations(b []byte) ([]APIDeclaration, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var d []APIDeclaration
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("model: declarations: %w", err)
	}
	return d, nil
}

// APIDeclaration is one provider's API-key route (CLK-3): its one host, the
// header the key goes in, fixed headers, its inference operations, the
// shape of their body, where the answer states its usage, and the models
// it serves, each a route with its price, context window and output limit.
type APIDeclaration struct {
	Provider string            `json:"provider"`
	Version  string            `json:"version"`
	Host     string            `json:"host"`
	Header   string            `json:"header"`
	Prefix   string            `json:"prefix,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Ops      []APIOp           `json:"ops"`
	Body     APIBody           `json:"body"`
	// UsageIn and UsageOut are the answer's token counts: each field's
	// value, times its weight, summed. A field not Optional that is
	// missing makes the answer report no usage.
	UsageIn  []UsageField `json:"usage_in"`
	UsageOut []UsageField `json:"usage_out"`
	// Unbilled are the statuses the provider does not bill a call for.
	// Any other answer that is not 2xx is charged the admitted worst case.
	Unbilled []int      `json:"unbilled"`
	Models   []APIModel `json:"models"`
}

// APIOp is one declared inference operation: always a POST of JSON.
type APIOp struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// APIBody is the operations' request shape: the top-level keys a body may
// carry and those it must; the key naming the model, which must be the
// route's; the key bounding output tokens; the key listing tools, whose
// "type" must be one of ToolTypes ("" for none given), so only tools the
// caller runs itself are declared; and the types a content "source" may
// have, so the provider never fetches an address or a stored file.
type APIBody struct {
	Keys        []string `json:"keys"`
	Required    []string `json:"required"`
	ModelKey    string   `json:"model_key"`
	MaxOutKey   string   `json:"max_out_key"`
	ToolsKey    string   `json:"tools_key,omitempty"`
	ToolTypes   []string `json:"tool_types,omitempty"`
	SourceTypes []string `json:"source_types"`
	OpaqueKeys  []string `json:"opaque_keys,omitempty"`
}

// UsageField is one usage figure in an answer, by its path of object keys.
type UsageField struct {
	Path     []string `json:"path"`
	Weight   int64    `json:"weight"`
	Optional bool     `json:"optional,omitempty"`
}

// APIModel is one route: a model of the provider, its price in minor units
// per million tokens, its context window and its most output tokens.
type APIModel struct {
	Route   string `json:"route"`
	Model   string `json:"model"`
	InPerM  int64  `json:"in_per_m"`
	OutPerM int64  `json:"out_per_m"`
	Context int64  `json:"context"`
	MaxOut  int64  `json:"max_out"`
}

// APIError is a call's typed refusal or failure. Its detail is a fixed code,
// then "http N" or a rule's name; never a value, so nothing in it needs
// redacting (CLK-4).
type APIError struct{ Detail string }

func (e *APIError) Error() string { return "model: " + e.Detail }

// API details.
const (
	DUndeclared = "undeclared" // no such route or operation; nothing sent
	DPrivate    = "private"    // a private call on a route not allowed private data; nothing sent
	DNoKey      = "nokey"      // no key is set for the route's provider; nothing sent
	DBody       = "body"       // the body is out of its declared shape; then the rule. Nothing sent
	DUpstream   = "upstream"   // the provider answered other than 2xx; then "http N"
	DAnswer     = "answer"     // the answer was too large, encoded or not JSON
)

// Body rules, after DBody.
const (
	ruleJSON   = "json"
	ruleKey    = "key"
	ruleModel  = "model"
	ruleMaxOut = "max-out"
	ruleTool   = "tool"
	ruleSource = "source"
	ruleDepth  = "depth"
	ruleSize   = "size"
)

const (
	// The model socket carries a call and an answer of at most 4 MiB
	// each (kernel/proc), so a body or an answer past these never crosses.
	maxBody   = 4 << 20 // a call's body
	maxAnswer = 3 << 20 // an answer read
	maxKey    = 512
	maxDepth  = 64
	callFor   = 10 * time.Minute
)

var (
	nameRE   = regexp.MustCompile(`\A[a-z0-9][a-z0-9.-]{0,63}\z`)
	hostRE   = regexp.MustCompile(`\A[a-z0-9.-]+(?::[0-9]{1,5})?\z`)
	pathRE   = regexp.MustCompile(`\A(?:/[A-Za-z0-9._-]+)+\z`)
	headerRE = regexp.MustCompile(`\A[A-Z][A-Za-z0-9-]{0,63}\z`)
	// A key is printable ASCII with no space, quote or backslash, so the
	// clerk's own JSON encoding of an answer spells it unescaped.
	keyRE = regexp.MustCompile(`\A[\x21\x23-\x5b\x5d-\x7e]{8,512}\z`)
)

// keyHeaders may carry the key; none is a header remotes commonly log.
var keyHeaders = []string{"Authorization", "X-Api-Key"}

// hostedKeys are top-level keys no body may declare: they have the provider
// act for the caller (server tools, stored prompts, background runs) or
// stream an answer this clerk meters whole.
var hostedKeys = []string{"stream", "background", "prompt", "conversation", "previous_response_id", "mcp_servers", "container", "web_search_options"}

// forbiddenHeader names a header a declaration may not set: the clerk's
// own, framing, or one whose name says it carries a credential.
func forbiddenHeader(h string) bool {
	l := strings.ToLower(h)
	if l == "host" || strings.HasPrefix(l, "content-") || l == "accept-encoding" || l == "connection" || l == "transfer-encoding" {
		return true
	}
	for _, w := range []string{"auth", "key", "token", "session", "cookie", "secret", "password", "beta"} {
		if strings.Contains(l, w) {
			return true
		}
	}
	return false
}

func (d *APIDeclaration) validate() error {
	switch {
	case !nameRE.MatchString(d.Provider) || d.Version == "":
		return fmt.Errorf("model: provider %q needs a name and a version", d.Provider)
	case !hostRE.MatchString(d.Host):
		return fmt.Errorf("model: %s: host %q", d.Provider, d.Host)
	case !slices.Contains(keyHeaders, d.Header):
		return fmt.Errorf("model: %s: the key's header %q", d.Provider, d.Header)
	case len(d.Ops) == 0 || len(d.Models) == 0 || len(d.UsageIn) == 0 || len(d.UsageOut) == 0:
		return fmt.Errorf("model: %s: needs operations, models and usage fields", d.Provider)
	}
	for h, v := range d.Headers {
		if !headerRE.MatchString(h) || forbiddenHeader(h) || h == d.Header || strings.ContainsAny(v, "\r\n") {
			return fmt.Errorf("model: %s: header %q", d.Provider, h)
		}
	}
	for _, op := range d.Ops {
		if !nameRE.MatchString(op.Name) || !pathRE.MatchString(op.Path) {
			return fmt.Errorf("model: %s: operation %q", d.Provider, op.Name)
		}
	}
	b := d.Body
	if b.ModelKey == "" || b.MaxOutKey == "" || len(b.SourceTypes) == 0 {
		return fmt.Errorf("model: %s: the body names its model and output keys and source types", d.Provider)
	}
	for _, k := range append([]string{b.ModelKey, b.MaxOutKey}, b.Required...) {
		if !slices.Contains(b.Keys, k) {
			return fmt.Errorf("model: %s: body key %q is not declared", d.Provider, k)
		}
	}
	if b.ToolsKey != "" && (!slices.Contains(b.Keys, b.ToolsKey) || len(b.ToolTypes) == 0) {
		return fmt.Errorf("model: %s: the tools key needs its types", d.Provider)
	}
	for _, k := range b.Keys {
		if slices.Contains(hostedKeys, k) {
			return fmt.Errorf("model: %s: body key %q has the provider act for the caller", d.Provider, k)
		}
	}
	for _, f := range append(slices.Clone(d.UsageIn), d.UsageOut...) {
		if len(f.Path) == 0 || f.Weight <= 0 {
			return fmt.Errorf("model: %s: a usage field needs a path and a positive weight", d.Provider)
		}
	}
	for _, m := range d.Models {
		if !nameRE.MatchString(m.Route) || m.Model == "" || m.InPerM < 0 || m.OutPerM < 0 || m.Context <= 0 || m.MaxOut <= 0 {
			return fmt.Errorf("model: %s: route %q", d.Provider, m.Route)
		}
	}
	return nil
}

// apiRoute is one route and its provider.
type apiRoute struct {
	d *APIDeclaration
	m APIModel
}

// APIs is the model clerk's API-key routes over its sealed keys.
type APIs struct {
	decls  map[string]*APIDeclaration
	routes map[string]apiRoute
	keys   *Keys
	client *http.Client
	// Log, if set, receives one fixed line per refusal that names a rule,
	// never a value (CLK-3: anything undeclared is refused and logged).
	Log func(string)
}

// NewAPIs validates the declarations; a bad one is an error, never a
// runtime surprise. Route names are unique across providers. Every dial
// goes through guard; roots nil trusts the system's authorities.
func NewAPIs(decls []APIDeclaration, keys *Keys, guard *netguard.Policy, roots *x509.CertPool) (*APIs, error) {
	if guard == nil || keys == nil {
		return nil, errors.New("model: API routes need a guard and a key store")
	}
	a := &APIs{decls: map[string]*APIDeclaration{}, routes: map[string]apiRoute{}, keys: keys, client: guarded(guard, roots)}
	for i := range decls {
		d := &decls[i]
		if err := d.validate(); err != nil {
			return nil, err
		}
		if a.decls[d.Provider] != nil {
			return nil, fmt.Errorf("model: provider %q declared twice", d.Provider)
		}
		a.decls[d.Provider] = d
		for _, m := range d.Models {
			if _, dup := a.routes[m.Route]; dup {
				return nil, fmt.Errorf("model: route %q declared twice", m.Route)
			}
			a.routes[m.Route] = apiRoute{d, m}
		}
	}
	return a, nil
}

// guarded is the transport this clerk owns: no proxy from the environment,
// no cookie jar, no redirects, no compression (the answer is redacted as
// plain bytes), and every dial through the guard. It is package clerk's
// own, repeated as clerk/plan repeats it, so no line is added to the
// trusted core.
func guarded(guard *netguard.Policy, roots *x509.CertPool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         guard.DialContext,
			TLSClientConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: 10 * time.Second,
			ForceAttemptHTTP2:   true,
			DisableCompression:  true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Prices are the routes' prices, for the clerk's Routes.
func (a *APIs) Prices() map[string]Price {
	p := map[string]Price{}
	for r, ar := range a.routes {
		p[r] = Price{InPerM: ar.m.InPerM, OutPerM: ar.m.OutPerM}
	}
	return p
}

func (a *APIs) refuse(detail string) error {
	if a.Log != nil {
		a.Log("agentos-clerk-model: refused an API call: " + detail)
	}
	return &APIError{detail}
}

// Call runs one API call for plan on route: op names the declared operation
// and body is its JSON. Every call is private (PLN-3: unlabelled data is
// private, and no label the clerk can check comes with a call yet), so a
// route whose key the owner did not allow private data refuses every call.
// It is admitted on c at its worst case (the
// body's bytes, or the context window if it carries content whose tokens
// its bytes do not bound, plus its declared output cap) before anything is
// sent, and settled with what the answer reported.
func (a *APIs) Call(c *Clerk, now int64, plan, route, op string, body []byte) ([]byte, error) {
	ar, ok := a.routes[route]
	if !ok || !slices.ContainsFunc(ar.d.Ops, func(o APIOp) bool { return o.Name == op }) {
		return nil, a.refuse(DUndeclared)
	}
	var path string
	for _, o := range ar.d.Ops {
		if o.Name == op {
			path = o.Path
		}
	}
	checked, in, maxOut, rule := ar.check(body)
	if rule != "" {
		return nil, a.refuse(DBody + " " + rule)
	}
	var reply []byte
	var u Usage
	var callErr error
	err := a.keys.use(ar.d.Provider, func(key []byte, private bool) error {
		if !private {
			return a.refuse(DPrivate)
		}
		adm, err := c.Admit(now, plan, route, in, maxOut)
		if err != nil {
			return err
		}
		reply, u, callErr = a.send(ar, path, checked, key)
		// An answer with no usage figure is charged its whole output cap:
		// its bytes bound nothing (thinking is billed past what is shown,
		// and some scripts run under four bytes a token).
		if merr := adm.Settle(now, u, maxOut, callErr); merr != nil {
			reply = nil
			return errors.Join(callErr, merr)
		}
		return callErr
	})
	if errors.Is(err, errNoKey) {
		return nil, a.refuse(DNoKey)
	}
	if err != nil {
		return nil, err
	}
	return reply, nil
}

// check holds body to the route's declared shape and returns the clerk's
// own encoding of it, its input bound and its output cap, or the rule it
// broke.
func (ar apiRoute) check(body []byte) ([]byte, int64, int64, string) {
	if len(body) > maxBody {
		return nil, 0, 0, ruleSize
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil || obj == nil {
		return nil, 0, 0, ruleJSON
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, 0, 0, ruleJSON
	}
	b := ar.d.Body
	for k := range obj {
		if !slices.Contains(b.Keys, k) {
			return nil, 0, 0, ruleKey
		}
	}
	for _, k := range b.Required {
		if _, ok := obj[k]; !ok {
			return nil, 0, 0, ruleKey
		}
	}
	if obj[b.ModelKey] != ar.m.Model {
		return nil, 0, 0, ruleModel
	}
	n, ok := obj[b.MaxOutKey].(json.Number)
	maxOut, err := strconv.ParseInt(string(n), 10, 64)
	if !ok || err != nil || maxOut <= 0 || maxOut > ar.m.MaxOut {
		return nil, 0, 0, ruleMaxOut
	}
	if b.ToolsKey != "" {
		if v, ok := obj[b.ToolsKey]; ok {
			tools, ok := v.([]any)
			if !ok {
				return nil, 0, 0, ruleTool
			}
			for _, t := range tools {
				tm, ok := t.(map[string]any)
				if !ok {
					return nil, 0, 0, ruleTool
				}
				typ, has := tm["type"]
				s, isStr := typ.(string)
				if has && !isStr || !slices.Contains(b.ToolTypes, s) {
					return nil, 0, 0, ruleTool
				}
			}
		}
	}
	sourced, rule := sources(obj, b.SourceTypes, b.OpaqueKeys, 0)
	if rule != "" {
		return nil, 0, 0, rule
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if enc.Encode(obj) != nil {
		return nil, 0, 0, ruleJSON
	}
	checked := bytes.TrimSuffix(out.Bytes(), []byte("\n"))
	// A token is at least one byte of the text it encodes, so the body's
	// bytes bound its input; content by source (an image, a document) is
	// bounded only by the context window.
	in := min(int64(len(checked)), ar.m.Context)
	if sourced {
		in = ar.m.Context
	}
	return checked, in, maxOut, ""
}

// sources walks v for content blocks: an object with a string "type" is
// one, and its "source", if any, must be an object of a declared type. The
// values under an opaque key (a tool's input schema, a tool call's
// arguments) are the caller's own data, which the provider fetches nothing
// for, so they are not walked. It reports whether any source was seen.
func sources(v any, types, opaque []string, depth int) (bool, string) {
	if depth > maxDepth {
		return false, ruleDepth
	}
	seen := false
	switch v := v.(type) {
	case map[string]any:
		if _, block := v["type"].(string); block {
			if s, ok := v["source"]; ok {
				sm, ok := s.(map[string]any)
				t, _ := sm["type"].(string)
				if !ok || !slices.Contains(types, t) {
					return false, ruleSource
				}
				seen = true
			}
		}
		for k, e := range v {
			if slices.Contains(opaque, k) {
				continue
			}
			s, rule := sources(e, types, opaque, depth+1)
			if rule != "" {
				return false, rule
			}
			seen = seen || s
		}
	case []any:
		for _, e := range v {
			s, rule := sources(e, types, opaque, depth+1)
			if rule != "" {
				return false, rule
			}
			seen = seen || s
		}
	}
	return seen, ""
}

// send makes the one request with the key added and reads the answer,
// redacted. An error before the request's headers were written is
// ErrNotSent.
func (a *APIs) send(ar apiRoute, path string, body, key []byte) ([]byte, Usage, error) {
	ctx, cancel := context.WithTimeout(context.Background(), callFor)
	defer cancel()
	var wrote bool
	var mu sync.Mutex
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{WroteHeaders: func() { mu.Lock(); wrote = true; mu.Unlock() }})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+ar.d.Host+path, bytes.NewReader(body))
	if err != nil {
		return nil, Usage{}, ErrNotSent
	}
	for h, v := range ar.d.Headers {
		req.Header.Set(h, v)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set(ar.d.Header, ar.d.Prefix+string(key))
	resp, err := a.client.Do(req)
	if err != nil {
		mu.Lock()
		sent := wrote
		mu.Unlock()
		if !sent {
			return nil, Usage{}, ErrNotSent
		}
		return nil, Usage{}, &APIError{DUpstream}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, maxAnswer))
		e := &APIError{DUpstream + " http " + strconv.Itoa(resp.StatusCode)}
		if slices.Contains(ar.d.Unbilled, resp.StatusCode) {
			return nil, Usage{Reported: true}, e
		}
		return nil, Usage{}, e
	}
	if ce := resp.Header.Get("Content-Encoding"); ce != "" && ce != "identity" {
		return nil, Usage{}, &APIError{DAnswer}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil || len(raw) > maxAnswer {
		return nil, Usage{}, &APIError{DAnswer}
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if dec.Decode(&v) != nil {
		return nil, Usage{}, &APIError{DAnswer}
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, Usage{}, &APIError{DAnswer}
	}
	// The answer crosses as the clerk's own encoding of what it decoded,
	// so no escape in the provider's text can spell the key past Redact.
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if enc.Encode(v) != nil {
		return nil, Usage{}, &APIError{DAnswer}
	}
	reply := Redact(bytes.TrimSuffix(out.Bytes(), []byte("\n")), key)
	return reply, ar.d.usage(v), nil
}

// usage is the answer's reported usage, or none if a required figure is
// missing or unusable.
func (d *APIDeclaration) usage(v any) Usage {
	in, ok1 := sum(v, d.UsageIn)
	out, ok2 := sum(v, d.UsageOut)
	if !ok1 || !ok2 {
		return Usage{}
	}
	return Usage{In: in, Out: out, Reported: true}
}

func sum(v any, fields []UsageField) (int64, bool) {
	var total int64
	for _, f := range fields {
		cur := v
		for _, k := range f.Path {
			m, ok := cur.(map[string]any)
			if !ok {
				cur = nil
				break
			}
			cur = m[k]
		}
		if cur == nil && f.Optional {
			continue
		}
		n, ok := cur.(json.Number)
		x, err := strconv.ParseInt(string(n), 10, 64)
		if !ok || err != nil || x < 0 {
			return 0, false
		}
		w, err := mul(x, f.Weight)
		if err != nil || total > (1<<62)-w {
			return 0, false
		}
		total += w
	}
	return total, true
}

// redacted stands in for the key wherever an answer carries it.
var redacted = []byte("[redacted]")

// Redact replaces key and its plain encodings (base64 in its four forms,
// hex in both cases) in b. It returns b, changed in place or replaced.
func Redact(b, key []byte) []byte {
	if len(key) == 0 {
		return b
	}
	forms := [][]byte{key}
	for _, e := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		forms = append(forms, []byte(e.EncodeToString(key)))
	}
	h := hex.EncodeToString(key)
	forms = append(forms, []byte(h), []byte(strings.ToUpper(h)))
	for _, f := range forms {
		if bytes.Contains(b, f) {
			b = bytes.ReplaceAll(b, f, redacted)
		}
	}
	return b
}

// KeyState is one provider's key as the owner's page shows it: whether a
// key is set and whether its routes may see private data (PLN-3). The key
// itself never leaves the clerk (CLK-1).
type KeyState struct {
	Provider string `json:"provider"`
	Set      bool   `json:"set"`
	Private  bool   `json:"private"`
}

// State lists every declared provider's key.
func (a *APIs) State() ([]KeyState, error) {
	set, err := a.keys.state()
	if err != nil {
		return nil, err
	}
	var out []KeyState
	for p := range a.decls {
		e, ok := set[p]
		out = append(out, KeyState{Provider: p, Set: ok, Private: ok && e})
	}
	slices.SortFunc(out, func(x, y KeyState) int { return strings.Compare(x.Provider, y.Provider) })
	return out, nil
}

// ErrKeyForm is a key that is not a declared provider's or not of a key's
// form: printable ASCII with no space, quote or backslash, 8 to 512 bytes.
var ErrKeyForm = errors.New("model: not a declared provider, or not a key's form")

// SetKey stores provider's key and whether its routes may see private
// data, replacing any.
func (a *APIs) SetKey(provider, key string, private bool) error {
	if a.decls[provider] == nil || !keyRE.MatchString(key) {
		return ErrKeyForm
	}
	return a.keys.set(provider, key, private)
}

// SetPrivate changes only the private-data label of a set key.
func (a *APIs) SetPrivate(provider string, private bool) error {
	if a.decls[provider] == nil {
		return ErrKeyForm
	}
	return a.keys.label(provider, private)
}

// RemoveKey removes provider's key; removing none is no error.
func (a *APIs) RemoveKey(provider string) error {
	if a.decls[provider] == nil {
		return ErrKeyForm
	}
	return a.keys.remove(provider)
}

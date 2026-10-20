package clerk

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Op is one declared request shape (CLK-3): the only HTTPS request a verb may
// become. The host and path are fixed here; a step's arguments fill only the
// {name} slots, each escaped as one path segment.
type Op struct {
	Verb    key.Verb
	Method  string
	URL     string   // https, fixed host, path may hold {arg} slots; none in scheme or host
	Slot    string   // secret slot sent with the request; "" sends none
	Header  string   // header that carries the secret; Authorization if empty
	Prefix  string   // text before the secret in that header, e.g. "Bearer "
	Body    string   // argument sent as the request body; "" sends none
	Content string   // content class the clerk reads this op as (KEY-2)
	Labels  []string // flow labels it reads the data as
}

// Exit is a clerk whose steps leave the box as HTTPS requests. It re-checks
// every step with Check, sends only a declared shape, adds the secret itself,
// and keeps the secret out of every answer it gives (CLK-1..4, KRN-8).
type Exit struct {
	name    string
	owner   ed25519.PublicKey
	ops     map[key.Verb]Op
	secrets *Secrets
	client  *http.Client

	mu    sync.Mutex
	state map[string]string // idem -> "done" | "unknown"
}

var slotRE = regexp.MustCompile(`\{([a-z][a-z-]*)\}`)

// NewExit validates every declaration; a bad one is an error, never a
// runtime surprise.
func NewExit(name string, owner ed25519.PublicKey, ops []Op, secrets *Secrets, client *http.Client) (*Exit, error) {
	x := &Exit{name: name, owner: owner, ops: map[key.Verb]Op{}, secrets: secrets, state: map[string]string{}}
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	x.client = &c
	for _, op := range ops {
		if err := x.declare(op); err != nil {
			return nil, err
		}
		x.ops[op.Verb] = op
	}
	return x, nil
}

func (x *Exit) declare(op Op) error {
	if !key.Valid(op.Verb) {
		return fmt.Errorf("clerk: %q is not a verb", op.Verb)
	}
	if _, dup := x.ops[op.Verb]; dup {
		return fmt.Errorf("clerk: verb %s declared twice", op.Verb)
	}
	if op.Method == "" || strings.ContainsAny(op.Method, " \t\r\n") {
		return errors.New("clerk: bad method")
	}
	u, err := url.Parse(op.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" {
		return errors.New("clerk: an op needs a plain https URL")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(u.Host, "{}") {
		return errors.New("clerk: slots belong in the path only")
	}
	names := key.ArgNames(op.Verb)
	have := func(n string) bool { return slices.Contains(names, n) }
	for _, seg := range strings.Split(u.Path, "/") {
		if !strings.ContainsAny(seg, "{}") {
			continue
		}
		m := slotRE.FindStringSubmatch(seg)
		if m == nil || m[0] != seg {
			return errors.New("clerk: a slot must be a whole path segment")
		}
		if !have(m[1]) {
			return fmt.Errorf("clerk: %s has no argument %q", op.Verb, m[1])
		}
	}
	if op.Body != "" && !have(op.Body) {
		return fmt.Errorf("clerk: %s has no argument %q", op.Verb, op.Body)
	}
	if op.Slot != "" && !x.secrets.Has(op.Slot) {
		return fmt.Errorf("clerk: no secret slot %q", op.Slot)
	}
	return nil
}

// Facts is the clerk's own reading of a step (KEY-2): the content and labels
// its declaration gives, and the amount argument if the verb has one.
func (x *Exit) Facts(s key.Step) (string, []string, int64) {
	op, ok := x.ops[s.Verb]
	if !ok {
		return "", nil, 0
	}
	var amount int64
	if a, ok := s.Args[key.ArgAmount]; ok {
		n, err := strconv.ParseInt(a.Value, 10, 64)
		if err != nil {
			n = -1
		}
		amount = n
	}
	return op.Content, op.Labels, amount
}

func (x *Exit) Do(r kernel.Request, v kernel.View) kernel.Result {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.state[r.Idem] == "done" {
		return kernel.Result{Outcome: "ok", Detail: "already done"}
	}
	op, ok := x.ops[r.Step.Verb]
	if !ok {
		return kernel.Result{Outcome: "failed", Detail: "undeclared"}
	}
	if rf := Check(x.owner, x.name, x.Facts, r, v); rf != nil {
		return kernel.Result{Outcome: "failed", Detail: rf.Code}
	}
	req, err := x.build(op, r)
	if err != nil {
		return kernel.Result{Outcome: "failed", Detail: err.Error()}
	}
	send := func(secret []byte) kernel.Result {
		if secret != nil {
			h := op.Header
			if h == "" {
				h = "Authorization"
			}
			req.Header.Set(h, op.Prefix+string(secret))
		}
		return x.send(req, r.Idem, secret)
	}
	if op.Slot == "" {
		return send(nil)
	}
	var res kernel.Result
	if err := x.secrets.with(op.Slot, func(s []byte) error { res = send(s); return nil }); err != nil {
		return kernel.Result{Outcome: "failed", Detail: "secret"}
	}
	return res
}

func (x *Exit) build(op Op, r kernel.Request) (*http.Request, error) {
	// Check has already matched the arguments to the declaration exactly.
	args := r.Step.Args
	var bad bool
	target := slotRE.ReplaceAllStringFunc(op.URL, func(m string) string {
		v := args[m[1:len(m)-1]].Value
		if v == "" || v == "." || v == ".." || strings.Contains(v, "/") {
			bad = true
		}
		return url.PathEscape(v)
	})
	if bad {
		return nil, errors.New("argument cannot fill a path segment")
	}
	var body io.Reader
	if op.Body != "" {
		body = strings.NewReader(args[op.Body].Value)
	}
	req, err := http.NewRequest(op.Method, target, body)
	if err != nil {
		return nil, errors.New("bad request")
	}
	req.Header.Set("Idempotency-Key", r.Idem)
	return req, nil
}

// send performs the one request and classifies the answer. A 2xx is done;
// a 4xx or a redirect was refused, so nothing happened; a 5xx, a 408 or no
// answer may have acted, so it is unknown and a probe decides (KRN-8).
func (x *Exit) send(req *http.Request, idem string, secret []byte) kernel.Result {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := x.client.Do(req.WithContext(ctx))
	if err != nil {
		x.state[idem] = "unknown"
		return kernel.Result{Outcome: "unknown", Detail: redact("no answer: "+err.Error(), secret)}
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	switch c := resp.StatusCode; {
	case c >= 200 && c < 300:
		x.state[idem] = "done"
		return kernel.Result{Outcome: "ok", Detail: "http " + strconv.Itoa(c)}
	case c == 408 || c >= 500:
		x.state[idem] = "unknown"
		return kernel.Result{Outcome: "unknown", Detail: "http " + strconv.Itoa(c)}
	default:
		return kernel.Result{Outcome: "failed", Detail: "http " + strconv.Itoa(c)}
	}
}

func (x *Exit) Probe(r kernel.Request, _ kernel.View) string {
	x.mu.Lock()
	defer x.mu.Unlock()
	// Never "notdone": after a restart this memory is empty, and the kernel
	// marks every in-flight step unknown, so a clerk that cannot say the step
	// was never sent must not invite a resend (KRN-8).
	if x.state[r.Idem] == "done" {
		return "done"
	}
	return "unknown"
}

// redact removes the secret, raw and URL-escaped, from text that may be
// logged (CLK-4).
func redact(s string, secret []byte) string {
	if len(secret) == 0 {
		return s
	}
	for _, p := range []string{string(secret), url.PathEscape(string(secret)), url.QueryEscape(string(secret))} {
		s = strings.ReplaceAll(s, p, "[redacted]")
	}
	return s
}

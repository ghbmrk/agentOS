package clerk

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/ghbmrk/agentos/broker/netguard"
)

// Call is one declared request an API clerk makes on its own account
// (CLK-3), named rather than keyed by a verb: the clerk's own code calls it,
// after its own check of the step it serves (Check) or for its own reads, and
// reads the answer. Op is the request's shape, as for an exit; its Verb,
// Idempotent, Content and Labels are a step's and stay empty.
type Call struct {
	Name string
	// Args names the values the call takes: each fills one path slot, query
	// parameter or body field, and a call is made only with exactly these.
	Args []string
	Op
	// Lists names JSON body fields sent as a one-element array of their
	// argument, as an API that takes label lists needs.
	Lists []string
	// Max is the most of an answer's body the clerk reads, in bytes; a longer
	// answer comes back as DTooLarge with no body.
	Max int64
}

// APIDeclaration describes one API clerk: its name, the only calls it may
// make, the home-network policy every dial goes through (DEV-2), and, as for
// an exit, an OAuth token endpoint and the clerk's clock.
type APIDeclaration struct {
	Name    string
	Calls   []Call
	Guard   *netguard.Policy
	Refresh string
	Clock   Clock
}

// Answer is what came back for one call: the status and the body, with the
// secret the clerk sent replaced by redacted (CLK-4).
type Answer struct {
	Status int
	Body   []byte
}

// DTooLarge: the answer passed the call's Max; its body was not kept.
const DTooLarge = "toolarge"

// redacted stands in for the clerk's secret wherever an answer carries it.
var redacted = []byte("[redacted]")

// API is a clerk whose own code reads and acts on one account over that
// account's declared HTTPS calls; the mail clerk over Gmail is the first.
// Where an Exit turns a kernel step into one request, an API is called by a
// clerk that has already checked its step, and hands back the answer's body,
// bounded, for the clerk to read. The rest is the exit's: a call not declared
// does not exist, a value fills only its one place, the secret is added here
// and never returned, and every dial goes through the guard.
type API struct {
	conn
	calls map[string]decl
}

// NewAPI validates the declaration as NewExit does; roots nil trusts the
// system's certificate authorities.
func NewAPI(d APIDeclaration, secrets *Secrets, roots *x509.CertPool) (*API, error) {
	if d.Name == "" {
		return nil, errors.New("clerk: a declaration needs a name")
	}
	if d.Guard == nil {
		return nil, errors.New("clerk: a declaration needs the home-network policy (DEV-2)")
	}
	a := &API{calls: map[string]decl{}}
	a.name, a.secrets, a.clock = d.Name, secrets, d.Clock
	slot := ""
	for _, c := range d.Calls {
		if c.Name == "" {
			return nil, errors.New("clerk: a call needs a name")
		}
		if _, dup := a.calls[c.Name]; dup {
			return nil, fmt.Errorf("clerk: call %s declared twice", c.Name)
		}
		if c.Verb != "" || c.Idempotent || c.Content != "" || len(c.Labels) > 0 {
			return nil, fmt.Errorf("clerk: call %s is named, not a step", c.Name)
		}
		if c.Max <= 0 {
			return nil, fmt.Errorf("clerk: call %s needs a bound on its answer", c.Name)
		}
		o, err := shape(c.Op, c.Name, c.Args, secrets)
		if err != nil {
			return nil, err
		}
		for _, f := range c.Lists {
			if c.Type != TypeJSON || c.Body[f] == "" {
				return nil, fmt.Errorf("clerk: call %s lists %q, which is not a JSON body field", c.Name, f)
			}
		}
		o.names, o.lists, o.max = slices.Clone(c.Args), slices.Clone(c.Lists), c.Max
		if c.Slot != "" {
			slot = c.Slot
		}
		a.calls[c.Name] = o
	}
	if err := a.open(d.Guard, d.Refresh, slot, roots); err != nil {
		return nil, err
	}
	return a, nil
}

// Call makes the declared call with exactly its arguments and returns the
// answer. A detail instead means no answer is in hand: the call is not
// declared or an argument does not fit (nothing sent), the credential did not
// open or the address is refused (nothing sent), no answer came (the remote
// may have acted), or the answer passed Max. A 401 acted on nothing, so with
// a refresh grant the clerk redeems a new token once and calls again; any
// other status is the caller's to read.
func (a *API) Call(ctx context.Context, name string, args map[string]string) (Answer, string) {
	c, ok := a.calls[name]
	if !ok {
		return Answer{}, DUndeclared
	}
	if len(args) != len(c.names) {
		return Answer{}, DArg
	}
	for _, n := range c.names {
		if _, ok := args[n]; !ok {
			return Answer{}, DArg + " " + n
		}
	}
	req, bad := c.request(args)
	if bad != "" {
		return Answer{}, bad
	}
	if c.Slot == "" {
		return a.do(ctx, c, req, nil)
	}
	if a.refresh == "" {
		var ans Answer
		if err := a.secrets.with(c.Slot, KindStatic, func(s []byte) error {
			req.Header.Set(c.header, c.Prefix+string(s))
			ans, bad = a.do(ctx, c, req, s)
			return nil
		}); err != nil {
			return Answer{}, DCredential
		}
		return ans, bad
	}
	tok, bad := a.access(a.clock.Now(), "")
	if bad != "" {
		return Answer{}, bad
	}
	req.Header.Set(c.header, c.Prefix+tok)
	ans, bad := a.do(ctx, c, req, []byte(tok))
	if bad != "" || ans.Status != http.StatusUnauthorized {
		return ans, bad
	}
	if tok, bad = a.access(a.clock.Now(), tok); bad != "" {
		return Answer{}, bad
	}
	if req, bad = c.request(args); bad != "" {
		return Answer{}, bad
	}
	req.Header.Set(c.header, c.Prefix+tok)
	return a.do(ctx, c, req, []byte(tok))
}

// RedactToken replaces the clerk's live access token in b, for a body the caller
// decoded from an answer (a provider's base64 message), where Call's own
// redaction could not see it. It returns b, changed in place or replaced.
func (a *API) RedactToken(b []byte) []byte {
	a.tmu.Lock()
	tok := a.token
	a.tmu.Unlock()
	if tok == "" {
		return b
	}
	return bytes.ReplaceAll(b, []byte(tok), redacted)
}

// do sends the one request and reads at most Max of the answer, with the
// secret sent, if any, redacted from it.
func (a *API) do(ctx context.Context, c decl, req *http.Request, secret []byte) (Answer, string) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := a.client.Do(req.WithContext(ctx))
	if err != nil {
		if errors.Is(err, netguard.ErrDenied) {
			return Answer{}, DBlocked
		}
		return Answer{}, DNoAnswer + " " + req.URL.Hostname()
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, c.max+1))
	if err != nil {
		return Answer{}, DNoAnswer + " " + req.URL.Hostname()
	}
	if int64(len(b)) > c.max {
		return Answer{Status: resp.StatusCode}, DTooLarge
	}
	if len(secret) > 0 {
		b = bytes.ReplaceAll(b, secret, redacted)
	}
	return Answer{Status: resp.StatusCode, Body: b}, ""
}

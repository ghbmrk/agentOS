package egress

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"
)

// A broker-held plan route (CRED-5) passes the CLI's own token refresh
// through the proxy. The provider answers it with fresh credentials, which
// must never reach the CLI (CRED-1): the proxy swaps each one for a
// placeholder and hands the real value to the Swapper (the vault side).
// It can swap only what it can find, so it forwards an exchange's response
// only in the exact shape the declaration gives, and drops anything else
// (CRED-5t trigger a). A response the declaration names as the provider
// refusing the login (trigger b) is not forwarded either. Both stop the
// route: further requests on the adapter are denied without reaching the
// provider, and the owner is told once (Config.RouteFailed). A refused
// login reopens when the owner resumes it (Resume); an unswappable one
// stays fallen back until a release requalifies the declaration.

// MaxExchangeResponse caps a credential exchange's response, in bytes.
const MaxExchangeResponse = 64 << 10

// maxText caps a FieldText value, and maxNumber a FieldNumber's digits,
// in bytes, so neither can carry a credential-sized value.
const (
	maxText   = 256
	maxNumber = 20
)

// Reasons a route stops. They are fixed text: the journal coalesces on
// them and the owner's notice is built from them.
const (
	ReasonUnswappable  = "credential exchange answered in an undeclared shape; dropped"
	ReasonLoginRefused = "provider refused the login"
)

type exchangeHooks struct {
	swapper     Swapper
	routeFailed func(adapter, reason string)
}

// Swapper holds credentials a provider issues through a broker-held route
// (CRED-5). Swap receives every credential of one response, keyed by field,
// and stores none of them: it returns the placeholder the CLI holds in
// place of each, and a commit that stores them all or none. The proxy
// checks the placeholders before it commits, so a refresh is never stored
// in part (a new access token beside an old refresh token). An error from
// either drops the response.
type Swapper interface {
	Swap(adapter string, creds map[string]string) (placeholders map[string]string, commit func() error, err error)
}

// ResponseRule declares the exact response of a credential exchange: a
// JSON object with these top-level fields and no others (ADP-10).
type ResponseRule struct {
	Fields []Field
}

// Field is one declared top-level field of an exchange response.
type Field struct {
	Name string
	Kind FieldKind
	// Pattern must match a FieldText value whole (it is anchored). It is
	// the declaration's statement that the value is not a credential, so
	// it should admit only the provider's fixed words.
	Pattern string
	// Optional fields may be absent; present ones are always checked.
	Optional bool

	re *regexp.Regexp
}

// FieldKind is what a declared field may hold.
type FieldKind string

const (
	// FieldCredential is a non-empty string the proxy swaps.
	FieldCredential FieldKind = "credential"
	// FieldNumber is a JSON number of at most 20 characters.
	FieldNumber FieldKind = "number"
	// FieldBool is a JSON boolean.
	FieldBool FieldKind = "bool"
	// FieldText is a string of at most 256 bytes matching Pattern.
	FieldText FieldKind = "text"
)

func (r *ResponseRule) compile() error {
	if len(r.Fields) == 0 {
		return errors.New("response rule declares no fields")
	}
	seen := map[string]bool{}
	cred := false
	for i := range r.Fields {
		f := &r.Fields[i]
		if f.Name == "" || seen[f.Name] {
			return fmt.Errorf("response field %q is unnamed or repeated", f.Name)
		}
		seen[f.Name] = true
		switch f.Kind {
		case FieldCredential, FieldNumber, FieldBool:
			if f.Pattern != "" {
				return fmt.Errorf("response field %s: only text takes a pattern", f.Name)
			}
			cred = cred || f.Kind == FieldCredential
		case FieldText:
			re, err := regexp.Compile(`\A(?:` + f.Pattern + `)\z`)
			if f.Pattern == "" || err != nil {
				return fmt.Errorf("response field %s: text needs a valid pattern", f.Name)
			}
			f.re = re
		default:
			return fmt.Errorf("response field %s: kind %q", f.Name, f.Kind)
		}
	}
	if !cred {
		return errors.New("response rule swaps no credential")
	}
	return nil
}

// swap checks resp against the rule and returns the body to forward, with
// every credential swapped, and the commit that stores them. Nothing is
// staged unless the whole response matches, and nothing is stored until
// the caller commits.
func (r *ResponseRule) swap(resp *http.Response, adapter string, sw Swapper) ([]byte, func() error, error) {
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return nil, nil, errors.New("not JSON")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxExchangeResponse+1))
	if err != nil || len(body) > MaxExchangeResponse {
		return nil, nil, errors.New("unreadable or too large")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil || obj == nil {
		return nil, nil, errors.New("not a JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, nil, errors.New("trailing data")
	}
	declared := map[string]*Field{}
	for i := range r.Fields {
		f := &r.Fields[i]
		declared[f.Name] = f
		if _, ok := obj[f.Name]; !ok && !f.Optional {
			return nil, nil, errors.New("declared field missing")
		}
	}
	creds := map[string]string{}
	for k, v := range obj {
		f, ok := declared[k]
		if !ok {
			return nil, nil, errors.New("undeclared field")
		}
		if !f.admits(v) {
			return nil, nil, errors.New("field out of shape")
		}
		if f.Kind == FieldCredential {
			creds[k] = v.(string)
		}
	}
	if len(creds) == 0 {
		return nil, nil, errors.New("no credential issued")
	}
	phs, commit, err := sw.Swap(adapter, creds)
	if err != nil || commit == nil || len(phs) != len(creds) {
		return nil, nil, errors.New("swap failed")
	}
	for k := range creds {
		ph := phs[k]
		if ph == "" {
			return nil, nil, errors.New("no placeholder")
		}
		for _, v := range creds {
			if strings.Contains(ph, v) {
				return nil, nil, errors.New("placeholder carries a credential")
			}
		}
		obj[k] = ph
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(obj); err != nil {
		return nil, nil, err
	}
	return out.Bytes(), commit, nil
}

func (f *Field) admits(v any) bool {
	switch f.Kind {
	case FieldCredential:
		s, ok := v.(string)
		return ok && s != ""
	case FieldNumber:
		n, ok := v.(json.Number)
		return ok && len(n) <= maxNumber
	case FieldBool:
		_, ok := v.(bool)
		return ok
	case FieldText:
		s, ok := v.(string)
		return ok && len(s) <= maxText && f.re.MatchString(s)
	}
	return false
}

// refused reports whether status is one the operation declares as the
// provider refusing the login.
func (op Operation) refused(status int) bool {
	for _, s := range op.Refused {
		if s == status {
			return true
		}
	}
	return false
}

// The causes a route stop records in RouteStops: codes, where the Reason
// constants are the text the owner and the journal's denials read.
const (
	StopLoginRefused = "login-refused"
	StopUnswappable  = "unswappable"
)

// RouteStops is the durable record of stopped routes (the journal's
// StopRoute, ReopenRoute and RouteStopped, OP-11). A route stopped twice
// keeps its cause, unless the second outranks it: every cause outranks
// StopLoginRefused (CRED-RS-4). ReopenRoute lifts a stop only while it has
// the cause named, and fails otherwise (CRED-RS-5).
type RouteStops interface {
	StopRoute(route, cause string) error
	ReopenRoute(route, cause string) error
	RouteStopped(route string) (cause string, stopped bool)
}

// memStops keeps route stops for a proxy with no Config.Stops.
type memStops map[string]string

func (m memStops) StopRoute(route, cause string) error {
	if cur, ok := m[route]; !ok || cur == StopLoginRefused {
		m[route] = cause
	}
	return nil
}

func (m memStops) ReopenRoute(route, cause string) error {
	if cur, ok := m[route]; ok && cur != cause {
		return fmt.Errorf("egress: %s is stopped for %s, not %s", route, cur, cause)
	}
	delete(m, route)
	return nil
}

func (m memStops) RouteStopped(route string) (string, bool) {
	c, ok := m[route]
	return c, ok
}

func stopCause(reason string) string {
	if reason == ReasonLoginRefused {
		return StopLoginRefused
	}
	return StopUnswappable
}

// stopReason is a recorded cause's Reason. A cause this proxy does not
// know is held as unswappable: only a release lifts it.
func stopReason(cause string) string {
	if cause == StopLoginRefused {
		return ReasonLoginRefused
	}
	return ReasonUnswappable
}

// stopped returns why adapter's route is stopped, if it is.
func (p *Proxy) stopped(adapter string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stoppedLocked(adapter)
}

// stoppedLocked is the higher of the recorded stop and the one held here
// (CRED-RS-4).
func (p *Proxy) stoppedLocked(adapter string) (string, bool) {
	r, ok := "", false
	if c, stored := p.stops.RouteStopped(adapter); stored {
		r, ok = stopReason(c), true
	}
	if h, held := p.held[adapter]; held && (!ok || r == ReasonLoginRefused) {
		r, ok = h, true
	}
	return r, ok
}

// stop stops adapter's route and tells the owner, once per stop; an
// unswappable stop raises a refused login's, and the owner is told again,
// since signing in no longer helps (CRED-RS-4). A stop the store cannot
// record is held in this proxy (fail closed).
func (p *Proxy) stop(adapter, reason string) {
	p.mu.Lock()
	cur, already := p.stoppedLocked(adapter)
	raise := !already || (cur == ReasonLoginRefused && reason != ReasonLoginRefused)
	if raise {
		if err := p.stops.StopRoute(adapter, stopCause(reason)); err != nil {
			p.held[adapter] = reason
		}
	}
	p.mu.Unlock()
	if raise {
		p.xch.routeFailed(adapter, reason)
	}
}

// ErrRequalify is Resume's answer for a route stopped by an unswappable
// response: only a release that requalifies the declaration reopens it
// (Requalify).
var ErrRequalify = errors.New("egress: route stays fallen back until a release requalifies it")

// Resume is the owner's path back to a route the provider refused the login
// on, once the owner has signed in again. Its caller authenticates the
// owner (CH-10). It does not reopen a route stopped by an unswappable
// response (ErrRequalify), nor one whose reopening the store cannot
// record.
func (p *Proxy) Resume(adapter string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if r, ok := p.stoppedLocked(adapter); ok && r != ReasonLoginRefused {
		return ErrRequalify
	}
	return p.reopen(adapter, StopLoginRefused)
}

// Requalify reopens adapter's route whatever stopped it: the release
// that requalified its declaration calls it (CRED-5t).
func (p *Proxy) Requalify(adapter string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	c, _ := p.stops.RouteStopped(adapter)
	return p.reopen(adapter, c)
}

// reopen lifts adapter's stop if it is recorded for cause; the store
// refuses one recorded for another (CRED-RS-5). mu must be held.
func (p *Proxy) reopen(adapter, cause string) error {
	if _, ok := p.stops.RouteStopped(adapter); ok {
		if err := p.stops.ReopenRoute(adapter, cause); err != nil {
			return fmt.Errorf("egress: route stays stopped: %w", err)
		}
	}
	delete(p.held, adapter)
	return nil
}

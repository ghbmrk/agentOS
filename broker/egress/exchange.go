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
// provider until Resume, and the owner is told once (Config.RouteFailed).

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
// (CRED-5). Swap stores value as the adapter's credential named field and
// returns the placeholder the CLI holds in its place. An error drops the
// response.
type Swapper interface {
	Swap(adapter, field, value string) (placeholder string, err error)
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
// every credential swapped. Nothing is swapped unless the whole response
// matches.
func (r *ResponseRule) swap(resp *http.Response, adapter string, sw Swapper) ([]byte, error) {
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return nil, errors.New("not JSON")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxExchangeResponse+1))
	if err != nil || len(body) > MaxExchangeResponse {
		return nil, errors.New("unreadable or too large")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil || obj == nil {
		return nil, errors.New("not a JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data")
	}
	declared := map[string]*Field{}
	for i := range r.Fields {
		f := &r.Fields[i]
		declared[f.Name] = f
		if _, ok := obj[f.Name]; !ok && !f.Optional {
			return nil, errors.New("declared field missing")
		}
	}
	for k, v := range obj {
		f, ok := declared[k]
		if !ok {
			return nil, errors.New("undeclared field")
		}
		if !f.admits(v) {
			return nil, errors.New("field out of shape")
		}
	}
	for _, f := range r.Fields {
		v, ok := obj[f.Name].(string)
		if f.Kind != FieldCredential || !ok {
			continue
		}
		ph, err := sw.Swap(adapter, f.Name, v)
		if err != nil {
			return nil, errors.New("swap failed")
		}
		if ph == "" || strings.Contains(ph, v) {
			return nil, errors.New("placeholder carries the credential")
		}
		obj[f.Name] = ph
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(obj); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
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

// stopped returns why adapter's route is stopped, if it is.
func (p *Proxy) stopped(adapter string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	r, ok := p.stops[adapter]
	return r, ok
}

// stop stops adapter's route and tells the owner, once per stop.
func (p *Proxy) stop(adapter, reason string) {
	p.mu.Lock()
	_, already := p.stops[adapter]
	if !already {
		p.stops[adapter] = reason
	}
	p.mu.Unlock()
	if !already {
		p.xch.routeFailed(adapter, reason)
	}
}

// Resume reopens a route stopped by an unswappable or refused response,
// once the owner has fixed it (signed in again, or a release requalified
// the CLI).
func (p *Proxy) Resume(adapter string) {
	p.mu.Lock()
	delete(p.stops, adapter)
	p.mu.Unlock()
}

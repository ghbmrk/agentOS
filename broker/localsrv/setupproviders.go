package localsrv

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// Providers is the vault process's provider setup (P2-2w c4e; CRED-5,
// CAP-9), served only while the vault's setup enrollment is open (egress
// K17). Its refusals are ProviderRefused, EnrollClosed and EnrollNotOpen.
type Providers interface {
	Providers() ([]localapi.SetupProvider, error)
	// PutAPIKey stores key in the vault under the provider's credential.
	PutAPIKey(provider, key string) error
	// SetPrivateOK records whether the provider may see private data.
	SetPrivateOK(provider string, ok bool) error
}

// ProviderRefused: the vault refused the provider or the key (400).
var ProviderRefused = errors.New("provider refused")

// KeyRefused: the provider did not accept the key when the vault checked
// it (ONB-3). KeyUnchecked: the vault could not check it. Neither stored
// the key.
var (
	KeyRefused   = errors.New("key refused by the provider")
	KeyUnchecked = errors.New("key not checked with the provider")
)

var (
	errKeyRefused   = sockets.Code(localapi.ErrKeyRefused)
	errKeyUnchecked = sockets.Code(localapi.ErrKeyUnchecked)
)

// providers lists the vault's providers; nil Providers lists none.
func (s *Setup) providers(_ context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	if err := decode(args, &struct{}{}); err != nil {
		return nil, err
	}
	if s.cfg.Providers == nil {
		return localapi.SetupProviders{Providers: []localapi.SetupProvider{}}, nil
	}
	ps, err := s.cfg.Providers.Providers()
	if err != nil {
		return nil, s.providerErr(err)
	}
	if ps == nil {
		ps = []localapi.SetupProvider{}
	}
	s.mu.Lock()
	for i := range ps {
		ps[i].Owed = nil // only the record says what is owed
		if ok, owed := s.rec.Owed[ps[i].ID]; owed {
			ps[i].Owed = &ok
		}
	}
	s.mu.Unlock()
	return localapi.SetupProviders{Providers: ps}, nil
}

// apiKey passes one key to the vault and keeps nothing (CRED-1): not the
// record, not an error, not a log. The shape is checked before the
// limit, so a malformed key never reaches the vault.
func (s *Setup) apiKey(_ context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var a localapi.APIKey
	if err := decode(args, &a); err != nil {
		return nil, err
	}
	if a.Provider == "" || !keyShaped(a.Key) {
		return nil, errBadArgs
	}
	if !s.allow(&s.keys, localapi.APIKeysPerMinute) {
		return nil, errLimited
	}
	if s.cfg.Providers == nil {
		return nil, errBadArgs
	}
	if err := s.cfg.Providers.PutAPIKey(a.Provider, a.Key); err != nil {
		return nil, s.providerErr(err)
	}
	return struct{}{}, nil
}

// privateOK records the owner's private-data answer for a provider the
// vault lists (CAP-9). The answer is owed in the setup record before the
// vault is asked anything, even its list, and cleared once the vault
// records it (#1544), so a vault that is down or locked, a failure, or a
// restart of the page or of agentosd at any point leaves finish waiting
// for the answer: a record that cannot take the answer asks the vault
// nothing, a list that fails keeps it owed, and a clear that cannot be
// written answers failed with the answer still owed. A provider the vault
// does not list is owed nothing, and finish counts only listed ones, so a
// stray id cannot hold setup open for good. A sealed vault (EnrollClosed)
// lists nothing and takes nothing, so the answer is not owed (#1623).
func (s *Setup) privateOK(_ context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var a localapi.PrivateOK
	if err := decode(args, &a); err != nil {
		return nil, err
	}
	if !providerShaped(a.Provider) || s.cfg.Providers == nil {
		return nil, errBadArgs
	}
	s.answer.Lock()
	defer s.answer.Unlock()
	s.mu.Lock()
	before, wasOwed := s.rec.Owed[a.Provider]
	if !wasOwed && len(s.rec.Owed) >= maxOwed {
		s.mu.Unlock()
		return nil, errLimited
	}
	err := s.setOwedLocked(a.Provider, &a.OK)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	// restore puts back what was owed before: the vault took nothing. A
	// restore that cannot be written leaves this answer owed, which still
	// holds finish.
	restore := func() {
		prev := &before
		if !wasOwed {
			prev = nil
		}
		s.mu.Lock()
		s.setOwedLocked(a.Provider, prev)
		s.mu.Unlock()
	}
	ps, err := s.cfg.Providers.Providers()
	if errors.Is(err, EnrollClosed) {
		restore()
	}
	if err != nil {
		return nil, s.providerErr(err)
	}
	if !listed(ps, a.Provider) {
		restore()
		return nil, errBadArgs
	}
	if err := s.cfg.Providers.SetPrivateOK(a.Provider, a.OK); err != nil {
		if errors.Is(err, ProviderRefused) {
			restore()
		}
		return nil, s.providerErr(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.setOwedLocked(a.Provider, nil); err != nil {
		return nil, err
	}
	return struct{}{}, nil
}

// owedListedLocked is whether the record owes an answer for a provider
// the vault lists. A list that fails counts as owing: finish cannot tell.
// A sealed vault (EnrollClosed) lists nothing, so nothing is owed: it
// sealed only through a finish that found nothing owed, takes no answer
// since, and would otherwise hold setup open for good after a seal whose
// finished record failed to save (#1623). Caller holds s.mu.
func (s *Setup) owedListedLocked() bool {
	if len(s.rec.Owed) == 0 || s.cfg.Providers == nil {
		return false
	}
	ps, err := s.cfg.Providers.Providers()
	if errors.Is(err, EnrollClosed) {
		return false
	}
	if err != nil {
		return true
	}
	for p := range s.rec.Owed {
		if listed(ps, p) {
			return true
		}
	}
	return false
}

func listed(ps []localapi.SetupProvider, id string) bool {
	for _, p := range ps {
		if p.ID == id {
			return true
		}
	}
	return false
}

// maxOwed bounds the providers the record can owe an answer for, so ids
// written while the vault cannot list them cannot grow it without end.
const maxOwed = 16

// providerShaped: 1 to 64 bytes of lower-case letters, digits, '-' and
// '_', the shape of the vault's provider ids.
func providerShaped(p string) bool {
	if p == "" || len(p) > 64 {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// providerErr maps the vault's refusal to a fixed code: a refused
// provider or key is bad args, a key the provider refused or could not
// check has its own code, a vault whose setup is closed cannot take
// providers here, and anything else failed.
func (s *Setup) providerErr(err error) error {
	switch {
	case errors.Is(err, KeyRefused):
		return errKeyRefused
	case errors.Is(err, KeyUnchecked):
		return errKeyUnchecked
	case errors.Is(err, ProviderRefused):
		return errBadArgs
	case errors.Is(err, EnrollClosed), errors.Is(err, EnrollNotOpen):
		return errUnavailable
	}
	return errFailed
}

// keyShaped: 1 to MaxAPIKey bytes of printable ASCII with no space, as
// the proxy sends a key in a header.
func keyShaped(k string) bool {
	if k == "" || len(k) > localapi.MaxAPIKey {
		return false
	}
	for i := 0; i < len(k); i++ {
		if k[i] <= ' ' || k[i] > '~' {
			return false
		}
	}
	return true
}

// setOwedLocked writes provider p's owed answer as *ok, or clears it when
// ok is nil, to the record, and keeps it in memory only once written. A
// closed setup owes nothing more. Caller holds s.mu.
func (s *Setup) setOwedLocked(p string, ok *bool) error {
	if s.closed {
		return errSetupClosed
	}
	next := s.rec
	next.Owed = make(map[string]bool, len(s.rec.Owed)+1)
	for k, v := range s.rec.Owed {
		next.Owed[k] = v
	}
	if ok == nil {
		delete(next.Owed, p)
	} else {
		next.Owed[p] = *ok
	}
	if len(next.Owed) == 0 {
		next.Owed = nil
	}
	if s.cfg.Record.Save(next) != nil {
		return errFailed
	}
	s.rec = next
	return nil
}

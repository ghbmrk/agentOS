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

func (s *Setup) privateOK(_ context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var a localapi.PrivateOK
	if err := decode(args, &a); err != nil {
		return nil, err
	}
	if a.Provider == "" || s.cfg.Providers == nil {
		return nil, errBadArgs
	}
	if err := s.cfg.Providers.SetPrivateOK(a.Provider, a.OK); err != nil {
		return nil, s.providerErr(err)
	}
	return struct{}{}, nil
}

// providerErr maps the vault's refusal to a fixed code: a refused
// provider or key is bad args, a vault whose setup is closed cannot take
// providers here, and anything else failed.
func (s *Setup) providerErr(err error) error {
	switch {
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

package modelroute

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// SetupProvider is one built-in provider as setup's AI step sees it
// (P2-2w c4e; CRED-5, CAP-9): whether the vault holds its API key and the
// owner's private-data answer. It never carries the key.
type SetupProvider struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Connected bool   `json:"connected"`
	PrivateOK bool   `json:"private_ok"`
}

// SetupProviderList is the vault process's answer to GET /setup/providers.
type SetupProviderList struct {
	Providers []SetupProvider `json:"providers"`
}

// SetupKeyRequest stores a provider's API key in the vault at setup. The
// key is reusable authentication material (CRED-1).
type SetupKeyRequest struct {
	Provider string `json:"provider"`
	Key      string `json:"key"`
}

// String and GoString keep the key out of logs.
func (SetupKeyRequest) String() string   { return "[provider API key]" }
func (SetupKeyRequest) GoString() string { return "[provider API key]" }

// SetupPrivateRequest records the owner's private-data answer for one
// provider (CAP-9).
type SetupPrivateRequest struct {
	Provider string `json:"provider"`
	OK       bool   `json:"ok"`
}

// ErrSetupRefused means the vault process refused the request itself: the
// provider is not a built-in adapter, its name is held by another kind of
// entry, or the key is not one the vault stores.
var ErrSetupRefused = errors.New("the vault process refused the provider or key")

// SetupProviders lists the built-in providers. It fails as Enroll does
// when setup's enrollment is not open (ErrEnrolled, ErrEnrollNotOpen) or
// the vault is locked (ErrVaultLocked).
func (v *Verifier) SetupProviders() ([]SetupProvider, error) {
	var res SetupProviderList
	if err := v.setupCall(http.MethodGet, "/setup/providers", nil, &res); err != nil {
		return nil, err
	}
	for _, p := range res.Providers {
		if p.ID == "" || p.Name == "" {
			return nil, errors.New("setup providers: malformed answer")
		}
	}
	return res.Providers, nil
}

// SetupAPIKey stores key as provider's API key in the vault.
func (v *Verifier) SetupAPIKey(provider, key string) error {
	body, _ := json.Marshal(SetupKeyRequest{Provider: provider, Key: key})
	var res struct{}
	return v.setupCall(http.MethodPost, "/setup/providers/key", body, &res)
}

// SetupPrivateOK records whether provider may receive private data.
func (v *Verifier) SetupPrivateOK(provider string, ok bool) error {
	body, _ := json.Marshal(SetupPrivateRequest{Provider: provider, OK: ok})
	var res struct{}
	return v.setupCall(http.MethodPost, "/setup/providers/private", body, &res)
}

func (v *Verifier) setupCall(method, path string, body []byte, res any) error {
	u := url.URL{Scheme: "http", Host: "agentos-egress", Path: path} // over the Unix socket
	req, err := http.NewRequest(method, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusServiceUnavailable:
		return ErrVaultLocked
	case http.StatusGone:
		return ErrEnrolled
	case http.StatusPreconditionFailed:
		return ErrEnrollNotOpen
	case http.StatusBadRequest:
		return ErrSetupRefused
	default:
		return fmt.Errorf("setup providers: vault process answered %s", resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<12)).Decode(res)
}

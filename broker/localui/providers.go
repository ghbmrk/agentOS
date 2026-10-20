package localui

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Providers is the vault process's provider routes on the unlock socket
// (#1266), as the AI providers page uses them; UnlockClient is the real
// one. The page shows and changes each provider's private-data answer
// (CAP-9, CH-3) and never sees a key (CRED-1).
type Providers interface {
	ProviderList(ctx context.Context) ([]ProviderStatus, error)
	// SetProviderPrivate allows (ok, approved with code) or withdraws
	// (no code needed) private data for the provider.
	SetProviderPrivate(ctx context.Context, id string, ok bool, code string) error
	// AddProviderKey stores the provider's API key after setup, approved
	// with code (CH-10). The vault process asks the provider about the key
	// first (ONB-3), so a refused key is stored nowhere.
	AddProviderKey(ctx context.Context, id, key, code string) error
}

// ProviderStatus is one built-in provider as the vault process reports
// it (modelroute.SetupProvider).
// PrivateByConfig: the box's configuration allows it private data, so
// the page cannot withdraw it (#1420).
type ProviderStatus struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Connected       bool   `json:"connected"`
	PrivateOK       bool   `json:"private_ok"`
	PrivateByConfig bool   `json:"private_by_config"`
	// Plan: the ChatGPT plan row, signed in with a login, not a key, so
	// the page draws no add-key form for it.
	Plan bool `json:"plan"`
}

// ProviderList implements Providers.
func (u *UnlockClient) ProviderList(ctx context.Context) ([]ProviderStatus, error) {
	var res struct {
		Providers []ProviderStatus `json:"providers"`
	}
	err := u.do(ctx, http.MethodGet, "/providers", nil, &res)
	return res.Providers, err
}

// SetProviderPrivate implements Providers.
func (u *UnlockClient) SetProviderPrivate(ctx context.Context, id string, ok bool, code string) error {
	return u.do(ctx, http.MethodPost, "/providers/private", struct {
		Provider string `json:"provider"`
		OK       bool   `json:"ok"`
		Code     string `json:"code"`
	}{id, ok, code}, nil)
}

// AddProviderKey implements Providers.
func (u *UnlockClient) AddProviderKey(ctx context.Context, id, key, code string) error {
	return u.do(ctx, http.MethodPost, "/providers/key", struct {
		Provider string `json:"provider"`
		Key      string `json:"key"`
		Code     string `json:"code"`
	}{id, key, code}, nil)
}

// providersView is the AI providers page.
type providersView struct {
	// Locked: the vault is not open; Down: the vault process is not
	// answering.
	Locked, Down bool
	Providers    []ProviderStatus
	// Withdrawing is the provider the page asks about before withdrawing.
	Withdrawing *ProviderStatus
	// NoneAllowed: no connected provider may see private content, so
	// the page says tasks that need it can't run (U-5).
	NoneAllowed bool
	Err         string
	Refresh     string
}

// providers serves the AI providers page behind sign-in (CH-7): the
// owner allows a connected provider private data with a code, or
// withdraws it after a confirmation (#1266; CAP-9, CH-3).
func (s *Server) providers(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	v := providersView{}
	vs, err := s.cfg.Vault.Status(ctx)
	switch {
	case err != nil && !isVaultError(err):
		v.Down, v.Refresh = true, "5"
		s.render(w, "providers", v)
		return
	case err != nil || vs.State != "open":
		v.Locked = true
		s.render(w, "providers", v)
		return
	}
	withdraw := ""
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		id := r.PostForm.Get("provider")
		var err error
		switch r.PostForm.Get("step") {
		case "allow":
			err = s.cfg.Providers.SetProviderPrivate(ctx, id, true, r.PostForm.Get("code"))
		case "addkey":
			err = s.cfg.Providers.AddProviderKey(ctx, id, strings.TrimSpace(r.PostForm.Get("key")), r.PostForm.Get("code"))
		case "withdraw":
			if r.PostForm.Get("confirm") != "1" {
				withdraw = id
				break
			}
			err = s.cfg.Providers.SetProviderPrivate(ctx, id, false, "")
		default:
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		if err == nil && withdraw == "" {
			http.Redirect(w, r, "/providers/", http.StatusSeeOther)
			return
		}
		if err != nil {
			v.Err = "That didn't go through. Try again."
			// Only a code's or a key's refusal carries owner wording
			// (egress errWrongCode, errLockedOut, errNoCodeGenerator,
			// errCodeRequired, errKeyRefused); other reasons are
			// internal. A key the provider could not be asked about
			// (502) is told as that.
			var ve *VaultError
			if errors.As(err, &ve) && ve.Status == http.StatusBadGateway {
				v.Err = "The key couldn't be checked with the provider, so nothing was saved. Try again."
			} else if errors.As(err, &ve) && (ve.Status == http.StatusForbidden || ve.Status == http.StatusTooManyRequests) && ve.Msg != "" {
				v.Err = ve.Msg
			}
		}
	}
	ps, err := s.cfg.Providers.ProviderList(ctx)
	if err != nil {
		// A refusal here is the vault locking since the check above.
		if v.Locked = isVaultError(err); !v.Locked {
			v.Down, v.Refresh = true, "5"
		}
		s.render(w, "providers", v)
		return
	}
	v.Providers, v.NoneAllowed = ps, true
	for i := range ps {
		if ps[i].Connected && ps[i].PrivateOK {
			v.NoneAllowed = false
		}
		if ps[i].ID == withdraw && ps[i].PrivateOK && !ps[i].PrivateByConfig {
			v.Withdrawing = &ps[i]
		}
	}
	s.render(w, "providers", v)
}

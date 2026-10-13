package egress

import (
	"context"
	"errors"
	"io"
	"net/http"
)

// KeyCheck declares how setup checks a pasted key with its provider
// (ONB-3, #1265): GET https://Host + Path with the key injected as the
// adapter's Injection says, plus Headers. Path is literal. A cheap,
// read-only endpoint (a model list) is the intent.
type KeyCheck struct {
	Path    string
	Headers map[string]string
}

// CheckKey's answers. Neither carries the key or the provider's words
// (CRED-1).
var (
	// ErrKeyRefused: the provider answered 401 or 403 to the key.
	ErrKeyRefused = errors.New("egress: the provider did not accept the key")
	// ErrKeyUnchecked: no answer about the key itself: the provider was
	// not reached, answered something else (busy, an outage, a redirect),
	// or the adapter declares no key check.
	ErrKeyUnchecked = errors.New("egress: the key could not be checked with the provider")
)

// CheckKey sends a's key check with key over rt and reports whether the
// provider accepts the key: nil for a 2xx answer. The response body is
// not read past a small bound, and no redirect is followed (rt is a bare
// transport), so the key goes only to https://Host.
func (a Adapter) CheckKey(ctx context.Context, rt http.RoundTripper, key []byte) error {
	kc := a.KeyCheck
	if kc == nil || a.validate() != nil {
		return ErrKeyUnchecked
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+a.Host+kc.Path, nil)
	if err != nil {
		return ErrKeyUnchecked
	}
	for h, v := range kc.Headers {
		req.Header.Set(h, v)
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set(a.Inject.Header, a.Inject.Prefix+string(key))
	resp, err := rt.RoundTrip(req)
	if err != nil {
		return ErrKeyUnchecked
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		return ErrKeyRefused
	}
	return ErrKeyUnchecked
}

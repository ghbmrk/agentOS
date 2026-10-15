package localsrv

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// SignIn starts a provider's device-code sign-in while setup runs (ONB-3,
// CRED-5; c4e2): agentosd's setup-mode provider worker runs the provider's
// own CLI, and the login it gets lands in the vault, never here.
type SignIn interface {
	// Ready reports whether provider's sign-in can start on this box now:
	// the provider declares one and its image is qualified.
	Ready(provider string) bool
	// Start starts provider's sign-in and returns the provider's own device
	// page, the one-time code the owner enters there, and who issued the
	// code. SignInBusy: that provider's last sign-in still waits.
	Start(ctx context.Context, provider string) (link, code, from string, err error)
}

// SignInBusy: the provider's last sign-in still waits for the owner.
var SignInBusy = errors.New("sign-in busy")

var errSignInBusy = sockets.Code(localapi.ErrSignInBusy)

// deviceCodeShaped is the code's shape, as the provider worker checks it.
var deviceCodeShaped = regexp.MustCompile(`\A[A-Z0-9-]{4,16}\z`)

// fromShaped is a provider's name as the page shows it.
var fromShaped = regexp.MustCompile(`\A[A-Za-z0-9][A-Za-z0-9 .-]{0,47}\z`)

// deviceCode starts the owner's plan sign-in for a provider the vault
// lists as signing in by device code and the box can sign in now. It
// relays the page, code and issuer and keeps nothing: not the record, not
// an error, not a log. A link that is not an https page, a code of the
// wrong shape or a nameless issuer answers failed, so the page never
// shows the owner something the provider did not issue.
func (s *Setup) deviceCode(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var a localapi.DeviceCodeStart
	if err := decode(args, &a); err != nil {
		return nil, err
	}
	if !providerShaped(a.Provider) {
		return nil, errBadArgs
	}
	if !s.allow(&s.signins, localapi.DeviceCodesPerMinute) {
		return nil, errLimited
	}
	if s.cfg.Providers == nil || s.cfg.SignIn == nil {
		return nil, errBadArgs
	}
	ps, err := s.cfg.Providers.Providers()
	if err != nil {
		return nil, s.providerErr(err)
	}
	if !signsIn(ps, a.Provider) || !s.cfg.SignIn.Ready(a.Provider) {
		return nil, errBadArgs
	}
	link, code, from, err := s.cfg.SignIn.Start(ctx, a.Provider)
	if errors.Is(err, SignInBusy) {
		return nil, errSignInBusy
	}
	if err != nil {
		return nil, errFailed
	}
	if u, perr := url.Parse(link); perr != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		len(link) > 256 || u.String() != link || !deviceCodeShaped.MatchString(code) || !fromShaped.MatchString(from) {
		return nil, errFailed
	}
	return localapi.DeviceCode{Link: link, Code: code, From: from}, nil
}

func signsIn(ps []localapi.SetupProvider, id string) bool {
	for _, p := range ps {
		if p.ID == id {
			return p.DeviceCode
		}
	}
	return false
}

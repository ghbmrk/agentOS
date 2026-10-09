package localui

import (
	"context"
	"errors"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// AgentosdSetup is Hooks over agentosd's setup ops on localui.sock
// (P2-2w c2; Security L6 on the P2-2w plan). agentosd serves them only
// until setup's finish is recorded and decides what finish needs: a code
// enrollment it saw the vault confirm. The code seed is made in the vault
// process (egress K17) and only passes through this page.
//
// Networks, BoxNumber, HostInfo, Send, TrustHost and the provider hooks
// are not served by agentosd yet: they answer nothing or an error, so the
// steps that need them wait.
type AgentosdSetup struct{ Owner Owner }

var errNotServed = errors.New("localui: not served by agentosd yet")

func (a AgentosdSetup) call(op string, args, out any) error {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	return a.Owner.Call(ctx, op, args, out)
}

// Wait returns once agentosd answers, so that a page started before
// agentosd does not read its silence as setup being closed.
func (a AgentosdSetup) Wait(ctx context.Context, every time.Duration) error {
	for {
		var r Refused
		if err := a.call(localapi.OpSetupProgress, nil, nil); err == nil || errors.As(err, &r) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(every):
		}
	}
}

func (a AgentosdSetup) Progress() Progress {
	var p localapi.SetupProgress
	if a.call(localapi.OpSetupProgress, nil, &p) != nil {
		return Progress{Phase: "booting"}
	}
	switch p.Phase {
	case "booting", "updating", "ready":
	default:
		return Progress{Phase: "booting"}
	}
	return Progress{Phase: p.Phase, Updated: p.Updated, Online: p.Online}
}

func (a AgentosdSetup) EnrollCode() (string, error) {
	var l localapi.EnrollLink
	if err := a.call(localapi.OpSetupEnroll, nil, &l); err != nil {
		return "", enrollErr(err)
	}
	return l.URI, nil
}

func (a AgentosdSetup) ConfirmCode(code string) (bool, error) {
	var c localapi.Confirmed
	if err := a.call(localapi.OpSetupConfirm, localapi.Confirm{Code: code}, &c); err != nil {
		return false, enrollErr(err)
	}
	return c.OK, nil
}

func enrollErr(err error) error {
	switch {
	case refused(err, localapi.ErrEnrolled):
		return ErrCodesEnrolled
	case refused(err, localapi.ErrNoEnrollment):
		return ErrNoCodeEnrollment
	case refused(err, localapi.ErrLimited):
		return ErrCodesLimited
	case refused(err, localapi.ErrEnrollUnavailable):
		return ErrCodesUnavailable
	}
	return err
}

// AlreadySetUp is true unless agentosd answers that setup is open: a
// refusal (setup closed) or no answer keeps setup closed, the safe side.
func (a AgentosdSetup) AlreadySetUp() bool {
	return a.call(localapi.OpSetupProgress, nil, nil) != nil
}

// Finish records the owner's number with agentosd, which closes setup for
// good and starts the owner channel. A vault that cannot finish setup's
// enrollment answers ErrCodesUnavailable.
func (a AgentosdSetup) Finish(owner string) error {
	err := a.call(localapi.OpSetupFinish, localapi.Finish{Owner: owner}, nil)
	if refused(err, localapi.ErrEnrollUnavailable) {
		return ErrCodesUnavailable
	}
	return err
}

func (AgentosdSetup) Networks() []string                 { return nil }
func (AgentosdSetup) JoinNetwork(string, string) error   { return errNotServed }
func (AgentosdSetup) BoxNumber() string                  { return "" }
func (AgentosdSetup) HostInfo() string                   { return "" }
func (AgentosdSetup) Send(string, string) error          { return errNotServed }
func (AgentosdSetup) TrustHost(bool) error               { return errNotServed }
func (AgentosdSetup) Providers() []Provider              { return nil }
func (AgentosdSetup) ConnectAPIKey(string, string) error { return errNotServed }
func (AgentosdSetup) SetPrivateOK(string, bool) error    { return errNotServed }
func (AgentosdSetup) StartDeviceCode(string) (string, string, error) {
	return "", "", errNotServed
}

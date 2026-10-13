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
// JoinNetwork goes through agentosd to its netjoin helper (P2-2w c3;
// Security L8), and Networks asks it for the networks in range (P2-2w
// c4b). Providers, ConnectAPIKey and SetPrivateOK go through agentosd to
// the vault process (P2-2w c4e; CRED-5, CAP-9). BoxNumber, HostInfo, Send,
// TrustHost and StartDeviceCode are not served by agentosd yet: they answer
// nothing or an error, so the steps that need them wait.
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

// Networks is the home networks agentosd's helper sees, or none: an
// error or a list over the bound gives the typed-name step.
func (a AgentosdSetup) Networks() []string {
	var n localapi.Networks
	if a.call(localapi.OpSetupNetworks, nil, &n) != nil || len(n.SSIDs) == 0 || len(n.SSIDs) > localapi.MaxNetworks {
		return nil
	}
	return n.SSIDs
}

func (a AgentosdSetup) Progress() Progress {
	var p localapi.SetupProgress
	if a.call(localapi.OpSetupProgress, nil, &p) != nil {
		return Progress{Phase: "booting"}
	}
	switch p.Phase {
	case "booting", "updating", "offline", "ready":
	default:
		return Progress{Phase: "booting"}
	}
	return Progress{Phase: p.Phase, Updated: p.Updated, Online: p.Online, NeverOnline: p.NeverOnline}
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

// JoinNetwork has agentosd's helper write the home Wi-Fi connection. It
// waits up to localapi.JoinTimeout, longer than agentosd's own call to the
// helper (Security L8.4); any error shows the page's one network error.
func (a AgentosdSetup) JoinNetwork(ssid, password string) error {
	ctx, cancel := context.WithTimeout(context.Background(), localapi.JoinTimeout)
	defer cancel()
	return a.Owner.Call(ctx, localapi.OpSetupJoin, localapi.Join{SSID: ssid, Password: password}, nil)
}

func (AgentosdSetup) BoxNumber() string         { return "" }
func (AgentosdSetup) HostInfo() string          { return "" }
func (AgentosdSetup) Send(string, string) error { return errNotServed }
func (AgentosdSetup) TrustHost(bool) error      { return errNotServed }

// Providers lists the vault's providers. An error lists none, so the AI
// step offers nothing and setup does not finish (ONB-3).
func (a AgentosdSetup) Providers() []Provider {
	var ps localapi.SetupProviders
	if err := a.call(localapi.OpSetupProviders, nil, &ps); err != nil {
		return nil
	}
	out := make([]Provider, 0, len(ps.Providers))
	for _, p := range ps.Providers {
		out = append(out, Provider{ID: p.ID, Name: p.Name, APIKey: p.APIKey, DeviceCode: p.DeviceCode, Connected: p.Connected, PrivateOK: p.PrivateOK})
	}
	return out
}

// ConnectAPIKey passes the key to agentosd, which passes it to the vault
// process; the page keeps nothing (CRED-1, CRED-5).
func (a AgentosdSetup) ConnectAPIKey(id, key string) error {
	return a.call(localapi.OpSetupAPIKey, localapi.APIKey{Provider: id, Key: key}, nil)
}

// SetPrivateOK records the owner's private-data answer in the vault, where
// the router reads it (CAP-9).
func (a AgentosdSetup) SetPrivateOK(id string, ok bool) error {
	return a.call(localapi.OpSetupPrivateOK, localapi.PrivateOK{Provider: id, OK: ok}, nil)
}

func (AgentosdSetup) StartDeviceCode(string) (string, string, error) {
	return "", "", errNotServed
}

// CardFinish is AgentosdSetup with the page's Owner Card step (HW-1,
// #1115): Finish reports a confirmed card to agentosd, whose finish holds
// until it is (card pending); a held card is not reported.
type CardFinish struct {
	AgentosdSetup
	Card interface{ Hold() error }
}

func (c CardFinish) Finish(owner string) error {
	if c.Card != nil && c.Card.Hold() == nil {
		if err := c.call(localapi.OpSetupCard, localapi.SetupCard{Confirmed: true}, nil); err != nil {
			return err
		}
	}
	return c.AgentosdSetup.Finish(owner)
}

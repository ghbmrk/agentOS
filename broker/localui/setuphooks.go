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
// c4b). BoxNumber, Send and PairTexts go through agentosd to the modem
// bridge (P2-2w c4c; §8.1, CH-12): agentosd sends only setup's fixed texts
// and passes on only PAIR texts. HostInfo, TrustHost and the provider
// hooks are not served by agentosd yet: they answer nothing or an error,
// so the steps that need them wait.
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

func (AgentosdSetup) HostInfo() string                   { return "" }
func (AgentosdSetup) TrustHost(bool) error               { return errNotServed }
func (AgentosdSetup) Providers() []Provider              { return nil }
func (AgentosdSetup) ConnectAPIKey(string, string) error { return errNotServed }
func (AgentosdSetup) SetPrivateOK(string, bool) error    { return errNotServed }
func (AgentosdSetup) StartDeviceCode(string) (string, string, error) {
	return "", "", errNotServed
}

// BoxNumber answers whether agentosd's modem line can text, and the box's
// own number when the line reports one; a SIM that texts without
// reporting its number answers "", true.
func (a AgentosdSetup) BoxNumber() (string, bool) {
	var l localapi.SetupLine
	if a.call(localapi.OpSetupLine, nil, &l) != nil || !l.Ready {
		return "", false
	}
	if !phoneRe.MatchString(l.Number) {
		return "", true
	}
	return l.Number, true
}

// Send has agentosd text one of setup's fixed texts. It waits up to
// localapi.SetupSendTimeout, longer than agentosd's own wait for the
// bridge (Security L8.4).
func (a AgentosdSetup) Send(to, text string) error {
	ctx, cancel := context.WithTimeout(context.Background(), localapi.SetupSendTimeout)
	defer cancel()
	return a.Owner.Call(ctx, localapi.OpSetupSend, localapi.SetupSend{To: to, Text: text}, nil)
}

// PairTexts offers each PAIR text that reaches the box to s (OfferText)
// and texts back its reply, until ctx ends or agentosd answers that setup
// is closed (§8.1 pairing). A text that arrives while it is not running is
// not offered again: the owner texts again.
func (a AgentosdSetup) PairTexts(ctx context.Context, s *Server, retry time.Duration) {
	for ctx.Err() == nil {
		var in localapi.SetupInbound
		cctx, cancel := context.WithTimeout(ctx, localapi.SetupInboundWait+callTimeout)
		err := a.Owner.Call(cctx, localapi.OpSetupInbound, nil, &in)
		cancel()
		switch {
		case refused(err, localapi.ErrSetupClosed):
			return
		case err != nil:
			select {
			case <-ctx.Done():
			case <-time.After(retry):
			}
			continue
		case in.From == "":
			continue
		}
		if reply, _ := s.OfferText(in.From, in.Text); reply != "" {
			a.Send(in.From, reply) // a reply that did not go: the page still shows the step
		}
	}
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

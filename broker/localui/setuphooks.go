package localui

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/card"
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
// the vault process (P2-2w c4e; CRED-5, CAP-9). BoxNumber, Send and
// PairTexts go through agentosd to the modem bridge (P2-2w c4c; §8.1,
// CH-12): agentosd sends only setup's fixed texts and passes on only PAIR
// texts. TrustHost goes to the vault process (P2-2w c4d), and HostInfo
// reads the PC's own names. StartDeviceCode goes to agentosd, which runs
// the provider's own CLI sign-in in a provider worker (#1264 c4e2b); the
// login lands in the vault and only the page, code and issuer come back.
type AgentosdSetup struct {
	Owner Owner
	// Vault saves the host step in the vault process; nil: not served.
	Vault HostTrust
	// Root is where HostInfo finds /sys and /proc; "" is "/".
	Root string
}

// HostTrust is the vault process's setup host step (egress /setup/host):
// trusted makes this PC a trusted host, or takes back a slot an earlier
// answer saved. It answers the PC's name, and ErrNoTrustChip on a PC
// without a TPM. UnlockClient is the real one.
type HostTrust interface {
	SetupTrust(ctx context.Context, trusted bool) (string, error)
}

// ErrNoTrustChip: this PC has no TPM, so it cannot be a trusted host;
// setup can go on only with "This is not my PC".
var ErrNoTrustChip = errors.New("this PC has no TPM")

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
// enrollment answers ErrCodesUnavailable, and a private-content answer
// agentosd still owes the vault answers ErrAnswerOwed.
func (a AgentosdSetup) Finish(owner string) error {
	err := a.call(localapi.OpSetupFinish, localapi.Finish{Owner: owner}, nil)
	if refused(err, localapi.ErrEnrollUnavailable) {
		return ErrCodesUnavailable
	}
	if refused(err, localapi.ErrAnswerOwed) {
		return ErrAnswerOwed
	}
	return err
}

// JoinNetwork has agentosd's helper write the home Wi-Fi connection. It
// waits up to localapi.JoinTimeout, longer than agentosd's own call to the
// helper (Security L8.4). A box that cannot join Wi-Fi at all answers
// ErrWiFiUnavailable (#1429); any other error shows the page's one network
// error.
func (a AgentosdSetup) JoinNetwork(ssid, password string) error {
	ctx, cancel := context.WithTimeout(context.Background(), localapi.JoinTimeout)
	defer cancel()
	err := a.Owner.Call(ctx, localapi.OpSetupJoin, localapi.Join{SSID: ssid, Password: password}, nil)
	if refused(err, localapi.ErrJoinUnavailable) {
		return fmt.Errorf("%w (%w)", ErrWiFiUnavailable, err)
	}
	return err
}

// Providers lists the vault's providers, each with the answer agentosd
// holds as owed (#1544). An error lists none, so the AI step offers
// nothing and setup does not finish (ONB-3).
func (a AgentosdSetup) Providers() []Provider {
	var ps localapi.SetupProviders
	if err := a.call(localapi.OpSetupProviders, nil, &ps); err != nil {
		return nil
	}
	out := make([]Provider, 0, len(ps.Providers))
	for _, p := range ps.Providers {
		out = append(out, Provider{ID: p.ID, Name: p.Name, APIKey: p.APIKey, DeviceCode: p.DeviceCode, Connected: p.Connected, PrivateOK: p.PrivateOK, Owed: p.Owed})
	}
	return out
}

// ConnectAPIKey passes the key to agentosd, which passes it to the vault
// process; the page keeps nothing (CRED-1, CRED-5). The vault checks the
// key with its provider first (ONB-3), so the call waits up to
// localapi.APIKeyTimeout, longer than agentosd waits for the vault
// (Security L8.4). Each refusal is named as the page's error, beside the
// code agentosd answered.
func (a AgentosdSetup) ConnectAPIKey(id, key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), localapi.APIKeyTimeout)
	defer cancel()
	err := a.Owner.Call(ctx, localapi.OpSetupAPIKey, localapi.APIKey{Provider: id, Key: key}, nil)
	for code, named := range map[string]error{
		localapi.ErrKeyRefused:        ErrKeyRefused,
		localapi.ErrKeyUnchecked:      ErrKeyUnchecked,
		localapi.ErrLimited:           ErrKeysLimited,
		localapi.ErrBadArgs:           ErrKeyNotTaken,
		localapi.ErrSetupClosed:       ErrSetupClosed,
		localapi.ErrEnrollUnavailable: ErrCodesUnavailable,
	} {
		if refused(err, code) {
			return fmt.Errorf("%w (%w)", named, err)
		}
	}
	return err
}

// SetPrivateOK records the owner's private-data answer in the vault, where
// the router reads it (CAP-9).
func (a AgentosdSetup) SetPrivateOK(id string, ok bool) error {
	return a.call(localapi.OpSetupPrivateOK, localapi.PrivateOK{Provider: id, OK: ok}, nil)
}

// StartDeviceCode starts provider id's plan sign-in through agentosd and
// answers the provider's page, the code and who issued it. It waits up to
// localapi.DeviceCodeTimeout, longer than agentosd waits for the CLI
// (Security L8.4).
func (a AgentosdSetup) StartDeviceCode(id string) (string, string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), localapi.DeviceCodeTimeout)
	defer cancel()
	var d localapi.DeviceCode
	err := a.Owner.Call(ctx, localapi.OpSetupDeviceCode, localapi.DeviceCodeStart{Provider: id}, &d)
	if refused(err, localapi.ErrSignInBusy) {
		return "", "", "", fmt.Errorf("%w (%w)", ErrSignInBusy, err)
	}
	if err != nil {
		return "", "", "", err
	}
	return d.Link, d.Code, d.From, nil
}

// TrustHost saves setup's host step in the vault process, which allows it
// with no code only between the code generator's confirmation and finish
// (§8.1, CRED-9).
func (a AgentosdSetup) TrustHost(trusted bool) error {
	if a.Vault == nil {
		return errNotServed
	}
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	_, err := a.Vault.SetupTrust(ctx, trusted)
	return err
}

// HostInfo names the PC for the pairing reply (§8.1, "I'm running on
// [host, RAM]"): the firmware's vendor and product names (DMI) and the
// RAM the kernel sees, rounded up to whole GB. Both are readable by
// any user and secret to no one, so the page reads them itself.
func (a AgentosdSetup) HostInfo() string {
	root := a.Root
	if root == "" {
		root = "/"
	}
	dmi := func(f string) string {
		b, err := os.ReadFile(filepath.Join(root, "sys/class/dmi/id", f))
		if err != nil {
			return ""
		}
		v := strings.TrimSpace(string(b))
		switch strings.ToLower(v) {
		case "to be filled by o.e.m.", "o.e.m.", "oem", "default string", "system manufacturer", "system product name",
			"system version", "not specified", "not applicable", "type1productconfigid", "none":
			return ""
		}
		return v
	}
	vendor, product := dmi("sys_vendor"), dmi("product_name")
	ram := ""
	if gb := memGB(filepath.Join(root, "proc/meminfo")); gb > 0 {
		ram = ", " + strconv.Itoa(gb) + " GB"
	}
	// The reply cuts the host at hostMax characters; the name gives way so
	// the RAM stays: the vendor goes first, then the product's tail.
	room := hostMax - len(ram)
	name := gsmSafe(product, room)
	if vendor != "" && !strings.HasPrefix(strings.ToLower(product), strings.ToLower(vendor)) {
		if full := gsmSafe(vendor+" "+product, hostMax); len(full) <= room {
			name = full
		} else if name == "" {
			name = gsmSafe(vendor, room)
		}
	}
	switch {
	case ram == "":
		return name
	case name == "":
		return "a PC with" + strings.TrimPrefix(ram, ",")
	}
	return name + ram
}

// memGB is MemTotal in /proc/meminfo rounded up to whole GB, or 0: the
// kernel sees a little less than is fitted (firmware and graphics keep
// some), so rounding up names what was sold.
func memGB(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) != 3 || fs[0] != "MemTotal:" || fs[2] != "kB" {
			continue
		}
		kb, err := strconv.ParseUint(fs[1], 10, 64)
		if err != nil {
			return 0
		}
		return int(math.Ceil(float64(kb) / (1 << 20)))
	}
	return 0
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

// APNet reports the card's Wi-Fi network to agentosd, which writes it for
// agentos-ap to serve at the confirm (#1185). The password goes only
// there (CRED-1).
func (a AgentosdSetup) APNet(ssid, password string) error {
	return a.call(localapi.OpSetupAPNet, localapi.SetupAPNet{SSID: ssid, Password: password}, nil)
}

// NetReporter takes the card's Wi-Fi network; AgentosdSetup is one.
type NetReporter interface {
	APNet(ssid, password string) error
}

// ServeCardNet is the card step's Provision with the card's network
// reported first (#1185): the confirm latches only after both, so
// agentos-ap has the network to switch to when it sees the latch. A
// report that fails fails the provision, and the card stays shown for a
// retry.
func ServeCardNet(provision func(*card.Card) error, a NetReporter) func(*card.Card) error {
	return func(c *card.Card) error {
		if err := a.APNet(c.WiFiName, c.WiFiPassword); err != nil {
			return fmt.Errorf("localui: reporting the card's Wi-Fi: %w", err)
		}
		return provision(c)
	}
}

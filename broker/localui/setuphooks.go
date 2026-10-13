package localui

import (
	"bufio"
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
// Security L8). TrustHost goes to the vault process (P2-2w c4d), and
// HostInfo reads the PC's own names. Networks, BoxNumber, Send and the
// provider hooks are not served by agentosd yet: they answer nothing or an
// error, so the steps that need them wait.
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

func (AgentosdSetup) Networks() []string                 { return nil }
func (AgentosdSetup) BoxNumber() string                  { return "" }
func (AgentosdSetup) Send(string, string) error          { return errNotServed }
func (AgentosdSetup) Providers() []Provider              { return nil }
func (AgentosdSetup) ConnectAPIKey(string, string) error { return errNotServed }
func (AgentosdSetup) SetPrivateOK(string, bool) error    { return errNotServed }
func (AgentosdSetup) StartDeviceCode(string) (string, string, error) {
	return "", "", errNotServed
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
		case "to be filled by o.e.m.", "default string", "system manufacturer", "system product name", "not applicable", "none":
			return ""
		}
		return v
	}
	vendor, product := dmi("sys_vendor"), dmi("product_name")
	name := product
	if vendor != "" && !strings.HasPrefix(strings.ToLower(product), strings.ToLower(vendor)) {
		name = strings.TrimSpace(vendor + " " + product)
	}
	// The reply cuts the host at 40 characters; the name gives way so
	// the RAM stays.
	name = gsmSafe(name, 34)
	gb := memGB(filepath.Join(root, "proc/meminfo"))
	switch {
	case gb == 0:
		return name
	case name == "":
		return "a PC with " + strconv.Itoa(gb) + " GB"
	}
	return name + ", " + strconv.Itoa(gb) + " GB"
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

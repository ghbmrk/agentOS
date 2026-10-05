package secondline_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/modem/at"
	"github.com/ghbmrk/agentos/broker/modem/atsim"
	"github.com/ghbmrk/agentos/broker/modem/secondline"
)

// REQ: ADP-12, DEP-3, CH-1

const (
	boxNum    = "+15550000100" // owner channel (CH-1)
	secondNum = "+15550000200"
	ownerNum  = "+15550000001"
	shopNum   = "+15550000777"
)

type line struct {
	dev *atsim.Device
	m   *at.Modem
}

func open(t *testing.T, c *modem.Carrier, p *at.Profile, model, number string) line {
	t.Helper()
	dev := atsim.New(p, model, c.Line(number), time.Millisecond)
	cfg := at.Config{Profile: p, Port: dev.Port(), Number: number, FramePace: time.Millisecond, Poll: 5 * time.Millisecond}
	if p == at.Quectel {
		dev.SetUAC(true)
		cfg.Audio = at.UACAudio(atsim.Card, dev.Runner())
	} else {
		cfg.Audio = at.SerialAudio(dev.SerialAudio)
	}
	m, err := at.Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return line{dev, m}
}

// disclosure stands in for the rendered "An automated assistant is calling
// for ..." audio: a recognizable non-silent pattern.
func disclosure() []byte {
	b := make([]byte, 3*at.FrameBytes)
	for i := range b {
		b[i] = byte(i*7 + 1)
	}
	return b
}

func roles(owner, second line) secondline.Roles {
	return secondline.Roles{OwnerICCID: owner.dev.ICCID(), SecondICCID: second.dev.ICCID()}
}

func dialed(dev *atsim.Device) []string {
	var out []string
	for _, c := range dev.Commands() {
		if strings.HasPrefix(c, "ATD") {
			out = append(out, c)
		}
	}
	return out
}

func TestWithoutASecondLineTheToolIsUnavailableAndNothingLeavesTheOwnerLine(t *testing.T) {
	c := modem.NewCarrier()
	owner := open(t, c, at.SIMCom, "SIMCOM_SIM7600G-H", boxNum)
	tool, err := secondline.New(secondline.Config{Owner: owner.m})
	if err != nil {
		t.Fatal(err)
	}
	if tool.Available() {
		t.Fatal("available without a second line")
	}
	if err := tool.Text(shopNum, "Table for 2 at 7?"); !errors.Is(err, secondline.ErrUnavailable) {
		t.Fatalf("Text: %v", err)
	}
	if _, err := tool.Call(context.Background(), shopNum); !errors.Is(err, secondline.ErrUnavailable) {
		t.Fatalf("Call: %v", err)
	}
	if _, ok := <-tool.Inbound(); ok {
		t.Fatal("inbound open without a second line")
	}
	time.Sleep(20 * time.Millisecond)
	if n := len(c.Log()); n != 0 || len(dialed(owner.dev)) != 0 {
		t.Fatalf("owner line carried %d texts and dialed %q", n, dialed(owner.dev))
	}
}

func TestThirdPartyTrafficUsesOnlyTheSecondLineAndCallsOpenWithTheDisclosure(t *testing.T) {
	c := modem.NewCarrier()
	shop := c.Line(shopNum)
	owner := open(t, c, at.SIMCom, "SIMCOM_SIM7600G-H", boxNum)
	second := open(t, c, at.Quectel, "EG25", secondNum)
	tool, err := secondline.New(secondline.Config{Owner: owner.m, Second: secondline.FromAT(second.m),
		Roles: roles(owner, second), Disclosure: disclosure(), OwnerPhone: ownerNum, CountryCode: "1"})
	if err != nil {
		t.Fatal(err)
	}
	// Never to the owner's phone or either of the box's numbers, in any format.
	for _, to := range []string{ownerNum, "5550000001", boxNum, secondNum, "1 (555) 000-0200"} {
		if err := tool.Text(to, "Reply with your code"); !errors.Is(err, secondline.ErrRecipient) {
			t.Errorf("Text to %s: %v", to, err)
		}
		if _, err := tool.Call(context.Background(), to); !errors.Is(err, secondline.ErrRecipient) {
			t.Errorf("Call to %s: %v", to, err)
		}
	}
	if err := tool.Text(shopNum, "Table for 2 at 7?"); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-shop.Inbox():
		if m.From != secondNum {
			t.Fatalf("third-party text came from %s", m.From)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no text")
	}

	type res struct {
		call secondline.Call
		err  error
	}
	got := make(chan res, 1)
	go func() {
		call, err := tool.Call(context.Background(), shopNum)
		got <- res{call, err}
	}()
	far := <-second.dev.Outgoing()
	if far.Number != shopNum {
		t.Fatalf("dialed %q", far.Number)
	}
	select {
	case r := <-got:
		t.Fatalf("Call returned before the far end answered: %v", r.err)
	case <-time.After(20 * time.Millisecond):
	}
	far.Answer()
	r := <-got
	if r.err != nil {
		t.Fatal(r.err)
	}
	// The first thing the far end hears is the disclosure, all of it.
	for end := time.Now().Add(time.Second); len(far.Heard()) < len(disclosure()) && time.Now().Before(end); {
		time.Sleep(time.Millisecond)
	}
	if h := far.Heard(); !bytes.HasPrefix(h, disclosure()) {
		t.Fatalf("far end heard %d bytes not starting with the disclosure", len(h))
	}
	if err := r.call.Say(context.Background(), make([]byte, at.FrameBytes)); err != nil {
		t.Fatal(err)
	}
	_ = r.call.Hangup(context.Background())

	for _, m := range c.Log() {
		if m.From == boxNum {
			t.Fatalf("owner line sent %+v", m)
		}
	}
	if d := dialed(owner.dev); len(d) != 0 {
		t.Fatalf("owner line dialed %q", d)
	}
}

func TestInboundOnTheSecondLineIsUntrustedAndNeverReachesTheOwnerChannel(t *testing.T) {
	c := modem.NewCarrier()
	phone := c.Line(ownerNum)
	owner := open(t, c, at.SIMCom, "SIMCOM_SIM7600G-H", boxNum)
	second := open(t, c, at.SIMCom, "SIMCOM_SIM7600G-H", secondNum)
	tool, err := secondline.New(secondline.Config{Owner: owner.m, Second: secondline.FromAT(second.m), Roles: roles(owner, second),
		Disclosure: disclosure(), OwnerPhone: ownerNum, CountryCode: "1"})
	if err != nil {
		t.Fatal(err)
	}
	// A third party's text is data for the agent, even one that reads
	// like a control word.
	c.Inject(shopNum, secondNum, "STOP")
	select {
	case u := <-tool.Inbound():
		if u.From != shopNum || u.Text != "STOP" {
			t.Fatalf("%+v", u)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no inbound")
	}
	// A text from the owner's number, real or forged, reaches no agent and
	// no owner channel; the owner is pointed to the main number once.
	_ = phone.Send(secondNum, "YES K3 482913")
	c.Inject(ownerNum, secondNum, "STOP")
	select {
	case m := <-phone.Inbox():
		if m.From != secondNum || m.Text != secondline.MainNumberText {
			t.Fatalf("owner got %+v", m)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("owner not told")
	}
	select {
	case u := <-tool.Inbound():
		t.Fatalf("agent got %+v", u)
	case m := <-owner.m.Inbox():
		t.Fatalf("owner channel got %+v", m)
	case m := <-phone.Inbox():
		t.Fatalf("second reply %+v", m)
	case <-time.After(60 * time.Millisecond):
	}
}

func TestASecondLineThatIsTheOwnerLineIsRefused(t *testing.T) {
	c := modem.NewCarrier()
	owner := open(t, c, at.SIMCom, "SIMCOM_SIM7600G-H", boxNum)
	if _, err := secondline.New(secondline.Config{Owner: owner.m, Second: secondline.FromAT(owner.m),
		Roles: roles(owner, owner), Disclosure: disclosure()}); !errors.Is(err, secondline.ErrOwnerLine) {
		t.Fatalf("same modem: %v", err)
	}
	// A different modem holding a SIM with the same number (a misconfigured
	// or cloned SIM) is refused too.
	twin := open(t, c, at.Quectel, "EC25", "+1 555 000 0100")
	if _, err := secondline.New(secondline.Config{Owner: owner.m, Second: secondline.FromAT(twin.m),
		Roles: secondline.Roles{OwnerICCID: owner.dev.ICCID(), SecondICCID: "89010000000000000099"}, Disclosure: disclosure()}); err == nil {
		t.Fatal("accepted a twin")
	}
	other := open(t, c, at.Quectel, "EC25", secondNum)
	if _, err := secondline.New(secondline.Config{Owner: owner.m, Second: secondline.FromAT(other.m), Roles: roles(owner, other)}); err == nil {
		t.Fatal("accepted a second line with no disclosure audio")
	}
}

// Roles follow the SIM, not the USB port: modems swapped between ports,
// an unknown SIM, or no owner line all fail closed (ADP-12, CH-1).
func TestRolesAreBoundToTheSIMAndFailClosed(t *testing.T) {
	c := modem.NewCarrier()
	owner := open(t, c, at.SIMCom, "SIMCOM_SIM7600G-H", boxNum)
	second := open(t, c, at.Quectel, "EG25", secondNum)
	set := roles(owner, second)
	cfg := func(o secondline.SIM, s *at.Modem, r secondline.Roles) secondline.Config {
		return secondline.Config{Owner: o, Second: secondline.FromAT(s), Roles: r, Disclosure: disclosure()}
	}
	if _, err := secondline.New(cfg(owner.m, second.m, set)); err != nil {
		t.Fatal(err)
	}
	// The modems came back on each other's ports, so the supervisor opened
	// them in the wrong roles.
	if _, err := secondline.New(cfg(second.m, owner.m, set)); !errors.Is(err, secondline.ErrSwapped) {
		t.Fatalf("swapped: %v", err)
	}
	for name, r := range map[string]secondline.Roles{
		"nothing recorded":      {},
		"owner SIM replaced":    {OwnerICCID: "89019999999999999999", SecondICCID: set.SecondICCID},
		"second SIM unrecorded": {OwnerICCID: set.OwnerICCID},
	} {
		if _, err := secondline.New(cfg(owner.m, second.m, r)); !errors.Is(err, secondline.ErrUnbound) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := secondline.New(cfg(nil, second.m, set)); !errors.Is(err, secondline.ErrUnbound) {
		t.Fatalf("no owner line: %v", err)
	}
	if err := set.Check(owner.m, second.m); err != nil {
		t.Fatalf("Check: %v", err)
	}
}

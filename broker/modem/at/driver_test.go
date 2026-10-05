package at_test

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/modem/at"
	"github.com/ghbmrk/agentos/broker/modem/atsim"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: HW-2, CH-1, CH-5, CH-17

const (
	boxNum   = "+15550000100"
	ownerNum = "+15550000001"
	shopNum  = "+15550000777"
)

type vendor struct {
	prof  *at.Profile
	model string
}

var vendors = []vendor{{at.Quectel, "EC25"}, {at.SIMCom, "SIMCOM_SIM7600G-H"}}

type rig struct {
	t       *testing.T
	carrier *modem.Carrier
	phone   *modem.Line
	dev     *atsim.Device
	m       *at.Modem
	mu      sync.Mutex
	now     time.Time
}

func newRig(t *testing.T, v vendor, keys at.KeySource, before func(*atsim.Device)) *rig {
	t.Helper()
	r := &rig{t: t, carrier: modem.NewCarrier(), now: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)}
	r.phone = r.carrier.Line(ownerNum)
	r.dev = atsim.New(v.prof, v.model, r.carrier.Line(boxNum), time.Millisecond)
	if v.prof == at.Quectel {
		r.dev.SetUAC(true)
	}
	if before != nil {
		before(r.dev)
	}
	m, err := at.Open(context.Background(), r.config(v, keys))
	if err != nil {
		t.Fatal(err)
	}
	r.m = m
	t.Cleanup(func() { _ = m.Close() })
	return r
}

func (r *rig) config(v vendor, keys at.KeySource) at.Config {
	cfg := at.Config{Profile: v.prof, Port: r.dev.Port(), Number: boxNum, Keys: keys,
		Now: r.clock, FramePace: time.Millisecond, Poll: 5 * time.Millisecond, Sweep: 20 * time.Millisecond, CountryCode: "1", Owner: ownerNum}
	if v.prof == at.Quectel {
		cfg.Audio = at.UACAudio(atsim.Card, r.dev.Runner())
	} else {
		cfg.Audio = at.SerialAudio(r.dev.SerialAudio)
	}
	return cfg
}

func (r *rig) clock() time.Time { r.mu.Lock(); defer r.mu.Unlock(); return r.now }

func (r *rig) advance(d time.Duration) { r.mu.Lock(); r.now = r.now.Add(d); r.mu.Unlock() }

func (r *rig) text() modem.SMS {
	r.t.Helper()
	select {
	case m := <-r.m.Inbox():
		return m
	case <-time.After(3 * time.Second):
		r.t.Fatal("no text reached the broker")
	}
	return modem.SMS{}
}

func (r *rig) phoneText() modem.SMS {
	r.t.Helper()
	select {
	case m := <-r.phone.Inbox():
		return m
	case <-time.After(3 * time.Second):
		r.t.Fatal("no text reached the phone")
	}
	return modem.SMS{}
}

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	end := time.Now().Add(3 * time.Second)
	for time.Now().Before(end) {
		if f() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func wait(t *testing.T, what string, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func TestOpenSpeaksEachVendorsDialectAndRefusesOtherModels(t *testing.T) {
	for _, v := range vendors {
		t.Run(v.prof.Name, func(t *testing.T) {
			r := newRig(t, v, at.KeysInBand, nil)
			cmds := strings.Join(r.dev.Commands(), "\n")
			for _, want := range append([]string{"ATE0", "AT+CMGF=0", "AT+CNMI=2,1,0,0,0", "AT+CLIP=1"}, v.prof.Init...) {
				if !strings.Contains(cmds, want) {
					t.Errorf("init lacks %q:\n%s", want, cmds)
				}
			}
			if r.m.Number() != boxNum {
				t.Fatalf("number %q", r.m.Number())
			}
		})
	}
	// A modem of the other family, or an unknown model, is refused before
	// any vendor command is sent to it.
	for _, c := range []struct {
		prof  *at.Profile
		model string
	}{{at.Quectel, "SIMCOM_SIM7600G-H"}, {at.SIMCom, "EC25"}, {at.Quectel, "EC21"}} {
		dev := atsim.New(c.prof, c.model, modem.NewCarrier().Line(boxNum), time.Millisecond)
		_, err := at.Open(context.Background(), at.Config{Profile: c.prof, Port: dev.Port()})
		if !errors.Is(err, at.ErrModel) {
			t.Errorf("%s with model %s: %v", c.prof.Name, c.model, err)
		}
		for _, cmd := range dev.Commands() {
			for _, vc := range c.prof.Init {
				if cmd == vc {
					t.Errorf("sent %q to an unqualified modem", cmd)
				}
			}
		}
	}
}

func TestTextsFlowBothWaysOverTheCarrierForBothVendors(t *testing.T) {
	long := strings.Repeat("Approve K3: send invoice 1042 to billing@acme.example. ", 8)[:400]
	for _, v := range vendors {
		t.Run(v.prof.Name, func(t *testing.T) {
			r := newRig(t, v, at.KeysInBand, nil)
			for _, text := range []string{"STOP", "café ☕ ok", long} {
				if err := r.phone.Send(boxNum, text); err != nil {
					t.Fatal(err)
				}
				got := r.text()
				if got.From != ownerNum || got.To != boxNum || got.Text != text {
					t.Fatalf("got %+v, want %q from the owner", got, text)
				}
				if err := r.m.Send(ownerNum, text); err != nil {
					t.Fatal(err)
				}
				if got := r.phoneText(); got.From != boxNum || got.Text != text {
					t.Fatalf("phone got %+v, want %q", got, text)
				}
			}
			log := r.carrier.Log()
			if n := log[len(log)-1].Segments; n != 3 {
				t.Fatalf("400-character text took %d segments, want 3", n)
			}
			eventually(t, "texts deleted from the modem", func() bool { return r.dev.Stored() == 0 })
		})
	}
}

func TestTextsStoredWhileTheBrokerWasDownOrWithALostNoticeArrive(t *testing.T) {
	carrier := modem.NewCarrier()
	phone := carrier.Line(ownerNum)
	dev := atsim.New(at.SIMCom, "SIMCOM_SIM7600G-H", carrier.Line(boxNum), time.Millisecond)
	_ = phone.Send(boxNum, "sent while the broker was down")
	eventually(t, "stored", func() bool { return dev.Stored() == 1 })
	m, err := at.Open(context.Background(), at.Config{Profile: at.SIMCom, Port: dev.Port(), Sweep: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	for _, want := range []string{"sent while the broker was down", "notice lost"} {
		if want == "notice lost" {
			dev.MuteCMTI(true)
			_ = phone.Send(boxNum, want)
		}
		select {
		case got := <-m.Inbox():
			if got.Text != want {
				t.Fatalf("got %q, want %q", got.Text, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%q never arrived", want)
		}
	}
}

func TestUnreadableAndIncompleteTextsAreDeletedNeverDelivered(t *testing.T) {
	r := newRig(t, vendors[1], at.KeysInBand, nil)
	r.dev.StorePDU("00040B915155000000F10004620140210000000101") // 8-bit data
	parts, err := at.EncodeDeliver(ownerNum, strings.Repeat("YES K3 ", 40), 9)
	if err != nil || len(parts) != 2 {
		t.Fatal(len(parts), err)
	}
	r.dev.StorePDU(parts[0]) // part 2 never comes
	eventually(t, "both deleted", func() bool { return r.dev.Stored() == 0 })
	r.advance(11 * time.Minute)
	eventually(t, "both dropped", func() bool { return r.m.Dropped() == 2 })
	select {
	case got := <-r.m.Inbox():
		t.Fatalf("delivered %q", got.Text)
	case <-time.After(50 * time.Millisecond):
	}
}

type fakeEngine struct {
	mu      sync.Mutex
	stopped bool
}

func (f *fakeEngine) Stop(context.Context) (journal.StopReport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped = true
	return journal.StopReport{}, nil
}
func (f *fakeEngine) Resume() error          { return nil }
func (f *fakeEngine) Stopped() bool          { f.mu.Lock(); defer f.mu.Unlock(); return f.stopped }
func (f *fakeEngine) List() []journal.Status { return nil }

var _ control.Engine = (*fakeEngine)(nil)

// The owner channel from P1-5 runs unchanged on the real driver: a STOP
// texted from the owner's phone crosses the carrier, the modem's AT port
// and the PDU codec, and the reply comes back the same way (CH-1, CH-2).
func TestOwnerChannelRunsOnTheDriver(t *testing.T) {
	for _, v := range vendors {
		t.Run(v.prof.Name, func(t *testing.T) {
			r := newRig(t, v, at.KeysInBand, nil)
			eng := &fakeEngine{}
			ch, err := owner.New(owner.Config{Owner: ownerNum, Modem: r.m, Engine: eng, Store: &owner.MemStore{},
				Secrets: owner.Secrets{TOTPSeed: []byte("12345678901234567890"), GridSeed: []byte("synthetic-grid-seed")}})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go ch.Run(ctx)
			_ = r.carrier.Line(shopNum).Send(boxNum, "STOP") // not the owner: ignored
			_ = r.phone.Send(boxNum, "STOP")
			if got := r.phoneText(); !strings.HasPrefix(got.Text, "Stopped.") || !eng.Stopped() {
				t.Fatalf("STOP: %q", got.Text)
			}
		})
	}
}

// speech is a voice-band signal with no keypad tones in it.
func speech(ms int) []byte {
	n := at.Rate * ms / 1000
	out := make([]byte, 0, 2*n)
	seed := uint32(7)
	for i := 0; i < n; i++ {
		seed = seed*1664525 + 1013904223
		noise := float64(int32(seed>>16)%2000) - 1000
		v := 3000*sinf(220, i) + 2000*sinf(330, i) + 1500*sinf(510, i) + noise
		s := uint16(int16(v))
		out = append(out, byte(s), byte(s>>8))
	}
	return out
}

func TestIncomingCallDecodesKeysInTheBrokerAndMutesThemForSpeech(t *testing.T) {
	for _, v := range vendors {
		for _, keys := range []at.KeySource{at.KeysInBand, at.KeysModem} {
			t.Run(v.prof.Name, func(t *testing.T) {
				r := newRig(t, v, keys, nil)
				far := r.dev.Ring(ownerNum)
				var c *at.Call
				select {
				case c = <-r.m.Calls():
				case <-time.After(3 * time.Second):
					t.Fatal("no incoming call")
				}
				if !c.Incoming() || c.Number() != ownerNum || c.State() != at.Ringing {
					t.Fatalf("call %q incoming=%v state=%v", c.Number(), c.Incoming(), c.State())
				}
				if err := c.Answer(context.Background()); err != nil {
					t.Fatal(err)
				}
				wait(t, "active", c.Active())

				// The box speaks; the far end hears it.
				hello := speech(200)
				if err := c.Say(context.Background(), hello); err != nil {
					t.Fatal(err)
				}
				eventually(t, "far end hears the box", func() bool { return len(far.Heard()) >= len(hello) })

				// The owner talks, then types a code on the keypad.
				var uplink []byte
				var got []byte
				done := make(chan struct{})
				go func() {
					defer close(done)
					for f := range c.Speech() {
						uplink = append(uplink, f...)
					}
				}()
				far.Say(speech(300))
				far.Press("482913")
				far.Say(speech(300))
				for len(got) < 6 {
					select {
					case k := <-c.Keys():
						got = append(got, k)
					case <-time.After(3 * time.Second):
						t.Fatalf("keys so far %q", got)
					}
				}
				if string(got) != "482913" {
					t.Fatalf("keys %q", got)
				}
				eventually(t, "uplink drained", func() bool { return far.Pending() == 0 })
				time.Sleep(20 * time.Millisecond)
				far.Hangup()
				wait(t, "ended", c.Ended())
				<-done
				if k := at.Decode(uplink); k != "" || at.HasTone(uplink) {
					t.Fatalf("speech side can hear keypad tones (decoded %q)", k)
				}
				if len(uplink) < len(speech(500)) {
					t.Fatalf("speech side got %d bytes", len(uplink))
				}
				cmds := strings.Join(r.dev.Commands(), "\n")
				for _, want := range append(v.prof.AudioOn, v.prof.AudioOff...) {
					if !strings.Contains(cmds, want) {
						t.Errorf("never sent %q", want)
					}
				}
			})
		}
	}
}

func TestDialedCallConnectsAndRejectsInjectionAndSecondCalls(t *testing.T) {
	for _, v := range vendors {
		t.Run(v.prof.Name, func(t *testing.T) {
			r := newRig(t, v, at.KeysInBand, nil)
			for _, bad := range []string{"", "12", "+1555;+CMGD=1,4", "+1555\rATH", "1555 000 0001", "*21#"} {
				if _, err := r.m.Dial(context.Background(), bad); !errors.Is(err, at.ErrNumber) {
					t.Errorf("Dial(%q): %v", bad, err)
				}
			}
			c, err := r.m.Dial(context.Background(), shopNum)
			if err != nil {
				t.Fatal(err)
			}
			far := <-r.dev.Outgoing()
			if far.Number != shopNum || c.Incoming() {
				t.Fatalf("dialed %q", far.Number)
			}
			if _, err := r.m.Dial(context.Background(), ownerNum); !errors.Is(err, at.ErrBusy) {
				t.Fatalf("second call: %v", err)
			}
			far.Answer()
			wait(t, "active", c.Active())
			if err := c.Say(context.Background(), speech(100)); err != nil {
				t.Fatal(err)
			}
			if err := c.Hangup(context.Background()); err != nil {
				t.Fatal(err)
			}
			wait(t, "ended", c.Ended())
			if !far.Ended() {
				t.Fatal("far end still connected")
			}
			if err := c.Say(context.Background(), speech(20)); !errors.Is(err, at.ErrCallEnded) {
				t.Fatalf("Say after hangup: %v", err)
			}
		})
	}
}

func TestQuectelWithoutUACHasNoAudioUntilEnsureUACRestartsIt(t *testing.T) {
	r := newRig(t, vendors[0], at.KeysInBand, func(d *atsim.Device) { d.SetUAC(false) })
	far := r.dev.Ring(ownerNum)
	c := <-r.m.Calls()
	_ = c.Answer(context.Background())
	wait(t, "active", c.Active())
	if err := c.Say(context.Background(), speech(20)); !errors.Is(err, at.ErrNoAudio) {
		t.Fatalf("Say without UAC: %v", err)
	}
	far.Hangup()
	wait(t, "ended", c.Ended())
	changed, err := r.m.EnsureUAC(context.Background())
	if err != nil || !changed || !r.dev.UAC() {
		t.Fatalf("EnsureUAC: %v %v uac=%v", changed, err, r.dev.UAC())
	}
	wait(t, "modem restart", r.m.Done())
}

func TestUnpluggedModemFailsSendsAndEndsCalls(t *testing.T) {
	r := newRig(t, vendors[1], at.KeysInBand, nil)
	_ = r.dev.Ring(ownerNum)
	c := <-r.m.Calls()
	_ = c.Answer(context.Background())
	wait(t, "active", c.Active())
	r.dev.Unplug()
	wait(t, "done", r.m.Done())
	wait(t, "call ended", c.Ended())
	if err := r.m.Send(ownerNum, "hello"); !errors.Is(err, modem.ErrDown) {
		t.Fatalf("Send: %v", err)
	}
}

func sinf(f float64, i int) float64 { return math.Sin(2 * math.Pi * f * float64(i) / at.Rate) }

// A sender ID can spell the owner's number. It arrives flagged and
// prefixed, and the owner channel ignores it (CH-1, CH-18).
func TestAlphanumericSenderSpellingTheOwnersNumberIsNeverTheOwner(t *testing.T) {
	// A sender ID holds at most 11 characters, so an owner number of 11
	// characters or fewer can be spelled exactly.
	const shortOwner = "+4670123456"
	r := newRig(t, vendors[1], at.KeysInBand, nil)
	r.dev.StorePDU(at.DeliverAlpha(shortOwner, "STOP"))
	got := r.text()
	if !got.Alphanumeric || got.From != "alpha:"+shortOwner {
		t.Fatalf("got %+v", got)
	}

	r = newRig(t, vendors[0], at.KeysInBand, nil)
	eng := &fakeEngine{}
	ch, err := owner.New(owner.Config{Owner: shortOwner, Modem: r.m, Engine: eng, Store: &owner.MemStore{},
		Secrets: owner.Secrets{TOTPSeed: []byte("12345678901234567890"), GridSeed: []byte("synthetic-grid-seed")}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ch.Run(ctx)
	r.dev.StorePDU(at.DeliverAlpha(shortOwner, "STOP"))
	eventually(t, "spoof deleted", func() bool { return r.dev.Stored() == 0 })
	time.Sleep(50 * time.Millisecond)
	if eng.Stopped() {
		t.Fatal("an alphanumeric sender stopped the box")
	}
}

// The owner's texts match their number whatever format the network uses.
func TestNationalFormatSendersAreWrittenAsE164(t *testing.T) {
	r := newRig(t, vendors[1], at.KeysInBand, nil)
	r.dev.StorePDU(at.DeliverNational("5550000001", "STATUS"))
	if got := r.text(); got.From != ownerNum || got.Alphanumeric {
		t.Fatalf("got %+v", got)
	}
	for _, c := range []struct{ in, cc, want string }{
		{"5555123456", "1", "+15555123456"},
		{"15555123456", "1", "+15555123456"},
		{"011447700900123", "1", "+447700900123"},
		{"07700900123", "44", "+447700900123"},
		{"00447700900123", "44", "+447700900123"},
		{"447700900123", "44", "+447700900123"},
		{"5555123456", "", "5555123456"},
		// Exit prefixes, a stray 0 after +, and the trunk 0 after the
		// country code.
		{"0015555123456", "1", "+15555123456"},
		{"+015555123456", "1", "+15555123456"},
		{"+01115555123456", "1", "+15555123456"},
		{"+1 (555) 512-3456", "1", "+15555123456"},
		{"+4407700900123", "44", "+447700900123"},
		{"+00447700900123", "44", "+447700900123"},
		{"+330612345678", "33", "+33612345678"},
		{"0612345678", "33", "+33612345678"},
		// Italy keeps its leading 0 after the country code.
		{"+390612345678", "39", "+390612345678"},
		{"0612345678", "39", "+390612345678"},
	} {
		if got := at.E164(c.in, 0, c.cc); got != c.want {
			t.Errorf("E164(%q, %q) = %q, want %q", c.in, c.cc, got, c.want)
		}
	}
	// An alphanumeric sender is never any number, whatever it spells.
	if at.SameNumber("alpha:"+ownerNum, ownerNum, "1") || at.SameNumber(ownerNum, "alpha:"+ownerNum, "1") {
		t.Fatal("an alpha sender matched a number")
	}
}

func TestSilentForgedReplayedAndStrayTextsAreNotDelivered(t *testing.T) {
	r := newRig(t, vendors[1], at.KeysInBand, nil)
	// Silent Type-0 and replace-message texts.
	r.dev.StorePDU(at.DeliverPID(ownerNum, 0x40, "STOP"))
	r.dev.StorePDU(at.DeliverPID(ownerNum, 0x41, "STOP"))
	// A long text whose part 2 arrives twice with different bodies.
	parts, _ := at.EncodeDeliver(ownerNum, strings.Repeat("send invoice 1042 ", 12), 5)
	evil, _ := at.EncodeDeliver(ownerNum, strings.Repeat("pay acct 9999 now ", 12), 5)
	r.dev.StorePDU(parts[1])
	r.dev.StorePDU(evil[1])
	r.dev.StorePDU(parts[0])
	eventually(t, "all deleted", func() bool { return r.dev.Stored() == 0 })
	eventually(t, "all dropped", func() bool { return r.m.Dropped() == 3 })
	// The owner hears once that the long text was garbled, not once per
	// forged part: a second conflict within the hour gets no reply.
	if got := r.phoneText(); got.Text != at.GarbledText {
		t.Fatalf("owner got %q", got.Text)
	}
	again, _ := at.EncodeDeliver(ownerNum, strings.Repeat("pay acct 1111 now ", 12), 7)
	again2, _ := at.EncodeDeliver(ownerNum, strings.Repeat("pay acct 2222 now ", 12), 7)
	r.dev.StorePDU(again[0])
	r.dev.StorePDU(again2[0])
	r.dev.StorePDU(again[1])
	eventually(t, "second conflict dropped", func() bool { return r.m.Dropped() == 4 })
	select {
	case m := <-r.phone.Inbox():
		t.Fatalf("second garbled reply %q", m.Text)
	case <-time.After(60 * time.Millisecond):
	}
	// The same PDU handed over twice (a delete that did not happen) is
	// delivered once.
	one, _ := at.EncodeDeliver(ownerNum, "YES K3 482913", 6)
	r.dev.StorePDU(one[0])
	if got := r.text(); got.Text != "YES K3 482913" {
		t.Fatalf("got %q", got.Text)
	}
	r.dev.StorePDU(one[0])
	eventually(t, "replay deleted", func() bool { return r.dev.Stored() == 0 })
	select {
	case got := <-r.m.Inbox():
		t.Fatalf("delivered %+v", got)
	case <-time.After(60 * time.Millisecond):
	}
	// A stored line that is not a PDU of the announced length stays put.
	r.dev.StorePDU("RDY")
	time.Sleep(60 * time.Millisecond)
	if r.dev.Stored() != 1 {
		t.Fatal("a stray line was deleted unread")
	}
}

func TestSIMNetworkAndSignalAreReportedInPlainWords(t *testing.T) {
	for _, c := range []struct {
		sim  string
		want string
	}{{"", "No SIM found. Check it is in the modem."}, {"SIM PIN", "The SIM is PIN-locked. Remove the PIN in a phone, then put it back."}} {
		dev := atsim.New(at.SIMCom, "SIMCOM_SIM7600G-H", modem.NewCarrier().Line(boxNum), time.Millisecond)
		dev.SetSIM(c.sim)
		_, err := at.Open(context.Background(), at.Config{Profile: at.SIMCom, Port: dev.Port()})
		var se *at.SIMError
		if !errors.As(err, &se) || se.Status.Line() != c.want {
			t.Fatalf("SIM %q: %v", c.sim, err)
		}
	}
	// A SIM still starting after a restart is waited for, not reported
	// missing.
	dev := atsim.New(at.SIMCom, "SIMCOM_SIM7600G-H", modem.NewCarrier().Line(boxNum), time.Millisecond)
	dev.SetSIMBusy(3)
	if m, err := at.Open(context.Background(), at.Config{Profile: at.SIMCom, Port: dev.Port()}); err != nil {
		t.Fatalf("busy SIM: %v", err)
	} else {
		_ = m.Close()
	}
	if l := (at.Status{}).Line(); strings.Contains(l, "signal") || strings.Contains(l, "Looking") {
		t.Fatalf("unknown SIM reads %q", l)
	}
	for _, v := range vendors {
		r := newRig(t, v, at.KeysInBand, nil)
		if s := r.m.Status(); !s.Registered() || s.Bars != 4 || !strings.HasPrefix(s.Line(), "Connected") {
			t.Fatalf("%s: %+v %q", v.prof.Name, s, s.Line())
		}
		if r.m.ICCID() == "" || r.m.ICCID() != r.dev.ICCID() {
			t.Fatalf("%s: ICCID %q", v.prof.Name, r.m.ICCID())
		}
		for _, n := range []struct {
			stat, rssi int
			want       string
		}{
			{3, 15, "The carrier refused the SIM. Check it is activated."},
			{2, 99, "No mobile signal here. Move the box nearer a window."},
			{2, 12, "Looking for the mobile network."},
			{5, 12, "Connected to a partner network (roaming), signal 2 of 4."},
			// LTE registered for texts only, or for emergency calls only.
			{6, 12, "Connected to the mobile network, signal 2 of 4."},
			{10, 12, "Connected to a partner network (roaming), signal 2 of 4."},
			{8, 12, "The carrier refused the SIM. Check it is activated."},
		} {
			r.dev.SetNetwork(n.stat, n.rssi)
			eventually(t, n.want, func() bool { return r.m.Status().Line() == n.want })
		}
		r.dev.SetSIM("")
		eventually(t, "SIM gone", func() bool { return r.m.Status().SIM == at.SIMMissing })
	}
}

// Downlink audio comes from an untrusted speech service: keypad tones in
// it are zeroed before they reach the call.
func TestTheBoxNeverPlaysKeypadTonesIntoACall(t *testing.T) {
	r := newRig(t, vendors[1], at.KeysInBand, nil)
	far := r.dev.Ring(ownerNum)
	c := <-r.m.Calls()
	_ = c.Answer(context.Background())
	wait(t, "active", c.Active())
	pcm := append(append(speech(200), atsim.Tone('5', 120, 60)...), speech(200)...)
	if err := c.Say(context.Background(), pcm); err != nil {
		t.Fatal(err)
	}
	eventually(t, "heard", func() bool { return len(far.Heard()) >= len(pcm) })
	if h := far.Heard(); at.HasTone(h) || at.Decode(h) != "" {
		t.Fatal("a keypad tone reached the far end")
	}
	far.Hangup()
}

package bridge_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeclient"
	"github.com/ghbmrk/agentos/broker/bridgeproto"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/modem/at"
	"github.com/ghbmrk/agentos/broker/modem/atsim"
	"github.com/ghbmrk/agentos/broker/modem/bridge"
	"github.com/ghbmrk/agentos/broker/modemlink"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: CH-1, CH-2

const (
	ownerNum = "+15550000999"
	boxNum   = "+15550000100"
)

// rig runs agentosd's end (a modemlink.Link on a real owner socket) and
// the bridge over simulated modems on one carrier.
type rig struct {
	t       *testing.T
	carrier *modem.Carrier
	phone   *modem.Line
	link    *modemlink.Link
	mu      sync.Mutex
	devs    []*atsim.Device
	iccid   string
	openErr error
	// preload, if set, stores texts in each new device before it opens.
	preload func(*atsim.Device)
	// failFirst names ops whose first call fails, as a dropped
	// connection does.
	failFirst map[string]bool
	// refuse is how many more inbound offers fail with refusal.
	refuse  int
	refusal string
	// refuseFrom, if set, refuses every offer from that sender.
	refuseFrom string
	// refuseText refuses each text so many more times, as limited and
	// paused in turn.
	refuseText map[string]int
	// skew moves agentosd's clock ahead, past its rate limit's minute.
	skew    atomic.Int64
	cancel  context.CancelFunc
	done    chan error
	dir     string
	srv     *sockets.Server
	srvStop context.CancelFunc
	last    *atsim.Device
}

// startAgentosd serves owner.sock with a fresh Link, as agentosd does when
// it starts: the line reads as down until the bridge reports it.
func (r *rig) startAgentosd() {
	r.t.Helper()
	r.link = modemlink.New(modemlink.Config{Owner: ownerNum, SendWait: 5 * time.Second, PollWait: 200 * time.Millisecond,
		Now: func() time.Time { return time.Now().Add(time.Duration(r.skew.Load())) },
		// agentosd's roles file, as the bridge reads it at each open.
		Record: func(iccid string) error { r.mu.Lock(); defer r.mu.Unlock(); r.iccid = iccid; return nil }})
	ctx, cancel := context.WithCancel(context.Background())
	r.srv, r.srvStop = &sockets.Server{Dir: r.dir}, cancel
	if err := r.srv.Start(ctx, sockets.Endpoint{Name: "owner.sock", Peer: sockets.Peer{Kind: "owner"}, Ops: r.link.Ops(), MaxConns: 8, HangupOps: map[string]bool{bridgeproto.OpOutbox: true}}); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) stopAgentosd() {
	r.srvStop()
	r.srv.Wait()
}

func newRig(t *testing.T, iccid func(*atsim.Device) string) *rig {
	t.Helper()
	return newRigWith(t, iccid, nil)
}

func newRigWith(t *testing.T, iccid func(*atsim.Device) string, preload func(*atsim.Device), failFirst ...string) *rig {
	t.Helper()
	r := &rig{t: t, carrier: modem.NewCarrier(), done: make(chan error, 1), preload: preload, failFirst: map[string]bool{}}
	for _, op := range failFirst {
		r.failFirst[op] = true
	}
	r.phone = r.carrier.Line(ownerNum)
	dir := t.TempDir()
	r.dir = dir
	r.startAgentosd()
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.iccid = iccid(atsim.New(at.SIMCom, "SIMCOM_SIM7600G-H", modem.NewCarrier().Line(boxNum), time.Millisecond))
	cfg := bridge.Config{
		Agentosd: &flaky{r: r, c: bridgeclient.Client{Path: filepath.Join(dir, "owner.sock")}},
		OpenOwner: func(ctx context.Context, check func(string) error) (bridge.Owner, error) {
			r.mu.Lock()
			err := r.openErr
			r.mu.Unlock()
			if err != nil {
				return nil, err
			}
			// Each open is a fresh port, as a reopened serial device is.
			dev := r.newDevice()
			return at.Open(ctx, at.Config{Profile: at.SIMCom, Port: dev.Port(), Number: boxNum, CountryCode: "1", Owner: ownerNum, CheckSIM: check, KeepUntilAck: true,
				Poll: 5 * time.Millisecond, Sweep: 20 * time.Millisecond})
		},
		OwnerICCID:   func() string { r.mu.Lock(); defer r.mu.Unlock(); return r.iccid },
		Retry:        50 * time.Millisecond,
		StateEvery:   time.Hour, // only the open's own report reaches agentosd
		InboundRetry: 10 * time.Millisecond,
		Logf:         t.Logf,
	}
	go func() { r.done <- bridge.Run(ctx, cfg) }()
	t.Cleanup(func() {
		cancel()
		if err := <-r.done; err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("bridge: %v", err)
		}
		r.stopAgentosd()
	})
	return r
}

// flaky fails the first call of each op in r.failFirst (for state, the
// first that reports the line ok).
type flaky struct {
	r *rig
	c bridge.Caller
}

func (f *flaky) Call(ctx context.Context, op string, args, out any) error {
	if st, ok := args.(bridgeproto.State); ok && st.OwnerLine != bridgeproto.StateOK {
		return f.c.Call(ctx, op, args, out) // only an ok report counts
	}
	f.r.mu.Lock()
	fail := f.r.failFirst[op]
	delete(f.r.failFirst, op)
	refused := ""
	if op == bridgeproto.OpInbound && f.r.refuse > 0 {
		f.r.refuse--
		refused = f.r.refusal
	}
	if in, ok := args.(bridgeproto.Inbound); ok && f.r.refuseFrom != "" && in.From == f.r.refuseFrom {
		refused = bridgeproto.RefusedPaused
	}
	if in, ok := args.(bridgeproto.Inbound); ok && f.r.refuseText[in.Text] > 0 {
		f.r.refuseText[in.Text]--
		refused = bridgeproto.RefusedLimited
		if f.r.refuseText[in.Text]%2 == 0 {
			refused = bridgeproto.RefusedPaused
		}
	}
	f.r.mu.Unlock()
	if fail {
		return errors.New("connection reset")
	}
	if refused != "" {
		return errors.New("bridgeclient: " + refused)
	}
	return f.c.Call(ctx, op, args, out)
}

func (r *rig) newDevice() *atsim.Device {
	r.mu.Lock()
	last := r.last
	r.mu.Unlock()
	var dev *atsim.Device
	if last != nil {
		dev = last.Reopen() // the same modem: its stored texts kept
	} else {
		dev = atsim.New(at.SIMCom, "SIMCOM_SIM7600G-H", r.carrier.Line(boxNum), time.Millisecond)
		if r.preload != nil {
			r.preload(dev)
		}
	}
	r.mu.Lock()
	r.last = dev
	r.devs = append(r.devs, dev)
	r.mu.Unlock()
	return dev
}

func recorded(d *atsim.Device) string { return d.ICCID() }

// waitNote waits for the owner line's local-page note to satisfy ok.
func (r *rig) waitNote(ok func(string) bool) string {
	r.t.Helper()
	var n string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if n = r.link.OwnerLineNote(); ok(n) {
			return n
		}
	}
	r.t.Fatalf("owner line note stayed %q", n)
	return n
}

func (r *rig) phoneGets() string {
	r.t.Helper()
	select {
	case m := <-r.phone.Inbox():
		return m.Text
	case <-time.After(5 * time.Second):
		r.t.Fatal("no text to the owner's phone")
	}
	return ""
}

// P2-3w part 1, end to end over the AT simulator and a real owner.sock:
// the owner's texts reach agentosd's owner channel, and its texts reach
// the owner's phone.
func TestOwnerTextsBothWays(t *testing.T) {
	r := newRig(t, recorded)
	r.waitNote(func(n string) bool { return n == "" })
	if err := r.phone.Send(boxNum, "STATUS"); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-r.link.Inbox():
		if m.From != ownerNum || m.Text != "STATUS" {
			t.Fatalf("delivered %+v", m)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the owner's text did not reach agentosd")
	}
	if err := r.link.Send(ownerNum, "Box: all well."); err != nil {
		t.Fatalf("send: %v", err)
	}
	if got := r.phoneGets(); got != "Box: all well." {
		t.Fatalf("phone got %q", got)
	}
}

// Security S-B8, UX U-B3: a SIM that is not the one recorded for the owner
// line is reported swapped, and no text passes either way; no recorded SIM
// is unbound.
func TestASwappedOrUnboundSIMStopsTheOwnerLine(t *testing.T) {
	r := newRig(t, func(*atsim.Device) string { return "89010000000000000000" })
	r.waitNote(func(n string) bool { return strings.HasPrefix(n, "The SIM in my phone modem changed.") })
	r.phone.Send(boxNum, "STOP")
	select {
	case m := <-r.link.Inbox():
		t.Fatalf("a text on a swapped SIM reached agentosd: %+v", m)
	case <-time.After(200 * time.Millisecond):
	}
	if err := r.link.Send(ownerNum, "hi"); !errors.Is(err, modem.ErrDown) {
		t.Fatalf("send on a swapped SIM: %v", err)
	}
	r.mu.Lock()
	r.iccid = ""
	r.mu.Unlock()
	r.waitNote(func(n string) bool {
		return strings.HasPrefix(n, "My phone modem's SIM isn't set up as my number yet.")
	})
	r.mu.Lock()
	r.iccid = r.devs[0].ICCID()
	r.mu.Unlock()
	r.waitNote(func(n string) bool { return n == "" })
	// The SIM is pulled: the modem restarts and opens without one.
	r.mu.Lock()
	r.openErr = &at.SIMError{Status: at.Status{SIM: at.SIMMissing}}
	dev := r.devs[len(r.devs)-1]
	r.mu.Unlock()
	dev.Unplug()
	r.waitNote(func(n string) bool { return strings.HasPrefix(n, "My phone modem has no SIM") })
}

// UX U-B1, U-B2: a modem that goes away reads as down; what could not be
// sent meanwhile is counted, and once it is back the owner gets one text
// with the count, nothing replayed.
func TestAnUnpluggedModemIsDownAndRecovers(t *testing.T) {
	r := newRig(t, recorded)
	r.waitNote(func(n string) bool { return n == "" })
	r.mu.Lock()
	r.openErr = errors.New("no modem")
	dev := r.devs[0]
	r.mu.Unlock()
	dev.Unplug()
	r.waitNote(func(n string) bool { return strings.HasPrefix(n, "I can't reach my phone modem.") })
	for i := 0; i < 2; i++ {
		if err := r.link.Send(ownerNum, "approve? code 123456"); !errors.Is(err, modem.ErrDown) {
			t.Fatalf("send while unplugged: %v", err)
		}
	}
	r.mu.Lock()
	r.openErr = nil
	r.mu.Unlock()
	r.waitNote(func(n string) bool { return n == "" })
	got := r.phoneGets()
	if !strings.HasPrefix(got, "I couldn't text you from ") || !strings.Contains(got, "2 texts didn't reach you.") {
		t.Fatalf("recovery text %q", got)
	}
	select {
	case m := <-r.phone.Inbox():
		t.Fatalf("replayed %q", m.Text)
	case <-time.After(200 * time.Millisecond):
	}
}

var _ = bridgeproto.OpState

// storeFromOwner stores texts from the owner, as if they arrived while the
// bridge was away.
func storeFromOwner(texts ...string) func(*atsim.Device) {
	return func(d *atsim.Device) {
		for i, text := range texts {
			pdus, err := at.EncodeDeliver(ownerNum, text, byte(i))
			if err != nil {
				panic(err)
			}
			for _, p := range pdus {
				d.StorePDU(p)
			}
		}
	}
}

// L3 on #170: texts stored while the bridge was away (the modem gives
// them up as they are read) reach agentosd, though it reads the line as
// down until the bridge says otherwise. The bridge's first report of the
// line and its first offer of a text both fail, as a dropped connection
// does: it reports again before reading any text, and offers the text
// again.
func TestTextsStoredWhileAwayReachAgentosd(t *testing.T) {
	r := newRigWith(t, recorded, storeFromOwner("STOP", "STATUS"), bridgeproto.OpState, bridgeproto.OpInbound)
	for _, want := range []string{"STOP", "STATUS"} {
		select {
		case m := <-r.link.Inbox():
			if m.From != ownerNum || m.Text != want {
				t.Fatalf("delivered %+v, want %q", m, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("the stored %q did not reach agentosd", want)
		}
	}
}

// L3 on #170: a SIM that is not the recorded one is turned away before a
// stored text is read off it, so its texts stay stored.
func TestAWrongSIMKeepsItsStoredTexts(t *testing.T) {
	r := newRigWith(t, func(*atsim.Device) string { return "8900000000000000001" }, storeFromOwner("STOP"))
	r.waitNote(func(n string) bool { return strings.Contains(n, "SIM") && strings.Contains(n, "changed") })
	r.mu.Lock()
	devs := append([]*atsim.Device(nil), r.devs...)
	r.mu.Unlock()
	for i, d := range devs {
		if n := d.Stored(); n != 1 {
			t.Fatalf("device %d keeps %d stored texts, want 1", i, n)
		}
	}
}

// gets waits for agentosd's owner channel to receive want.
func (r *rig) gets(want string) {
	r.t.Helper()
	select {
	case m := <-r.link.Inbox():
		if m.From != ownerNum || m.Text != want {
			r.t.Fatalf("delivered %+v, want %q", m, want)
		}
	case <-time.After(5 * time.Second):
		r.t.Fatalf("%q did not reach agentosd", want)
	}
}

func (r *rig) stored() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last.Stored()
}

// L3 on #170 (MUST-A): a text agentosd keeps refusing as paused is
// offered again for as long as the line is ok, the line being reported
// again before each offer, and stays on the modem until agentosd takes
// it.
func TestATextRefusedManyTimesIsStillDelivered(t *testing.T) {
	r := newRig(t, recorded)
	r.waitNote(func(n string) bool { return n == "" })
	r.mu.Lock()
	r.refuse, r.refusal = 20, bridgeproto.RefusedPaused
	r.mu.Unlock()
	if err := r.phone.Send(boxNum, "STOP"); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		r.mu.Lock()
		left := r.refuse
		r.mu.Unlock()
		if left == 10 {
			if n := r.stored(); n != 1 {
				t.Fatalf("%d stored while agentosd refuses, want 1", n)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the text was not offered again")
		}
	}
	r.gets("STOP")
	for deadline := time.Now().Add(5 * time.Second); r.stored() != 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("a taken text was left on the modem")
		}
	}
}

// L3 on #170 (MUST-A): a STOP sent while agentosd restarts reaches the
// restarted agentosd, which reads the line as down until the bridge says
// otherwise.
func TestAStopSentWhileAgentosdRestartsReachesIt(t *testing.T) {
	r := newRig(t, recorded)
	r.waitNote(func(n string) bool { return n == "" })
	r.stopAgentosd()
	if err := r.phone.Send(boxNum, "STOP"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond) // offers fail meanwhile
	r.startAgentosd()
	r.gets("STOP")
}

// L3 on #170 (MUST-A): a text the bridge had not handed over when it
// stopped (here, the modem dropped while agentosd was unreachable) stays
// on the modem and is delivered after the next open, once.
func TestATextInHandWhenTheModemDropsIsDeliveredAfterReopen(t *testing.T) {
	r := newRig(t, recorded)
	r.waitNote(func(n string) bool { return n == "" })
	r.mu.Lock()
	r.refuse, r.refusal = 1<<30, "connection reset"
	r.mu.Unlock()
	if err := r.phone.Send(boxNum, "STOP"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	r.mu.Lock()
	dev := r.last
	r.refuse = 0
	r.mu.Unlock()
	dev.Unplug()
	r.gets("STOP")
	select {
	case m := <-r.link.Inbox():
		t.Fatalf("delivered twice: %+v", m)
	case <-time.After(200 * time.Millisecond):
	}
}

// L3 on #170 (MUST-1): a text agentosd could not even read (a long text,
// escaped past agentosd's request size, here with the owner's number) or
// would refuse as malformed (past MaxText) is dropped, not offered for
// ever, so the owner's STOP behind it arrives.
func TestAnUnreadableTextDoesNotHoldUpTheOwner(t *testing.T) {
	r := newRigWith(t, recorded, func(d *atsim.Device) {
		store := func(from, text string, ref byte) {
			pdus, err := at.EncodeDeliver(from, text, ref)
			if err != nil {
				panic(err)
			}
			for _, p := range pdus {
				d.StorePDU(p)
			}
		}
		// 72 parts, past what EncodeDeliver makes: part 1 of a 2-part
		// text, renumbered (UDH 05 00 03 ref total seq).
		two, err := at.EncodeDeliver(ownerNum, strings.Repeat("<", 2*153), 1)
		if err != nil || !strings.Contains(two[0], "0500030102") {
			panic(fmt.Sprint("template: ", err))
		}
		for seq := 1; seq <= 72; seq++ {
			d.StorePDU(strings.Replace(two[0], "050003010201", fmt.Sprintf("0500030148%02X", seq), 1))
		}
		store(ownerNum, strings.Repeat("é", bridgeproto.MaxText/2+1), 2) // 2 bytes each
		store(ownerNum, "STOP", 3)
	})
	r.gets("STOP")
	for deadline := time.Now().Add(5 * time.Second); r.stored() != 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d texts left on the modem", r.stored())
		}
	}
}

// L3 on #170 (MUST-2): with the modem's memory full of a stranger's
// unfinished long texts, the owner's STOP still gets in: no one else's
// text is kept, so memory frees as it is read.
func TestAStrangerCannotFillTheModemsMemory(t *testing.T) {
	r := newRigWith(t, recorded, func(d *atsim.Device) {
		d.SetCapacity(4)
		for ref := byte(1); ref <= 8; ref++ {
			pdus, _ := at.EncodeDeliver("+15550000123", strings.Repeat("part of a long text ", 12), ref)
			d.StorePDU(pdus[0]) // never completed
		}
		pdus, _ := at.EncodeDeliver(ownerNum, "STOP", 9)
		d.StorePDU(pdus[0])
	})
	r.gets("STOP")
}

// L3 on #170 (N9): a state report agentosd did not hear is sent again
// soon, not at the next StateEvery (an hour here).
func TestAMissedStateReportIsSentAgain(t *testing.T) {
	r := newRigWith(t, recorded, nil, bridgeproto.OpState)
	r.waitNote(func(n string) bool { return n == "" })
}

// L3 on #170 (A10'): a text in hand is offered only while its modem
// answers: when the modem drops, the bridge reopens at once, though
// agentosd still refuses the text.
func TestTheBridgeReopensWhileATextIsRefused(t *testing.T) {
	r := newRig(t, recorded)
	r.waitNote(func(n string) bool { return n == "" })
	r.mu.Lock()
	r.refuse, r.refusal = 1<<30, "connection reset"
	opened := len(r.devs)
	dev := r.last
	r.mu.Unlock()
	if err := r.phone.Send(boxNum, "STOP"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	dev.Unplug()
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		r.mu.Lock()
		n := len(r.devs)
		r.mu.Unlock()
		if n > opened {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the bridge did not reopen while a text was refused")
		}
	}
	r.mu.Lock()
	r.refuse = 0
	r.mu.Unlock()
	r.gets("STOP")
}

// L3 on #170 (MUST-1): anyone else's text is deleted as it is read and
// offered once, so a refusal of it, however long it lasts, never holds up
// the owner's STOP.
func TestAStrangersTextIsOfferedOnce(t *testing.T) {
	r := newRig(t, recorded)
	r.waitNote(func(n string) bool { return n == "" })
	r.mu.Lock()
	r.refuseFrom = "+15550000123"
	r.mu.Unlock()
	if err := r.carrier.Line("+15550000123").Send(boxNum, "hello"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := r.phone.Send(boxNum, "STOP"); err != nil {
		t.Fatal(err)
	}
	r.gets("STOP")
}

// Security on #170 (round 4): a text from the owner's number past the
// modem's held limit is not kept, yet it is still offered until agentosd
// takes it, once, whatever agentosd refuses meanwhile.
func TestAnOwnersTextPastTheHeldLimitIsStillDelivered(t *testing.T) {
	r := newRig(t, recorded)
	r.waitNote(func(n string) bool { return n == "" })
	r.mu.Lock()
	r.refuseText = map[string]int{"t01": 1 << 30, "t33": 6}
	dev := r.last
	r.mu.Unlock()
	for i := 1; i <= 33; i++ {
		pdus, err := at.EncodeDeliver(ownerNum, fmt.Sprintf("t%02d", i), byte(i))
		if err != nil {
			t.Fatal(err)
		}
		dev.StorePDU(pdus[0])
	}
	// t01 is refused, so t02 to t32 wait behind it, kept; t33 is not.
	for deadline := time.Now().Add(5 * time.Second); dev.Stored() != 32; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d stored, want 32 kept", dev.Stored())
		}
	}
	r.mu.Lock()
	r.refuseText["t01"] = 0
	r.mu.Unlock()
	got := map[string]int{}
	for deadline := time.Now().Add(10 * time.Second); len(got) < 33; {
		select {
		case m := <-r.link.Inbox():
			got[m.Text]++
		case <-time.After(500 * time.Millisecond):
			// agentosd takes 20 a minute: move its clock on a minute.
			r.skew.Add(int64(time.Minute))
		}
		if time.Now().After(deadline) {
			t.Fatalf("delivered %d of 33: %v", len(got), got)
		}
	}
	select {
	case m := <-r.link.Inbox():
		t.Fatalf("delivered twice: %+v", m)
	case <-time.After(200 * time.Millisecond):
	}
	r.mu.Lock()
	left := r.refuseText["t33"]
	r.mu.Unlock()
	if left != 0 {
		t.Fatalf("t33 was refused only %d times", 6-left)
	}
}

// P2-2w d2b, CH-19: a SIM the owner confirms on the page (agentosd checks
// the code) is recorded by agentosd, and the bridge takes it at its next
// open: the owner line works again, without a restart. A swapped SIM is
// offered by its last four digits.
func TestTheOwnerAdoptsANewSIM(t *testing.T) {
	r := newRig(t, func(*atsim.Device) string { return "89010000000000000000" })
	r.waitNote(func(n string) bool { return strings.HasSuffix(n, "until you confirm it below.") })
	r.mu.Lock()
	real := r.devs[0].ICCID()
	r.mu.Unlock()
	tag, ends := r.link.SIM()
	if tag == "" || !strings.HasSuffix(strings.TrimRight(real, "Ff"), ends) || len(ends) != 4 {
		t.Fatalf("SIM() = %q, %q for %q", tag, ends, real)
	}
	if err := r.link.Adopt(tag); err != nil {
		t.Fatal(err)
	}
	r.waitNote(func(n string) bool { return n == "" })
	// The simulator's earlier ports still drain the carrier line, so the
	// line is shown working by a text out.
	if err := r.link.Send(ownerNum, "Box: back."); err != nil {
		t.Fatalf("send on the adopted SIM: %v", err)
	}
	if got := r.phoneGets(); got != "Box: back." {
		t.Fatalf("phone got %q", got)
	}
	// Unbound (nothing recorded) is set up the same way; the modem
	// restarts to read the cleared record.
	r.mu.Lock()
	r.iccid = ""
	dev := r.devs[len(r.devs)-1]
	r.mu.Unlock()
	dev.Unplug()
	r.waitNote(func(n string) bool { return strings.HasSuffix(n, "Set it up below.") })
	tag, _ = r.link.SIM()
	if err := r.link.Adopt(tag); err != nil {
		t.Fatal(err)
	}
	r.waitNote(func(n string) bool { return n == "" })
}

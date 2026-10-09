package at_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/modem/at"
	"github.com/ghbmrk/agentos/broker/modem/atsim"
)

// REQ: CH-1, CH-2

func openKeep(t *testing.T, dev *atsim.Device, check func(string) error, now ...func() time.Time) (*at.Modem, error) {
	t.Helper()
	cfg := at.Config{Profile: at.SIMCom, Port: dev.Port(), Number: boxNum, CountryCode: "1",
		Owner: ownerNum, KeepUntilAck: true, CheckSIM: check, Sweep: 20 * time.Millisecond}
	if len(now) > 0 {
		cfg.Now = now[0]
	}
	m, err := at.Open(context.Background(), cfg)
	if err == nil {
		t.Cleanup(func() { m.Close() })
	}
	return m, err
}

func store(t *testing.T, dev *atsim.Device, from, text string, ref byte) {
	t.Helper()
	pdus, err := at.EncodeDeliver(from, text, ref)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pdus {
		dev.StorePDU(p)
	}
}

func next(t *testing.T, m *at.Modem) modem.SMS {
	t.Helper()
	select {
	case s := <-m.Inbox():
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("no text delivered")
	}
	return modem.SMS{}
}

func waitStored(t *testing.T, dev *atsim.Device, want int) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if dev.Stored() == want {
			return
		}
	}
	t.Fatalf("%d texts stored, want %d", dev.Stored(), want)
}

// L3 on #170 (MUST-A): with KeepUntilAck a delivered text stays on the
// modem until its taker acks it, is delivered once while this Modem holds
// it (sweeps skip it), and a reader that never acked gets it again at the
// next open with the same Ref.
func TestAKeptTextStaysStoredUntilAcked(t *testing.T) {
	dev := atsim.New(at.SIMCom, "SIMCOM_SIM7600G-H", modem.NewCarrier().Line(boxNum), time.Millisecond)
	store(t, dev, ownerNum, "STOP", 1)
	store(t, dev, ownerNum, strings.Repeat("a long text in parts ", 12), 2)
	m, err := openKeep(t, dev, nil)
	if err != nil {
		t.Fatal(err)
	}
	first := map[string]string{}
	for i := 0; i < 2; i++ {
		s := next(t, m)
		if s.Ref == "" {
			t.Fatalf("no Ref on %+v", s)
		}
		first[s.Text] = s.Ref
	}
	time.Sleep(100 * time.Millisecond) // several sweeps
	select {
	case s := <-m.Inbox():
		t.Fatalf("delivered again while held: %+v", s)
	default:
	}
	if n := dev.Stored(); n < 3 {
		t.Fatalf("%d stored before any ack", n)
	}
	m.Close()

	// The reader went away without acking: the next open delivers both
	// again, with the same Refs.
	dev2 := dev.Reopen()
	m2, err := openKeep(t, dev2, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		s := next(t, m2)
		if first[s.Text] != s.Ref {
			t.Fatalf("Ref of %q changed: %q, then %q", s.Text, first[s.Text], s.Ref)
		}
		if err := m2.Ack(s.Ref); err != nil {
			t.Fatal(err)
		}
	}
	waitStored(t, dev2, 0)
}

// L3 on #170 (SHOULD 1): CheckSIM runs before any stored text is listed
// or read, so a SIM that is not the expected one keeps its texts.
func TestCheckSIMRunsBeforeAnyTextIsRead(t *testing.T) {
	dev := atsim.New(at.SIMCom, "SIMCOM_SIM7600G-H", modem.NewCarrier().Line(boxNum), time.Millisecond)
	store(t, dev, ownerNum, "STOP", 1)
	wrong := errors.New("not this SIM")
	var got string
	if _, err := openKeep(t, dev, func(iccid string) error { got = iccid; return wrong }); !errors.Is(err, wrong) {
		t.Fatalf("open: %v", err)
	}
	if got == "" || got != dev.ICCID() {
		t.Fatalf("CheckSIM was given %q, want %q", got, dev.ICCID())
	}
	for _, c := range dev.Commands() {
		if strings.HasPrefix(c, "AT+CMGL") || strings.HasPrefix(c, "AT+CMGR") || strings.HasPrefix(c, "AT+CMGD") {
			t.Fatalf("%s ran before the SIM was checked", c)
		}
	}
	if dev.Stored() != 1 {
		t.Fatalf("%d stored, want 1", dev.Stored())
	}
}

// L3 on #170 (MUST-2): only the owner's texts are kept until acked;
// anyone else's, whole or a part of a longer text, are deleted as they are
// read, so they cannot fill the modem's memory.
func TestOnlyTheOwnersTextsAreKept(t *testing.T) {
	dev := atsim.New(at.SIMCom, "SIMCOM_SIM7600G-H", modem.NewCarrier().Line(boxNum), time.Millisecond)
	store(t, dev, shopNum, "hello", 1)
	for ref := byte(2); ref < 6; ref++ {
		pdus, _ := at.EncodeDeliver(shopNum, strings.Repeat("part of a long text ", 12), ref)
		dev.StorePDU(pdus[0]) // never completed
	}
	m, err := openKeep(t, dev, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s := next(t, m); s.Ref != "" || s.Text != "hello" {
		t.Fatalf("a stranger's text was kept: %+v", s)
	}
	waitStored(t, dev, 0)
}

// L3 on #170 (N7, N11): a repeated +CMTI for a held text neither deletes
// nor delivers it again, and a second stored copy of a text is deleted.
func TestAHeldTextIsLeftAloneAndCopiesAreDeleted(t *testing.T) {
	dev := atsim.New(at.SIMCom, "SIMCOM_SIM7600G-H", modem.NewCarrier().Line(boxNum), time.Millisecond)
	pdus, _ := at.EncodeDeliver(ownerNum, "STOP", 1)
	dev.StorePDU(pdus[0])
	m, err := openKeep(t, dev, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := next(t, m)
	dev.Renotify(0)
	dev.StorePDU(pdus[0]) // the same text again: a delete that did not happen
	time.Sleep(150 * time.Millisecond)
	select {
	case again := <-m.Inbox():
		t.Fatalf("delivered again: %+v", again)
	default:
	}
	waitStored(t, dev, 1) // the held one; the copy is gone
	if err := m.Ack(s.Ref); err != nil {
		t.Fatal(err)
	}
	waitStored(t, dev, 0)
}

// L3 on #170 (N12): a long text's Ref covers every part: two texts that
// share a first part have different Refs.
func TestARefCoversEveryPart(t *testing.T) {
	var mu sync.Mutex
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	dev := atsim.New(at.SIMCom, "SIMCOM_SIM7600G-H", modem.NewCarrier().Line(boxNum), time.Millisecond)
	head := strings.Repeat("a", 153)
	store(t, dev, ownerNum, head+"first ending", 7)
	m, err := openKeep(t, dev, nil, clock)
	if err != nil {
		t.Fatal(err)
	}
	a := next(t, m)
	m.Ack(a.Ref)
	waitStored(t, dev, 0)
	mu.Lock()
	now = now.Add(time.Hour) // past the driver's memory of the first part
	mu.Unlock()
	store(t, dev, ownerNum, head+"other ending", 7)
	b := next(t, m)
	if b.Text == a.Text || b.Ref == a.Ref {
		t.Fatalf("two texts sharing a first part: %q %q, Refs %q %q", a.Text, b.Text, a.Ref, b.Ref)
	}
}

package at_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/modem/at"
	"github.com/ghbmrk/agentos/broker/modem/atsim"
)

// REQ: CH-1, CH-2

func openKeep(t *testing.T, dev *atsim.Device, check func(string) error) (*at.Modem, error) {
	t.Helper()
	m, err := at.Open(context.Background(), at.Config{Profile: at.SIMCom, Port: dev.Port(), Number: boxNum, CountryCode: "1",
		Owner: ownerNum, KeepUntilAck: true, CheckSIM: check, Sweep: 20 * time.Millisecond})
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

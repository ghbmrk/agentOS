package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/modem/at"
)

// The simulated modem behind a pseudo-terminal answers the bridge's own
// serial opener and driver, as a USB serial port would.
func TestSimulatedModemOverAPty(t *testing.T) {
	if _, err := os.Stat("/dev/ptmx"); err != nil {
		t.Skip("no /dev/ptmx")
	}
	carrier := modem.NewCarrier()
	phone := carrier.Line(phoneNum)
	m, err := plugModem(carrier, -1)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	port, err := at.OpenSerial(m.Slave)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	drv, err := at.Open(ctx, at.Config{Profile: at.SIMCom, Port: port, CountryCode: "1", KeepUntilAck: true,
		Poll: 5 * time.Millisecond, Sweep: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	// The driver's reader blocks on the slave until the master hangs up.
	defer func() { m.Close(); drv.Close() }()
	if err := drv.Send(phoneNum, "hello"); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-phone.Inbox():
		if msg.From != boxNum {
			t.Fatalf("from %q", msg.From)
		}
	case <-ctx.Done():
		t.Fatal("no text reached the phone")
	}
}

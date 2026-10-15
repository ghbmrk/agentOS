package daemon

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/modem"
)

// REQ: CH-15, CH-7

// heldLine holds every text sent once armed until let is closed, telling
// entered of the first: an owner alert still in the modem.
type heldLine struct {
	modem.Modem
	armed   atomic.Bool
	once    sync.Once
	entered chan struct{}
	let     chan struct{}
}

func (m *heldLine) Send(to, text string) error {
	if m.armed.Load() {
		m.once.Do(func() { close(m.entered) })
		<-m.let
	}
	return m.Modem.Send(to, text)
}

// Owner O34: a text a page call started after its reply (here the
// wrong-code alert) is still being sent when agentosd is told to stop;
// Wait, after which agentosd exits, does not return until it is sent.
func TestShutdownWaitsForAPageTextInTheModem(t *testing.T) {
	dir := t.TempDir()
	line := &heldLine{Modem: modem.NewCarrier().Line("+15550000009"), entered: make(chan struct{}), let: make(chan struct{})}
	cancel, d := startWith(t, dir, func(c *Config) {
		c.Auth, c.OwnerState = nil, filepath.Join(dir, "owner.json")
		c.PageSocket = &PageSocket{UID: os.Getuid()}
		c.Modem = line
	})
	defer cancel()
	line.armed.Store(true)
	sock := filepath.Join(dir, "run", localapi.Socket)
	if r := send(t, sock, localapi.OpSignIn, localapi.SignIn{Code: "000000"}); !r.OK {
		t.Fatalf("sign-in: %+v", r)
	}
	select {
	case <-line.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the wrong code was not texted")
	}
	cancel()
	waited := make(chan struct{})
	go func() { d.Wait(); close(waited) }()
	select {
	case <-waited:
		t.Fatal("Wait returned with the alert still in the modem")
	case <-time.After(300 * time.Millisecond):
	}
	close(line.let)
	select {
	case <-waited:
	case <-time.After(10 * time.Second):
		t.Fatal("Wait did not return after the alert was sent")
	}
}

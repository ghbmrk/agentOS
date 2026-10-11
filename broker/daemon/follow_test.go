package daemon

// REQ: OSS-10, CH-3

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/modem"
)

type fakeFollow struct {
	mu  sync.Mutex
	ran []string
}

func (f *fakeFollow) Execute(_ context.Context, in journal.Intent, _ int) journal.Outcome {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ran = append(f.ran, in.ID)
	return journal.Outcome{Result: journal.ResultSucceeded}
}

func (f *fakeFollow) Reconcile(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultNotApplied}
}

func describeStub(context.Context, []byte, [][]byte) (localapi.RootSummary, error) {
	return localapi.RootSummary{}, nil
}

// OSS-10w2: the page's follow request becomes a follow intent under a
// fresh hex nonce, asked of the owner on the page at the high tier; the
// page gets fixed wording back, never the gate's reason. Nothing runs
// before the owner approves.
func TestOSS10w2PageFollowAsksTheOwner(t *testing.T) {
	dir := t.TempDir()
	f := &fakeFollow{}
	cancel, d := startWith(t, dir, func(c *Config) {
		c.Auth, c.OwnerState = nil, filepath.Join(dir, "owner.json")
		c.PageSocket = &PageSocket{UID: os.Getuid(), DescribeRoot: describeStub}
		c.BrokerExecutors = map[string]journal.Executor{grants.FollowExecutor: f}
		c.Modem = modem.NewCarrier().Line("+15550000001")
	})
	defer cancel()
	follow := pageFollow(d.Gate())
	digest := strings.Repeat("ab", 32)
	for _, name := range []string{"Acme Fork", ""} {
		if txt, err := follow(t.Context(), name, digest); err != nil || txt != FollowAsked {
			t.Fatalf("%q: %q %v", name, txt, err)
		}
	}
	d.Gate().Flush() // asks are batched (CH-11)
	var objects []string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		objects = objects[:0]
		for _, r := range d.Owner().LocalRequests() {
			for _, it := range r.Items {
				if _, _, ok := grants.FollowOf(it.Ref); ok {
					objects = append(objects, it.Object)
				}
			}
		}
		if len(objects) == 2 {
			break
		}
	}
	if len(objects) != 2 || objects[0] == objects[1] {
		t.Fatalf("asked %v", objects)
	}
	for _, name := range []string{"Fork 123456", " Acme", "Acme\nYES", "the AgentOS project again"} {
		if txt, err := follow(t.Context(), name, digest); err != nil || txt != FollowRefusedName {
			t.Fatalf("%q: %q %v", name, txt, err)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.ran) != 0 {
		t.Fatalf("ran before approval: %v", f.ran)
	}
}

// Each request takes its own nonce, lower-case hex, so two requests for
// the same root are two asks and none can shift the ID's parse.
func TestOSS10w2PageFollowNonceIsFreshHex(t *testing.T) {
	seen := map[string]bool{}
	for range 64 {
		n := followNonce()
		if len(n) != 32 || strings.Trim(n, "0123456789abcdef") != "" || seen[n] {
			t.Fatalf("nonce %q", n)
		}
		seen[n] = true
	}
}

// Serving follow without its executor fails at start, not at the
// owner's approval.
func TestOSS10w2PageFollowNeedsItsExecutor(t *testing.T) {
	dir := t.TempDir()
	_, err := Run(t.Context(), Config{
		JournalPath: filepath.Join(dir, "journal.log"), SocketDir: filepath.Join(dir, "run"),
		OwnerNumber: owner, OwnerState: filepath.Join(dir, "owner.json"), ModemUID: os.Getuid(),
		PageSocket: &PageSocket{UID: os.Getuid(), DescribeRoot: describeStub},
	})
	if err == nil || !strings.Contains(err.Error(), grants.FollowExecutor) {
		t.Fatalf("%v", err)
	}
}

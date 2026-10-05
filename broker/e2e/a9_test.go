package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/guest"
	"github.com/ghbmrk/agentos/broker/meter"
)

// REQ: CH-2, DEP-1
// SPEC v0.12 IDs (PR #15; move into REQ when it merges): ARC-6
//
// TestA9OfflineScenario is the broker scenario registered in
// assurance/dep-targets.json: boot the daemon with its guest plane, take
// STOP and STATUS from the owner, serve a guest's broker tools and owner
// inbox, then restart and recover, with no network at all. tools/depaudit.py
// runs it with every connect and DNS lookup logged; any attempt off the
// box fails the gate. Model egress is not wired here, as on the box before
// the vault can be unlocked (P2-4).

const ownerNumber = "+15550000001"

// unlocked stands in for a session the owner unlocked with a code (CH-3);
// code checking is the owner channel's (P1-5), not this scenario's.
type unlocked struct{}

func (unlocked) IsOwner(from string) bool       { return from == ownerNumber }
func (unlocked) SessionUnlocked(time.Time) bool { return true }

func ownerText(t *testing.T, sock, msg string) string {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	b, _ := json.Marshal(map[string]any{"op": "message", "args": map[string]string{"from": ownerNumber, "text": msg}})
	c.Write(append(b, '\n'))
	line, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		OK     bool
		Result struct{ Replies []string }
	}
	if err := json.Unmarshal(line, &r); err != nil || !r.OK || len(r.Result.Replies) == 0 {
		t.Fatalf("%s: %s", msg, line)
	}
	return r.Result.Replies[0]
}

type broker struct {
	cancel context.CancelFunc
	d      *daemon.Daemon
	plane  *guest.Plane
}

func boot(t *testing.T, dir string) *broker {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	d, err := daemon.Run(ctx, daemon.Config{
		JournalPath: filepath.Join(dir, "journal.log"),
		SocketDir:   filepath.Join(dir, "run"),
		OwnerNumber: ownerNumber,
		ModemUID:    os.Getuid(),
		Admission:   admission.Config{CapacityMB: 4500, HeadroomMB: 600},
		Auth:        unlocked{},
	})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	mtr, err := meter.Open(meter.Config{Path: filepath.Join(dir, "meter.json"), MachineCap: meter.DefaultMachineCap, OverallCap: meter.DefaultOverallCap})
	if err != nil {
		t.Fatal(err)
	}
	plane, err := guest.New(guest.Config{
		Dir: filepath.Join(dir, "run", "guests"), Machines: &machines{private: map[string]bool{}},
		Effects: d.Engine(), Meter: mtr,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &broker{cancel: cancel, d: d, plane: plane}
}

func (b *broker) stop() {
	b.plane.Shutdown()
	b.cancel()
	b.d.Wait()
}

func guestCall(t *testing.T, b *broker, id, method, path, body string) (int, string) {
	t.Helper()
	dir, err := b.plane.Open(id)
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, guest.Socket)
	c := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	req, _ := http.NewRequest(method, "http://broker"+path, strings.NewReader(body))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

func TestA9OfflineScenario(t *testing.T) {
	dir, err := os.MkdirTemp("", "a9") // short: socket paths have a length limit
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	owner := filepath.Join(dir, "run", daemon.OwnerSocket)

	b := boot(t, dir)
	if r := ownerText(t, owner, "STOP"); !strings.HasPrefix(r, "Stopped.") {
		t.Fatalf("STOP: %q", r)
	}
	if r := ownerText(t, owner, "STATUS"); !strings.HasPrefix(r, "Stopped.") {
		t.Fatalf("STATUS: %q", r)
	}
	if code, body := guestCall(t, b, "m1", "POST", "/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`); code != 200 || !strings.Contains(body, "effect_request") {
		t.Fatalf("broker tools: %d %s", code, body)
	}
	if code, _ := guestCall(t, b, "m1", "POST", "/model/openai/v1/chat/completions", `{}`); code != http.StatusServiceUnavailable {
		t.Fatalf("model route without egress: %d", code)
	}
	if _, err := b.plane.DeliverOwner("m1", "hello", false); err != nil {
		t.Fatal(err)
	}
	if code, body := guestCall(t, b, "m1", "GET", "/owner/next", ""); code != 200 || !strings.Contains(body, "hello") {
		t.Fatalf("owner inbox: %d %s", code, body)
	}
	b.stop()

	// Recover: the journal replays, STOP still holds, RESUME works.
	b = boot(t, dir)
	defer b.stop()
	if r := ownerText(t, owner, "STATUS"); !strings.HasPrefix(r, "Stopped.") {
		t.Fatalf("STOP lost across restart: %q", r)
	}
	if code, _ := guestCall(t, b, "m1", "POST", "/mcp", `{"jsonrpc":"2.0","id":1,"method":"ping"}`); code != 200 {
		t.Fatalf("guest plane after restart: %d", code)
	}
}

// TestCH2GuestFloodLeavesStopWorking: a guest that opens thousands of
// connections to its socket cannot starve the broker process that serves
// the owner's STOP (CH-2): its open connections are capped per machine.
func TestCH2GuestFloodLeavesStopWorking(t *testing.T) {
	dir, err := os.MkdirTemp("", "flood")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	b := boot(t, dir)
	defer b.stop()
	gdir, err := b.plane.Open("m1")
	if err != nil {
		t.Fatal(err)
	}
	fds := func() int { e, _ := os.ReadDir("/proc/self/fd"); return len(e) }
	before := fds()
	var held []net.Conn
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	for i := 0; i < 3000; i++ {
		c, err := net.DialTimeout("unix", filepath.Join(gdir, guest.Socket), 20*time.Millisecond)
		if err == nil {
			held = append(held, c)
		}
	}
	time.Sleep(200 * time.Millisecond)
	// This process holds both ends: the guest's dials and what the broker
	// accepted. The broker's share is what exceeds the guest's own.
	if broker := fds() - before - len(held); broker > 32 {
		t.Fatalf("the broker holds %d descriptors for one guest's flood", broker)
	}
	t0 := time.Now()
	if r := ownerText(t, filepath.Join(dir, "run", daemon.OwnerSocket), "STOP"); !strings.HasPrefix(r, "Stopped.") {
		t.Fatalf("STOP under flood: %q", r)
	}
	if d := time.Since(t0); d > 2*time.Second {
		t.Fatalf("STOP took %v under flood", d)
	}
}

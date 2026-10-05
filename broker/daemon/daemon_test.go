package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: CH-2, ARC-2

const owner = "+15550000001"

type unlocked struct{}

func (unlocked) IsOwner(from string) bool       { return from == owner }
func (unlocked) SessionUnlocked(time.Time) bool { return true }

func start(t *testing.T, dir string) (context.CancelFunc, *Daemon) {
	return startWith(t, dir, nil)
}

func startWith(t *testing.T, dir string, mod func(*Config)) (context.CancelFunc, *Daemon) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cfg := Config{
		JournalPath: filepath.Join(dir, "journal.log"),
		SocketDir:   filepath.Join(dir, "run"),
		OwnerNumber: owner,
		ModemUID:    os.Getuid(),
		Machines:    []string{"m1"},
		Admission:   admission.Config{CapacityMB: 4500, HeadroomMB: 600},
		Auth:        unlocked{},
	}
	if mod != nil {
		mod(&cfg)
	}
	d, err := Run(ctx, cfg)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	return cancel, d
}

func send(t *testing.T, sock, op string, args any) sockets.Response {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	b, _ := json.Marshal(map[string]any{"op": op, "args": args})
	c.Write(append(b, '\n'))
	line, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var r sockets.Response
	if err := json.Unmarshal(line, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func text(t *testing.T, dir, from, msg string) []string {
	t.Helper()
	r := send(t, filepath.Join(dir, "run", OwnerSocket), "message", map[string]string{"from": from, "text": msg})
	if !r.OK {
		t.Fatalf("%s: %s", msg, r.Error)
	}
	var out struct{ Replies []string }
	if err := json.Unmarshal(r.Result, &out); err != nil {
		t.Fatal(err)
	}
	return out.Replies
}

// The broker runs here with no model, no guest runtime, no executor, and no
// network: only its journal and its sockets. STOP, STATUS, HELP, and RESUME
// must all work, and STOP must survive a restart.
func TestCH2ControlWordsOverTheOwnerSocketWithEverythingElseDown(t *testing.T) {
	dir, err := os.MkdirTemp("", "bk")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	cancel, d := start(t, dir)
	if r := text(t, dir, owner, "stop"); len(r) != 1 || !strings.HasPrefix(r[0], "Stopped.") {
		t.Fatalf("STOP: %q", r)
	}
	if r := text(t, dir, owner, "STATUS"); len(r) != 1 || !strings.HasPrefix(r[0], "Stopped.") || !strings.Contains(r[0], "Machines:") {
		t.Fatalf("STATUS: %q", r)
	}
	if r := text(t, dir, owner, "HELP"); len(r) != 1 || !strings.Contains(r[0], "RESUME") {
		t.Fatalf("HELP: %q", r)
	}
	if r := text(t, dir, owner, "plan my week"); len(r) != 1 || !strings.Contains(r[0], "not running") {
		t.Fatalf("task chat with no agent: %q", r)
	}
	if r := text(t, dir, "+15559999999", "RESUME"); len(r) != 0 {
		t.Fatalf("stranger got %q", r)
	}
	cancel()
	d.Wait()

	// Restart: STOP is in the journal, so the broker comes back stopped.
	cancel, d = start(t, dir)
	defer func() { cancel(); d.Wait() }()
	if r := text(t, dir, owner, "Status"); !strings.HasPrefix(r[0], "Stopped.") {
		t.Fatalf("STOP lost across restart: %q", r)
	}
	r := text(t, dir, owner, "RESUME")
	code := strings.Fields(strings.SplitN(r[0], "RESUME ", 2)[1])[0]
	if r := text(t, dir, owner, "RESUME "+code); !strings.HasPrefix(r[0], "Resumed.") {
		t.Fatalf("RESUME with code %s: %q", code, r)
	}
	if r := text(t, dir, owner, "STATUS"); !strings.HasPrefix(r[0], "Running.") {
		t.Fatalf("after RESUME: %q", r)
	}
}

// STATUS tells the owner, in fixed words, when the agent machine is not
// running, in place of the machine counts (UX-56-1 on #56).
func TestCH2StatusSaysWhyTheAgentIsDown(t *testing.T) {
	dir, err := os.MkdirTemp("", "bk")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	var mu sync.Mutex
	line := "Agent: starting, waiting for memory."
	cancel, d := startWith(t, dir, func(c *Config) {
		c.AgentStatus = func() string { mu.Lock(); defer mu.Unlock(); return line }
	})
	defer func() { cancel(); d.Wait() }()
	if r := text(t, dir, owner, "STATUS"); !strings.HasSuffix(r[0], " Agent: starting, waiting for memory.") {
		t.Fatalf("STATUS while the agent waits: %q", r)
	}
	mu.Lock()
	line = ""
	mu.Unlock()
	if r := text(t, dir, owner, "STATUS"); !strings.Contains(r[0], "Machines:") || strings.Contains(r[0], "Agent:") {
		t.Fatalf("STATUS while the agent runs: %q", r)
	}
}

// REQ: TIM-1, CH-11

// STATUS carries the box clock's time check on the owner socket (W9a,
// clock K7, UX-68-3).
func TestCH2StatusCarriesTheClockLine(t *testing.T) {
	dir, err := os.MkdirTemp("", "bk")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	cancel, d := startWith(t, dir, func(c *Config) {
		c.Notes = []func() string{func() string {
			return "Time check: box clock held since 09:05 (it jumped by about 3 hours, unconfirmed)."
		}}
	})
	defer func() { cancel(); d.Wait() }()
	if r := text(t, dir, owner, "STATUS"); !strings.HasSuffix(r[0], " Time check: box clock held since 09:05 (it jumped by about 3 hours, unconfirmed).") {
		t.Fatalf("STATUS: %q", r)
	}
}

func TestGuestSocketCannotSendOwnerMessages(t *testing.T) {
	dir, err := os.MkdirTemp("", "bk")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	cancel, d := start(t, dir)
	defer func() { cancel(); d.Wait() }()

	g := filepath.Join(dir, "run", GuestSocket("m1"))
	if r := send(t, g, "message", map[string]string{"from": owner, "text": "RESUME"}); r.OK {
		t.Fatal("guest socket accepted an owner message")
	}
	r := send(t, g, "whoami", nil)
	if !r.OK || !strings.Contains(string(r.Result), `"id":"m1"`) {
		t.Fatalf("whoami: %+v %s", r, r.Result)
	}
}

func TestRunRefusesMissingOwnerNumber(t *testing.T) {
	dir, _ := os.MkdirTemp("", "bk")
	defer os.RemoveAll(dir)
	if _, err := Run(context.Background(), Config{JournalPath: filepath.Join(dir, "j"), SocketDir: filepath.Join(dir, "r")}); err == nil {
		t.Fatal("started with no owner number")
	}
}

func TestRunRefusesBadMachineIDsAndAdmissionConfig(t *testing.T) {
	dir, _ := os.MkdirTemp("", "bk")
	defer os.RemoveAll(dir)
	base := Config{JournalPath: filepath.Join(dir, "j"), SocketDir: filepath.Join(dir, "r"), OwnerNumber: owner,
		Admission: admission.Config{CapacityMB: 1000, HeadroomMB: 100}}
	for _, ids := range [][]string{{"m1", "m1"}, {"../x"}, {"M1"}} {
		c := base
		c.Machines = ids
		if _, err := Run(context.Background(), c); err == nil {
			t.Errorf("accepted machines %q", ids)
		}
	}
	c := base
	c.Admission.HeadroomMB = -1
	if _, err := Run(context.Background(), c); err == nil {
		t.Error("accepted negative headroom")
	}
}

func TestOwnerSocketRefusesAnyUIDButTheModemBridge(t *testing.T) {
	dir, _ := os.MkdirTemp("", "bk")
	defer os.RemoveAll(dir)
	ctx, cancel := context.WithCancel(context.Background())
	d, err := Run(ctx, Config{JournalPath: filepath.Join(dir, "j"), SocketDir: filepath.Join(dir, "run"),
		OwnerNumber: owner, ModemUID: os.Getuid() + 1, Auth: unlocked{},
		Admission: admission.Config{CapacityMB: 1000, HeadroomMB: 100}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); d.Wait() }()
	r := send(t, filepath.Join(dir, "run", OwnerSocket), "message", map[string]string{"from": owner, "text": "RESUME"})
	if r.OK || r.Error != string(sockets.ErrPeer) {
		t.Fatalf("wrong uid reached the owner socket: %+v", r)
	}
	if d.Engine().Stopped() {
		t.Fatal("unreachable")
	}
}

func TestCH2IdleOwnerConnectionsAreClosed(t *testing.T) {
	old := ownerIdle
	ownerIdle = 100 * time.Millisecond
	defer func() { ownerIdle = old }()
	dir, _ := os.MkdirTemp("", "bk")
	defer os.RemoveAll(dir)
	cancel, d := start(t, dir)
	defer func() { cancel(); d.Wait() }()
	sock := filepath.Join(dir, "run", OwnerSocket)
	// Fill every slot with silent connections; the owner must still get in.
	var idle []net.Conn
	for i := 0; i < 8; i++ {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		idle = append(idle, c)
	}
	defer func() {
		for _, c := range idle {
			c.Close()
		}
	}()
	time.Sleep(300 * time.Millisecond)
	idle[0].SetReadDeadline(time.Now().Add(time.Second))
	if _, err := idle[0].Read(make([]byte, 1)); err == nil {
		t.Fatal("idle owner connection still open")
	}
	r := send(t, sock, "message", map[string]string{"from": owner, "text": "STOP"})
	if !r.OK || !d.Engine().Stopped() {
		t.Fatalf("STOP after idle connections: %+v", r)
	}
}

// P2-3w: the modem bridge's ops are served on the owner socket beside
// "message", which they cannot replace.
func TestOwnerSocketServesTheBridgeOps(t *testing.T) {
	dir := t.TempDir()
	var got []string
	cancel, _ := startWith(t, dir, func(c *Config) {
		c.OwnerOps = map[string]sockets.Handler{
			"state": func(_ context.Context, p sockets.Peer, _ json.RawMessage) (any, error) {
				got = append(got, p.Kind)
				return "noted", nil
			},
			"message": func(context.Context, sockets.Peer, json.RawMessage) (any, error) { return "hijacked", nil },
		}
	})
	defer cancel()
	sock := filepath.Join(dir, "run", OwnerSocket)
	if r := send(t, sock, "state", map[string]string{}); !r.OK || string(r.Result) != `"noted"` || len(got) != 1 || got[0] != "owner" {
		t.Fatalf("state: %+v %v", r, got)
	}
	if r := send(t, sock, "message", map[string]string{"from": "+15550000999", "text": "STATUS"}); string(r.Result) == `"hijacked"` {
		t.Fatal("an extra op replaced message")
	}
}

// With the bridge on, an owner text must pass the bridge's checks (line,
// sender, size, rate): the raw "message" op, which takes any sender, is
// not served, and no extra op can put it back (security F1 on #170).
func TestABridgeOnlyOwnerSocketRefusesRawMessages(t *testing.T) {
	dir := t.TempDir()
	cancel, _ := startWith(t, dir, func(c *Config) {
		c.BridgeOnly = true
		c.OwnerOps = map[string]sockets.Handler{
			"state":   func(context.Context, sockets.Peer, json.RawMessage) (any, error) { return "noted", nil },
			"message": func(context.Context, sockets.Peer, json.RawMessage) (any, error) { return "hijacked", nil },
		}
	})
	defer cancel()
	sock := filepath.Join(dir, "run", OwnerSocket)
	if r := send(t, sock, "message", map[string]string{"from": "+15550000999", "text": "STATUS"}); r.OK || !strings.Contains(r.Error, "unknown op") {
		t.Fatalf("message served with the bridge on: %+v", r)
	}
	if r := send(t, sock, "state", map[string]string{}); !r.OK {
		t.Fatalf("state: %+v", r)
	}
}

// agentosd gives the owner socket to the bridge user's group (security R3
// on #170); the bridge's uid still connects.
func TestTheOwnerSocketIsTheBridgeGroups(t *testing.T) {
	dir := t.TempDir()
	gid := os.Getgid()
	cancel, _ := startWith(t, dir, func(c *Config) { c.ModemGID = &gid })
	defer cancel()
	sock := filepath.Join(dir, "run", OwnerSocket)
	for p, want := range map[string]os.FileMode{sock: 0o660, filepath.Dir(sock): 0o711} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != want {
			t.Fatalf("%s mode %v, want %v", p, fi.Mode().Perm(), want)
		}
	}
	if r := send(t, sock, "message", map[string]string{"from": "+15550000999", "text": "STATUS"}); !r.OK {
		t.Fatalf("the bridge's uid was refused: %+v", r)
	}
}

// L3 on #170 (A15): the bridge's ops end when the bridge hangs up, so the
// outbox's long poll hands no text to a dead bridge.
func TestTheBridgeOpsEndWhenTheBridgeHangsUp(t *testing.T) {
	dir := t.TempDir()
	ended := make(chan error, 1)
	cancel, _ := startWith(t, dir, func(c *Config) {
		c.OwnerOps = map[string]sockets.Handler{
			"outbox": func(ctx context.Context, _ sockets.Peer, _ json.RawMessage) (any, error) {
				select {
				case <-ctx.Done():
					ended <- ctx.Err()
				case <-time.After(3 * time.Second):
					ended <- nil
				}
				return nil, nil
			},
		}
	})
	defer cancel()
	c, err := net.Dial("unix", filepath.Join(dir, "run", OwnerSocket))
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte(`{"op":"outbox","args":{}}` + "\n"))
	time.Sleep(50 * time.Millisecond)
	c.Close()
	if err := <-ended; err == nil {
		t.Fatal("the poll ran on after the bridge hung up")
	}
}

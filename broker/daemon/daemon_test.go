package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: CH-2, ARC-2

const owner = "+15550000001"

type unlocked struct{}

func (unlocked) IsOwner(from string) bool       { return from == owner }
func (unlocked) SessionUnlocked(time.Time) bool { return true }

func start(t *testing.T, dir string) (context.CancelFunc, *Daemon) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	d, err := Run(ctx, Config{
		JournalPath: filepath.Join(dir, "journal.log"),
		SocketDir:   filepath.Join(dir, "run"),
		OwnerNumber: owner,
		Machines:    []string{"m1"},
		Auth:        unlocked{},
	})
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

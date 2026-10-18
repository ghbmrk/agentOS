package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeclient"
	"github.com/ghbmrk/agentos/broker/localapi"
)

// REQ: P2-2w-c4c-r1-1, P2-2w-c4c-r1-2, P2-2w-c4c-r1-5, CH-12

// A synthetic owner's number (555-01xx is reserved for fiction).
const modemOwner = "+15550100100"

// logRec collects what agentosd logs, to show the number never reaches it.
type logRec struct {
	mu    sync.Mutex
	lines []string
}

func (l *logRec) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *logRec) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

// finishSetup drives setup from enrollment to finish over localui.sock,
// as the page does, and returns run's answer.
func finishSetup(t *testing.T, m setupMode, owner string) (string, error) {
	t.Helper()
	type result struct {
		owner string
		err   error
	}
	done := make(chan result, 1)
	go func() { o, err := m.run(context.Background()); done <- result{o, err} }()
	c := bridgeclient.Client{Path: filepath.Join(m.Dir, localapi.Socket)}
	call := func(op string, args, out any) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return c.Call(ctx, op, args, out)
	}
	deadline := time.Now().Add(5 * time.Second)
	for call(localapi.OpSetupProgress, nil, nil) != nil {
		if time.Now().After(deadline) {
			t.Fatal("setup never served")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := call(localapi.OpSetupEnroll, nil, &localapi.EnrollLink{}); err != nil {
		t.Fatalf("enroll %v", err)
	}
	var ok localapi.Confirmed
	if err := call(localapi.OpSetupConfirm, localapi.Confirm{Code: "123456"}, &ok); err != nil || !ok.OK {
		t.Fatalf("confirm %v %v", err, ok)
	}
	// Finish's answer may race the socket closing; run's answer decides.
	call(localapi.OpSetupFinish, localapi.Finish{Owner: owner}, nil)
	select {
	case r := <-done:
		return r.owner, r.err
	case <-time.After(5 * time.Second):
		t.Fatal("setup did not end at finish")
	}
	return "", nil
}

// modemEnvAt is a modem.env path under a fresh /etc stand-in whose
// agentos directory does not exist yet.
func modemEnvAt(t *testing.T) string {
	return filepath.Join(t.TempDir(), "etc", "agentos", "modem.env")
}

// -1: setup's finish leaves the owner's number where agentos-modem reads
// it at start, root's alone (0600) in a 0755 directory.
func TestFinishWritesTheOwnerNumberToModemEnv(t *testing.T) {
	m := newSetupMode(t)
	m.ModemEnv = modemEnvAt(t)
	if err := os.MkdirAll(filepath.Dir(filepath.Dir(m.ModemEnv)), 0o755); err != nil {
		t.Fatal(err)
	}
	dirMade := make(chan bool, 1)
	m.Progress = func() localapi.SetupProgress {
		_, err := os.Stat(filepath.Dir(m.ModemEnv))
		select {
		case dirMade <- err == nil:
		default:
		}
		return localapi.SetupProgress{Phase: "ready", Updated: true, Online: true}
	}
	if o, err := finishSetup(t, m, modemOwner); err != nil || o != modemOwner {
		t.Fatalf("run %q %v", o, err)
	}
	// The directory is made while setup runs, so the path unit watches it
	// before the file appears.
	if !<-dirMade {
		t.Fatal("/etc/agentos was not made before finish")
	}
	b, err := os.ReadFile(m.ModemEnv)
	if err != nil || string(b) != "OWNER_NUMBER="+modemOwner+"\n" {
		t.Fatalf("modem.env %q %v", b, err)
	}
	if fi, _ := os.Stat(m.ModemEnv); fi.Mode() != 0o600 {
		t.Fatalf("modem.env mode %v", fi.Mode())
	}
	if fi, _ := os.Stat(filepath.Dir(m.ModemEnv)); fi.Mode().Perm() != 0o755 {
		t.Fatalf("/etc/agentos mode %v", fi.Mode())
	}
}

// -1: every other line stays, in order, and exactly one OWNER_NUMBER line
// is left, first, however many the file held; a continued line is not a
// key, and an owner line's continuation goes with it.
func TestModemEnvKeepsOtherLines(t *testing.T) {
	p := modemEnvAt(t)
	os.MkdirAll(filepath.Dir(p), 0o755)
	old := "# the owner's\nCOUNTRY_CODE=44\nOWNER_NUMBER=+15550100199\n  OWNER_NUMBER = +15550100198\\\n+1\n" +
		"NOTE=a\\\nOWNER_NUMBER=part-of-NOTE\nBOX_NUMBER=+15550100101\\"
	os.WriteFile(p, []byte(old), 0o644)
	wrote, err := setOwnerNumber(p, modemOwner)
	if err != nil || !wrote {
		t.Fatalf("set %v %v", wrote, err)
	}
	want := "OWNER_NUMBER=" + modemOwner + "\n# the owner's\nCOUNTRY_CODE=44\nNOTE=a\\\nOWNER_NUMBER=part-of-NOTE\n" +
		"BOX_NUMBER=+15550100101\\\n"
	if b, _ := os.ReadFile(p); string(b) != want {
		t.Fatalf("modem.env\n%s\nwant\n%s", b, want)
	}
	if fi, _ := os.Stat(p); fi.Mode() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	// Already right: nothing is written, so the bridge is not restarted.
	fi1, _ := os.Stat(p)
	if wrote, err := setOwnerNumber(p, modemOwner); err != nil || wrote {
		t.Fatalf("second set %v %v", wrote, err)
	}
	if fi2, _ := os.Stat(p); !os.SameFile(fi1, fi2) {
		t.Fatal("an unchanged modem.env was replaced")
	}
}

// -1: only an E.164 number is written; a newline would add a line the
// bridge reads as another variable.
func TestModemEnvRefusesANumberThatIsNotE164(t *testing.T) {
	for _, bad := range []string{"+15551234567\nX=1", "", "15550100100", "+05550100100", "+1555010010012345"} {
		p := modemEnvAt(t)
		if wrote, err := setOwnerNumber(p, bad); err == nil || wrote {
			t.Fatalf("%q: %v %v", bad, wrote, err)
		}
		if _, err := os.Stat(filepath.Dir(p)); !os.IsNotExist(err) {
			t.Fatalf("%q: made the directory: %v", bad, err)
		}
	}
}

// -1: a modem.env that is a link, a directory or a pipe is refused, not
// followed or replaced; so is an /etc/agentos that is a link.
func TestModemEnvRefusesAFileThatIsNotRegular(t *testing.T) {
	target := filepath.Join(t.TempDir(), "elsewhere")
	os.WriteFile(target, []byte("KEEP=1\n"), 0o600)
	cases := map[string]func(p string) error{
		"link": func(p string) error { return os.Symlink(target, p) },
		"dir":  func(p string) error { return os.Mkdir(p, 0o755) },
	}
	for name, make := range cases {
		p := modemEnvAt(t)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := make(p); err != nil {
			t.Fatal(err)
		}
		if wrote, err := setOwnerNumber(p, modemOwner); err == nil || wrote {
			t.Fatalf("%s: %v %v", name, wrote, err)
		}
	}
	if b, _ := os.ReadFile(target); string(b) != "KEEP=1\n" {
		t.Fatalf("followed the link: %q", b)
	}
	p := modemEnvAt(t)
	os.MkdirAll(filepath.Dir(filepath.Dir(p)), 0o755)
	os.Symlink(filepath.Dir(target), filepath.Dir(p))
	if wrote, err := setOwnerNumber(p, modemOwner); err == nil || wrote {
		t.Fatalf("linked directory: %v %v", wrote, err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(target), "modem.env")); !os.IsNotExist(err) {
		t.Fatalf("wrote through the linked directory: %v", err)
	}
}

// -1, -2: no refusal or failure puts the number in a log line or an error.
func TestModemEnvNeverLogsTheNumber(t *testing.T) {
	logs := &logRec{}
	link := modemEnvAt(t)
	os.MkdirAll(filepath.Dir(link), 0o755)
	os.Symlink("/nonexistent", link)
	readOnly := filepath.Join(t.TempDir(), "ro")
	os.Mkdir(readOnly, 0o555)
	for _, c := range []struct{ path, owner string }{
		{link, modemOwner},
		{modemEnvAt(t), modemOwner + "\nX=1"},
		{filepath.Join(readOnly, "agentos", "modem.env"), modemOwner},
		{filepath.Join(t.TempDir(), "agentos", "modem.env", "x"), modemOwner},
	} {
		if _, err := setOwnerNumber(c.path, c.owner); err != nil && strings.Contains(err.Error(), "5550100100") {
			t.Fatalf("error carries the number: %v", err)
		}
		writeOwnerEnv(c.path, c.owner, logs.logf)
	}
	got := logs.all()
	if got == "" {
		t.Fatal("no failure was logged")
	}
	if strings.Contains(got, "5550100100") {
		t.Fatalf("log carries the number:\n%s", got)
	}
}

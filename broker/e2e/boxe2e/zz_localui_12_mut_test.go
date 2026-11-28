//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ghbmrk/agentos/broker/e2e/boxe2e/codexstub"
	"github.com/ghbmrk/agentos/broker/modem"
)

// REQ: HW-10

// MUT-kill-localui-12 (#6776): tests that kill the statement-deletion
// survivors in guesttask_linux.go and pty_linux.go.

// serveMCP serves h on a fresh unix socket, as agentosd serves a machine's
// guest plane, and returns its path.
func serveMCP(t *testing.T, h http.Handler) string {
	dir, err := os.MkdirTemp("", "lu12")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return sock
}

// mcpAnswers is a guest plane that answers each method with the JSON-RPC
// reply answer gives: a result, or an error when code is non-zero.
func mcpAnswers(answer func(method string) (result any, code int)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			http.Error(w, "bad request", 400)
			return
		}
		result, code := answer(in.Method)
		if code != 0 {
			json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": in.ID,
				"error": map[string]any{"code": code, "message": in.Method + " refused"}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": in.ID, "result": result})
	})
}

// noTools is a guest plane that initializes and offers no tool.
func noTools(method string) (any, int) {
	if method == "tools/list" {
		return map[string]any{"tools": []any{}}, 0
	}
	return map[string]any{}, 0
}

// A driver with no plan stub fails before it reaches the guest plane, even
// where the plane answers.
func TestLocalUI12ProviderTaskNeedsTheStub(t *testing.T) {
	d := &driver{guestSock: serveMCP(t, mcpAnswers(noTools))}
	if err := d.providerTask(); err == nil || err.Error() != "no plan stub" {
		t.Fatalf("no stub: %v", err)
	}
}

// With no socket of its own, the driver waits on the box's agent socket.
func TestLocalUI12ProviderTaskDefaultsToTheAgentSocket(t *testing.T) {
	if _, err := os.Lstat(agentSock); err == nil {
		t.Skip("this host has an agent socket")
	}
	old := sockWait
	sockWait = 10 * time.Millisecond
	defer func() { sockWait = old }()
	d := &driver{stub: codexstub.New()}
	err := d.providerTask()
	if err == nil || !strings.Contains(err.Error(), "lstat "+agentSock+":") {
		t.Fatalf("default socket: %v", err)
	}
}

// A refused initialize, or a refused tools/list, ends the task with that
// method's error, not with what a later call says.
func TestLocalUI12ProviderTaskStopsOnARefusedHandshake(t *testing.T) {
	for _, refused := range []string{"initialize", "tools/list"} {
		d := &driver{stub: codexstub.New(), guestSock: serveMCP(t, mcpAnswers(func(m string) (any, int) {
			if m == refused {
				return nil, -32001
			}
			return noTools(m)
		}))}
		err := d.providerTask()
		if want := refused + ": error -32001 " + refused + " refused"; err == nil || err.Error() != want {
			t.Errorf("%s refused: %v, want %q", refused, err, want)
		}
	}
}

// systemctlPrints points the driver's systemctl at a script that prints
// out and exits with code, for the test only.
func systemctlPrints(t *testing.T, out string, code int) {
	script := filepath.Join(t.TempDir(), "systemctl")
	body := "#!/bin/sh\nprintf '%s\\n' '" + out + "'\nexit " + strconv.Itoa(code) + "\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	old := tools["systemctl"]
	tools["systemctl"] = script
	t.Cleanup(func() { tools["systemctl"] = old })
}

const showCodex = "{ path=/usr/lib/agentos/agentosd ; argv[]=/usr/lib/agentos/agentosd -image codex=/usr/lib/agentos/images/codex ; ignore_errors=no }"

// A driver given no command line reads the unit's; a failed systemctl is
// an error even when it printed a command line; a failed read is
// hasImage's error.
func TestLocalUI12HasImageReadsTheUnitByDefault(t *testing.T) {
	systemctlPrints(t, showCodex, 0)
	if has, err := (&driver{}).hasImage("codex"); err != nil || !has {
		t.Fatalf("unit's command line: %v %v", has, err)
	}
	systemctlPrints(t, showCodex, 1)
	if argv, err := unitArgv(); err == nil || !strings.HasPrefix(err.Error(), "agentosd's command line: exit status 1") {
		t.Fatalf("failed systemctl: %q %v", argv, err)
	}
	gone := errors.New("argv gone")
	d := &driver{agentosdArgv: func() ([]string, error) { return nil, gone }}
	if has, err := d.hasImage("codex"); !errors.Is(err, gone) || has {
		t.Fatalf("failed read: %v %v", has, err)
	}
}

// A show line with no argv is an error, not an empty command line.
func TestLocalUI12ExecArgvNeedsArgv(t *testing.T) {
	if argv, err := execArgv("{ path=/x ; ignore_errors=no }"); err == nil || argv != nil {
		t.Fatalf("no argv: %q %v", argv, err)
	}
}

// short puts a text on one line and cuts it to logLineMax.
func TestLocalUI12ShortIsOneShortLine(t *testing.T) {
	if got := short("a\n b"); got != "a b" {
		t.Errorf("short on two lines: %q", got)
	}
	if got := short(strings.Repeat("x", logLineMax+5)); len(got) != logLineMax {
		t.Errorf("short of a long line: %d bytes", len(got))
	}
}

// Each call takes the next id, and a call that reaches no socket fails
// with its method named.
func TestLocalUI12CallNumbersAndFailsWithoutASocket(t *testing.T) {
	c := &mcpClient{sock: filepath.Join(t.TempDir(), "none")}
	for i := 1; i <= 2; i++ {
		if _, err := c.call("initialize", nil); err == nil || !strings.HasPrefix(err.Error(), "initialize: ") {
			t.Fatalf("no socket: %v", err)
		}
		if c.id != i {
			t.Fatalf("call %d took id %d", i, c.id)
		}
	}
}

// An answer that is not 200 OK is an error, whatever its body says.
func TestLocalUI12CallRefusesANon200Answer(t *testing.T) {
	sock := serveMCP(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	c := &mcpClient{sock: sock}
	if res, err := c.call("initialize", nil); err == nil || err.Error() != "initialize: 500 <nil>" {
		t.Fatalf("500: %s %v", res, err)
	}
}

// A call closes the answer it read: an answer past the 1 MiB it reads is
// cut off, so the guest plane's writer stops instead of waiting out the
// client's timeout.
func TestLocalUI12CallClosesTheAnswer(t *testing.T) {
	done := make(chan struct{})
	sock := serveMCP(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		defer close(done)
		chunk := make([]byte, 64<<10)
		for i := 0; i < 256; i++ { // 16 MiB
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	c := &mcpClient{sock: sock}
	if _, err := c.call("initialize", nil); err == nil || err.Error() != "initialize: unreadable answer" {
		t.Fatalf("long answer: %v", err)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the answer was left open: the guest plane is still writing")
	}
}

// A uid of 0 or more is given the slave, mode 0600; a uid the process may
// not give it fails the plug.
func TestLocalUI12PlugModemGivesTheSlave(t *testing.T) {
	if _, err := os.Stat("/dev/ptmx"); err != nil {
		t.Skip("no /dev/ptmx")
	}
	if os.Getuid() != 0 {
		m, err := plugModem(modem.NewCarrier(), os.Getuid()+1)
		if err == nil {
			m.Close()
			t.Fatal("plugged with a slave given to another user")
		}
		return
	}
	const uid = 4242
	m, err := plugModem(modem.NewCarrier(), uid)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	var st unix.Stat_t
	if err := unix.Stat(m.Slave, &st); err != nil {
		t.Fatal(err)
	}
	if st.Uid != uid || st.Mode&0o777 != 0o600 {
		t.Fatalf("slave owner %d mode %o", st.Uid, st.Mode&0o777)
	}
}

// Close closes the held slave as well as the master.
func TestLocalUI12CloseReleasesTheSlave(t *testing.T) {
	if _, err := os.Stat("/dev/ptmx"); err != nil {
		t.Skip("no /dev/ptmx")
	}
	m, err := plugModem(modem.NewCarrier(), -1)
	if err != nil {
		t.Fatal(err)
	}
	f, ok := m.hold.(*os.File)
	if !ok {
		m.Close()
		t.Fatalf("held slave %T", m.hold)
	}
	m.Close()
	if err := f.Close(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("held slave still open after Close: %v", err)
	}
}

const fdChildEnv = "BOXE2E_LOCALUI12_FDS"

// plugUnderFdLimit runs in a child process (fdChildEnv set to k): it lets
// the process hold only descriptors below its lowest free one plus k,
// plugs a modem, and prints what plugModem returned as one line. "polled"
// says the runtime's poller already held descriptors, so the count says
// nothing.
func plugUnderFdLimit(k int) string {
	carrier := modem.NewCarrier()
	a, err := unix.Dup(2)
	if err != nil {
		return "dup: " + err.Error()
	}
	unix.Close(a)
	for fd := 0; fd < a+16; fd++ {
		if l, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd)); err == nil && strings.Contains(l, "eventpoll") {
			return "polled"
		}
	}
	var old unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &old); err != nil {
		return "getrlimit: " + err.Error()
	}
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{Cur: uint64(a + k), Max: old.Max}); err != nil {
		return "setrlimit: " + err.Error()
	}
	m, err := plugModem(carrier, -1)
	unix.Setrlimit(unix.RLIMIT_NOFILE, &old)
	var pe *fs.PathError
	switch {
	case err == nil:
		m.Close()
		return "plugged"
	case errors.As(err, &pe) && pe.Op == "open" && strings.HasPrefix(pe.Path, "/dev/pts/") && errors.Is(err, unix.EMFILE):
		return "slave EMFILE"
	case err == unix.EMFILE:
		return "ptmx EMFILE"
	}
	return "other: " + err.Error()
}

// Out of descriptors, plugModem fails with the open that ran out: of
// /dev/ptmx when none is left, of the slave when only the master's and the
// poller's fit.
func TestLocalUI12PlugModemUnderAnFdLimit(t *testing.T) {
	if k := os.Getenv(fdChildEnv); k != "" {
		n, _ := strconv.Atoi(k)
		os.Stdout.WriteString("localui12: " + plugUnderFdLimit(n) + "\n")
		return
	}
	if _, err := os.Stat("/dev/ptmx"); err != nil {
		t.Skip("no /dev/ptmx")
	}
	// once is one child's result at k; a child stopped at its minute, or
	// killed by the runtime's throw when its poller started inside the
	// limit, reads "no result". The child gets no -test.timeout: its timer
	// would start the poller before the plug.
	once := func(k int) string {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLocalUI12PlugModemUnderAnFdLimit$", "-test.count=1")
		cmd.Env = append(os.Environ(), fdChildEnv+"="+strconv.Itoa(k))
		out, _ := cmd.Output()
		for _, l := range strings.Split(string(out), "\n") {
			if r, ok := strings.CutPrefix(l, "localui12: "); ok {
				return r
			}
		}
		return "no result"
	}
	// child is the first result at k from a child whose poller had not
	// started before the plug: any timer can start it first, so such a
	// child, or one the runtime's throw stopped, is run again, a bounded
	// number of times. "polled" means every attempt's poller had started;
	// past k=0 that is a miss, not a skip, so a mutant cannot skip it.
	child := func(k int) string {
		got := ""
		for i := 0; i < 8; i++ {
			if got = once(k); got != "polled" && got != "no result" {
				return got
			}
		}
		return got
	}
	if got := child(0); got == "polled" {
		t.Skip("the runtime's poller holds descriptors before the plug")
	} else if got != "ptmx EMFILE" {
		t.Fatalf("no descriptor left: %s, want the open of /dev/ptmx refused", got)
	}
	var seen []string
	for k := 1; k <= 8; k++ {
		got := child(k)
		if got == "slave EMFILE" {
			return
		}
		seen = append(seen, strconv.Itoa(k)+": "+got)
	}
	t.Fatalf("no limit failed the slave's open: %s", strings.Join(seen, "; "))
}

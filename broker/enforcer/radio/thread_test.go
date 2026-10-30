package radio_test

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/radio"
	"github.com/ghbmrk/agentos/broker/enforcer/radio/confine"
	"github.com/ghbmrk/agentos/broker/enforcer/radio/thread"
)

// REQ: NET-2

// mdnsArg makes this test binary a stand-in for the Matter controller: on
// each read it asks mDNS on infra0 for one service type and reports the
// instances it heard.
const mdnsArg = "radio-probe-mdns"

// The test binary's other roles, re-executed by confine; TestMain (package
// radio) runs the trampoline first, so these run confined.
func init() {
	switch {
	case len(os.Args) == 2 && os.Args[1] == thread.AdapterArg:
		if err := thread.Adapter(); err != nil {
			fmt.Fprintf(os.Stderr, "adapter: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	case len(os.Args) == 3 && os.Args[1] == mdnsArg:
		radio.NewServer(radio.StackThread, os.NewFile(3, "interface")).Serve(func(radio.Request) ([]byte, radio.Code) {
			names, err := browse(os.Args[2], thread.Infra)
			if err != nil {
				fmt.Fprintf(os.Stderr, "mdns: %v\n", err)
			}
			b, _ := json.Marshal(names)
			return b, radio.CodeOK
		})
		os.Exit(0)
	}
}

// fakeDaemon is ot-daemon's command socket: it records each command and
// answers from answers (default Done).
type fakeDaemon struct {
	mu      sync.Mutex
	got     []string
	answers map[string]string
}

func (f *fakeDaemon) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.got)
}

func startFake(t *testing.T, answers map[string]string) (*fakeDaemon, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), thread.Socket)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &fakeDaemon{answers: answers}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					cmd := strings.TrimSuffix(line, "\n")
					f.mu.Lock()
					f.got = append(f.got, cmd)
					a, ok := f.answers[cmd]
					f.mu.Unlock()
					if !ok {
						a = "Done\r\n"
					}
					io.WriteString(c, "> "+a)
				}
			}()
		}
	}()
	return f, path
}

var network = radio.Device{Name: thread.Network, Stack: radio.StackThread}

// adapter runs Serve against the fake and returns a host attached to it.
func adapter(t *testing.T, sock string, devices ...radio.Device) (*radio.Host, chan error) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	syscall.SetNonblock(fds[0], true)
	ours, theirs := os.NewFile(uintptr(fds[0]), "host"), os.NewFile(uintptr(fds[1]), "adapter")
	done := make(chan error, 1)
	go func() { done <- thread.Serve(sock, theirs, time.Second) }()
	h, err := radio.NewHost(radio.Config{Devices: devices, Timeout: 5 * time.Second,
		Notify: func(radio.Notification) {}, Log: func(string) {}})
	if err != nil {
		t.Fatal(err)
	}
	h.Attach(radio.StackThread, ours)
	t.Cleanup(func() { ours.Close() })
	return h, done
}

var bringUp = []string{"dataset active -x", "dataset init new", "dataset commit active", "srp server enable", "ifconfig up", "thread start"}

// TestStackOnlyDeclaredOps (NET-2 Confined radio stacks), Thread's row:
// Thread declares only the read of its network; the host refuses every
// other op before the adapter sees it, the adapter refuses a read of any
// other device, and ot-daemon receives only the adapter's closed list of
// commands, whatever the host asks. A hostile answer from ot-daemon is a
// failed read, never passed through. Catches a wide adapter.
func TestStackOnlyDeclaredOps(t *testing.T) {
	t.Run("thread", func(t *testing.T) {
		f, sock := startFake(t, map[string]string{
			"dataset active -x": "Error 23: NotFound\r\n",
			"state":             "leader\r\nDone\r\n",
		})
		other := radio.Device{Name: "lock", Stack: radio.StackThread}
		h, _ := adapter(t, sock, network, other)
		b, err := h.State(thread.Network)
		if err != nil || string(b) != `{"Role":"leader"}` {
			t.Fatalf("read: %s, %v", b, err)
		}
		if _, err := h.State(other.Name); !errors.Is(err, radio.ErrRefused) {
			t.Errorf("read of another device: %v, want refused", err)
		}
		for _, op := range []radio.Op{radio.OpOn, radio.OpOff, radio.OpLevel, radio.OpLock, radio.OpShut, radio.OpClose,
			radio.OpReturnToDock, radio.OpConnect, radio.OpDisconnect, radio.OpWrite, radio.OpSubscribe} {
			req := radio.Request{Op: op, Device: thread.Network}
			switch op {
			case radio.OpLevel:
				req.Level = 1
			case radio.OpWrite:
				req.Char, req.Data = "c", []byte{1}
			case radio.OpSubscribe:
				req.Char = "c"
			}
			if _, err := h.Call(req); !errors.Is(err, radio.ErrNotDeclared) {
				t.Errorf("%s: %v, want not declared", op, err)
			}
		}
		got := f.commands()
		if want := append(slices.Clone(bringUp), "state"); !slices.Equal(got, want) {
			t.Errorf("ot-daemon got %q, want %q", got, want)
		}
		for _, c := range got {
			if !slices.Contains(thread.Commands, c) {
				t.Errorf("%q is not on the adapter's list", c)
			}
		}
	})

	t.Run("a formed network is not formed again", func(t *testing.T) {
		f, sock := startFake(t, map[string]string{"dataset active -x": "0e080000000000010000\r\nDone\r\n"})
		h, _ := adapter(t, sock, network)
		h.State(thread.Network)
		if got := f.commands(); slices.Contains(got, "dataset init new") {
			t.Errorf("an existing dataset was replaced: %q", got)
		}
	})

	for _, c := range []struct{ what, answer string }{
		{"a role off the list", "leader; anything\r\nDone\r\n"},
		{"two lines", "leader\r\nrouter\r\nDone\r\n"},
		{"an error", "Error 7: InvalidArgs\r\n"},
		{"no end", strings.Repeat("leader\r\n", 40) + "Done\r\n"},
		{"a long line", strings.Repeat("x", 2000) + "\r\nDone\r\n"},
	} {
		t.Run("hostile ot-daemon: "+c.what, func(t *testing.T) {
			f, sock := startFake(t, map[string]string{"state": c.answer})
			h, _ := adapter(t, sock, network)
			if b, err := h.State(thread.Network); err == nil {
				t.Errorf("read passed %q through", b)
			}
			// What the bad answer left unread never answers the next read:
			// a fault ends the session, and the next read opens another.
			f.mu.Lock()
			f.answers["state"] = "child\r\nDone\r\n"
			f.mu.Unlock()
			if b, err := h.State(thread.Network); err != nil || string(b) != `{"Role":"child"}` {
				t.Errorf("the read after it: %s, %v", b, err)
			}
		})
	}

	t.Run("bring-up fails closed", func(t *testing.T) {
		_, sock := startFake(t, map[string]string{"thread start": "Error 13: InvalidState\r\n"})
		_, done := adapter(t, sock, network)
		select {
		case err := <-done:
			if err == nil {
				t.Error("the adapter served after ot-daemon refused to start")
			}
		case <-time.After(5 * time.Second):
			t.Error("the adapter served after ot-daemon refused to start")
		}
	})
}

// TestSrpReachesController (NET-2 Confined radio stacks; spikes/ENF-radio
// consequence 1): ot-daemon, built by build-ot.sh and run under
// confine.Thread with a simulated radio, forms a network through the
// adapter; a simulated Thread node joins it and registers a service over
// SRP; and a process in the Matter controller's profile, joined to the
// Thread namespace, resolves that service over mDNS on infra0, the
// namespace having no LAN interface. Catches the spike's one unverified
// inference (that ot-daemon advertises on a dummy link).
func TestSrpReachesController(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	src := os.Getenv("AGENTOS_OT_BIN")
	if src == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("AGENTOS_OT_BIN unset: build it with broker/enforcer/radio/thread/build-ot.sh")
		}
		t.Skip("AGENTOS_OT_BIN unset (broker/enforcer/radio/thread/build-ot.sh)")
	}
	const uid, matterUID = 4243, 4244
	root, err := os.MkdirTemp("", "thread")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	os.Chmod(root, 0o755)
	bin := filepath.Join(root, "bin")
	state := filepath.Join(root, "state")
	os.Mkdir(bin, 0o755)
	os.Mkdir(state, 0o700)
	if err := os.Chown(state, uid, uid); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"ot-daemon", "ot-rcp", "ot-cli-ftd"} {
		copyExe(t, filepath.Join(src, f), filepath.Join(bin, f))
	}
	self := filepath.Join(bin, "radio.test")
	copyExe(t, os.Args[0], self)

	args, err := thread.DaemonArgs("spinel+hdlc+forkpty://"+filepath.Join(bin, "ot-rcp")+"?forkpty-arg=1", state, true)
	if err != nil {
		t.Fatal(err)
	}
	logs := &logWriter{t: t}
	daemon, iface, err := confine.Start(confine.Spec{Profile: confine.Thread(uid, uid), Path: filepath.Join(bin, "ot-daemon"),
		Args: args, Dir: state, Self: self, Stderr: logs})
	if err != nil {
		t.Fatal(err)
	}
	iface.Close()
	defer daemon.Stop()
	ad, conn, err := confine.Start(confine.Spec{Profile: confine.ThreadAdapter(uid, uid), Path: self,
		Args: []string{thread.AdapterArg}, Dir: state, Self: self, Stderr: logs})
	if err != nil {
		t.Fatal(err)
	}
	defer ad.Stop()
	h, err := radio.NewHost(radio.Config{Devices: []radio.Device{network}, Timeout: 15 * time.Second,
		Notify: func(radio.Notification) {}, Log: func(s string) { logs.Write([]byte(s)) }})
	if err != nil {
		t.Fatal(err)
	}
	h.Attach(radio.StackThread, conn)
	role := ""
	for end := time.Now().Add(90 * time.Second); role != `{"Role":"leader"}` && time.Now().Before(end); time.Sleep(time.Second) {
		b, err := h.State(thread.Network)
		role = string(b)
		if err != nil {
			t.Logf("read: %v", err)
		}
	}
	if role != `{"Role":"leader"}` {
		t.Fatalf("the network did not form: %s", role)
	}

	// The test, as root, reads the dataset off ot-daemon's socket to hand
	// to the simulated node (the adapter never returns it).
	dataset, err := ask(filepath.Join(state, thread.Socket), "dataset active -x")
	if err != nil || len(dataset) != 1 {
		t.Fatalf("dataset: %q %v", dataset, err)
	}

	// The simulated node shares the namespace's lo with the simulated RCP.
	nodeDir := filepath.Join(root, "node")
	os.MkdirAll(filepath.Join(nodeDir, "tmp"), 0o755)
	node := exec.Command(filepath.Join(bin, "ot-cli-ftd"), "2")
	node.Dir = nodeDir
	node.Stdout, node.Stderr = logs, logs
	stdin, err := node.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := daemon.InNet(node.Start); err != nil {
		t.Fatal(err)
	}
	defer func() { node.Process.Kill(); node.Wait() }()
	for _, c := range []string{"dataset set active " + dataset[0], "ifconfig up", "thread start",
		"srp client host name agentos-node", "srp client host address auto",
		"srp client service add agentos-light _agentos._udp 4242", "srp client autostart enable"} {
		fmt.Fprintf(stdin, "%s\n", c)
		time.Sleep(200 * time.Millisecond)
	}

	matter, mconn, err := confine.Start(confine.Spec{Profile: confine.Matter(matterUID, matterUID), Net: daemon,
		Path: self, Args: []string{mdnsArg, "_agentos._udp"}, Self: self, Stderr: logs})
	if err != nil {
		t.Fatal(err)
	}
	defer matter.Stop()
	mh, err := radio.NewHost(radio.Config{Devices: []radio.Device{network}, Timeout: 15 * time.Second,
		Notify: func(radio.Notification) {}, Log: func(string) {}})
	if err != nil {
		t.Fatal(err)
	}
	mh.Attach(radio.StackThread, mconn)
	var heard []string
	for end := time.Now().Add(120 * time.Second); time.Now().Before(end); time.Sleep(2 * time.Second) {
		b, err := mh.State(thread.Network)
		if err != nil {
			t.Fatalf("the Matter probe: %v", err)
		}
		heard = nil
		json.Unmarshal(b, &heard)
		if slices.Contains(heard, "agentos-light._agentos._udp.local") {
			return
		}
	}
	logs.dump()
	t.Fatalf("the Matter controller's namespace did not resolve the SRP service; heard %q", heard)
}

// ask sends one command to ot-daemon's socket and returns its lines.
func ask(sock, cmd string) ([]string, error) {
	c, err := net.Dial("unix", sock)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(c, "%s\n", cmd)
	r := bufio.NewReader(c)
	var out []string
	for {
		l, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		l = strings.TrimPrefix(strings.TrimRight(l, "\r\n"), "> ")
		switch {
		case l == "Done":
			return out, nil
		case strings.HasPrefix(l, "Error"):
			return nil, errors.New(l)
		case l != "":
			out = append(out, l)
		}
	}
}

func copyExe(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o755); err != nil {
		t.Fatal(err)
	}
}

// logWriter keeps the stacks' output for a failure.
type logWriter struct {
	t  *testing.T
	mu sync.Mutex
	b  []byte
}

func (w *logWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.b = append(w.b, p...)
	return len(p), nil
}

func (w *logWriter) dump() {
	w.mu.Lock()
	defer w.mu.Unlock()
	b := w.b
	if len(b) > 64<<10 {
		b = b[len(b)-64<<10:]
	}
	w.t.Logf("stacks' output (last 64 KiB):\n%s", b)
}

// browse sends one legacy-unicast mDNS query (RFC 6762 §6.7: from a port
// other than 5353, so the answer comes back unicast) for service's PTR
// records on link ifname and returns the instance names answered within
// two seconds.
func browse(service, ifname string) ([]string, error) {
	c, err := net.ListenPacket("udp6", "[::]:0")
	if err != nil {
		return nil, err
	}
	defer c.Close()
	q := []byte{0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(service+".local", ".") {
		q = append(append(q, byte(len(label))), label...)
	}
	q = append(q, 0, 0, 12, 0, 1) // PTR, IN
	dst := &net.UDPAddr{IP: net.ParseIP("ff02::fb"), Port: 5353, Zone: ifname}
	if _, err := c.WriteTo(q, dst); err != nil {
		return nil, err
	}
	var names []string
	buf := make([]byte, 9000)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		n, _, err := c.ReadFrom(buf)
		if err != nil {
			return names, nil // the deadline ends the browse
		}
		for _, name := range ptrs(buf[:n]) {
			if !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
	}
}

// ptrs returns the targets of a DNS message's PTR answers; a malformed
// message yields what parsed before the fault.
func ptrs(m []byte) []string {
	if len(m) < 12 {
		return nil
	}
	qd, an := binary.BigEndian.Uint16(m[4:]), binary.BigEndian.Uint16(m[6:])
	off := 12
	for range qd {
		_, n, ok := dnsName(m, off)
		if !ok || n+4 > len(m) {
			return nil
		}
		off = n + 4
	}
	var out []string
	for range an {
		_, n, ok := dnsName(m, off)
		if !ok || n+10 > len(m) {
			return out
		}
		typ, rdlen := binary.BigEndian.Uint16(m[n:]), int(binary.BigEndian.Uint16(m[n+8:]))
		rd := n + 10
		if rd+rdlen > len(m) {
			return out
		}
		if typ == 12 {
			if target, _, ok := dnsName(m, rd); ok {
				out = append(out, target)
			}
		}
		off = rd + rdlen
	}
	return out
}

// dnsName decodes the name at off, following compression pointers, and
// returns it with the offset just past it in place.
func dnsName(m []byte, off int) (string, int, bool) {
	var labels []string
	end, jumps := -1, 0
	for {
		if off >= len(m) {
			return "", 0, false
		}
		l := int(m[off])
		switch {
		case l == 0:
			if end < 0 {
				end = off + 1
			}
			return strings.Join(labels, "."), end, true
		case l&0xc0 == 0xc0:
			if off+1 >= len(m) || jumps > 16 {
				return "", 0, false
			}
			if end < 0 {
				end = off + 2
			}
			off, jumps = int(binary.BigEndian.Uint16(m[off:])&0x3fff), jumps+1
		default:
			if off+1+l > len(m) {
				return "", 0, false
			}
			labels = append(labels, string(m[off+1:off+1+l]))
			off += 1 + l
		}
	}
}

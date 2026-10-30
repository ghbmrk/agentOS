package ble

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/radio"
	"github.com/ghbmrk/agentos/broker/enforcer/radio/confine"
)

// REQ: NET-2

const (
	testUUID    = "00002a9d-0000-1000-8000-00805f9b34fb" // synthetic measurement characteristic
	controlUUID = "00002a9f-0000-1000-8000-00805f9b34fb"
	scaleAddr   = "AA:BB:CC:DD:EE:FF" // synthetic
	scalePath   = ObjectPath("/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF")
	measurePath = scalePath + "/service0010/char0011"
	controlPath = scalePath + "/service0010/char0014"
	bluezName   = ":1.0"
)

// stackArg makes this test binary the BLE stack (TestNoRawHCI,
// TestBusPolicyRefusesUndeclaredCalls).
const stackArg = "ble-test-stack"

func TestMain(m *testing.M) {
	confine.Trampoline()
	if len(os.Args) == 4 && os.Args[1] == stackArg {
		os.Exit(testStack(os.Args[2], os.Args[3]))
	}
	os.Exit(m.Run())
}

// testStack is the stack as the enforcer runs it, after two probes of what
// an exploit inside it would try first: a raw HCI socket, and, when probe
// is "bus", a BlueZ call outside busCalls on its own bus connection. Either
// one succeeding exits before the stack serves, so the host's call fails.
func testStack(cfg, probe string) int {
	fd, err := syscall.Socket(31 /* AF_BLUETOOTH */, syscall.SOCK_RAW, 1 /* BTPROTO_HCI */)
	if err != syscall.EPERM {
		fmt.Fprintf(os.Stderr, "raw HCI socket: fd %d, %v\n", fd, err)
		return 3
	}
	if probe == "bus" {
		c, _ := ParseConfig(cfg)
		b, err := Dial(c.Bus, func(*Message) {})
		if err != nil {
			fmt.Fprintf(os.Stderr, "dial: %v\n", err)
			return 4
		}
		_, err = b.Call(bluez, "/org/bluez/hci0", "org.bluez.Adapter1", "StartDiscovery", "", 5*time.Second)
		var ce *CallError
		if !errors.As(err, &ce) || ce.Name != "org.freedesktop.DBus.Error.AccessDenied" {
			fmt.Fprintf(os.Stderr, "StartDiscovery: %v\n", err)
			return 4
		}
		b.Close()
	}
	if err := Main([]string{cfg}); err != nil {
		fmt.Fprintf(os.Stderr, "stack: %v\n", err)
	}
	return 0
}

type call struct {
	Path          ObjectPath
	Iface, Member string
	Body          []any
}

// fakeBluez is BlueZ for one adapter with one known device, the scale, on
// a private bus socket. Run as a bus (serve), it is also the bus driver;
// joined to a real dbus-daemon (join), it owns org.bluez there. It records
// every call that reaches BlueZ and the uid of each peer.
type fakeBluez struct {
	t         *testing.T
	mu        sync.Mutex
	calls     []call
	uids      []uint32
	serial    uint32
	connected bool
	rules     []string // AddMatch rules
	badSerial bool     // a call's serial was not one more than the last
	wmu       sync.Mutex
}

func (f *fakeBluez) record() []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// serve listens on path as the bus itself.
func (f *fakeBluez) serve(path string) {
	ln, err := net.Listen("unix", path)
	if err != nil {
		f.t.Fatal(err)
	}
	os.Chmod(path, 0o666)
	f.t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.conn(c)
		}
	}()
}

func (f *fakeBluez) conn(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	line, err := r.ReadString('\n')
	if err != nil {
		return
	}
	raw, err := c.(*net.UnixConn).SyscallConn()
	if err != nil {
		return
	}
	var cred *syscall.Ucred
	raw.Control(func(fd uintptr) { cred, _ = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED) })
	uid, _ := hex.DecodeString(strings.TrimSpace(strings.TrimPrefix(line, "\x00AUTH EXTERNAL ")))
	if cred == nil || string(uid) != strconv.Itoa(int(cred.Uid)) {
		io.WriteString(c, "REJECTED EXTERNAL\r\n")
		return
	}
	f.mu.Lock()
	f.uids = append(f.uids, cred.Uid)
	f.mu.Unlock()
	io.WriteString(c, "OK 0123456789abcdef0123456789abcdef\r\n")
	if l, err := r.ReadString('\n'); err != nil || l != "BEGIN\r\n" {
		return
	}
	f.loop(c, r, true)
}

// join connects to a real bus at path as root and takes org.bluez.
func (f *fakeBluez) join(path string) {
	c, err := net.Dial("unix", path)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { c.Close() })
	r := bufio.NewReader(c)
	io.WriteString(c, "\x00AUTH EXTERNAL "+hex.EncodeToString([]byte(strconv.Itoa(os.Getuid())))+"\r\n")
	if l, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(l, "OK ") {
		f.t.Fatalf("fake BlueZ auth: %q %v", l, err)
	}
	io.WriteString(c, "BEGIN\r\n")
	for _, m := range []*Message{
		{Type: typeCall, Path: "/org/freedesktop/DBus", Interface: busDriver, Member: "Hello", Destination: busDriver},
		{Type: typeCall, Path: "/org/freedesktop/DBus", Interface: busDriver, Member: "RequestName", Destination: busDriver, Sig: "su", Body: []any{bluez, uint32(4)}},
	} {
		f.send(c, m)
		for {
			got, err := readMessage(r)
			if err != nil {
				f.t.Fatal(err)
			}
			if got.Type == typeError {
				f.t.Fatalf("fake BlueZ %s: %s", m.Member, got.ErrorName)
			}
			if got.Type == typeReturn && got.ReplySerial == m.Serial {
				break
			}
		}
	}
	go f.loop(c, r, false)
}

func (f *fakeBluez) send(c net.Conn, m *Message) {
	f.wmu.Lock()
	defer f.wmu.Unlock()
	f.serial++
	m.Serial = f.serial
	b, err := m.Encode()
	if err != nil {
		panic(err)
	}
	c.Write(b)
}

func (f *fakeBluez) loop(c net.Conn, r *bufio.Reader, driver bool) {
	next := uint32(1)
	for {
		m, err := readMessage(r)
		if err != nil {
			return
		}
		if m.Type != typeCall {
			continue
		}
		if driver && m.Serial != next {
			f.mu.Lock()
			f.badSerial = true
			f.mu.Unlock()
		}
		next++
		reply := &Message{Type: typeReturn, ReplySerial: m.Serial, Destination: m.Sender}
		fail := func(name string) { reply.Type, reply.ErrorName = typeError, name }
		var after []*Message
		switch {
		case driver && m.Destination == busDriver:
			reply.Sender = busDriver
			switch m.Member {
			case "Hello":
				reply.Sig, reply.Body = "s", []any{":1.1"}
			case "GetNameOwner":
				reply.Sig, reply.Body = "s", []any{bluezName}
			case "AddMatch":
				f.mu.Lock()
				f.rules = append(f.rules, m.Body[0].(string))
				f.mu.Unlock()
			default:
				fail("org.freedesktop.DBus.Error.UnknownMethod")
			}
		case m.Destination == bluez || !driver:
			if driver {
				reply.Sender = bluezName
			}
			f.mu.Lock()
			f.calls = append(f.calls, call{m.Path, m.Interface, m.Member, m.Body})
			f.mu.Unlock()
			known := m.Path == scalePath
			switch m.Interface + "." + m.Member {
			case ifaceDevice + ".Connect", ifaceDevice + ".Disconnect":
				if !known {
					fail("org.freedesktop.DBus.Error.UnknownObject")
				}
				f.mu.Lock()
				f.connected = m.Member == "Connect"
				f.mu.Unlock()
			case ifaceProps + ".Get":
				f.mu.Lock()
				reply.Sig, reply.Body = "v", []any{Variant{Sig: "b", Value: f.connected}}
				f.mu.Unlock()
			case ifaceObjMgr + ".GetManagedObjects":
				reply.Sig, reply.Body = "a{oa{sa{sv}}}", []any{managed(scalePath, map[string]string{"char0011": testUUID, "char0014": controlUUID})}
			case ifaceChar + ".WriteValue":
				// The device answers on the measurement characteristic.
				after = []*Message{propsChanged(0, bluezName, measurePath, m.Body[0].([]byte))}
			case ifaceChar + ".StartNotify":
				// A forged notification from another peer, one on a
				// characteristic nobody subscribed to, then BlueZ's own.
				forged := propsChanged(0, ":1.9", m.Path, []byte{0x66})
				other := propsChanged(0, bluezName, controlPath, []byte{0x77})
				if m.Path == controlPath {
					other.Path = measurePath
				}
				after = []*Message{forged, other, propsChanged(0, bluezName, m.Path, []byte{0x42})}
				if !driver {
					after = after[1:] // the daemon stamps the sender; it cannot be forged there
				}
			default:
				fail("org.freedesktop.DBus.Error.UnknownMethod")
			}
		default:
			fail("org.freedesktop.DBus.Error.ServiceUnknown")
		}
		f.send(c, reply)
		for _, s := range after {
			s.Destination = m.Sender
			if !driver {
				s.Sender = ""
			}
			f.send(c, s)
		}
	}
}

// managed is GetManagedObjects' answer for one device whose
// characteristics are named by their path's last element.
func managed(dev ObjectPath, chars map[string]string) []any {
	out := []any{Entry{Key: dev, Value: []any{Entry{Key: ifaceDevice, Value: []any{
		Entry{Key: "Address", Value: Variant{Sig: "s", Value: scaleAddr}}}}}}}
	for _, n := range slices.Sorted(func(yield func(string) bool) {
		for k := range chars {
			if !yield(k) {
				return
			}
		}
	}) {
		out = append(out, Entry{Key: dev + "/service0010/" + ObjectPath(n), Value: []any{Entry{Key: ifaceChar, Value: []any{
			Entry{Key: "UUID", Value: Variant{Sig: "s", Value: strings.ToUpper(chars[n])}},
			Entry{Key: "Service", Value: Variant{Sig: "o", Value: dev + "/service0010"}}}}}})
	}
	return out
}

func newFuzzStack() *stack {
	s := &stack{devices: map[string]Device{}, log: io.Discard, owner: bluezName,
		chars: map[[2]string]ObjectPath{}, subs: map[ObjectPath]sub{measurePath: {"scale", "measure"}}}
	s.srv = radio.NewServer(radio.StackBLE, nopConn{})
	s.bus = &Bus{conn: nopNetConn{}, calls: map[uint32]chan *Message{}, done: make(chan struct{})}
	return s
}

type nopConn struct{}

func (nopConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (nopConn) Write(b []byte) (int, error) { return len(b), nil }
func (nopConn) Close() error                { return nil }

func testConfig(bus string) Config {
	return Config{Bus: bus, Adapter: "hci0", Devices: []Device{{Name: "scale", Address: scaleAddr,
		Chars: map[string]string{"measure": testUUID, "control": controlUUID}}}}
}

// hostFor is the enforcer's radio host, naming more than the stack serves:
// a device ("lamp") and a characteristic ("firmware") the stack's own
// configuration lacks, so the stack's second check is seen.
func hostFor(t *testing.T, notes chan radio.Notification) *radio.Host {
	h, err := radio.NewHost(radio.Config{
		Devices: []radio.Device{
			{Name: "scale", Stack: radio.StackBLE, Chars: []string{"measure", "control", "firmware"}},
			{Name: "lamp", Stack: radio.StackBLE},
		},
		Notify:  func(n radio.Notification) { notes <- n },
		Log:     func(string) {},
		Timeout: 20 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// TestServesOnlyDeclaredOps (NET-2 Confined radio stacks): through the
// host, against a fake BlueZ on a private bus socket, each declared op
// reaches exactly its BlueZ method on the configured device's objects, a
// subscribed characteristic's notification reaches the host, and an op or
// characteristic off the host's list, or off the stack's own
// configuration, never reaches BlueZ. Raw frames that skip the host are
// refused by the stack too. Catches a wide BLE stack.
func TestServesOnlyDeclaredOps(t *testing.T) {
	dir := t.TempDir()
	f := &fakeBluez{t: t}
	f.serve(filepath.Join(dir, "bus"))
	hostEnd, stackEnd := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- Run(testConfig(filepath.Join(dir, "bus")), stackEnd, testLog{t}) }()
	notes := make(chan radio.Notification, 8)
	h := hostFor(t, notes)
	h.Attach(radio.StackBLE, hostEnd)

	type step struct {
		r    radio.Request
		want error
	}
	for _, s := range []step{
		// Off the host's list: refused before a byte reaches the stack.
		{radio.Request{Op: radio.OpOn, Device: "scale"}, radio.ErrNotDeclared},
		{radio.Request{Op: radio.OpLock, Device: "scale"}, radio.ErrNotDeclared},
		{radio.Request{Op: radio.OpWrite, Device: "scale", Char: "reset", Data: []byte{1}}, radio.ErrNotDeclared},
		{radio.Request{Op: radio.OpRead, Device: "kettle"}, radio.ErrUnknownDevice},
		// On the host's list, off the stack's configuration: refused by
		// the stack before the bus.
		{radio.Request{Op: radio.OpConnect, Device: "lamp"}, radio.ErrRefused},
		{radio.Request{Op: radio.OpWrite, Device: "scale", Char: "firmware", Data: []byte{1}}, radio.ErrRefused},
		{radio.Request{Op: radio.OpSubscribe, Device: "scale", Char: "firmware"}, radio.ErrRefused},
	} {
		if _, err := h.Call(s.r); !errors.Is(err, s.want) {
			t.Errorf("%s %s %s: %v, want %v", s.r.Op, s.r.Device, s.r.Char, err, s.want)
		}
	}
	if got := f.record(); len(got) != 0 {
		t.Fatalf("refused requests reached BlueZ: %+v", got)
	}

	if _, err := h.Call(radio.Request{Op: radio.OpConnect, Device: "scale"}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if b, err := h.Call(radio.Request{Op: radio.OpRead, Device: "scale"}); err != nil || !bytes.Equal(b, []byte{1}) {
		t.Fatalf("read: %x %v", b, err)
	}
	if _, err := h.Call(radio.Request{Op: radio.OpSubscribe, Device: "scale", Char: "measure"}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	select {
	case n := <-notes:
		if n.Device != "scale" || n.Char != "measure" || !bytes.Equal(n.Data, []byte{0x42}) {
			t.Errorf("notification %+v; the forged or unsubscribed one came through", n)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no notification")
	}
	if _, err := h.Call(radio.Request{Op: radio.OpWrite, Device: "scale", Char: "control", Data: []byte{1, 2}}); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case n := <-notes:
		if n.Char != "measure" || !bytes.Equal(n.Data, []byte{1, 2}) {
			t.Errorf("notification %+v", n)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no notification after the write")
	}
	// A disconnect forgets the device's subscriptions and characteristic
	// paths: after a reconnect, a write looks its characteristic up again,
	// and the device's answer on the unsubscribed measurement is dropped.
	for _, r := range []radio.Request{
		{Op: radio.OpDisconnect, Device: "scale"},
		{Op: radio.OpConnect, Device: "scale"},
		{Op: radio.OpWrite, Device: "scale", Char: "control", Data: []byte{3}},
		{Op: radio.OpRead, Device: "scale"}, // after the answer, on the same link
	} {
		if _, err := h.Call(r); err != nil {
			t.Fatalf("%s: %v", r.Op, err)
		}
	}
	if len(notes) != 0 {
		t.Errorf("notification after the disconnect: %+v", <-notes)
	}

	want := []call{
		{scalePath, ifaceDevice, "Connect", nil},
		{scalePath, ifaceProps, "Get", []any{ifaceDevice, "Connected"}},
		{"/", ifaceObjMgr, "GetManagedObjects", nil},
		{measurePath, ifaceChar, "StartNotify", nil},
		{"/", ifaceObjMgr, "GetManagedObjects", nil},
		{controlPath, ifaceChar, "WriteValue", []any{[]byte{1, 2}, []any{}}},
		{scalePath, ifaceDevice, "Disconnect", nil},
		{scalePath, ifaceDevice, "Connect", nil},
		{"/", ifaceObjMgr, "GetManagedObjects", nil},
		{controlPath, ifaceChar, "WriteValue", []any{[]byte{3}, []any{}}},
		{scalePath, ifaceProps, "Get", []any{ifaceDevice, "Connected"}},
	}
	got := f.record()
	if fmt.Sprintf("%#v", got) != fmt.Sprintf("%#v", want) {
		t.Errorf("BlueZ saw\n%#v\nwant\n%#v", got, want)
	}
	f.mu.Lock()
	rules, badSerial := slices.Clone(f.rules), f.badSerial
	f.mu.Unlock()
	if want := []string{
		"type='signal',sender='org.bluez',interface='org.freedesktop.DBus.Properties',member='PropertiesChanged',path_namespace='/org/bluez/hci0'",
		"type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged',arg0='org.bluez'",
	}; !slices.Equal(rules, want) {
		t.Errorf("match rules %q", rules)
	}
	if badSerial {
		t.Error("the stack's call serials do not count up from 1")
	}
	for _, c := range got {
		if !slices.Contains(busCalls, struct{ Iface, Member string }{c.Iface, c.Member}) {
			t.Errorf("%s.%s is outside busCalls, so the bus policy would refuse it", c.Iface, c.Member)
		}
	}

	t.Run("raw frames past the host", func(t *testing.T) {
		before := len(f.record())
		hostEnd, stackEnd := net.Pipe()
		go Run(testConfig(filepath.Join(dir, "bus")), stackEnd, testLog{t})
		defer hostEnd.Close()
		for i, frame := range []string{
			`{"ID":1,"Op":"on","Device":"scale"}`,
			`{"ID":2,"Op":"write","Device":"scale","Char":"firmware","Data":"AQ=="}`,
			`{"ID":3,"Op":"connect","Device":"lamp"}`,
			`{"ID":4,"Op":"scan","Device":"scale"}`,
			`{"ID":5,"Op":"read","Device":"scale","Char":"measure"}`,
		} {
			hostEnd.SetDeadline(time.Now().Add(10 * time.Second))
			hostEnd.Write(append(binary.BigEndian.AppendUint32(nil, uint32(len(frame))), frame...))
			var n [4]byte
			if _, err := io.ReadFull(hostEnd, n[:]); err != nil {
				t.Fatalf("frame %d: %v", i, err)
			}
			b := make([]byte, binary.BigEndian.Uint32(n[:]))
			io.ReadFull(hostEnd, b)
			var u radio.Up
			if err := json.Unmarshal(b, &u); err != nil || u.Code != radio.CodeRefused {
				t.Errorf("frame %s: answered %s", frame, b)
			}
		}
		if got := f.record(); len(got) != before {
			t.Errorf("raw frames reached BlueZ: %+v", got[before:])
		}
	})

	hostEnd.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Error("the stack outlived its host link")
	}
}

// TestStackEndsWhenBluezRestarts: BlueZ's name moving to a new owner, which
// forgets every subscription, ends the stack, so its supervisor restarts
// it rather than it serving stale state.
func TestStackEndsWhenBluezRestarts(t *testing.T) {
	s := newFuzzStack()
	b := s.bus
	s.signal(&Message{Type: typeSignal, Sender: busDriver, Interface: busDriver, Member: "NameOwnerChanged",
		Sig: "sss", Body: []any{bluez, bluezName, ":1.8"}})
	select {
	case <-b.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the stack kept serving after BlueZ changed owner")
	}
}

type nopNetConn struct{ net.Conn }

func (nopNetConn) Close() error { return nil }

// TestNotifyBounds: a notification of radio.MaxData bytes reaches the
// host; one byte more is dropped, not cut.
func TestNotifyBounds(t *testing.T) {
	var out, log bytes.Buffer
	s := newFuzzStack()
	s.srv = radio.NewServer(radio.StackBLE, bufConn{&out})
	s.log = &log
	s.signal(propsChanged(1, bluezName, measurePath, make([]byte, radio.MaxData+1)))
	if out.Len() != 0 {
		t.Errorf("a %d-byte notification was sent", radio.MaxData+1)
	}
	s.signal(propsChanged(1, bluezName, measurePath, make([]byte, radio.MaxData)))
	if out.Len() == 0 || log.Len() != 0 {
		t.Errorf("a %d-byte notification: sent %d bytes, logged %q", radio.MaxData, out.Len(), log.String())
	}
}

type bufConn struct{ *bytes.Buffer }

func (bufConn) Close() error { return nil }

// TestConfigRefusesMalformed: the stack's argument is decoded strictly.
func TestConfigRefusesMalformed(t *testing.T) {
	good, err := testConfig("/run/bus").Arg()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseConfig(good); err != nil {
		t.Fatal(err)
	}
	for _, arg := range []string{
		strings.Replace(good, `"hci0"`, `"hci0/../x"`, 1),
		strings.Replace(good, scaleAddr, "aa:bb:cc:dd:ee:ff", 1),
		strings.Replace(good, testUUID, "2a9d", 1),
		strings.Replace(good, `"scale"`, `"sc ale"`, 1),
		strings.Replace(good, `"/run/bus"`, `"run/bus"`, 1),
		strings.Replace(good, `"Adapter"`, `"Extra":1,"Adapter"`, 1),
		good + "{}",
		strings.Replace(good, `"scale"`, `"sc\u007fale"`, 1),
		strings.Replace(good, `"scale"`, `"`+strings.Repeat("s", radio.MaxName+1)+`"`, 1),
		good + strings.Repeat(" ", maxConfig+1-len(good)),
	} {
		if _, err := ParseConfig(arg); err == nil {
			t.Errorf("accepted %.80s", arg)
		}
	}
	for _, arg := range []string{
		strings.Replace(good, `"scale"`, `"sc~ale!"`, 1),
		strings.Replace(good, `"scale"`, `"`+strings.Repeat("s", radio.MaxName)+`"`, 1),
		good + strings.Repeat(" ", maxConfig-len(good)),
	} {
		if _, err := ParseConfig(arg); err != nil {
			t.Errorf("refused %.80s: %v", arg, err)
		}
	}
}

// TestNoRawHCI (NET-2 Confined radio stacks): the stack, started by
// confine.Start under confine.BLE as its own user, cannot open a raw HCI
// socket and still reaches BlueZ on the bus socket, authenticated as that
// user. Catches a BLE stack that needs, or gets, raw radio access.
func TestNoRawHCI(t *testing.T) {
	if !asRoot(t) {
		return
	}
	dir := sharedDir(t)
	f := &fakeBluez{t: t}
	f.serve(filepath.Join(dir, "bus"))
	connectConfined(t, dir, filepath.Join(dir, "bus"), "", 4242, false)
	if got := f.record(); len(got) != 1 || got[0].Member != "Connect" {
		t.Errorf("BlueZ saw %+v, want one Connect", got)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !slices.Equal(f.uids, []uint32{4242}) {
		t.Errorf("bus peers %v, want the stack's user 4242 only", f.uids)
	}
}

// TestBusPolicyRefusesUndeclaredCalls (NET-2 Confined radio stacks): on a
// real dbus-daemon whose default policy allows everything, BusPolicy for
// the stack's user makes the daemon refuse a BlueZ call outside busCalls
// (the adapter's StartDiscovery, sent by the confined process on its own
// connection) before it reaches BlueZ, while the stack's declared calls
// still go through. Catches an exploited stack using BlueZ beyond its ops.
func TestBusPolicyRefusesUndeclaredCalls(t *testing.T) {
	if !asRoot(t) {
		return
	}
	daemon, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Fatalf("dbus-daemon: %v", err)
	}
	dir := sharedDir(t)
	// dbus-daemon's policy names users, so the stack runs as a user both
	// this machine and CI's runner name: nobody.
	nobody, err := user.Lookup("nobody")
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.Atoi(nobody.Uid)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := BusPolicy("nobody")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ble.conf"), []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}
	bus := filepath.Join(dir, "bus")
	conf := `<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <listen>unix:path=` + bus + `</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow user="*"/>
    <allow own="*"/>
    <allow send_destination="*"/>
    <allow receive_type="method_call"/>
    <allow receive_type="method_return"/>
    <allow receive_type="error"/>
    <allow receive_type="signal"/>
  </policy>
  <include>` + filepath.Join(dir, "ble.conf") + `</include>
</busconfig>
`
	if err := os.WriteFile(filepath.Join(dir, "bus.conf"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(daemon, "--config-file="+filepath.Join(dir, "bus.conf"), "--nofork", "--nopidfile", "--print-address")
	cmd.Stderr = testLog{t}
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	if _, err := bufio.NewReader(out).ReadString('\n'); err != nil {
		t.Fatalf("dbus-daemon did not start: %v", err)
	}
	f := &fakeBluez{t: t}
	f.join(bus)
	connectConfined(t, dir, bus, "bus", uint32(uid), true)
	var saw []string
	for _, c := range f.record() {
		saw = append(saw, c.Member)
	}
	if want := []string{"Connect", "Get", "GetManagedObjects", "StartNotify", "GetManagedObjects", "WriteValue", "Disconnect"}; !slices.Equal(saw, want) {
		t.Errorf("BlueZ saw %v, want %v (and never StartDiscovery)", saw, want)
	}
}

// connectConfined starts the stack confined as uid (and the same gid), with probe passed to
// testStack, and connects the scale through the host; full also reads,
// subscribes (and takes the notification), writes and disconnects.
func connectConfined(t *testing.T, dir, bus, probe string, uid uint32, full bool) {
	t.Helper()
	bin := filepath.Join(dir, "ble.test")
	b, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, b, 0o755); err != nil {
		t.Fatal(err)
	}
	arg, err := testConfig(bus).Arg()
	if err != nil {
		t.Fatal(err)
	}
	if probe == "" {
		probe = "none"
	}
	proc, conn, err := confine.Start(confine.Spec{Profile: confine.BLE(uid, uid), Self: bin, Path: bin,
		Args: []string{stackArg, arg, probe}, Stderr: testLog{t}})
	if err != nil {
		t.Fatal(err)
	}
	defer proc.Stop()
	notes := make(chan radio.Notification, 8)
	h := hostFor(t, notes)
	h.Attach(radio.StackBLE, conn)
	if _, err := h.Call(radio.Request{Op: radio.OpConnect, Device: "scale"}); err != nil {
		t.Fatalf("connect through the confined stack: %v", err)
	}
	if !full {
		return
	}
	for _, r := range []radio.Request{
		{Op: radio.OpRead, Device: "scale"},
		{Op: radio.OpSubscribe, Device: "scale", Char: "measure"},
		{Op: radio.OpWrite, Device: "scale", Char: "control", Data: []byte{1}},
	} {
		if _, err := h.Call(r); err != nil {
			t.Fatalf("%s through the confined stack: %v", r.Op, err)
		}
	}
	select {
	case n := <-notes:
		if n.Char != "measure" || !bytes.Equal(n.Data, []byte{0x42}) {
			t.Errorf("notification %+v", n)
		}
	case <-time.After(10 * time.Second):
		t.Error("no notification through the bus")
	}
	if _, err := h.Call(radio.Request{Op: radio.OpDisconnect, Device: "scale"}); err != nil {
		t.Fatalf("disconnect through the confined stack: %v", err)
	}
}

// sharedDir is a directory the stack's user can reach.
func sharedDir(t *testing.T) string {
	dir, err := os.MkdirTemp("", "ble")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

const nestedEnv = "AGENTOS_BLE_USERNS"

// asRoot runs the calling test as root: directly when it is, otherwise
// again as root of a user namespace that maps the runner's subordinate ids
// (as radio's TestRadioCannotChangeRule does), so the stack can drop to
// another user. It reports whether this process should run the test.
func asRoot(t *testing.T) bool {
	t.Helper()
	if os.Geteuid() == 0 {
		return true
	}
	required := os.Getenv("CI") != "" || os.Getenv("AGENTOS_REQUIRE_NETNS") == "1"
	if _, err := exec.LookPath("newuidmap"); err != nil {
		if required {
			t.Fatalf("newuidmap missing: %v", err)
		}
		t.Skip("needs root or subordinate ids (newuidmap)")
	}
	cmd := exec.Command("unshare", "--map-root-user", "--map-auto", "--",
		os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), nestedEnv+"=1")
	out, err := cmd.CombinedOutput()
	t.Logf("as root of a user namespace:\n%s", out)
	if err != nil {
		t.Fatalf("user namespace run failed: %v", err)
	}
	return false
}

type testLog struct{ t *testing.T }

func (w testLog) Write(b []byte) (int, error) {
	w.t.Logf("%s", bytes.TrimRight(b, "\n"))
	return len(b), nil
}

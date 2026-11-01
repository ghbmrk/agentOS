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
	"runtime"
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

// testStack is the stack as the enforcer runs it, after probes of what an
// exploit inside it would try first: a raw HCI socket, and, by probe, its
// own bus connection's sends ("bus", probeSend) or receipts ("rx",
// probeReceive). Any probe failing exits before the stack serves, so the
// host's call fails.
func testStack(cfg, probe string) int {
	fd, err := syscall.Socket(31 /* AF_BLUETOOTH */, syscall.SOCK_RAW, 1 /* BTPROTO_HCI */)
	if err != syscall.EPERM {
		fmt.Fprintf(os.Stderr, "raw HCI socket: fd %d, %v\n", fd, err)
		return 3
	}
	c, _ := ParseConfig(cfg)
	probes := map[string]func(string) error{"bus": probeSend, "rx": probeReceive}
	if p := probes[probe]; p != nil {
		if err := p(c.Bus); err != nil {
			fmt.Fprintf(os.Stderr, "probe %s: %v\n", probe, err)
			return 4
		}
	}
	if err := Main([]string{cfg}); err != nil {
		fmt.Fprintf(os.Stderr, "stack: %v\n", err)
	}
	return 0
}

// testIface names the probes' messages, and testPeer the other bus
// peer's service.
const (
	testIface = "org.agentos.test"
	testPeer  = "org.agentos.test.Peer"
)

var denied = "org.freedesktop.DBus.Error.AccessDenied"

// probeSend, on its own connection, makes calls outside the policy (an
// adapter call on BlueZ, a bus driver call the stack never makes, a call on
// another service) and broadcasts a Leak signal, then marks its end with
// GetManagedObjects on "/". Each call must be refused by the bus.
func probeSend(bus string) error {
	b, err := Dial(bus, allSignals(func(*Message) {}))
	if err != nil {
		return err
	}
	defer b.Close()
	for _, c := range []struct {
		dest          string
		path          ObjectPath
		iface, member string
	}{
		{bluez, "/org/bluez/hci0", "org.bluez.Adapter1", "StartDiscovery"},
		{busDriver, "/org/freedesktop/DBus", busDriver, "ListNames"},
		{busDriver, "/org/freedesktop/DBus", busDriver, "StartServiceByName"},
		{testPeer, "/", "org.freedesktop.DBus.Peer", "Ping"},
	} {
		sig, args := Signature(""), []any(nil)
		if c.member == "StartServiceByName" {
			sig, args = "su", []any{testPeer, uint32(0)}
		}
		_, err := b.Call(c.dest, c.path, c.iface, c.member, sig, 5*time.Second, args...)
		if ce := (*CallError)(nil); !errors.As(err, &ce) || ce.Name != denied {
			return fmt.Errorf("%s.%s on %s: %v", c.iface, c.member, c.dest, err)
		}
	}
	if err := emit(b, &Message{Type: typeSignal, Path: "/", Interface: testIface, Member: "Leak"}); err != nil {
		return err
	}
	_, err = b.Call(bluez, "/", ifaceObjMgr, "GetManagedObjects", "", 5*time.Second)
	return err
}

// probeReceive, on its own connection, asks for every signal, marks that
// with GetManagedObjects on "/", and then takes signals until BlueZ's
// Sentinel: any other testIface signal before it, which only another peer
// sends, fails, and so does no signal from the bus driver.
func probeReceive(bus string) error {
	sigs := make(chan *Message, 64)
	b, err := Dial(bus, allSignals(func(m *Message) { sigs <- m }))
	if err != nil {
		return err
	}
	defer b.Close()
	if _, err := b.Call(busDriver, "/org/freedesktop/DBus", busDriver, "AddMatch", "s", 5*time.Second, "type='signal'"); err != nil {
		return err
	}
	if _, err := b.Call(bluez, "/", ifaceObjMgr, "GetManagedObjects", "", 5*time.Second); err != nil {
		return err
	}
	driver := false
	for {
		select {
		case m := <-sigs:
			switch {
			case m.Sender == busDriver:
				driver = true
			case m.Interface == testIface && m.Member == "Sentinel":
				if !driver {
					return errors.New("no signal from the bus driver")
				}
				return nil
			case m.Interface == testIface:
				return fmt.Errorf("took %s from %s", m.Member, m.Sender)
			}
		case <-time.After(10 * time.Second):
			return errors.New("no Sentinel")
		}
	}
}

// emit sends m, a signal, on b.
func emit(b *Bus, m *Message) error {
	b.mu.Lock()
	b.serial++
	m.Serial = b.serial
	b.mu.Unlock()
	raw, err := m.Encode()
	if err != nil {
		return err
	}
	b.wmu.Lock()
	defer b.wmu.Unlock()
	_, err = b.conn.Write(raw)
	return err
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
	busConn   net.Conn // join's connection to the bus
	peer      net.Conn // serve's last peer connection, the stack's
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
	f.peer = c
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
	f.busConn = c
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
			got, err := readMessage(r, all)
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

// inject writes a raw frame, as the bus, to serve's last peer.
func (f *fakeBluez) inject(b []byte) {
	f.mu.Lock()
	c := f.peer
	f.mu.Unlock()
	f.wmu.Lock()
	defer f.wmu.Unlock()
	if _, err := c.Write(b); err != nil {
		f.t.Fatal(err)
	}
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
		m, err := readMessage(r, all)
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
		var rawAfter [][]byte // frames no encoder makes: any bus peer may send them
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
				if driver && m.Member == "Connect" {
					rawAfter = [][]byte{oversized(), malformed()}
				}
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
		for _, b := range rawAfter {
			f.wmu.Lock()
			c.Write(b)
			f.wmu.Unlock()
		}
		for _, s := range after {
			s.Destination = m.Sender
			if !driver {
				s.Sender = ""
			}
			f.send(c, s)
		}
	}
}

// oversized is a signal frame one byte past MaxMessage, as a stock bus
// (32 MiB limit) delivers from any peer.
func oversized() []byte {
	b := []byte{'l', typeSignal, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0}
	le.PutUint32(b[4:], MaxMessage-16+1)
	return append(b, make([]byte, MaxMessage-16+1)...)
}

// malformed is a whole frame that does not decode: a signal whose bool is 2.
func malformed() []byte {
	b, _ := (&Message{Type: typeSignal, Serial: 1, Path: "/", Interface: "a.b", Member: "C", Sig: "b", Body: []any{true}}).Encode()
	b[len(b)-4] = 2
	return b
}

// TestReadSkipsWhatDoesNotDecode: a frame too long, one whose header
// fields are too long, one whose header or body does not decode, and one
// keep refuses are each read past and skipped, so the next message still
// arrives; a frame with no byte order loses the stream and ends the read.
func TestReadSkipsWhatDoesNotDecode(t *testing.T) {
	good := mustEncode(t, propsChanged(2, bluezName, measurePath, []byte{1}))
	longHead := []byte{'l', typeSignal, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0}
	le.PutUint32(longHead[12:], maxHeader+1)
	longHead = append(longHead, make([]byte, maxHeader+8)...)
	badHead := withField(t, &Message{Type: typeSignal, Serial: 1, Path: "/", Interface: "a.b", Member: "C"}, 1, "s", "/x")
	le.PutUint32(badHead[4:], 8)
	badHead = append(badHead, make([]byte, 8)...)
	refused := mustEncode(t, propsChanged(3, ":1.9", measurePath, []byte{1}))
	r := bytes.NewReader(slices.Concat(oversized(), longHead, badHead, malformed(), refused, good, []byte("x234567890123456")))
	for i, want := range []error{errSkipped, errSkipped, errSkipped, errSkipped, errSkipped, nil} {
		m, err := readMessage(r, func(m *Message) bool { return m.Sender == bluezName })
		if !errors.Is(err, want) || (want == nil && m.Serial != 2) {
			t.Fatalf("message %d: %v, %+v", i, err, m)
		}
	}
	if _, err := readMessage(r, all); err == nil || errors.Is(err, errSkipped) {
		t.Fatalf("no byte order: %v", err)
	}
	short := oversized()[:MaxMessage-4]
	if _, err := readMessage(bytes.NewReader(short), all); err == nil || errors.Is(err, errSkipped) {
		t.Fatalf("a long frame cut short: %v", err)
	}
	// Cut short in a skipped body, a kept body, or a header.
	for _, b := range [][]byte{badHead[:len(badHead)-1], refused[:len(refused)-1], good[:len(good)-1], good[:20]} {
		if _, err := readMessage(bytes.NewReader(b), func(m *Message) bool { return m.Sender == bluezName }); err == nil || errors.Is(err, errSkipped) {
			t.Fatalf("a frame cut short at %d: %v", len(b), err)
		}
	}
}

// TestReadDecodesOnlyWanted (NET-2, A18): the stack, started by Run
// against the fake bus, reads a signal's header before its body, so a
// 0.8 MB PropertiesChanged from a peer other than BlueZ is read past
// undecoded, allocating under an eighth of its size, while the same from
// BlueZ decodes (and allocates more than its size). The frames reach the
// connection Run dialled, so a Signals that Run or Main hands Dial in
// place of the stack's own (one keeping everything) fails here. A reply
// is decoded only while its call waits, and a method call never. Catches
// a bus peer inflating bodies in the stack until a memory cap kills it.
func TestReadDecodesOnlyWanted(t *testing.T) {
	dir := t.TempDir()
	f := &fakeBluez{t: t}
	f.serve(filepath.Join(dir, "bus"))
	hostEnd, stackEnd := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- Run(testConfig(filepath.Join(dir, "bus")), stackEnd, testLog{t}) }()
	h := hostFor(t, make(chan radio.Notification, 8))
	h.Attach(radio.StackBLE, hostEnd)
	// A read is Properties.Get on the bus, whose reply follows the frame
	// in the stream: its answer says the stack has read the frame.
	readOp := func() {
		if _, err := h.Call(radio.Request{Op: radio.OpRead, Device: "scale"}); err != nil {
			t.Fatalf("read: %v", err)
		}
	}
	readOp() // the stack is up, and its first call's lazy allocations are made
	flood := func(sender string) []byte {
		props := make([]any, 50000)
		for i := range props {
			props[i] = Entry{Key: "k", Value: Variant{Sig: "y", Value: uint8(i)}}
		}
		return mustEncode(t, &Message{Type: typeSignal, Serial: 1, Sender: sender, Destination: ":1.1", Path: measurePath,
			Interface: ifaceProps, Member: "PropertiesChanged", Sig: "sa{sv}as", Body: []any{ifaceChar, props, []any{}}})
	}
	read := func(frame []byte) uint64 {
		var m0, m1 runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m0)
		f.inject(frame)
		readOp()
		runtime.ReadMemStats(&m1)
		return m1.TotalAlloc - m0.TotalAlloc
	}
	forged := flood(":1.9")
	if n := read(forged); n > uint64(len(forged)/8) {
		t.Errorf("another peer's %d-byte signal: %d bytes allocated", len(forged), n)
	}
	if n := read(flood(bluezName)); n < uint64(len(forged)) {
		t.Errorf("BlueZ's %d-byte signal: %d bytes allocated", len(forged), n)
	}
	hostEnd.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Error("the stack outlived its host link")
	}

	b := &Bus{calls: map[uint32]chan *Message{5: make(chan *Message, 1)}}
	for _, c := range []struct {
		m    *Message
		want bool
	}{
		{&Message{Type: typeReturn, ReplySerial: 5}, true},
		{&Message{Type: typeError, ReplySerial: 5}, true},
		{&Message{Type: typeReturn, ReplySerial: 6}, false},
		{&Message{Type: typeError, ReplySerial: 6}, false},
		{&Message{Type: typeCall, Serial: 5}, false},
	} {
		if b.wants(c.m) != c.want {
			t.Errorf("%+v: wanted %v", c.m, !c.want)
		}
	}
}

// TestDeviceDropForgets: BlueZ reporting the device's link down forgets its
// characteristic paths and subscriptions, as a disconnect op does; the same
// signal from another peer, or for another object, changes nothing.
func TestDeviceDropForgets(t *testing.T) {
	s := newFuzzStack()
	s.chars[[2]string{"scale", "measure"}] = measurePath
	drop := func(sender string, path ObjectPath, connected bool) *Message {
		return &Message{Type: typeSignal, Serial: 1, Sender: sender, Path: path, Interface: ifaceProps,
			Member: "PropertiesChanged", Sig: "sa{sv}as", Body: []any{ifaceDevice,
				[]any{Entry{Key: "Connected", Value: Variant{Sig: "b", Value: connected}}}, []any{}}}
	}
	for _, m := range []*Message{
		drop(":1.9", scalePath, false),
		drop(bluezName, "/org/bluez/hci0/dev_11_22_33_44_55_66", false),
		drop(bluezName, scalePath, true),
	} {
		s.signal(m)
		if len(s.chars) != 1 || len(s.subs) != 1 {
			t.Fatalf("%s %s: forgot the scale", m.Sender, m.Path)
		}
	}
	s.signal(drop(bluezName, scalePath, false))
	if len(s.chars) != 0 || len(s.subs) != 0 {
		t.Errorf("the link dropped and the stack kept %v %v", s.chars, s.subs)
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
	s := &stack{devices: map[string]Device{}, byPath: map[ObjectPath]string{scalePath: "scale"}, log: io.Discard, owner: bluezName,
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
		strings.Replace(good, controlUUID, testUUID, 1), // two names, one UUID
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
	connectConfined(t, dir, filepath.Join(dir, "bus"), "", 4242, false, nil)
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
// the stack's user makes the daemon refuse, before it is delivered, every
// message the confined process sends on its own connection outside the
// declared calls: an adapter call on BlueZ, bus driver calls the stack
// never makes, a call on another service and a broadcast signal (probeSend),
// while the stack's declared calls still go through. Catches an exploited
// stack using BlueZ beyond its ops, or reaching any other service on the
// bus.
func TestBusPolicyRefusesUndeclaredCalls(t *testing.T) {
	if !asRoot(t) {
		return
	}
	dir, bus, uid := policyBus(t)
	f := &fakeBluez{t: t}
	f.join(bus)
	leaks := make(chan *Message, 8)
	peer := testBusPeer(t, bus, func(m *Message) {
		if m.Interface == testIface {
			leaks <- m
		}
	})
	if _, err := peer.Call(busDriver, "/org/freedesktop/DBus", busDriver, "AddMatch", "s", 5*time.Second, "type='signal',interface='"+testIface+"'"); err != nil {
		t.Fatal(err)
	}
	connectConfined(t, dir, bus, "bus", uid, true, func() {
		probed(t, f)
		barrier(t, peer)
		select {
		case m := <-leaks:
			t.Errorf("another peer took the stack's %s signal", m.Member)
		default:
		}
	})
	var saw []string
	for _, c := range f.record() {
		saw = append(saw, c.Member)
	}
	if want := []string{"GetManagedObjects", "Connect", "Get", "GetManagedObjects", "StartNotify", "GetManagedObjects", "WriteValue", "Disconnect"}; !slices.Equal(saw, want) {
		t.Errorf("BlueZ saw %v, want %v (and never StartDiscovery)", saw, want)
	}
}

// TestBusPolicyRefusesOtherPeers (NET-2, A18): on the same daemon,
// another bus peer's method call to the stack's connection is refused,
// and its unicast and broadcast signals never reach it, while the bus
// driver's and BlueZ's still do (probeReceive). Catches a compromised
// peer on the enforcer's bus (a Thread or Matter stack) flooding the BLE
// stack until BlueZ's replies miss their timeout.
func TestBusPolicyRefusesOtherPeers(t *testing.T) {
	if !asRoot(t) {
		return
	}
	dir, bus, uid := policyBus(t)
	f := &fakeBluez{t: t}
	f.join(bus)
	peer := testBusPeer(t, bus, func(*Message) {})
	connectConfined(t, dir, bus, "rx", uid, false, func() {
		probed(t, f)
		stack := nameOf(t, peer, uid)
		_, err := peer.Call(stack, "/", testIface, "Poke", "", 5*time.Second)
		if ce := (*CallError)(nil); !errors.As(err, &ce) || ce.Name != denied {
			t.Errorf("another peer's call to the stack: %v", err)
		}
		for _, dest := range []string{stack, ""} {
			if err := emit(peer, &Message{Type: typeSignal, Path: "/", Interface: testIface, Member: "Flood", Destination: dest}); err != nil {
				t.Fatal(err)
			}
		}
		barrier(t, peer)
		f.send(f.busConn, &Message{Type: typeSignal, Path: "/", Interface: testIface, Member: "Sentinel", Destination: stack})
	})
}

// policyBus starts a dbus-daemon whose default policy allows everything,
// with BusPolicy for nobody, a user both this machine and CI's runner name
// (dbus-daemon's policy names users), and returns a directory that user
// can reach, the bus socket and nobody's uid.
func policyBus(t *testing.T) (dir, bus string, uid uint32) {
	t.Helper()
	daemon, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Fatalf("dbus-daemon: %v", err)
	}
	dir = sharedDir(t)
	nobody, err := user.Lookup("nobody")
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(nobody.Uid)
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
	bus = filepath.Join(dir, "bus")
	conf := `<busconfig>
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
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	if _, err := bufio.NewReader(out).ReadString('\n'); err != nil {
		t.Fatalf("dbus-daemon did not start: %v", err)
	}
	return dir, bus, uint32(n)
}

// testBusPeer is another peer on the bus, as root, owning testPeer.
func testBusPeer(t *testing.T, bus string, signal func(*Message)) *Bus {
	t.Helper()
	b, err := Dial(bus, allSignals(signal))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	if _, err := b.Call(busDriver, "/org/freedesktop/DBus", busDriver, "RequestName", "su", 5*time.Second, testPeer, uint32(4)); err != nil {
		t.Fatal(err)
	}
	return b
}

// probed waits for a probe's end mark: GetManagedObjects on "/".
func probed(t *testing.T, f *fakeBluez) {
	t.Helper()
	for range 100 {
		for _, c := range f.record() {
			if c.Member == "GetManagedObjects" && c.Path == "/" {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the probe never finished")
}

// barrier returns once the bus has handled everything b sent before it.
func barrier(t *testing.T, b *Bus) {
	t.Helper()
	if _, err := b.Call(busDriver, "/org/freedesktop/DBus", busDriver, "GetId", "", 5*time.Second); err != nil {
		t.Fatal(err)
	}
}

// nameOf is the unique name of the one connection uid has on b's bus.
func nameOf(t *testing.T, b *Bus, uid uint32) string {
	t.Helper()
	r, err := b.Call(busDriver, "/org/freedesktop/DBus", busDriver, "ListNames", "", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, n := range r[0].([]any) {
		n := n.(string)
		if !strings.HasPrefix(n, ":") {
			continue
		}
		u, err := b.Call(busDriver, "/org/freedesktop/DBus", busDriver, "GetConnectionUnixUser", "s", 5*time.Second, n)
		if err == nil && u[0] == uid {
			got = append(got, n)
		}
	}
	if len(got) != 1 {
		t.Fatalf("connections of uid %d: %v", uid, got)
	}
	return got[0]
}

// connectConfined starts the stack confined as uid (and the same gid), with probe passed to
// testStack, runs during (if any) while the probe runs, and connects the
// scale through the host; full also reads, subscribes (and takes the
// notification), writes and disconnects.
func connectConfined(t *testing.T, dir, bus, probe string, uid uint32, full bool, during func()) {
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
	// The view is the test's bus, and the loader this cgo-linked (so
	// dynamic) test binary needs; the enforcer's binary is static. A
	// path the host lacks is left out.
	p := confine.BLE(uid, uid)
	p.View = []string{bus, "/lib", "/lib64", "/usr/lib", "/usr/lib64"}
	proc, conn, err := confine.Start(confine.Spec{Profile: p, Self: bin, Path: bin,
		Args: []string{stackArg, arg, probe}, Stderr: testLog{t}})
	if err != nil {
		t.Fatal(err)
	}
	defer proc.Stop()
	if during != nil {
		during()
	}
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

// all keeps every message.
func all(*Message) bool { return true }

// allSignals wants every signal and gives it to the function.
type allSignals func(*Message)

func (allSignals) wants(*Message) bool { return true }
func (f allSignals) signal(m *Message) { f(m) }

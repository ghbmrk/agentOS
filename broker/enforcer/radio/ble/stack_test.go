package ble

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/radio"
)

// REQ: NET-2

// asBluez answers as the bus driver and BlueZ do for the stack's start
// (Hello, GetNameOwner, AddMatch), and each other method with over's
// answer for it, if any.
func asBluez(over map[string]func(*Message) *Message) func(*Message) *Message {
	return func(m *Message) *Message {
		switch m.Member {
		case "Hello":
			return &Message{Type: typeReturn, Sig: "s", Body: []any{":1.1"}}
		case "GetNameOwner":
			return &Message{Type: typeReturn, Sig: "s", Body: []any{bluezName}}
		}
		if f := over[m.Member]; f != nil {
			return f(m)
		}
		return nil
	}
}

func errReply(name string) func(*Message) *Message {
	return func(*Message) *Message { return &Message{Type: typeError, ErrorName: name} }
}

func objects(objs ...any) func(*Message) *Message {
	return func(*Message) *Message {
		return &Message{Type: typeReturn, Sig: "a{oa{sa{sv}}}", Body: []any{objs}}
	}
}

// object is one GetManagedObjects entry: path, with interface iface
// holding the property UUID.
func object(path ObjectPath, iface, uuid string) any {
	return Entry{Key: path, Value: []any{Entry{Key: iface, Value: []any{
		Entry{Key: "UUID", Value: Variant{Sig: "s", Value: uuid}}}}}}
}

// stackOn is the stack for testConfig's scale, on a stub bus answering
// as asBluez(over) does.
func stackOn(t *testing.T, over map[string]func(*Message) *Message) (*stack, *stubBus) {
	t.Helper()
	sb := newStubBus(t, authOK, false, asBluez(over))
	s := newFuzzStack()
	s.cfg = testConfig(sb.path)
	s.devices["scale"] = s.cfg.Devices[0]
	s.subs = map[ObjectPath]sub{}
	b, err := Dial(sb.path, s)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	s.bus = b
	return s, sb
}

// TestHandleCodes: each bus outcome reaches the host as its own code,
// not as a generic failure: BlueZ not knowing the object is the device
// not answering, the bus refusing is a refusal, and a characteristic is
// looked up only among the configured device's characteristics, by its
// UUID, once per connection. Catches a stack that guesses between
// objects or hides why an op failed.
func TestHandleCodes(t *testing.T) {
	write := radio.Request{Op: radio.OpWrite, Device: "scale", Char: "control", Data: []byte{1}}
	for _, c := range []struct {
		name string
		over map[string]func(*Message) *Message
		r    radio.Request
		want radio.Code
	}{
		{"read of an unknown object", map[string]func(*Message) *Message{"Get": errReply("org.freedesktop.DBus.Error.UnknownObject")},
			radio.Request{Op: radio.OpRead, Device: "scale"}, radio.CodeUnreachable},
		{"write to a characteristic not there", map[string]func(*Message) *Message{"GetManagedObjects": objects(object(measurePath, ifaceChar, testUUID))},
			write, radio.CodeUnreachable},
		{"subscribe to a characteristic not there", map[string]func(*Message) *Message{"GetManagedObjects": objects(object(controlPath, ifaceChar, controlUUID))},
			radio.Request{Op: radio.OpSubscribe, Device: "scale", Char: "measure"}, radio.CodeUnreachable},
		{"lookup refused", map[string]func(*Message) *Message{"GetManagedObjects": errReply(denied)}, write, radio.CodeRefused},
		{"lookup answered with nothing", map[string]func(*Message) *Message{"GetManagedObjects": func(*Message) *Message { return &Message{Type: typeReturn} }},
			write, radio.CodeFailed},
		{"same UUID under another device", map[string]func(*Message) *Message{"GetManagedObjects": objects(
			object("/org/bluez/hci0/dev_11_22_33_44_55_66/service0010/char0014", ifaceChar, controlUUID),
			object(controlPath, ifaceChar, controlUUID))}, write, radio.CodeOK},
		{"same UUID on a descriptor", map[string]func(*Message) *Message{"GetManagedObjects": objects(
			object(controlPath+"/desc0015", "org.bluez.GattDescriptor1", controlUUID),
			object(controlPath, ifaceChar, controlUUID))}, write, radio.CodeOK},
	} {
		s, sb := stackOn(t, c.over)
		if _, code := s.handle(c.r); code != c.want {
			t.Errorf("%s: code %d, want %d; BlueZ saw %+v", c.name, code, c.want, sb.called())
		}
	}

	// Two writes look the characteristic up once, and write to it.
	s, sb := stackOn(t, map[string]func(*Message) *Message{"GetManagedObjects": objects(object(controlPath, ifaceChar, controlUUID))})
	for range 2 {
		if _, code := s.handle(write); code != radio.CodeOK {
			t.Fatalf("write: code %d", code)
		}
	}
	var lookups, writes int
	for _, c := range sb.called() {
		switch {
		case c.Member == "GetManagedObjects":
			lookups++
		case c.Member == "WriteValue" && c.Path == controlPath:
			writes++
		}
	}
	if lookups != 1 || writes != 2 {
		t.Errorf("two writes: %d lookups, %d writes to %s; BlueZ saw %+v", lookups, writes, controlPath, sb.called())
	}

	// A method off busCalls never reaches the bus, whoever asks.
	before := len(sb.called())
	if _, err := s.bluez("/org/bluez/hci0", "org.bluez.Adapter1", "StartDiscovery", ""); err == nil {
		t.Error("the stack called Adapter1.StartDiscovery")
	}
	s.bluez("/", ifaceObjMgr, "GetManagedObjects", "") // a declared call after it, as a barrier
	if got := sb.called()[before:]; len(got) != 1 || got[0].Member != "GetManagedObjects" {
		t.Errorf("BlueZ saw %+v", got)
	}
}

// runStack runs the stack for cfg as the host's peer and returns how Run
// ended, or a timeout error after d.
func runStack(t *testing.T, cfg Config, d time.Duration) (error, net.Conn) {
	t.Helper()
	hostEnd, stackEnd := net.Pipe()
	t.Cleanup(func() { hostEnd.Close() })
	done := make(chan error, 1)
	go func() { done <- Run(cfg, stackEnd, testLog{t}) }()
	select {
	case err := <-done:
		return err, hostEnd
	case <-time.After(d):
		return errors.New("Run still serving"), hostEnd
	}
}

// TestRunRefusesWhatCannotServe: Run returns an error, and closes the
// host's link, for a configuration that does not check (before dialling
// the bus), a bus it cannot reach, and a BlueZ it cannot name: an error
// reply, no answer, an empty or non-string name. An empty bus path is
// the system bus.
func TestRunRefusesWhatCannotServe(t *testing.T) {
	sb := newStubBus(t, authOK, false, asBluez(nil))
	bad := testConfig(sb.path)
	bad.Adapter = "hci0/../x"
	if err, _ := runStack(t, bad, 2*time.Second); err == nil || !strings.Contains(err.Error(), "adapter") {
		t.Errorf("a bad adapter: %v", err)
	}
	select {
	case <-sb.ended:
		t.Error("a bad configuration dialled the bus")
	default:
	}
	err, host := runStack(t, testConfig(filepath.Join(t.TempDir(), "none")), 5*time.Second)
	if err == nil {
		t.Error("ran on a missing bus")
	}
	host.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, rerr := host.Read(make([]byte, 1)); rerr == nil || errors.Is(rerr, os.ErrDeadlineExceeded) {
		t.Errorf("a missing bus left the host's link open: %v", rerr)
	}
	for name, owner := range map[string]func(*Message) *Message{
		"no owner":    errReply("org.freedesktop.DBus.Error.NameHasNoOwner"),
		"no answer":   func(*Message) *Message { return &Message{Type: typeReturn} },
		"empty owner": func(*Message) *Message { return &Message{Type: typeReturn, Sig: "s", Body: []any{""}} },
		"owner not a string": func(*Message) *Message {
			return &Message{Type: typeReturn, Sig: "u", Body: []any{uint32(1)}}
		},
	} {
		sb := newStubBus(t, authOK, false, func(m *Message) *Message {
			if m.Member == "GetNameOwner" {
				return owner(m)
			}
			return asBluez(nil)(m)
		})
		err, host := runStack(t, testConfig(sb.path), 5*time.Second)
		if err == nil || err.Error() == "Run still serving" {
			t.Errorf("%s: %v", name, err)
		}
		host.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, rerr := host.Read(make([]byte, 1)); rerr == nil || errors.Is(rerr, os.ErrDeadlineExceeded) {
			t.Errorf("%s left the host's link open: %v", name, rerr)
		}
		if ce := (*CallError)(nil); name == "no owner" && !errors.As(err, &ce) {
			t.Errorf("no owner: %v is not BlueZ's error", err)
		}
	}
	// The system bus: Run reaches it, or names it in its error.
	sys := testConfig("")
	err, _ = runStack(t, sys, 20*time.Second)
	if err == nil || !(strings.Contains(err.Error(), SystemBus) || strings.Contains(err.Error(), "BlueZ not on the bus")) {
		t.Errorf("an empty bus path: %v", err)
	}
}

// TestRunEndsWithItsLinks: the bus going away ends Run and closes the
// host's link; the host's link ending ends Run and closes the bus
// connection. Catches a stack serving with no bus, or holding the bus
// with no host.
func TestRunEndsWithItsLinks(t *testing.T) {
	sb := newStubBus(t, authOK, false, asBluez(nil))
	hostEnd, stackEnd := net.Pipe()
	defer hostEnd.Close()
	done := make(chan error, 1)
	go func() { done <- Run(testConfig(sb.path), stackEnd, testLog{t}) }()
	for len(sb.called()) < 4 { // Hello, GetNameOwner and two AddMatch
		time.Sleep(time.Millisecond)
	}
	sb.drop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the stack outlived its bus")
	}

	sb = newStubBus(t, authOK, false, asBluez(nil))
	hostEnd, stackEnd = net.Pipe()
	go func() { done <- Run(testConfig(sb.path), stackEnd, testLog{t}) }()
	for len(sb.called()) < 4 {
		time.Sleep(time.Millisecond)
	}
	hostEnd.Close()
	select {
	case <-sb.ended:
	case <-time.After(5 * time.Second):
		t.Fatal("the stack held the bus after its host link ended")
	}
	<-done
}

// TestDeviceDropForgetsUnderRun: the stack Run builds knows its devices'
// object paths, so BlueZ reporting the scale's link down makes the next
// write look its characteristic up again.
func TestDeviceDropForgetsUnderRun(t *testing.T) {
	dir := t.TempDir()
	f := &fakeBluez{t: t}
	f.serve(filepath.Join(dir, "bus"))
	hostEnd, stackEnd := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- Run(testConfig(filepath.Join(dir, "bus")), stackEnd, testLog{t}) }()
	defer func() { hostEnd.Close(); <-done }()
	h := hostFor(t, make(chan radio.Notification, 8))
	h.Attach(radio.StackBLE, exited{}, hostEnd)
	write := radio.Request{Op: radio.OpWrite, Device: "scale", Char: "control", Data: []byte{1}}
	if _, err := h.Call(write); err != nil {
		t.Fatal(err)
	}
	drop := mustEncode(t, &Message{Type: typeSignal, Serial: 1, Sender: bluezName, Destination: ":1.1", Path: scalePath,
		Interface: ifaceProps, Member: "PropertiesChanged", Sig: "sa{sv}as", Body: []any{ifaceDevice,
			[]any{Entry{Key: "Connected", Value: Variant{Sig: "b", Value: false}}}, []any{}}})
	f.inject(drop)
	// A read's reply follows the signal in the stream: the stack has taken it.
	if _, err := h.Call(radio.Request{Op: radio.OpRead, Device: "scale"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Call(write); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, c := range f.record() {
		if c.Member == "GetManagedObjects" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("%d lookups across the drop, want 2: %+v", n, f.record())
	}
}

// TestSignalTakesOnlyCharacteristicValues: a Value from another interface
// on a subscribed characteristic's path (a descriptor's, say) is not a
// notification, and nothing is logged for it.
func TestSignalTakesOnlyCharacteristicValues(t *testing.T) {
	var out, log bytes.Buffer
	s := newFuzzStack()
	s.srv = radio.NewServer(radio.StackBLE, bufConn{&out})
	s.log = &log
	m := propsChanged(1, bluezName, measurePath, []byte{1})
	m.Body[0] = "org.bluez.GattDescriptor1"
	s.signal(m)
	m = propsChanged(1, bluezName, controlPath, []byte{1}) // not subscribed
	s.signal(m)
	if out.Len() != 0 || log.Len() != 0 {
		t.Errorf("sent %q, logged %q", out.String(), log.String())
	}
}

// TestBusPolicyNamesAUser: the policy is written only for a user name, so
// no name can carry markup into the bus daemon's configuration.
func TestBusPolicyNamesAUser(t *testing.T) {
	for _, u := range []string{"", "Nobody", "1ble", `a"/><allow send_destination="*`, strings.Repeat("a", 33)} {
		if p, err := BusPolicy(u); err == nil {
			t.Errorf("a policy for %q:\n%s", u, p)
		}
	}
	if _, err := BusPolicy("ble_stack-1"); err != nil {
		t.Errorf("ble_stack-1: %v", err)
	}
}

// TestConfigNamesOnce: Arg checks what it encodes, and two devices may
// not share a name.
func TestConfigNamesOnce(t *testing.T) {
	c := testConfig("/run/bus")
	c.Adapter = "x"
	if _, err := c.Arg(); err == nil {
		t.Error("encoded a bad adapter")
	}
	c = testConfig("/run/bus")
	other := c.Devices[0]
	other.Address = "11:22:33:44:55:66"
	c.Devices = append(c.Devices, other)
	if _, err := c.Arg(); err == nil {
		t.Error("encoded two devices named scale")
	}
	c.Devices[1].Name = "scale2"
	if _, err := c.Arg(); err != nil {
		t.Errorf("two devices: %v", err)
	}
}

// TestWantsNothingBeforeStart: until start has learned BlueZ's unique
// name, the stack takes no signal, not even the bus driver's, nor one
// whose sender is as empty as the owner not yet learned.
func TestWantsNothingBeforeStart(t *testing.T) {
	s := newFuzzStack()
	s.owner = ""
	for _, m := range []*Message{
		{Type: typeSignal, Sender: busDriver, Interface: busDriver, Member: "NameOwnerChanged", Sig: "sss"},
		propsChanged(1, "", measurePath, []byte{1}),
	} {
		if s.wants(m) {
			t.Errorf("before start the stack wants %s from %q", m.Member, m.Sender)
		}
	}
	s.owner = bluezName
	if !s.wants(propsChanged(1, bluezName, measurePath, []byte{1})) {
		t.Error("after start the stack does not want BlueZ's PropertiesChanged")
	}
}

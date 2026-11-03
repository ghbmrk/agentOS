// Package ble is the enforcer's Bluetooth Low Energy stack (NET-2 Confined
// radio stacks; briefs/ENF.md decision 6, slices k and #3906): the process
// radio/confine.BLE runs, a client of BlueZ on the system bus that serves
// exactly radio.Declared[radio.StackBLE] through radio.Server, for the
// devices and characteristics its configuration names.
//
// It reaches the radio only through BlueZ, over the bus's Unix socket
// (confine.BLE allows no other socket family, so no raw HCI), and calls
// only the BlueZ methods in busCalls; BusPolicy turns that table into the
// system bus policy for the stack's user, so the bus refuses any other
// BlueZ call even from an exploited process. The bus carries values a
// device controls, so the D-Bus decoder (wire.go) is strict and fuzzed.
package ble

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/radio"
)

// SystemBus is the system bus's socket, the one file confine.BLE's view
// shows the stack: the same path as confine.SystemBus, which this package
// cannot import (TestBusIsTheViewsBus holds them equal).
const SystemBus = "/run/dbus/system_bus_socket"

// Device is one device the stack serves: the host's name for it, its
// Bluetooth address, and its characteristics by the host's name, each
// with its GATT UUID.
type Device struct {
	Name    string
	Address string            // "AA:BB:CC:DD:EE:FF"
	Chars   map[string]string // name -> 128-bit UUID, lower case
}

// Config is what the stack serves, passed as its one argument (Arg).
type Config struct {
	Bus     string // the bus socket; empty is SystemBus
	Adapter string // "hci0"
	Devices []Device
}

var (
	reAddress = regexp.MustCompile(`^[0-9A-F]{2}(:[0-9A-F]{2}){5}$`)
	reUUID    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reAdapter = regexp.MustCompile(`^hci[0-9]{1,2}$`)
)

// maxConfig bounds the configuration argument.
const maxConfig = 64 << 10

// Arg encodes c as the stack's argument.
func (c Config) Arg() (string, error) {
	if err := c.check(); err != nil {
		return "", err
	}
	b, err := json.Marshal(c)
	return string(b), err
}

// ParseConfig decodes the stack's argument strictly.
func ParseConfig(arg string) (Config, error) {
	var c Config
	if len(arg) > maxConfig {
		return c, errors.New("ble: config too long")
	}
	d := json.NewDecoder(strings.NewReader(arg))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil || d.More() {
		return Config{}, fmt.Errorf("ble: config: %v", err)
	}
	return c, c.check()
}

func (c Config) check() error {
	if !reAdapter.MatchString(c.Adapter) {
		return errors.New("ble: config: adapter")
	}
	if c.Bus != "" && !strings.HasPrefix(c.Bus, "/") {
		return errors.New("ble: config: bus path")
	}
	seen := map[string]bool{}
	for _, d := range c.Devices {
		if !name(d.Name) || seen[d.Name] || !reAddress.MatchString(d.Address) {
			return fmt.Errorf("ble: config: device %q", d.Name)
		}
		seen[d.Name] = true
		uuids := map[string]bool{}
		for n, u := range d.Chars {
			if !name(n) || !reUUID.MatchString(u) || uuids[u] {
				return fmt.Errorf("ble: config: device %q characteristic %q", d.Name, n)
			}
			uuids[u] = true
		}
	}
	return nil
}

// name is radio's name rule: printable ASCII, no space, at most
// radio.MaxName bytes.
func name(s string) bool {
	if s == "" || len(s) > radio.MaxName {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

// BlueZ's names.
const (
	bluez       = "org.bluez"
	ifaceDevice = "org.bluez.Device1"
	ifaceChar   = "org.bluez.GattCharacteristic1"
	ifaceProps  = "org.freedesktop.DBus.Properties"
	ifaceObjMgr = "org.freedesktop.DBus.ObjectManager"
)

// busCalls is every BlueZ method the stack calls: stack.bluez refuses any
// other, and BusPolicy allows only these. There is no adapter method, so
// no discovery, pairing or adapter power from this process.
var busCalls = []struct{ Iface, Member string }{
	{ifaceDevice, "Connect"},
	{ifaceDevice, "Disconnect"},
	{ifaceChar, "WriteValue"},
	{ifaceChar, "StartNotify"},
	{ifaceProps, "Get"},
	{ifaceObjMgr, "GetManagedObjects"},
}

// callTimeout bounds one BlueZ call, inside the host's 10 s.
const callTimeout = 8 * time.Second

// Main runs the stack with args[0] as its Config, serving the host on fd 3,
// until the host, the bus or BlueZ ends it.
func Main(args []string) error {
	if len(args) != 1 {
		return errors.New("ble: want one argument, the config")
	}
	c, err := ParseConfig(args[0])
	if err != nil {
		return err
	}
	return Run(c, os.NewFile(3, "interface"), os.Stderr)
}

type sub struct{ device, char string }

type stack struct {
	cfg     Config
	devices map[string]Device
	byPath  map[ObjectPath]string // device object path -> device name
	srv     *radio.Server
	bus     *Bus
	log     io.Writer

	mu    sync.Mutex
	owner string                   // BlueZ's unique name, set once by start
	chars map[[2]string]ObjectPath // (device, char) -> resolved path
	subs  map[ObjectPath]sub
}

// Run serves the host on conn until it ends, the bus connection ends, or
// BlueZ's name changes owner (a restarted BlueZ forgets every
// subscription, so the stack ends and the host's supervisor restarts it).
// log takes one line per fault, never a device's data.
func Run(c Config, conn io.ReadWriteCloser, log io.Writer) error {
	if err := c.check(); err != nil {
		return err
	}
	if c.Bus == "" {
		c.Bus = SystemBus
	}
	s := &stack{cfg: c, devices: map[string]Device{}, byPath: map[ObjectPath]string{}, log: log,
		chars: map[[2]string]ObjectPath{}, subs: map[ObjectPath]sub{}}
	for _, d := range c.Devices {
		s.devices[d.Name] = d
		s.byPath[s.devicePath(d)] = d.Name
	}
	s.srv = radio.NewServer(radio.StackBLE, conn)
	bus, err := Dial(c.Bus, s)
	if err != nil {
		conn.Close()
		return err
	}
	s.bus = bus
	defer bus.Close()
	if err := s.start(); err != nil {
		conn.Close()
		return err
	}
	go func() {
		<-bus.Done()
		conn.Close()
	}()
	return s.srv.Serve(s.handle)
}

// start learns BlueZ's unique name and asks for its characteristics'
// changes and its name's owner changes. The owner is set before either
// match is added, so the read loop never sees it change.
func (s *stack) start() error {
	r, err := s.bus.Call(busDriver, "/org/freedesktop/DBus", busDriver, "GetNameOwner", "s", callTimeout, bluez)
	if err != nil {
		return fmt.Errorf("ble: BlueZ not on the bus: %w", err)
	}
	if len(r) != 1 {
		return ErrWire
	}
	owner, ok := r[0].(string)
	if !ok || owner == "" {
		return ErrWire
	}
	s.mu.Lock()
	s.owner = owner
	s.mu.Unlock()
	for _, rule := range []string{
		"type='signal',sender='" + bluez + "',interface='" + ifaceProps + "',member='PropertiesChanged',path_namespace='/org/bluez/" + s.cfg.Adapter + "'",
		"type='signal',sender='" + busDriver + "',interface='" + busDriver + "',member='NameOwnerChanged',arg0='" + bluez + "'",
	} {
		if _, err := s.bus.Call(busDriver, "/org/freedesktop/DBus", busDriver, "AddMatch", "s", callTimeout, rule); err != nil {
			return err
		}
	}
	return nil
}

// bluez calls one of busCalls on BlueZ.
func (s *stack) bluez(path ObjectPath, iface, member string, sig Signature, args ...any) ([]any, error) {
	if !slices.Contains(busCalls, struct{ Iface, Member string }{iface, member}) {
		return nil, fmt.Errorf("ble: %s.%s is not a declared BlueZ call", iface, member)
	}
	return s.bus.Call(bluez, path, iface, member, sig, callTimeout, args...)
}

func (s *stack) devicePath(d Device) ObjectPath {
	return ObjectPath("/org/bluez/" + s.cfg.Adapter + "/dev_" + strings.ReplaceAll(d.Address, ":", "_"))
}

// handle serves one request radio.Server has held to BLE's declared ops.
// The device, and the characteristic for write and subscribe, must be in
// this stack's configuration, or the request is refused before the bus.
func (s *stack) handle(r radio.Request) ([]byte, radio.Code) {
	d, ok := s.devices[r.Device]
	if !ok {
		return nil, radio.CodeRefused
	}
	if r.Char != "" {
		if _, ok := d.Chars[r.Char]; !ok {
			return nil, radio.CodeRefused
		}
	}
	dev := s.devicePath(d)
	switch r.Op {
	case radio.OpConnect:
		_, err := s.bluez(dev, ifaceDevice, "Connect", "")
		return nil, s.code(err)
	case radio.OpDisconnect:
		_, err := s.bluez(dev, ifaceDevice, "Disconnect", "")
		s.forget(d.Name)
		return nil, s.code(err)
	case radio.OpRead:
		body, err := s.bluez(dev, ifaceProps, "Get", "ss", ifaceDevice, "Connected")
		if err != nil {
			return nil, s.code(err)
		}
		if len(body) == 1 {
			if v, ok := body[0].(Variant); ok {
				if c, ok := v.Value.(bool); ok {
					if c {
						return []byte{1}, radio.CodeOK
					}
					return []byte{0}, radio.CodeOK
				}
			}
		}
		return nil, radio.CodeFailed
	case radio.OpWrite:
		p, code := s.resolve(d, r.Char)
		if code != radio.CodeOK {
			return nil, code
		}
		data := r.Data
		if data == nil {
			data = []byte{}
		}
		_, err := s.bluez(p, ifaceChar, "WriteValue", "aya{sv}", data, []any{})
		return nil, s.code(err)
	case radio.OpSubscribe:
		p, code := s.resolve(d, r.Char)
		if code != radio.CodeOK {
			return nil, code
		}
		s.mu.Lock()
		s.subs[p] = sub{device: d.Name, char: r.Char}
		s.mu.Unlock()
		if _, err := s.bluez(p, ifaceChar, "StartNotify", ""); err != nil {
			s.mu.Lock()
			delete(s.subs, p)
			s.mu.Unlock()
			return nil, s.code(err)
		}
		return nil, radio.CodeOK
	}
	return nil, radio.CodeRefused
}

// code maps a bus outcome to the interface's codes: no reply, or BlueZ
// not knowing the device, is the device not answering; the bus's policy
// refusing is a refusal.
func (s *stack) code(err error) radio.Code {
	var ce *CallError
	switch {
	case err == nil:
		return radio.CodeOK
	case errors.Is(err, ErrTimeout):
		return radio.CodeUnreachable
	case errors.As(err, &ce):
		switch ce.Name {
		case "org.freedesktop.DBus.Error.AccessDenied":
			return radio.CodeRefused
		case "org.freedesktop.DBus.Error.UnknownObject", "org.freedesktop.DBus.Error.NoReply",
			"org.bluez.Error.NotConnected", "org.bluez.Error.DoesNotExist":
			return radio.CodeUnreachable
		}
	}
	fmt.Fprintf(s.log, "ble: bus call failed: %v\n", err)
	return radio.CodeFailed
}

// resolve finds a configured characteristic's object path under the
// device by its UUID. BlueZ numbers characteristic objects as it
// discovers them, so the path is looked up once per connection; two
// characteristics with the UUID under one device are refused, not guessed
// between.
func (s *stack) resolve(d Device, char string) (ObjectPath, radio.Code) {
	key := [2]string{d.Name, char}
	s.mu.Lock()
	p, ok := s.chars[key]
	s.mu.Unlock()
	if ok {
		return p, radio.CodeOK
	}
	body, err := s.bluez("/", ifaceObjMgr, "GetManagedObjects", "")
	if err != nil {
		return "", s.code(err)
	}
	if len(body) != 1 {
		return "", radio.CodeFailed
	}
	objs, _ := body[0].([]any)
	prefix := string(s.devicePath(d)) + "/"
	want := d.Chars[char]
	var found []ObjectPath
	for _, o := range objs {
		e, _ := o.(Entry)
		path, _ := e.Key.(ObjectPath)
		ifaces, _ := e.Value.([]any)
		if !strings.HasPrefix(string(path), prefix) {
			continue
		}
		for _, i := range ifaces {
			ie, _ := i.(Entry)
			if n, _ := ie.Key.(string); n != ifaceChar {
				continue
			}
			props, _ := ie.Value.([]any)
			if u, ok := prop(props, "UUID").(string); ok && strings.ToLower(u) == want {
				found = append(found, path)
			}
		}
	}
	switch len(found) {
	case 0:
		return "", radio.CodeUnreachable
	case 1:
		s.mu.Lock()
		s.chars[key] = found[0]
		s.mu.Unlock()
		return found[0], radio.CodeOK
	}
	fmt.Fprintf(s.log, "ble: device %s has %d characteristics with %s's UUID\n", d.Name, len(found), char)
	return "", radio.CodeFailed
}

// prop is the value of name in an a{sv}, or nil.
func prop(props []any, name string) any {
	for _, p := range props {
		e, _ := p.(Entry)
		if k, _ := e.Key.(string); k == name {
			if v, ok := e.Value.(Variant); ok {
				return v.Value
			}
		}
	}
	return nil
}

// forget drops a device's resolved paths and subscriptions: a disconnect
// ends BlueZ's notifications, and a reconnect may number the objects anew.
func (s *stack) forget(device string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.chars {
		if k[0] == device {
			delete(s.chars, k)
		}
	}
	for p, sb := range s.subs {
		if sb.device == device {
			delete(s.subs, p)
		}
	}
}

// wants reads a signal's header, before its body is decoded: only the bus
// driver's NameOwnerChanged, and PropertiesChanged from BlueZ's unique
// name, are taken, and nothing before start.
func (s *stack) wants(m *Message) bool {
	s.mu.Lock()
	owner := s.owner
	s.mu.Unlock()
	switch {
	case owner == "":
		return false // before start: nothing is subscribed
	case m.Sender == busDriver:
		return m.Interface == busDriver && m.Member == "NameOwnerChanged" && m.Sig == "sss"
	}
	return m.Sender == owner && m.Interface == ifaceProps && m.Member == "PropertiesChanged" && m.Sig == "sa{sv}as"
}

// signal takes one bus signal wants takes, and drops any other. Only
// BlueZ's own PropertiesChanged on a subscribed characteristic, carrying a
// byte-array Value, becomes a notification. BlueZ's name changing owner
// ends the stack.
func (s *stack) signal(m *Message) {
	if !s.wants(m) {
		return
	}
	s.mu.Lock()
	owner := s.owner
	sb, ok := s.subs[m.Path]
	s.mu.Unlock()
	if m.Sender == busDriver {
		if m.Body[0] == bluez && m.Body[2] != owner {
			fmt.Fprintf(s.log, "ble: BlueZ changed owner\n")
			go s.bus.Close()
		}
		return
	}
	changed, _ := m.Body[1].([]any)
	if m.Body[0] == ifaceDevice {
		// The device dropped the link: BlueZ ends its notifications and may
		// number its objects anew on reconnect, as after a disconnect op.
		if c, ok := prop(changed, "Connected").(bool); ok && !c {
			if d, ok := s.byPath[m.Path]; ok {
				s.forget(d)
			}
		}
		return
	}
	if !ok || m.Body[0] != ifaceChar {
		return
	}
	v, ok := prop(changed, "Value").([]byte)
	if !ok || len(v) > radio.MaxData {
		return
	}
	if err := s.srv.Notify(sb.device, sb.char, bytes.Clone(v)); err != nil {
		fmt.Fprintf(s.log, "ble: notify: %v\n", err)
	}
}

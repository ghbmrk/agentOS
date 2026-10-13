package main

import (
	"context"
	"reflect"
	"testing"

	"github.com/godbus/dbus/v5"

	"github.com/ghbmrk/agentos/broker/netjoin"
)

// REQ: ONB-3, CRED-1

// scanBus is NetworkManager with one ethernet and one Wi-Fi device that
// has seen two access points. It records every call.
type scanBus struct {
	calls []busCall
	devs  []dbus.ObjectPath
}

type scanObj struct {
	dbus.BusObject // nil: any method nmBus must not use panics
	bus            *scanBus
	path           dbus.ObjectPath
}

func (b *scanBus) obj(p dbus.ObjectPath) dbus.BusObject { return scanObj{bus: b, path: p} }

const (
	eth  = nmPath + "/Devices/1"
	wlan = nmPath + "/Devices/2"
	ap1  = nmPath + "/AccessPoint/7"
	ap2  = nmPath + "/AccessPoint/8"
)

func (o scanObj) CallWithContext(_ context.Context, method string, _ dbus.Flags, args ...any) *dbus.Call {
	b := o.bus
	b.calls = append(b.calls, busCall{o.path, method, args})
	ok := func(v any) *dbus.Call { return &dbus.Call{Body: []any{dbus.MakeVariant(v)}} }
	switch {
	case method == wirelessIface+".GetAllAccessPoints" && o.path == wlan:
		return &dbus.Call{Body: []any{[]dbus.ObjectPath{ap1, ap2}}}
	case method != propsGet || len(args) != 2:
	case args[1] == "Devices":
		return ok(b.devs)
	case args[1] == "DeviceType" && o.path == eth:
		return ok(uint32(1))
	case args[1] == "DeviceType" && o.path == wlan:
		return ok(netjoin.DeviceWifi)
	case args[1] == "Ssid" && o.path == ap1:
		return ok([]byte("Home Net"))
	case args[1] == "Ssid" && o.path == ap2:
		return ok([]byte("Neighbor"))
	case args[1] == "Strength" && o.path == ap1:
		return ok(uint8(40))
	case args[1] == "Strength" && o.path == ap2:
		return ok(uint8(70))
	}
	return &dbus.Call{Err: dbus.Error{Name: "org.freedesktop.DBus.Error.UnknownMethod"}}
}

// Acceptance test 3: the scan makes only its reads, on NetworkManager's
// paths, and GetAllAccessPoints on the Wi-Fi device alone: no RequestScan,
// no write, no other device method.
func TestTheScanMakesOnlyItsReads(t *testing.T) {
	b := &scanBus{devs: []dbus.ObjectPath{eth, wlan}}
	got := netjoin.NewScanner(nmBus{obj: b.obj}).Scan(context.Background())
	if want := []string{"Neighbor", "Home Net"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Scan = %q, want %q", got, want)
	}
	want := []busCall{
		{nmPath, propsGet, []any{nmDest, "Devices"}},
		{eth, propsGet, []any{deviceIface, "DeviceType"}},
		{wlan, propsGet, []any{deviceIface, "DeviceType"}},
		{wlan, wirelessIface + ".GetAllAccessPoints", nil},
		{ap1, propsGet, []any{apIface, "Ssid"}},
		{ap1, propsGet, []any{apIface, "Strength"}},
		{ap2, propsGet, []any{apIface, "Ssid"}},
		{ap2, propsGet, []any{apIface, "Strength"}},
	}
	if !reflect.DeepEqual(b.calls, want) {
		t.Fatalf("calls:\n%v\nwant:\n%v", b.calls, want)
	}
}

// Paths NetworkManager hands back are checked before they are called:
// a device or access point outside its own tree is never reached.
func TestTheScanChecksItsPaths(t *testing.T) {
	b := &scanBus{devs: []dbus.ObjectPath{"/org/freedesktop/systemd1", nmPath + "/AccessPoint/7"}}
	nm := nmBus{obj: b.obj}
	if got := netjoin.NewScanner(nm).Scan(context.Background()); len(got) != 0 {
		t.Fatalf("Scan = %q", got)
	}
	if len(b.calls) != 1 {
		t.Fatalf("a path outside the device tree was called: %v", b.calls[1:])
	}
	if _, err := nm.AccessPoints(context.Background(), string(ap1)); err == nil {
		t.Fatal("GetAllAccessPoints on an access point")
	}
	if _, err := nm.APSsid(context.Background(), string(wlan)); err == nil {
		t.Fatal("an Ssid read on a device")
	}
	if len(b.calls) != 1 {
		t.Fatalf("refused paths reached the bus: %v", b.calls[1:])
	}
}

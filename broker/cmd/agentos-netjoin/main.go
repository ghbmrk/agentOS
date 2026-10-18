// Command agentos-netjoin is the helper that writes the home Wi-Fi
// connection during setup (P2-2w c3; Security L8 on the P2-2w plan). It
// runs as its own user with no capabilities, holds only polkit's
// settings.modify.system (50-agentos-netjoin.rules), and serves agentosd's
// uid alone on one socket (netjoin.Endpoint): the join, and a read-only
// scan of the networks NetworkManager has seen (P2-2w c4b).
//
// It talks to NetworkManager over the system bus through nmBus, which
// makes only the calls netjoin.NM and netjoin.ScanNM name. Nothing it logs carries the
// request.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/godbus/dbus/v5"

	"github.com/ghbmrk/agentos/broker/netjoin"
	"github.com/ghbmrk/agentos/broker/sockets"
)

func main() {
	c, err := parseFlags(os.Args[1:])
	if err != nil {
		os.Exit(2)
	}
	log.SetFlags(0)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		log.Fatal("agentos-netjoin: no system bus")
	}
	defer conn.Close()
	nm := nmBus{obj: func(p dbus.ObjectPath) dbus.BusObject { return conn.Object(nmDest, p) }}
	s := &sockets.Server{Dir: c.dir}
	if err := s.Start(ctx, netjoin.Endpoint(c.joiner(nm), netjoin.NewScanner(nm), c.agentosdUID)); err != nil {
		log.Fatalf("agentos-netjoin: %v", err)
	}
	s.Wait()
}

// config is the helper's flags.
type config struct {
	dir         string
	agentosdUID int
	// station and ap are the join's interfaces (S-R4, #1428): with no
	// station, or one in ap, every join answers failed.
	station string
	ap      ifaces
}

// ifaces is a repeatable string flag.
type ifaces []string

func (f *ifaces) String() string     { return strings.Join(*f, ",") }
func (f *ifaces) Set(v string) error { *f = append(*f, v); return nil }

func parseFlags(args []string) (config, error) {
	var c config
	fs := flag.NewFlagSet("agentos-netjoin", flag.ContinueOnError)
	fs.StringVar(&c.dir, "dir", "/run/agentos-netjoin", "the socket's directory (the unit's RuntimeDirectory)")
	// agentosd runs as root (its unit sets no User=).
	fs.IntVar(&c.agentosdUID, "agentosd-uid", 0, "the only uid served")
	fs.StringVar(&c.station, "station", "", "the one interface the home connection may use (none: every join fails)")
	fs.Var(&c.ap, "ap-iface", "an interface agentos-ap may run the access point on (its -iface; repeatable)")
	err := fs.Parse(args)
	return c, err
}

func (c config) joiner(nm netjoin.NM) *netjoin.Joiner {
	return netjoin.NewJoiner(nm, c.station, c.ap)
}

// NetworkManager's D-Bus names (the D-Bus API of NetworkManager 1.22+,
// which added AddConnection2 and Update2).
const (
	nmDest        = "org.freedesktop.NetworkManager"
	nmPath        = dbus.ObjectPath("/org/freedesktop/NetworkManager")
	settingsPath  = dbus.ObjectPath("/org/freedesktop/NetworkManager/Settings")
	settingsIface = "org.freedesktop.NetworkManager.Settings"
	connIface     = "org.freedesktop.NetworkManager.Settings.Connection"
	activeIface   = "org.freedesktop.NetworkManager.Connection.Active"
	propsGet      = "org.freedesktop.DBus.Properties.Get"
	// The scan's reads (P2-2w c4b).
	devicesPath   = nmPath + "/Devices"
	apPath        = nmPath + "/AccessPoint"
	deviceIface   = "org.freedesktop.NetworkManager.Device"
	wirelessIface = "org.freedesktop.NetworkManager.Device.Wireless"
	apIface       = "org.freedesktop.NetworkManager.AccessPoint"
	// GetConnectionByUuid's error for no such connection.
	errInvalidConnection = "org.freedesktop.NetworkManager.Settings.InvalidConnection"
	// NM_SETTINGS_ADD_CONNECTION2_FLAG_TO_DISK and
	// NM_SETTINGS_UPDATE2_FLAG_TO_DISK: kept across reboots.
	toDisk uint32 = 0x1
)

// nmBus is netjoin.NM and netjoin.ScanNM over godbus. Each method makes
// exactly one call: for the join, three Settings methods and three
// property reads; for the scan, GetAllAccessPoints and four property
// reads, none of which needs a polkit action. obj is the bus's
// Object, a seam so tests can record the calls.
type nmBus struct {
	obj func(dbus.ObjectPath) dbus.BusObject
}

func (b nmBus) GetConnectionByUuid(ctx context.Context, uuid string) (string, error) {
	var p dbus.ObjectPath
	err := b.obj(settingsPath).CallWithContext(ctx, settingsIface+".GetConnectionByUuid", 0, uuid).Store(&p)
	var de dbus.Error
	if errors.As(err, &de) && de.Name == errInvalidConnection {
		return "", netjoin.ErrNoConnection
	}
	if err != nil {
		return "", err
	}
	if !connPath(p) {
		return "", errors.New("netjoin: not a connection path")
	}
	return string(p), nil
}

func (b nmBus) AddConnection2(ctx context.Context, s netjoin.Settings) (string, error) {
	var p dbus.ObjectPath
	var result map[string]dbus.Variant
	err := b.obj(settingsPath).CallWithContext(ctx, settingsIface+".AddConnection2", 0,
		variants(s), toDisk, map[string]dbus.Variant{}).Store(&p, &result)
	return string(p), err
}

func (b nmBus) Update2(ctx context.Context, path string, s netjoin.Settings) error {
	p := dbus.ObjectPath(path)
	if !connPath(p) {
		return errors.New("netjoin: not a connection path")
	}
	var result map[string]dbus.Variant
	return b.obj(p).CallWithContext(ctx, connIface+".Update2", 0,
		variants(s), toDisk, map[string]dbus.Variant{}).Store(&result)
}

func (b nmBus) ActiveConnections(ctx context.Context) ([]string, error) {
	var ps []dbus.ObjectPath
	if err := b.get(ctx, nmPath, nmDest, "ActiveConnections", &ps); err != nil {
		return nil, err
	}
	return paths(ps), nil
}

func (b nmBus) ActiveUUID(ctx context.Context, path string) (string, error) {
	var u string
	err := b.get(ctx, dbus.ObjectPath(path), activeIface, "Uuid", &u)
	return u, err
}

func (b nmBus) ActiveState(ctx context.Context, path string) (uint32, error) {
	var s uint32
	err := b.get(ctx, dbus.ObjectPath(path), activeIface, "State", &s)
	return s, err
}

func (b nmBus) Devices(ctx context.Context) ([]string, error) {
	var ps []dbus.ObjectPath
	if err := b.get(ctx, nmPath, nmDest, "Devices", &ps); err != nil {
		return nil, err
	}
	return paths(ps), nil
}

func (b nmBus) DeviceType(ctx context.Context, dev string) (uint32, error) {
	if !under(dbus.ObjectPath(dev), devicesPath) {
		return 0, errors.New("netjoin: not a device path")
	}
	var t uint32
	err := b.get(ctx, dbus.ObjectPath(dev), deviceIface, "DeviceType", &t)
	return t, err
}

func (b nmBus) AccessPoints(ctx context.Context, dev string) ([]string, error) {
	p := dbus.ObjectPath(dev)
	if !under(p, devicesPath) {
		return nil, errors.New("netjoin: not a device path")
	}
	var ps []dbus.ObjectPath
	if err := b.obj(p).CallWithContext(ctx, wirelessIface+".GetAllAccessPoints", 0).Store(&ps); err != nil {
		return nil, err
	}
	return paths(ps), nil
}

func (b nmBus) APSsid(ctx context.Context, ap string) ([]byte, error) {
	if !under(dbus.ObjectPath(ap), apPath) {
		return nil, errors.New("netjoin: not an access point path")
	}
	var s []byte
	err := b.get(ctx, dbus.ObjectPath(ap), apIface, "Ssid", &s)
	return s, err
}

func (b nmBus) APStrength(ctx context.Context, ap string) (uint8, error) {
	if !under(dbus.ObjectPath(ap), apPath) {
		return 0, errors.New("netjoin: not an access point path")
	}
	var s uint8
	err := b.get(ctx, dbus.ObjectPath(ap), apIface, "Strength", &s)
	return s, err
}

func paths(ps []dbus.ObjectPath) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = string(p)
	}
	return out
}

// under: a valid path below root.
func under(p, root dbus.ObjectPath) bool {
	return p.IsValid() && strings.HasPrefix(string(p), string(root)+"/")
}

// get is one org.freedesktop.DBus.Properties.Get.
func (b nmBus) get(ctx context.Context, path dbus.ObjectPath, iface, prop string, out any) error {
	if !path.IsValid() || !strings.HasPrefix(string(path), string(nmPath)+"/") && path != nmPath {
		return errors.New("netjoin: not a NetworkManager path")
	}
	var v dbus.Variant
	if err := b.obj(path).CallWithContext(ctx, propsGet, 0, iface, prop).Store(&v); err != nil {
		return err
	}
	return dbus.Store([]any{v.Value()}, out)
}

// connPath: one of NetworkManager's connection settings objects.
func connPath(p dbus.ObjectPath) bool { return under(p, settingsPath) }

// variants is s as D-Bus a{sa{sv}}: the SSID goes as ay, autoconnect and
// hidden as b, psk-flags as u.
func variants(s netjoin.Settings) map[string]map[string]dbus.Variant {
	out := map[string]map[string]dbus.Variant{}
	for g, props := range s {
		m := map[string]dbus.Variant{}
		for k, v := range props {
			m[k] = dbus.MakeVariant(v)
		}
		out[g] = m
	}
	return out
}

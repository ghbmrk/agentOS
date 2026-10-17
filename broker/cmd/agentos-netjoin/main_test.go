package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"

	"github.com/ghbmrk/agentos/broker/netjoin"
)

// REQ: ONB-3, CRED-1, DEV-2, CH-7

const canary = "CANARY-netjoin-cmd-5b1e"

type busCall struct {
	path   dbus.ObjectPath
	method string
	args   []any
}

// fakeBus is NetworkManager on the system bus: it records every call and
// brings the connection up after each write.
type fakeBus struct {
	calls  []busCall
	conn   dbus.ObjectPath
	active []dbus.ObjectPath
	n      int
}

type fakeObj struct {
	dbus.BusObject // nil: any method nmBus must not use panics
	bus            *fakeBus
	path           dbus.ObjectPath
}

func (b *fakeBus) obj(p dbus.ObjectPath) dbus.BusObject { return fakeObj{bus: b, path: p} }

func (b *fakeBus) activate() {
	b.n++
	b.active = []dbus.ObjectPath{dbus.ObjectPath(fmt.Sprintf("%s/ActiveConnection/%d", nmPath, b.n))}
}

func (o fakeObj) CallWithContext(_ context.Context, method string, _ dbus.Flags, args ...any) *dbus.Call {
	b := o.bus
	b.calls = append(b.calls, busCall{o.path, method, args})
	switch method {
	case settingsIface + ".GetConnectionByUuid":
		if b.conn == "" {
			return &dbus.Call{Err: dbus.Error{Name: errInvalidConnection}}
		}
		return &dbus.Call{Body: []any{b.conn}}
	case settingsIface + ".AddConnection2":
		b.conn = settingsPath + "/7"
		b.activate()
		return &dbus.Call{Body: []any{b.conn, map[string]dbus.Variant{}}}
	case connIface + ".Update2":
		b.activate()
		return &dbus.Call{Body: []any{map[string]dbus.Variant{}}}
	case propsGet:
		switch args[1] {
		case "ActiveConnections":
			return &dbus.Call{Body: []any{dbus.MakeVariant(b.active)}}
		case "Uuid":
			return &dbus.Call{Body: []any{dbus.MakeVariant(netjoin.UUID)}}
		case "State":
			return &dbus.Call{Body: []any{dbus.MakeVariant(uint32(netjoin.StateActivated))}}
		}
	}
	return &dbus.Call{Err: dbus.Error{Name: "org.freedesktop.DBus.Error.UnknownMethod"}}
}

// Security L8.3: the helper calls GetConnectionByUuid, AddConnection2 and
// Update2 on the one connection, and reads three properties; no
// ListConnections, GetSettings, GetSecrets, Delete, device method, or
// activation. The writes go to disk with L8.4's types.
func TestTheHelperMakesOnlyItsOwnCalls(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	b := &fakeBus{}
	j := netjoin.NewJoiner(nmBus{obj: b.obj}, "wlan1", []string{"wlan0"})
	for i := range 2 {
		if c := j.Join(context.Background(), "home", canary); c != netjoin.Joined {
			t.Fatalf("join %d: %s", i, c)
		}
	}
	var writes []busCall
	for _, c := range b.calls {
		switch {
		case c.method == settingsIface+".GetConnectionByUuid" && c.path == settingsPath:
			if !reflect.DeepEqual(c.args, []any{netjoin.UUID}) {
				t.Errorf("lookup args %v", c.args)
			}
		case c.method == settingsIface+".AddConnection2" && c.path == settingsPath,
			c.method == connIface+".Update2" && c.path == settingsPath+"/7":
			writes = append(writes, c)
		case c.method == propsGet && c.path == nmPath && reflect.DeepEqual(c.args, []any{nmDest, "ActiveConnections"}):
		case c.method == propsGet && strings.HasPrefix(string(c.path), string(nmPath)+"/ActiveConnection/") &&
			len(c.args) == 2 && c.args[0] == activeIface && (c.args[1] == "Uuid" || c.args[1] == "State"):
		default:
			t.Errorf("unexpected call %s on %s %v", c.method, c.path, c.args)
		}
	}
	if len(writes) != 2 || !strings.HasSuffix(writes[0].method, ".AddConnection2") || !strings.HasSuffix(writes[1].method, ".Update2") {
		t.Fatalf("writes %v, want AddConnection2 then Update2", writes)
	}
	for _, w := range writes {
		if len(w.args) != 3 || w.args[1] != toDisk || !reflect.DeepEqual(w.args[2], map[string]dbus.Variant{}) {
			t.Fatalf("%s flags/args %v", w.method, w.args[1:])
		}
		s := w.args[0].(map[string]map[string]dbus.Variant)
		for _, f := range []struct{ group, key, sig string }{
			{"connection", "id", "s"}, {"connection", "uuid", "s"}, {"connection", "type", "s"},
			{"connection", "autoconnect", "b"}, {"connection", "interface-name", "s"},
			{"802-11-wireless", "ssid", "ay"}, {"802-11-wireless", "mode", "s"}, {"802-11-wireless", "hidden", "b"},
			{"802-11-wireless-security", "key-mgmt", "s"}, {"802-11-wireless-security", "psk", "s"},
			{"802-11-wireless-security", "psk-flags", "u"},
		} {
			v, ok := s[f.group][f.key]
			if !ok || v.Signature().String() != f.sig {
				t.Errorf("%s.%s = %v, want type %s", f.group, f.key, v, f.sig)
			}
		}
		if s["802-11-wireless-security"]["psk"].Value() != canary || !bytes.Equal(s["802-11-wireless"]["ssid"].Value().([]byte), []byte("home")) {
			t.Error("the request's SSID and PSK were not sent")
		}
		want := netjoin.ConnectionSettings("home", canary, "wlan1")
		if len(s) != len(want) {
			t.Errorf("groups %d, want %d", len(s), len(want))
		}
		for g, props := range want {
			if len(s[g]) != len(props) {
				t.Errorf("%s has %d keys, want %d", g, len(s[g]), len(props))
			}
		}
	}
	if strings.Contains(logs.String(), canary) {
		t.Fatal("the PSK was logged")
	}
}

// A lookup that finds nothing is NetworkManager's InvalidConnection
// error, read as no connection; any other bus error is not, and a path
// outside Settings is never written.
func TestLookupErrorsAndPathsAreChecked(t *testing.T) {
	b := &fakeBus{}
	nm := nmBus{obj: b.obj}
	if _, err := nm.GetConnectionByUuid(context.Background(), netjoin.UUID); err != netjoin.ErrNoConnection {
		t.Fatalf("InvalidConnection gave %v", err)
	}
	b.conn = "/org/freedesktop/NetworkManager/Devices/1"
	if _, err := nm.GetConnectionByUuid(context.Background(), netjoin.UUID); err == nil {
		t.Fatal("a non-connection path was accepted")
	}
	n := len(b.calls)
	if err := nm.Update2(context.Background(), "/org/freedesktop/NetworkManager/Devices/1", netjoin.ConnectionSettings("home", canary, "wlan1")); err == nil {
		t.Fatal("Update2 on a non-connection path")
	}
	if _, err := nm.ActiveUUID(context.Background(), "/org/freedesktop/systemd1"); err == nil {
		t.Fatal("a read outside NetworkManager")
	}
	if len(b.calls) != n {
		t.Fatalf("refused paths reached the bus: %v", b.calls[n:])
	}
	for _, c := range b.calls {
		for _, a := range c.args {
			if strings.Contains(fmt.Sprint(a), canary) {
				t.Fatal("canary in a lookup")
			}
		}
	}
}

// Acceptance test 7, unit half (Security L8.1).
func TestTheUnitIsHardened(t *testing.T) {
	b, err := os.ReadFile("agentos-netjoin.service")
	if err != nil {
		t.Fatal(err)
	}
	set := map[string][]string{}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "[") {
			continue
		}
		k, v, _ := strings.Cut(l, "=")
		set[k] = append(set[k], v)
	}
	for k, want := range map[string][]string{
		"User":                    {"agentos-netjoin"},
		"Group":                   {"agentos-netjoin"},
		"CapabilityBoundingSet":   {""},
		"NoNewPrivileges":         {"yes"},
		"RestrictAddressFamilies": {"AF_UNIX"},
		"IPAddressDeny":           {"any"},
		"ProtectSystem":           {"strict"},
		"ProtectHome":             {"yes"},
		"RuntimeDirectory":        {"agentos-netjoin"},
		"RuntimeDirectoryMode":    {"0700"},
		"MemoryDenyWriteExecute":  {"yes"},
	} {
		if strings.Join(set[k], "|") != strings.Join(want, "|") {
			t.Errorf("%s = %q, want %q", k, set[k], want)
		}
	}
	// Exactly one writable path, the socket's directory; no secrets or
	// settings from the environment.
	for _, k := range []string{
		"AmbientCapabilities", "EnvironmentFile", "Environment", "PassEnvironment",
		"ReadWritePaths", "StateDirectory", "CacheDirectory", "LogsDirectory",
		"ConfigurationDirectory", "TemporaryFileSystem", "BindPaths", "PrivateTmp",
		"SupplementaryGroups", "DynamicUser",
	} {
		if v, ok := set[k]; ok {
			t.Errorf("%s=%q is set", k, v)
		}
	}
	exec := strings.Join(set["ExecStart"], "")
	if !strings.Contains(exec, " -dir /run/agentos-netjoin ") {
		t.Errorf("ExecStart %q does not serve the RuntimeDirectory", exec)
	}
}

// execArgs is a unit's ExecStart split into its arguments, the binary
// dropped, with backslash continuations joined.
func execArgs(t *testing.T, unit string) []string {
	t.Helper()
	b, err := os.ReadFile(unit)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(string(b), "\\\n", " ")
	for _, l := range strings.Split(text, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "ExecStart="); ok {
			return strings.Fields(v)[1:]
		}
	}
	t.Fatalf("%s has no ExecStart", unit)
	return nil
}

// S-R4 (#1428): the unit names every interface agentos-ap's unit may run
// the access point on, and no station until #936 ships one, so the
// helper as installed refuses every join before any bus call.
func TestTheUnitRefusesTheAccessPointInterface(t *testing.T) {
	c, err := parseFlags(execArgs(t, "agentos-netjoin.service"))
	if err != nil {
		t.Fatal(err)
	}
	if c.station != "" {
		t.Errorf("the unit names station %q before #936 ships one", c.station)
	}
	ap := execArgs(t, "../agentos-ap/agentos-ap.service")
	var served []string
	for i, a := range ap {
		if a == "-iface" && i+1 < len(ap) {
			served = append(served, ap[i+1])
		}
	}
	if len(served) == 0 {
		t.Fatal("agentos-ap's unit names no -iface")
	}
	for _, s := range served {
		if !slices.Contains(c.ap, s) {
			t.Errorf("agentos-ap serves on %s, which -ap-iface %v leaves out", s, c.ap)
		}
	}
	b := &fakeBus{}
	if got := c.joiner(nmBus{obj: b.obj}).Join(context.Background(), "home", canary); got != netjoin.Failed || len(b.calls) != 0 {
		t.Fatalf("the unit's helper answered %q after %d bus calls, want failed after none", got, len(b.calls))
	}
}

// The flags reach the Joiner: -station and every -ap-iface.
func TestTheFlagsReachTheJoiner(t *testing.T) {
	c, err := parseFlags([]string{"-dir", "/run/x", "-agentosd-uid", "7", "-station", "wlan1", "-ap-iface", "wlan0", "-ap-iface", "wlan2"})
	if err != nil {
		t.Fatal(err)
	}
	if c.dir != "/run/x" || c.agentosdUID != 7 || c.station != "wlan1" || !slices.Equal(c.ap, []string{"wlan0", "wlan2"}) {
		t.Fatalf("parsed %+v", c)
	}
	for _, tc := range []struct {
		args []string
		want netjoin.Code
	}{
		{[]string{"-station", "wlan1", "-ap-iface", "wlan0"}, netjoin.Joined},
		{[]string{"-station", "wlan0", "-ap-iface", "wlan0"}, netjoin.Failed},
		{[]string{"-station", "wlan2", "-ap-iface", "wlan0", "-ap-iface", "wlan2"}, netjoin.Failed},
		{[]string{"-station", "wlan1"}, netjoin.Failed},
	} {
		c, err := parseFlags(tc.args)
		if err != nil {
			t.Fatal(err)
		}
		b := &fakeBus{}
		if got := c.joiner(nmBus{obj: b.obj}).Join(context.Background(), "home", canary); got != tc.want {
			t.Errorf("%v: answered %q, want %q", tc.args, got, tc.want)
		}
	}
	if _, err := parseFlags([]string{"-bogus"}); err == nil {
		t.Error("an unknown flag parsed")
	}
}

// Acceptance test 7, polkit half (Security L8.2), as a fixed-text check:
// the rule's code, comments aside, is exactly this, so its one YES is
// under the helper's user and settings.modify.system, and every other
// path is NOT_HANDLED.
func TestThePolkitRuleGrantsOneActionToTheHelper(t *testing.T) {
	b, err := os.ReadFile("50-agentos-netjoin.rules")
	if err != nil {
		t.Fatal(err)
	}
	var code []string
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "//") {
			continue
		}
		code = append(code, strings.Join(strings.Fields(l), " "))
	}
	want := []string{
		`polkit.addRule(function(action, subject) {`,
		`if (subject.user == "agentos-netjoin" &&`,
		`action.id == "org.freedesktop.NetworkManager.settings.modify.system") {`,
		`return polkit.Result.YES;`,
		`}`,
		`return polkit.Result.NOT_HANDLED;`,
		`});`,
	}
	if !reflect.DeepEqual(code, want) {
		t.Fatalf("rule is\n%s\nwant\n%s", strings.Join(code, "\n"), strings.Join(want, "\n"))
	}
	if n := strings.Count(string(b), "polkit.Result.YES"); n != 1 {
		t.Fatalf("%d YES results", n)
	}
}

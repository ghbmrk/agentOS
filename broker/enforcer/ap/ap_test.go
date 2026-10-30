package ap

// REQ: NET-3, HW-10

import (
	"bytes"
	"errors"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

var update = flag.Bool("update", false, "rewrite testdata/*.golden")

// fixtureLayout is the OpenWrt One: its 2.5 GbE port carries the
// networks and the admin VLAN, its 1 GbE port the device VLANs.
func fixtureLayout() Layout {
	return Layout{
		Uplink: "eth0", DeviceUplink: "eth1",
		Owner: 10, Household: 20, Guests: 30, Admin: 99,
		Addr: netip.MustParsePrefix("10.70.0.2/24"),
		Radios: []Radio{
			{Name: "radio0", Path: "platform/soc/18000000.wifi", Band: "2g", HTMode: "HE20", Channel: "auto", Country: "US"},
			{Name: "radio1", Path: "platform/soc/18000000.wifi+1", Band: "5g", HTMode: "HE80", Channel: "auto", Country: "US"},
		},
		SSID:        SSIDs{Setup: "Home setup", Owner: "Home", Household: "Home family", Guests: "Home guests", Devices: "Home things"},
		EnforcerKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEnforcerSyntheticTestKeyOnly000000000000000",
	}
}

// fixturePolicy names every device with text that must not reach the
// access point: ids, hosts and destinations are all core-proposed.
func fixturePolicy() policy.Document {
	return policy.Document{
		Version:      3,
		Destinations: []string{"core-held-destination.example"},
		Devices: []policy.Device{
			{ID: "core-held-id-tv", Network: policy.NetDevices, WiFi: "vlan101", Allow: []string{"core-held-host-tv.example"}, VendorCloud: true, Everyday: true},
			{ID: "core-held-id-plug", Network: policy.NetDevices, WiFi: "vlan102", Class: policy.ClassPlug, Secure: "off"},
			{ID: "core-held-id-cam", Network: policy.NetDevices, WiFi: "vlan104", Class: policy.ClassCamera},
			{ID: "core-held-id-lock", Network: policy.NetDevices, Class: policy.ClassLock, Secure: "lock"},
			{ID: "core-held-id-laptop", Network: policy.NetHousehold, Everyday: true},
		},
	}
}

// fixtureKeys are synthetic canaries, never real passwords.
func fixtureKeys() Keys {
	return Keys{
		Setup: "CANARYSETUPAAAAAAAAAAAAAAA", Owner: "CANARYOWNERAAAAAAAAAAAAAAA",
		Household: "CANARYHOUSEHOLDAAAAAAAAAAA", Guests: "CANARYGUESTSAAAAAAAAAAAAAA",
		Devices: "CANARYDEVICESUNUSEDAAAAAAA",
		Device: map[string]DeviceKey{
			"core-held-id-tv":   {VLAN: 101, Password: "CANARYTVAAAAAAAAAAAAAAAAAA"},
			"core-held-id-plug": {VLAN: 102, Password: "CANARYPLUGAAAAAAAAAAAAAAAA"},
			"core-held-id-cam":  {VLAN: 104, Password: "CANARYCAMAAAAAAAAAAAAAAAAA"},
		},
	}
}

func files(t *testing.T, d policy.Document, l Layout, k Keys) map[string]string {
	t.Helper()
	fs, err := Config(d, l, k)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, f := range fs {
		out[f.Path] = string(f.Data)
	}
	return out
}

// TestGoldenConfig: the fixture policy renders to exactly the files in
// testdata, twice; each device is on its own VLAN with its own password;
// and no value the core holds appears in any file, nor any password in
// the policy document the core proposes. Catches agentOS holding a Wi-Fi
// password, and core-proposed text reaching the access point.
func TestGoldenConfig(t *testing.T) {
	d, l, k := fixturePolicy(), fixtureLayout(), fixtureKeys()
	got := files(t, d, l, k)
	again := files(t, d, l, k)
	for _, p := range Paths {
		if got[p] != again[p] {
			t.Fatalf("two renders of %s differ", p)
		}
		golden := filepath.Join("testdata", strings.ReplaceAll(strings.TrimPrefix(p, "/"), "/", "_")+".golden")
		if *update {
			if err := os.WriteFile(golden, []byte(got[p]), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatal(err)
		}
		if got[p] != string(want) {
			t.Errorf("%s differs from %s (run with -update and review the diff):\n%s", p, golden, got[p])
		}
	}
	all := strings.Join([]string{got[PathNetwork], got[PathWireless], got[PathFirewall], got[PathDHCP], got[PathDropbear], got[PathAuthKeys]}, "\n")
	if strings.Contains(all, "core-held") {
		t.Error("a core-proposed id, host or destination reached the access point")
	}
	doc, err := policy.Encode(d)
	if err != nil {
		t.Fatal(err)
	}
	for id, dk := range k.Device {
		if bytes.Contains(doc, []byte(dk.Password)) {
			t.Errorf("the policy document holds %s's password", id)
		}
		station := "\toption vid '" + itoa(dk.VLAN) + "'\n\toption key '" + dk.Password + "'\n"
		if !strings.Contains(got[PathWireless], station) {
			t.Errorf("%s's password does not put it on VLAN %d", id, dk.VLAN)
		}
	}
	for _, s := range []string{"option address", "option ip6addr", "option gateway", "option dns"} {
		if strings.Contains(got[PathNetwork], s) {
			t.Errorf("the access point has %q: it should hold only its admin address", s)
		}
	}
	if strings.Count(got[PathNetwork], "proto 'static'") != 2 { // loopback and admin
		t.Error("the access point holds an address outside its admin VLAN")
	}
	if !strings.Contains(got[PathDropbear], "option Interface 'admin'") || !strings.Contains(got[PathDropbear], "PasswordAuth 'off'") {
		t.Error("SSH is not admin-VLAN and key only")
	}
	if strings.Contains(got[PathWireless], "CANARYSETUP") {
		t.Error("the setup network outlived enrolment")
	}
}

// TestSetupNetworkOnlyBeforeEnrolment: before enrolment the access point
// broadcasts the setup network alone, on the Owner VLAN, with the
// sticker's password; enrolment replaces it with four networks whose
// passwords the enforcer made (HW-10).
func TestSetupNetworkOnlyBeforeEnrolment(t *testing.T) {
	d, l := policy.Document{Version: 1}, fixtureLayout()
	k := Keys{Setup: "CANARYSETUPAAAAAAAAAAAAAAA"}
	got := files(t, d, l, k)[PathWireless]
	if strings.Count(got, "config wifi-iface") != len(l.Radios) || !strings.Contains(got, "option ssid 'Home setup'") ||
		!strings.Contains(got, "option network 'owner'") || strings.Contains(got, "household") || strings.Contains(got, "guests") {
		t.Fatalf("before enrolment:\n%s", got)
	}
	if _, err := Config(fixturePolicy(), l, k); !errors.Is(err, ErrKeys) {
		t.Errorf("devices before enrolment: %v", err)
	}
	if c, ok := k.NetworkCard(l, NetSetup); !ok || c.Password != k.Setup {
		t.Errorf("setup card before enrolment: %+v", c)
	}
	if _, ok := k.NetworkCard(l, policy.NetOwner); ok {
		t.Error("an Owner card before enrolment")
	}
	if err := k.Enrol(); err != nil {
		t.Fatal(err)
	}
	if err := k.Enrol(); err == nil {
		t.Error("a second enrolment replaced the networks' passwords")
	}
	got = files(t, d, l, k)[PathWireless]
	if strings.Contains(got, k.Setup) || strings.Contains(got, "Home setup") || !strings.Contains(got, k.Owner) {
		t.Fatalf("after enrolment:\n%s", got)
	}
	for _, n := range []string{policy.NetOwner, policy.NetHousehold, policy.NetGuests} {
		c, ok := k.NetworkCard(l, n)
		if !ok || c.Password == "" || !strings.HasPrefix(c.QR, "WIFI:T:WPA;S:") {
			t.Errorf("%s card %+v", n, c)
		}
	}
	if _, ok := k.NetworkCard(l, NetSetup); ok {
		t.Error("the page still shows the setup network after enrolment")
	}
}

// TestRevokeOneRepairsNoOther: removing a device, re-keying one or moving
// one to another VLAN changes that device's password and line only; every
// other device and network keeps its password, so none re-pairs. Catches
// a shared secret.
func TestRevokeOneRepairsNoOther(t *testing.T) {
	d, l := fixturePolicy(), fixtureLayout()
	k := Keys{Setup: "CANARYSETUPAAAAAAAAAAAAAAA"}
	if err := k.Enrol(); err != nil {
		t.Fatal(err)
	}
	fresh, err := k.Sync(d)
	if err != nil || len(fresh) != 3 {
		t.Fatalf("first sync: %v %v", fresh, err)
	}
	before := k.clone()
	lines := func(k Keys) map[string]string {
		w := files(t, d, l, k)[PathWireless]
		out := map[string]string{}
		for id, dk := range k.Device {
			out[id] = "option vid '" + itoa(dk.VLAN) + "'\n\toption key '" + dk.Password + "'"
			if !strings.Contains(w, out[id]) {
				t.Fatalf("%s missing from config", id)
			}
		}
		return out
	}
	was := lines(k)
	same := func(skip string) {
		t.Helper()
		if k.Owner != before.Owner || k.Household != before.Household || k.Guests != before.Guests || k.Devices != before.Devices {
			t.Error("a network's password changed")
		}
		now := lines(k)
		for id, line := range was {
			if id != skip && now[id] != line {
				t.Errorf("%s re-paired when %s changed", id, skip)
			}
		}
	}

	// Revoke the plug by removing it.
	d.Devices = append(d.Devices[:1:1], d.Devices[2:]...)
	if fresh, err := k.Sync(d); err != nil || len(fresh) != 0 {
		t.Fatalf("revoke: %v %v", fresh, err)
	}
	same("core-held-id-plug")
	if strings.Contains(files(t, d, l, k)[PathWireless], before.Device["core-held-id-plug"].Password) {
		t.Error("a revoked password still joins")
	}
	if _, ok := k.DeviceCard(l, "core-held-id-plug"); ok {
		t.Error("the page still shows a revoked password")
	}
	delete(was, "core-held-id-plug")

	// Re-key the camera.
	if err := k.Rekey("core-held-id-cam"); err != nil {
		t.Fatal(err)
	}
	if k.Device["core-held-id-cam"].Password == before.Device["core-held-id-cam"].Password {
		t.Error("re-key kept the password")
	}
	same("core-held-id-cam")
	was = lines(k)

	// Move the TV to another VLAN: a new pairing, nobody else's.
	d.Devices[0].WiFi = "vlan120"
	if fresh, err := k.Sync(d); err != nil || len(fresh) != 1 || fresh[0] != "core-held-id-tv" {
		t.Fatalf("move: %v %v", fresh, err)
	}
	same("core-held-id-tv")

	// A device re-added under a revoked id gets a new password.
	d.Devices = append(d.Devices, policy.Device{ID: "core-held-id-plug", Network: policy.NetDevices, WiFi: "vlan102", Everyday: true})
	if _, err := k.Sync(d); err != nil {
		t.Fatal(err)
	}
	if k.Device["core-held-id-plug"].Password == before.Device["core-held-id-plug"].Password {
		t.Error("a revoked password came back")
	}
}

// TestConfigRefuses: keys out of step with the policy, equal passwords, a
// VLAN that is a network's on a shared port, and layout values that would
// need quoting all fail, so the previous config stays on the access point.
func TestConfigRefuses(t *testing.T) {
	d := fixturePolicy()
	cases := map[string]func(*policy.Document, *Layout, *Keys){
		"device without key": func(d *policy.Document, _ *Layout, _ *Keys) {
			d.Devices = append(d.Devices, policy.Device{ID: "x", Network: policy.NetDevices, WiFi: "vlan130", Everyday: true})
		},
		"key without device": func(d *policy.Document, _ *Layout, _ *Keys) { d.Devices = d.Devices[1:] },
		"key on other VLAN": func(_ *policy.Document, _ *Layout, k *Keys) {
			k.Device["core-held-id-tv"] = DeviceKey{VLAN: 111, Password: k.Device["core-held-id-tv"].Password}
		},
		"equal passwords": func(_ *policy.Document, _ *Layout, k *Keys) {
			k.Device["core-held-id-cam"] = DeviceKey{VLAN: 104, Password: k.Device["core-held-id-tv"].Password}
		},
		"device password equals a network's": func(_ *policy.Document, _ *Layout, k *Keys) {
			k.Device["core-held-id-cam"] = DeviceKey{VLAN: 104, Password: k.Guests}
		},
		"short password": func(_ *policy.Document, _ *Layout, k *Keys) { k.Owner = "short" },
		"quote in password": func(_ *policy.Document, _ *Layout, k *Keys) {
			k.Guests = "CANARY'option-injected-AA"
		},
		"device VLAN is a network's": func(d *policy.Document, l *Layout, k *Keys) {
			l.DeviceUplink = l.Uplink
			d.Devices[0].WiFi = "vlan10"
			k.Device["core-held-id-tv"] = DeviceKey{VLAN: 10, Password: k.Device["core-held-id-tv"].Password}
		},
		"quote in SSID":      func(_ *policy.Document, l *Layout, _ *Keys) { l.SSID.Guests = "Guests'\n\toption isolate '0" },
		"long SSID":          func(_ *policy.Document, l *Layout, _ *Keys) { l.SSID.Owner = strings.Repeat("a", 33) },
		"two networks named": func(_ *policy.Document, l *Layout, _ *Keys) { l.SSID.Guests = l.SSID.Owner },
		"VLANs collide":      func(_ *policy.Document, l *Layout, _ *Keys) { l.Guests = l.Owner },
		"bad uplink":         func(_ *policy.Document, l *Layout, _ *Keys) { l.Uplink = "eth0;reboot" },
		"network address":    func(_ *policy.Document, l *Layout, _ *Keys) { l.Addr = netip.MustParsePrefix("10.70.0.0/24") },
		"bad key":            func(_ *policy.Document, l *Layout, _ *Keys) { l.EnforcerKey = "ssh-ed25519 AAAA\ncommand=\"reboot\"" },
		"bad radio":          func(_ *policy.Document, l *Layout, _ *Keys) { l.Radios[0].Country = "US'" },
	}
	for name, mutate := range cases {
		d2, l, k := d, fixtureLayout(), fixtureKeys()
		d2.Devices = append([]policy.Device{}, d.Devices...)
		mutate(&d2, &l, &k)
		if _, err := Config(d2, l, k); err == nil {
			t.Errorf("%s: rendered", name)
		}
	}
	if _, err := Config(d, fixtureLayout(), fixtureKeys()); err != nil {
		t.Fatalf("the fixture itself: %v", err)
	}
}

// TestCardOnlyFromKeys: the page's card carries the device's own password
// and a QR text with the SSID escaped.
func TestCardOnlyFromKeys(t *testing.T) {
	l, k := fixtureLayout(), fixtureKeys()
	l.SSID.Devices = `a;b:c,d\e"f`
	c, ok := k.DeviceCard(l, "core-held-id-tv")
	if !ok || c.Password != "CANARYTVAAAAAAAAAAAAAAAAAA" || c.QR != `WIFI:T:WPA;S:a\;b\:c\,d\\e\"f;P:CANARYTVAAAAAAAAAAAAAAAAAA;;` {
		t.Fatalf("%+v", c)
	}
	if _, ok := k.DeviceCard(l, "core-held-id-lock"); ok {
		t.Error("a radio device got a Wi-Fi card")
	}
}

func (k Keys) clone() Keys {
	c := k
	c.Device = map[string]DeviceKey{}
	for id, dk := range k.Device {
		c.Device[id] = dk
	}
	return c
}

func itoa(n int) string { return vname(n)[1:] }

// TestValueRules: the character and length rules every UCI value passes,
// at each boundary, so a value one past a limit is refused and one at it
// is kept.
func TestValueRules(t *testing.T) {
	for _, c := range []struct {
		fn   func(string) bool
		s    string
		want bool
	}{
		{word, "!", true}, {word, "~", true}, {word, " ", false}, {word, "\x7f", false}, {word, "a b", false},
		{word, "'", false}, {word, `"`, false}, {word, `\`, false}, {word, "#", false}, {word, "", false},
		{word, strings.Repeat("a", 255), true}, {word, strings.Repeat("a", 256), false}, {word, "é", false},
		{ssid, "Home", true}, {ssid, "Home 2", true}, {ssid, " Home", false}, {ssid, "Home ", false}, {ssid, "", false},
		{ssid, strings.Repeat("a", 32), true}, {ssid, strings.Repeat("a", 33), false}, {ssid, "a'b", false},
		{ifname, "eth0", true}, {ifname, "a_b-9", true}, {ifname, "AZaz09_-", true}, {ifname, "-eth", false},
		{ifname, strings.Repeat("a", 10), true}, {ifname, strings.Repeat("a", 11), false}, {ifname, "", false},
		{ifname, "eth.0", false}, {ifname, "a/b", false}, {ifname, "a:b", false}, {ifname, "a@b", false},
		{ifname, "a[b", false}, {ifname, "a`b", false}, {ifname, "a{b", false},
	} {
		if got := c.fn(c.s); got != c.want {
			t.Errorf("%q: got %v", c.s, got)
		}
	}
	for v, ok := range map[int]bool{1: false, 2: true, 4094: true, 4095: false} {
		l := fixtureLayout()
		l.Admin = v
		if err := l.Check(); (err == nil) != ok {
			t.Errorf("admin VLAN %d: %v", v, err)
		}
	}
	for n, ok := range map[int]bool{7: false, 8: true, 63: true, 64: false} {
		k := fixtureKeys()
		k.Guests = strings.Repeat("G", n)
		if _, err := Config(fixturePolicy(), fixtureLayout(), k); (err == nil) != ok {
			t.Errorf("password of %d: %v", n, err)
		}
	}
}

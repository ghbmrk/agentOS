package ap

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

// Layout is the access point's wiring and names. Like nft.Layout it comes
// from the enforcer's image and setup, never from the core or the policy,
// and Check refuses anything that would need quoting in a UCI file.
type Layout struct {
	// Uplink is the access point's wired port that carries the networks'
	// and the admin VLAN to the enforcer; DeviceUplink carries one VLAN
	// per device to the enforcer's device trunk (nft.Layout.Trunk). They
	// may be the same port only if no device VLAN equals a network's.
	Uplink, DeviceUplink string
	// The VLAN of each network and of the access point's admin address.
	// The setup network rides the Owner VLAN: before enrolment the
	// enforcer serves only its enrolment page there (HW-10, NET-4).
	Owner, Household, Guests, Admin int
	// Addr is the access point's one address, on the admin VLAN, which
	// the enforcer's firewall lets only the wired admin port reach.
	Addr netip.Prefix
	// Radios are the access point's radios as its stock config names
	// them. The Devices network is on the first only: most home devices
	// join only 2.4 GHz.
	Radios []Radio
	SSID   SSIDs
	// EnforcerKey is the enforcer's SSH public key in authorized_keys
	// form ("ssh-ed25519 AAAA..."): the only login the access point
	// accepts.
	EnforcerKey string
}

// Radio is one wifi-device section.
type Radio struct {
	Name, Path, Band, HTMode, Channel, Country string
}

// SSIDs are the networks' names, set at setup.
type SSIDs struct {
	Setup, Owner, Household, Guests, Devices string
}

// Check refuses a layout whose values could not be written into a UCI
// file unquoted-safe, whose VLANs collide, or whose address is not one.
func (l Layout) Check() error {
	bad := func(f string, a ...any) error { return fmt.Errorf("%w: "+f, append([]any{ErrLayout}, a...)...) }
	if !ifname(l.Uplink) || !ifname(l.DeviceUplink) {
		return bad("uplink %q or %q", l.Uplink, l.DeviceUplink)
	}
	nets := []int{l.Owner, l.Household, l.Guests, l.Admin}
	for i, v := range nets {
		if v < 2 || v > 4094 || slices.Contains(nets[:i], v) {
			return bad("VLAN %d", v)
		}
	}
	if !l.Addr.IsValid() || !l.Addr.Addr().Is4() || l.Addr.Masked().Addr() == l.Addr.Addr() {
		return bad("address %v", l.Addr)
	}
	if len(l.Radios) == 0 {
		return bad("no radio")
	}
	for i, r := range l.Radios {
		for _, v := range []string{r.Name, r.Path, r.Band, r.HTMode, r.Channel, r.Country} {
			if !word(v) {
				return bad("radio %q value %q", r.Name, v)
			}
		}
		if slices.ContainsFunc(l.Radios[:i], func(o Radio) bool { return o.Name == r.Name }) {
			return bad("radio %q twice", r.Name)
		}
	}
	s := l.SSID
	ssids := []string{s.Setup, s.Owner, s.Household, s.Guests, s.Devices}
	for i, v := range ssids {
		// Setup and Owner never broadcast together, so only the four
		// networks' names must differ.
		if !ssid(v) || i > 0 && slices.Contains(ssids[1:i], v) {
			return bad("network name %q", v)
		}
	}
	kt, kb, ok := strings.Cut(l.EnforcerKey, " ")
	if !ok || !word(kt) || !word(kb) || !strings.HasPrefix(kt, "ssh-") && !strings.HasPrefix(kt, "ecdsa-") {
		return bad("enforcer key")
	}
	return nil
}

// File is one file the access point holds, by absolute path.
type File struct {
	Path string
	Data []byte
}

// The files the enforcer writes on the access point, in the order it
// writes them. ap/push accepts no other path.
const (
	PathNetwork  = "/etc/config/network"
	PathWireless = "/etc/config/wireless"
	PathFirewall = "/etc/config/firewall"
	PathDHCP     = "/etc/config/dhcp"
	PathDropbear = "/etc/config/dropbear"
	PathAuthKeys = "/etc/dropbear/authorized_keys"
)

// Paths is every path Config writes.
var Paths = []string{PathNetwork, PathWireless, PathFirewall, PathDHCP, PathDropbear, PathAuthKeys}

// Config renders the access point's whole configuration for policy d.
// Devices appear only by VLAN number and their passwords only from k, so
// no text the core proposed (a device id, a host name) reaches a file.
// Before enrolment it broadcasts the setup network alone.
func Config(d policy.Document, l Layout, k Keys) ([]File, error) {
	if err := l.Check(); err != nil {
		return nil, err
	}
	devs, err := devices(d, l, k)
	if err != nil {
		return nil, err
	}
	if err := k.check(); err != nil {
		return nil, err
	}
	return []File{
		{PathNetwork, network(l, devs)},
		{PathWireless, wireless(l, k, devs)},
		{PathFirewall, []byte(firewall)},
		{PathDHCP, []byte(dhcp)},
		{PathDropbear, []byte(dropbear)},
		{PathAuthKeys, []byte(authPrefix + l.EnforcerKey + "\n")},
	}, nil
}

// devices is the device keys sorted by VLAN, after checking that k holds
// exactly the Devices-network devices of d, each on its VLAN in d, and
// that no device VLAN collides with a network's on a shared port.
func devices(d policy.Document, l Layout, k Keys) ([]DeviceKey, error) {
	want, err := vlans(d)
	if err != nil {
		return nil, err
	}
	if len(want) > 0 && !k.Enrolled() {
		return nil, fmt.Errorf("%w: devices before enrolment", ErrKeys)
	}
	if len(want) != len(k.Device) {
		return nil, fmt.Errorf("%w: keys not synced to version %d", ErrKeys, d.Version)
	}
	var out []DeviceKey
	for id, v := range want {
		dk, ok := k.Device[id]
		if !ok || dk.VLAN != v {
			return nil, fmt.Errorf("%w: keys not synced to version %d", ErrKeys, d.Version)
		}
		if l.DeviceUplink == l.Uplink && slices.Contains([]int{l.Owner, l.Household, l.Guests, l.Admin}, v) {
			return nil, fmt.Errorf("%w: device VLAN %d is a network's", ErrPolicy, v)
		}
		out = append(out, dk)
	}
	slices.SortFunc(out, func(a, b DeviceKey) int { return a.VLAN - b.VLAN })
	return out, nil
}

// check refuses a password that is not one WPA accepts or that needs
// quoting, and two equal passwords.
func (k Keys) check() error {
	pws := []string{k.Setup}
	if k.Enrolled() {
		pws = append(pws, k.Owner, k.Household, k.Guests, k.Devices)
	}
	for _, dk := range k.Device {
		pws = append(pws, dk.Password)
	}
	for _, p := range pws {
		if len(p) < 8 || len(p) > 63 || !word(p) {
			return fmt.Errorf("%w: a password is not 8 to 63 plain characters", ErrKeys)
		}
	}
	return k.distinct()
}

func network(l Layout, devs []DeviceKey) []byte {
	var w uci
	w.section("interface", "loopback", "device", "lo", "proto", "static", "ipaddr", "127.0.0.1", "netmask", "255.0.0.0")
	// IPv6 is off on every port and VLAN, so the access point has no
	// link-local address either. The admin VLAN holds its only address,
	// with no gateway: it starts no connection anywhere.
	for _, p := range slices.Compact([]string{l.Uplink, l.DeviceUplink}) {
		w.section("device", "", "name", p, "ipv6", "0")
	}
	w.vlan(l.Uplink, l.Admin)
	w.section("interface", "admin", "device", vdev(l.Uplink, l.Admin), "proto", "static",
		"ipaddr", l.Addr.String())
	// Every other network is a bridge with no address and IPv6 off, so
	// a Wi-Fi client has nothing on the access point to reach.
	bridge := func(name, port string, vid int) {
		w.vlan(port, vid)
		w.section("device", "", "name", "br-"+name, "type", "bridge", "ipv6", "0", "ports", vdev(port, vid))
		w.section("interface", name, "device", "br-"+name, "proto", "none")
	}
	bridge("owner", l.Uplink, l.Owner)
	bridge("household", l.Uplink, l.Household)
	bridge("guests", l.Uplink, l.Guests)
	for _, dk := range devs {
		bridge(vname(dk.VLAN), l.DeviceUplink, dk.VLAN)
	}
	return w.bytes()
}

func wireless(l Layout, k Keys, devs []DeviceKey) []byte {
	var w uci
	for _, r := range l.Radios {
		w.section("wifi-device", r.Name, "type", "mac80211", "path", r.Path, "band", r.Band,
			"htmode", r.HTMode, "channel", r.Channel, "country", r.Country, "cell_density", "0")
	}
	// Every network has WPS and 802.11r fast roaming off and management
	// frame protection on where the client supports it.
	iface := func(name, radio, net, ssid, enc, key string, extra ...string) {
		w.section("wifi-iface", name, append([]string{"device", radio, "mode", "ap", "network", net, "ssid", ssid,
			"encryption", enc, "key", key, "ieee80211w", "1", "wps_pushbutton", "0", "ieee80211r", "0"}, extra...)...)
	}
	if !k.Enrolled() {
		for _, r := range l.Radios {
			iface("setup_"+r.Name, r.Name, "owner", l.SSID.Setup, "sae-mixed", k.Setup)
		}
		return w.bytes()
	}
	for _, r := range l.Radios {
		iface("owner_"+r.Name, r.Name, "owner", l.SSID.Owner, "sae-mixed", k.Owner)
		iface("household_"+r.Name, r.Name, "household", l.SSID.Household, "sae-mixed", k.Household)
		iface("guests_"+r.Name, r.Name, "guests", l.SSID.Guests, "sae-mixed", k.Guests, "isolate", "1")
	}
	// The Devices network: WPA2 with one password per device, each on
	// its own VLAN; a device whose password is no station's gets no VLAN,
	// and dynamic_vlan 2 refuses it. The stations' keys become hostapd's
	// wpa_psk_file (D-225).
	r := l.Radios[0].Name
	iface("devices", r, "", l.SSID.Devices, "psk2+ccmp", k.Devices, "isolate", "1", "dynamic_vlan", "2")
	for _, dk := range devs {
		v := strconv.Itoa(dk.VLAN)
		w.section("wifi-vlan", "", "name", vname(dk.VLAN), "iface", "devices", "vid", v, "network", vname(dk.VLAN))
		w.section("wifi-station", "", "iface", "devices", "vid", v, "key", dk.Password)
	}
	return w.bytes()
}

// The access point accepts input only on its admin VLAN and forwards
// nothing it routes; bridged Wi-Fi traffic is the enforcer's to filter.
const firewall = `config defaults
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'REJECT'
	option synflood_protect '1'

config zone
	option name 'admin'
	list network 'admin'
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'REJECT'
`

// No DHCP, DNS or router advertisements from the access point: the
// enforcer serves each network (NET-2 Hardening).
const dhcp = `config dnsmasq
	option port '0'
	option noresolv '1'
	option localuse '0'

config odhcpd 'odhcpd'
	option maindhcp '0'
`

// SSH only on the admin VLAN, by key only.
const dropbear = `config dropbear 'main'
	option enable '1'
	option Interface 'admin'
	option Port '22'
	option PasswordAuth 'off'
	option RootPasswordAuth 'off'
	option RootLogin '1'
`

// The enforcer's key may run commands and nothing else.
const authPrefix = "no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty "

func vdev(port string, vid int) string { return port + "." + strconv.Itoa(vid) }
func vname(vid int) string             { return "v" + strconv.Itoa(vid) }

// uci writes UCI sections. Every value was checked by Layout.Check or
// Keys.check to hold no quote, backslash or control character.
type uci struct{ b strings.Builder }

func (w *uci) section(typ, name string, kv ...string) {
	if w.b.Len() > 0 {
		w.b.WriteString("\n")
	}
	w.b.WriteString("config " + typ)
	if name != "" {
		w.b.WriteString(" '" + name + "'")
	}
	w.b.WriteString("\n")
	for i := 0; i < len(kv); i += 2 { // kv is always pairs
		if kv[i+1] == "" {
			continue
		}
		verb := "option"
		if kv[i] == "ports" {
			verb = "list"
		}
		w.b.WriteString("\t" + verb + " " + kv[i] + " '" + kv[i+1] + "'\n")
	}
}

func (w *uci) vlan(port string, vid int) {
	w.section("device", "", "type", "8021q", "ifname", port, "vid", strconv.Itoa(vid), "name", vdev(port, vid), "ipv6", "0")
}

func (w *uci) bytes() []byte { return []byte(w.b.String()) }

// word is 1 to 255 printable ASCII characters other than a space, quote,
// backslash or the UCI comment sign.
func word(s string) bool {
	if s == "" || len(s) > 255 {
		return false
	}
	for _, c := range s {
		if c <= ' ' || c > '~' || c == '\'' || c == '"' || c == '\\' || c == '#' {
			return false
		}
	}
	return true
}

// ssid is 1 to 32 printable ASCII characters with no quote or backslash;
// spaces are allowed inside, not at the ends.
func ssid(s string) bool {
	if s == "" || len(s) > 32 || strings.TrimSpace(s) != s {
		return false
	}
	return word(strings.ReplaceAll(s, " ", "_"))
}

// ifname is a Linux interface name of [A-Za-z0-9_-], short enough for
// "<name>.<4094>" to fit the kernel's 15 bytes.
func ifname(s string) bool {
	if s == "" || len(s) > 10 || s[0] == '-' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

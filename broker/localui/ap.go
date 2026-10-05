package localui

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// APConfig describes the box's own Wi-Fi access point (CH-7) and the
// network around it (CH-9, ONB-5).
type APConfig struct {
	// Iface is the wireless interface the access point runs on.
	Iface string
	// Uplink is the interface to the home network, for passthrough; ""
	// when there is none yet.
	Uplink string
	// Addr is the box's address on the access point, with the client
	// subnet's length, e.g. 10.42.0.1/24.
	Addr netip.Prefix
	// SSID and Password come from the Owner Card.
	SSID, Password string
	// WPA2 adds WPA2-PSK beside WPA3-SAE, by owner opt-in for older phones
	// (CH-7). Off by default.
	WPA2 bool
	// Channel is the 2.4 GHz channel (default 6).
	Channel int
	// Country is the regulatory domain, two capital letters (default US).
	Country string
	// Passthrough lets Wi-Fi clients reach the internet through Uplink
	// once the box has one, so phones stay joined (ONB-5).
	Passthrough bool
}

// AccessPoint is the hardware seam: a driver brings up the access point,
// its DHCP and DNS, and the firewall from the configurations below. The
// real driver lands with the image (P2-1) and is tested on hardware (A1,
// A6); tests use the pure configuration functions.
type AccessPoint interface {
	Start(ctx context.Context, cfg APConfig) error
	// SetPassthrough turns ONB-5 passthrough on once an uplink exists.
	SetPassthrough(on bool, uplink string) error
	Stop() error
}

// UIPort is the local UI's TCP port.
const UIPort = 80

var (
	ifaceRe   = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)
	countryRe = regexp.MustCompile(`^[A-Z]{2}$`)
)

// Validate refuses any configuration that could expose the local UI beyond
// the access point (CH-9) or inject into a generated configuration.
func (c *APConfig) Validate() error {
	if err := c.ValidateServe(); err != nil {
		return err
	}
	if c.Channel == 0 {
		c.Channel = 6
	}
	if c.Country == "" {
		c.Country = "US"
	}
	switch {
	case c.Channel < 1 || c.Channel > 13:
		return errors.New("localui: channel")
	case !countryRe.MatchString(c.Country):
		return errors.New("localui: country code")
	}
	if n := len(c.SSID); n < 1 || n > 32 || !printable(c.SSID) {
		return errors.New("localui: SSID must be 1-32 printable ASCII characters")
	}
	// hostapd reads '|' in sae_password as a parameter separator.
	if n := len(c.Password); n < 8 || n > 63 || !printable(c.Password) || strings.Contains(c.Password, "|") ||
		strings.TrimSpace(c.Password) != c.Password {
		return errors.New("localui: Wi-Fi password must be 8-63 printable ASCII characters")
	}
	if c.Passthrough && c.Uplink == "" {
		return errors.New("localui: passthrough needs an uplink")
	}
	return nil
}

// ValidateServe checks what serving the page needs (CH-9): the access
// point's interface and its private address. The page's own process
// (agentos-localui) gets no Wi-Fi password; only the access point's driver
// needs Validate.
func (c *APConfig) ValidateServe() error {
	switch {
	case !ifaceRe.MatchString(c.Iface):
		return errors.New("localui: access point interface name")
	case c.Uplink != "" && (!ifaceRe.MatchString(c.Uplink) || c.Uplink == c.Iface):
		return errors.New("localui: uplink interface name")
	case !c.Addr.IsValid() || !c.Addr.Addr().Is4() || !c.Addr.Addr().IsPrivate():
		return errors.New("localui: access point address must be a private IPv4 address")
	case c.Addr.Bits() < 16 || c.Addr.Bits() > 30:
		return errors.New("localui: access point subnet must be /16 to /30")
	case c.Addr.Addr() == c.Addr.Masked().Addr():
		return errors.New("localui: access point address is the network address")
	}
	return nil
}

func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// HostapdConf is the hostapd configuration for CH-7: WPA3-SAE with
// management frame protection required, WPA2-PSK only by opt-in (then
// transition mode, MFP optional for those clients), and client isolation.
func HostapdConf(c APConfig) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	mgmt, mfp := "SAE", 2
	if c.WPA2 {
		mgmt, mfp = "SAE WPA-PSK", 1
	}
	var b strings.Builder
	line := func(k string, v any) { fmt.Fprintf(&b, "%s=%v\n", k, v) }
	line("interface", c.Iface)
	line("driver", "nl80211")
	line("ssid", c.SSID)
	line("country_code", c.Country)
	line("ieee80211d", 1)
	line("hw_mode", "g")
	line("channel", c.Channel)
	line("ieee80211n", 1)
	line("auth_algs", 1)
	line("wpa", 2)
	line("wpa_key_mgmt", mgmt)
	line("rsn_pairwise", "CCMP")
	line("sae_password", c.Password)
	if c.WPA2 {
		line("wpa_passphrase", c.Password)
	}
	line("ieee80211w", mfp)
	line("sae_require_mfp", 1)
	line("sae_pwe", 2)
	// Clients cannot reach each other (CH-7).
	line("ap_isolate", 1)
	line("max_num_sta", 8)
	return b.String(), nil
}

// DnsmasqConf is DHCP and DNS for the access point. Before passthrough,
// every name resolves to the box, so phones' captive-portal checks land on
// the local UI and the setup page opens by itself (ONB-5). With
// passthrough, names resolve normally and the checks pass.
func DnsmasqConf(c APConfig) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	box := c.Addr.Addr()
	subnet := c.Addr.Masked()
	first, last := hostRange(subnet, box)
	var b strings.Builder
	line := func(s string, a ...any) { fmt.Fprintf(&b, s+"\n", a...) }
	line("interface=%s", c.Iface)
	line("bind-interfaces")
	line("except-interface=lo")
	line("no-hosts")
	line("dhcp-authoritative")
	line("dhcp-range=%s,%s,%s,1h", first, last, maskOf(subnet.Bits()))
	line("dhcp-option=option:router,%s", box)
	line("dhcp-option=option:dns-server,%s", box)
	if c.Passthrough {
		line("no-poll")
	} else {
		line("no-resolv")
		line("address=/#/%s", box)
	}
	return b.String(), nil
}

// NftRules is the nftables ruleset for CH-9 and ONB-5. Wi-Fi clients
// reach only the local UI, DHCP and DNS on the box, and, with passthrough,
// the internet through address translation, never the home network's
// private addresses. Nothing else on the box (agent machines, executors,
// the uplink) can open a connection to a Wi-Fi client, and nothing off the
// access point can reach the local UI.
func NftRules(c APConfig) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	ap, box, subnet := c.Iface, c.Addr.Addr(), c.Addr.Masked()
	var b strings.Builder
	line := func(s string, a ...any) { fmt.Fprintf(&b, s+"\n", a...) }
	line("table inet agentos_ap {")
	line("  chain input {")
	line("    type filter hook input priority filter; policy accept;")
	line(`    iifname "%s" ip saddr %s ip daddr %s tcp dport %d accept`, ap, subnet, box, UIPort)
	line(`    iifname "%s" udp dport { 53, 67 } accept`, ap)
	line(`    iifname "%s" tcp dport 53 accept`, ap)
	line(`    iifname "%s" drop`, ap)
	line(`    iifname != "%s" tcp dport %d ip daddr %s drop`, ap, UIPort, box)
	line("  }")
	line("  chain forward {")
	line("    type filter hook forward priority filter; policy accept;")
	if c.Passthrough {
		line(`    iifname "%s" oifname "%s" ip saddr %s ip daddr != { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } accept`, ap, c.Uplink, subnet)
		line(`    iifname "%s" oifname "%s" ct state established,related accept`, c.Uplink, ap)
	}
	line(`    iifname "%s" drop`, ap)
	line(`    oifname "%s" drop`, ap)
	line("  }")
	if c.Passthrough {
		line("  chain postrouting {")
		line("    type nat hook postrouting priority srcnat; policy accept;")
		line(`    oifname "%s" ip saddr %s masquerade`, c.Uplink, subnet)
		line("  }")
	}
	line("}")
	return b.String(), nil
}

// hostRange returns the DHCP pool: the subnet's hosts above the box's own
// address, or below it when the box sits at the top.
func hostRange(subnet netip.Prefix, box netip.Addr) (netip.Addr, netip.Addr) {
	size := uint32(1) << (32 - subnet.Bits())
	base := u32(subnet.Addr())
	b := u32(box)
	lo, hi := base+1, base+size-2
	if b-base < size/2 {
		lo = b + 1
	} else {
		hi = b - 1
	}
	return a4(lo), a4(hi)
}

func maskOf(bits int) netip.Addr { return a4(^uint32(0) << (32 - bits)) }

func u32(a netip.Addr) uint32 {
	x := a.As4()
	return uint32(x[0])<<24 | uint32(x[1])<<16 | uint32(x[2])<<8 | uint32(x[3])
}

func a4(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

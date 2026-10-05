package localui

import (
	"os/exec"
	"strings"
	"testing"
)

// REQ: CH-7, CH-9, ONB-5

// CH-7: WPA3-SAE with management frame protection, WPA2 only by opt-in,
// and clients isolated from each other.
func TestHostapdConf(t *testing.T) {
	c := testAP()
	conf, err := HostapdConf(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ssid=AgentOS-7K3M\n", "wpa=2\n", "wpa_key_mgmt=SAE\n", "sae_password=ABCD-EFGH-JKLM-NPQR\n",
		"ieee80211w=2\n", "sae_require_mfp=1\n", "ap_isolate=1\n", "rsn_pairwise=CCMP\n"} {
		if !strings.Contains(conf, want) {
			t.Fatalf("missing %q in:\n%s", want, conf)
		}
	}
	if strings.Contains(conf, "WPA-PSK") || strings.Contains(conf, "wpa_passphrase") {
		t.Fatal("WPA2 on without opt-in")
	}
	c.WPA2 = true
	conf, _ = HostapdConf(c)
	for _, want := range []string{"wpa_key_mgmt=SAE WPA-PSK\n", "wpa_passphrase=ABCD-EFGH-JKLM-NPQR\n", "ieee80211w=1\n", "ap_isolate=1\n"} {
		if !strings.Contains(conf, want) {
			t.Fatalf("opt-in: missing %q", want)
		}
	}
}

// No value can inject a line into a generated configuration.
func TestConfigInjectionRefused(t *testing.T) {
	for _, f := range []func(*APConfig){
		func(c *APConfig) { c.SSID = "x\nap_isolate=0" },
		func(c *APConfig) { c.Password = "abcdefgh\nwpa=1" },
		func(c *APConfig) { c.Password = "abcdefgh|id=x" },
		func(c *APConfig) { c.Password = "short" },
		func(c *APConfig) { c.Iface = "wlan0\ninterface=eth0" },
		func(c *APConfig) { c.Uplink = "eth0 drop" },
		func(c *APConfig) { c.Country = "us\n" },
		func(c *APConfig) { c.SSID = strings.Repeat("x", 33) },
		func(c *APConfig) { c.Uplink = ""; c.Passthrough = true },
	} {
		c := testAP()
		f(&c)
		if _, err := HostapdConf(c); err == nil {
			t.Fatalf("accepted %+v", c)
		}
		if _, err := NftRules(c); err == nil {
			t.Fatalf("nft accepted %+v", c)
		}
	}
}

// ONB-5: before passthrough every name resolves to the box, so captive
// checks open the setup page; with passthrough, names resolve normally.
func TestDnsmasqConf(t *testing.T) {
	c := testAP()
	conf, err := DnsmasqConf(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"interface=wlan0\n", "bind-interfaces\n", "address=/#/10.42.0.1\n",
		"dhcp-range=10.42.0.2,10.42.0.254,255.255.255.0,1h\n", "dhcp-option=option:dns-server,10.42.0.1\n"} {
		if !strings.Contains(conf, want) {
			t.Fatalf("missing %q in:\n%s", want, conf)
		}
	}
	c.Passthrough = true
	conf, _ = DnsmasqConf(c)
	if strings.Contains(conf, "address=/#/") {
		t.Fatal("captive DNS left on with passthrough")
	}
}

// CH-9 and ONB-5's isolation: Wi-Fi clients reach only the UI, DHCP and DNS
// on the box, and with passthrough the internet but not private addresses;
// nothing reaches a Wi-Fi client unasked; the UI port is closed to every
// other interface.
func TestNftRules(t *testing.T) {
	c := testAP()
	rules, err := NftRules(c)
	if err != nil {
		t.Fatal(err)
	}
	nftCheck(t, rules)
	for _, want := range []string{
		`iifname "wlan0" ip saddr 10.42.0.0/24 ip daddr 10.42.0.1 tcp dport 80 accept`,
		`iifname "wlan0" drop`,
		`iifname != "wlan0" tcp dport 80 ip daddr 10.42.0.1 drop`,
		`oifname "wlan0" drop`,
	} {
		if !strings.Contains(rules, want) {
			t.Fatalf("missing %q in:\n%s", want, rules)
		}
	}
	if strings.Contains(rules, "masquerade") || strings.Contains(rules, `oifname "eth0" ip saddr`) {
		t.Fatal("forwarding open without passthrough")
	}
	c.Passthrough = true
	rules, _ = NftRules(c)
	for _, want := range []string{"192.168.0.0/16", "masquerade", `iifname "eth0" oifname "wlan0" ct state established,related accept`} {
		if !strings.Contains(rules, want) {
			t.Fatalf("passthrough: missing %q", want)
		}
	}
	// Every accept toward a Wi-Fi client is for replies only.
	for _, l := range strings.Split(rules, "\n") {
		if strings.Contains(l, `oifname "wlan0"`) && strings.Contains(l, "accept") && !strings.Contains(l, "established,related") {
			t.Fatalf("unsolicited path to Wi-Fi clients: %s", l)
		}
	}
	nftCheck(t, rules)
}

// nftCheck has nft parse the rules, when it is installed.
func nftCheck(t *testing.T, rules string) {
	t.Helper()
	if nft, err := exec.LookPath("nft"); err == nil {
		cmd := exec.Command(nft, "-c", "-f", "-")
		cmd.Stdin = strings.NewReader(rules)
		if out, err := cmd.CombinedOutput(); err != nil {
			if strings.Contains(string(out), "Operation not permitted") {
				t.Skip("nft -c needs privilege here")
			}
			t.Fatalf("nft rejects the rules: %s", out)
		}
	}
}

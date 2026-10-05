package at

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// REQ: HW-2

// The udev rule keeps the modem ports to the broker: every serial node of
// both qualified vendors, and the Quectel sound card, is 0600 and owned by
// the broker's modem user with no seat ACL, and ModemManager is told to
// ignore the modems.
func TestUdevRuleIsolatesTheModemPorts(t *testing.T) {
	b, err := os.ReadFile("udev/71-agentos-modem.rules")
	if err != nil {
		t.Fatal(err)
	}
	pair := regexp.MustCompile(`^([A-Z]+(?:\{[A-Za-z_]+\})?)(==|!=|=|\+=|-=|:=)"([^"]*)"$`)
	type rule map[string]string
	var rules []rule
	for n, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		r := rule{}
		for _, kv := range strings.Split(l, ", ") {
			m := pair.FindStringSubmatch(kv)
			if m == nil {
				t.Fatalf("line %d: cannot parse %q", n+1, kv)
			}
			r[m[1]+m[2]] = m[3]
		}
		rules = append(rules, r)
	}
	has := func(match func(rule) bool) rule {
		for _, r := range rules {
			if match(r) {
				return r
			}
		}
		return nil
	}
	for _, p := range Profiles {
		tty := has(func(r rule) bool { return r["SUBSYSTEM=="] == "tty" && r["ATTRS{idVendor}=="] == p.USBVendor })
		if tty == nil || tty["KERNEL=="] != "ttyUSB*" {
			t.Fatalf("%s: no ttyUSB rule", p.Name)
		}
		if tty["MODE="] != "0600" || tty["OWNER="] != "agentos-modem" || tty["GROUP="] != "agentos-modem" || tty["TAG-="] != "uaccess" ||
			tty["ENV{ID_MM_DEVICE_IGNORE}="] != "1" {
			t.Fatalf("%s: tty rule %v", p.Name, tty)
		}
		usb := has(func(r rule) bool { return r["SUBSYSTEM=="] == "usb" && r["ATTR{idVendor}=="] == p.USBVendor })
		if usb == nil || usb["ENV{ID_MM_DEVICE_IGNORE}="] != "1" {
			t.Fatalf("%s: ModemManager not told to ignore the device", p.Name)
		}
		if p.Audio == AudioUAC {
			snd := has(func(r rule) bool { return r["SUBSYSTEM=="] == "sound" && r["ATTRS{idVendor}=="] == p.USBVendor })
			if snd == nil || snd["MODE="] != "0600" || snd["OWNER="] != "agentos-modem" || snd["TAG-="] != "uaccess" {
				t.Fatalf("%s: sound rule %v", p.Name, snd)
			}
		}
	}
	for _, r := range rules {
		if g, ok := r["GROUP="]; ok && g != "agentos-modem" {
			t.Fatalf("group %q can open the modem", g)
		}
		if m, ok := r["MODE="]; ok && m != "0600" {
			t.Fatalf("mode %s", m)
		}
	}
}

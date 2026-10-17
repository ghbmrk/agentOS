package main

import (
	"context"
	"encoding/xml"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"

	"github.com/ghbmrk/agentos/broker/netjoin"
)

// REQ: ONB-3, CRED-1

type busRule struct {
	XMLName xml.Name
	Attrs   []xml.Attr `xml:",any,attr"`
}

type busPolicy struct {
	Attrs []xml.Attr `xml:",any,attr"`
	Rules []busRule  `xml:",any"`
}

type busConfig struct {
	XMLName  xml.Name    `xml:"busconfig"`
	Policies []busPolicy `xml:"policy"`
	Other    []busRule   `xml:",any"`
}

// TestTheBusPolicyAllowsOnlyTheHelpersCalls parses the helper's system bus
// policy (c3 r1; Security L8, "What a compromised helper reaches"): one
// policy for the helper's user, a deny of everything sent to
// NetworkManager, then one allow per method nmBus calls. The allowed set
// is the set the recorded join (both outcomes) and scan make, so the
// policy and the code cannot drift: a new call fails here until the
// policy names it, and GetSecrets, Delete or a property write never pass.
func TestTheBusPolicyAllowsOnlyTheHelpersCalls(t *testing.T) {
	b, err := os.ReadFile("agentos-netjoin.conf")
	if err != nil {
		t.Fatal(err)
	}
	var c busConfig
	if err := xml.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Other) != 0 || len(c.Policies) != 1 {
		t.Fatalf("want one policy and nothing else, got %d policies and %d other elements", len(c.Policies), len(c.Other))
	}
	p := c.Policies[0]
	if len(p.Attrs) != 1 || p.Attrs[0].Name.Local != "user" || p.Attrs[0].Value != "agentos-netjoin" {
		t.Fatalf("policy %v, want user=agentos-netjoin alone", p.Attrs)
	}
	if len(p.Rules) == 0 || p.Rules[0].XMLName.Local != "deny" ||
		!reflect.DeepEqual(attrs(p.Rules[0]), map[string]string{"send_destination": nmDest}) {
		t.Fatalf("first rule %v, want a bare deny of sends to %s", p.Rules[0], nmDest)
	}
	var allowed []string
	for _, r := range p.Rules[1:] {
		a := attrs(r)
		if r.XMLName.Local != "allow" || len(a) != 4 || a["send_destination"] != nmDest ||
			a["send_type"] != "method_call" || a["send_interface"] == "" || a["send_member"] == "" {
			t.Fatalf("rule %s %v, want an allow of one method_call to %s", r.XMLName.Local, a, nmDest)
		}
		allowed = append(allowed, a["send_interface"]+"."+a["send_member"])
	}
	sort.Strings(allowed)

	fb := &fakeBus{}
	j := netjoin.NewJoiner(nmBus{obj: fb.obj}, "wlan1", []string{"wlan0"})
	for i := range 2 {
		if r := j.Join(context.Background(), "home", canary); r != netjoin.Joined {
			t.Fatalf("join %d: %s", i, r)
		}
	}
	sb := &scanBus{devs: []dbus.ObjectPath{eth, wlan}}
	netjoin.NewScanner(nmBus{obj: sb.obj}).Scan(context.Background())
	seen := map[string]bool{}
	for _, c := range append(fb.calls, sb.calls...) {
		seen[c.method] = true
	}
	var made []string
	for m := range seen {
		made = append(made, m)
	}
	sort.Strings(made)
	if !reflect.DeepEqual(allowed, made) {
		t.Fatalf("policy allows\n%s\nthe helper calls\n%s", strings.Join(allowed, "\n"), strings.Join(made, "\n"))
	}
}

// The image installs the policy where the system bus reads it.
func TestTheImageInstallsTheBusPolicy(t *testing.T) {
	b, err := os.ReadFile("../../../image/build.sh")
	if err != nil {
		t.Fatal(err)
	}
	want := `install -D -m 0644 "$REPO/broker/cmd/agentos-netjoin/agentos-netjoin.conf" "$STAGE/usr/share/dbus-1/system.d/agentos-netjoin.conf"`
	if !strings.Contains(string(b), want) {
		t.Fatalf("image/build.sh lacks\n%s", want)
	}
}

func attrs(r busRule) map[string]string {
	m := map[string]string{}
	for _, a := range r.Attrs {
		m[a.Name.Local] = a.Value
	}
	return m
}

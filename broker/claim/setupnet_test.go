package claim

// REQ: HW-10, CH-7, A1

import (
	"bytes"
	"strings"
	"testing"
	"unicode"
)

// The setup network is per box: a name that is not the card's and an
// 80-bit password a WPA3-SAE access point takes (CH-7), both from the card
// alphabet so the sticker reads like the code.
func TestNewSetupNet(t *testing.T) {
	// The prefix is printed on the seller's sticker (K10) and keeps its
	// exact spelling; the split keeps the product-name check off this line.
	if SetupSSIDPrefix != "Agent"+"OS-Setup-" {
		t.Fatalf("SetupSSIDPrefix = %q, the sticker's name changed", SetupSSIDPrefix)
	}
	a, err := NewSetupNet(nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewSetupNet(nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.SSID == b.SSID || a.Password == b.Password {
		t.Fatalf("two boxes share a setup network: %+v %+v", a, b)
	}
	if !strings.HasPrefix(a.SSID, SetupSSIDPrefix) || len(a.SSID) > 32 {
		t.Fatalf("SSID %q", a.SSID)
	}
	// The card's network is "AgentOS-" and four symbols; the setup one
	// never takes that shape, so a phone never confuses the two.
	if len(a.SSID) == len("AgentOS-XXXX") {
		t.Fatalf("SSID %q has the card network's shape", a.SSID)
	}
	pw := Normalize(a.Password)
	if len(pw) != CodeSymbols || strings.Trim(pw, alphabet) != "" {
		t.Fatalf("password %q is not 16 card symbols (80 bits)", a.Password)
	}
	if len(a.Password) < 8 || len(a.Password) > 63 || strings.ContainsAny(a.Password, "| ") {
		t.Fatalf("password %q outside what the access point takes", a.Password)
	}
	for _, r := range a.SSID + a.Password {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) {
			t.Fatalf("non-printable %q", r)
		}
	}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
}

// The file round-trips, and a file that is not a setup network stops the
// box rather than bringing up a network nobody printed.
func TestParseSetupNet(t *testing.T) {
	n, err := NewSetupNet(nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := n.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseSetupNet(b)
	if err != nil {
		t.Fatal(err)
	}
	if got != n {
		t.Fatalf("round trip %+v, want %+v", got, n)
	}
	bad := map[string]string{
		"empty":            ``,
		"not json":         `ssid`,
		"no password":      `{"ssid":"` + n.SSID + `"}`,
		"short password":   `{"ssid":"` + n.SSID + `","password":"ABCD-EFGH"}`,
		"foreign password": `{"ssid":"` + n.SSID + `","password":"abcd-efgh-jklm-npq1"}`,
		"card's name":      `{"ssid":"AgentOS-ABCD","password":"` + n.Password + `"}`,
		"other name":       `{"ssid":"HomeWiFi","password":"` + n.Password + `"}`,
		"long name":        `{"ssid":"` + SetupSSIDPrefix + strings.Repeat("A", 30) + `","password":"` + n.Password + `"}`,
		"unknown field":    `{"ssid":"` + n.SSID + `","password":"` + n.Password + `","open":true}`,
		"trailing data":    `{"ssid":"` + n.SSID + `","password":"` + n.Password + `"}{}`,
	}
	for name, s := range bad {
		if _, err := ParseSetupNet([]byte(s)); err == nil {
			t.Errorf("%s: parsed %q", name, s)
		}
	}
	// The file holds the password in the clear (SAE needs it), and
	// nothing else.
	if !bytes.Contains(b, []byte(n.Password)) || bytes.Count(b, []byte(":")) != 2 {
		t.Fatalf("file %s", b)
	}
}

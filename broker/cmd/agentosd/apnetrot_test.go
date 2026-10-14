package main

// REQ: REC-4, CH-7, ARC-1

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/apnet"
)

func writeAPNet(t *testing.T, n apnet.Network) string {
	t.Helper()
	b, err := n.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "ap-net.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestARotatedWiFiNetworkReplacesTheCardsOwnRootOnly(t *testing.T) {
	p := writeAPNet(t, apnet.Network{SSID: "AgentOS-AB2C", Password: "ABCD-EFGH-JKLM-NP23"})
	rot := apnet.Network{SSID: "AgentOS-AB2C", Password: "QRST-UVWX-YZ23-4567"}
	if err := rotateAPNet(p)(rot); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := apnet.Parse(b)
	if err != nil || got != rot {
		t.Fatalf("file holds another network: %v", err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
}

func TestARotatedWiFiNetworkIsRefusedUnlessItRotatesTheCardsOwn(t *testing.T) {
	cur := apnet.Network{SSID: "AgentOS-AB2C", Password: "ABCD-EFGH-JKLM-NP23"}
	for name, n := range map[string]apnet.Network{
		"another name":     {SSID: "AgentOS-ZZ99", Password: "QRST-UVWX-YZ23-4567"},
		"not a card shape": {SSID: "AgentOS-AB2C", Password: "short"},
		"injection":        {SSID: "AgentOS-AB2C", Password: "QRST-UVWX-YZ23-456\n"},
	} {
		p := writeAPNet(t, cur)
		before, _ := os.ReadFile(p)
		err := rotateAPNet(p)(n)
		if err == nil {
			t.Fatalf("%s: written", name)
		}
		if strings.Contains(err.Error(), "QRST") || strings.Contains(err.Error(), "ABCD") {
			t.Fatalf("%s: error names a password: %v", name, err)
		}
		if after, _ := os.ReadFile(p); !bytes.Equal(before, after) {
			t.Fatalf("%s: file changed", name)
		}
	}

	missing := filepath.Join(t.TempDir(), "ap-net.json")
	if rotateAPNet(missing)(apnet.Network{SSID: "AgentOS-AB2C", Password: "QRST-UVWX-YZ23-4567"}) == nil {
		t.Fatal("wrote a rotation before setup wrote the first network")
	}
	if _, err := os.Lstat(missing); err == nil {
		t.Fatal("created the file")
	}
	if rotateAPNet("") != nil {
		t.Fatal("no path still serves the op")
	}
}

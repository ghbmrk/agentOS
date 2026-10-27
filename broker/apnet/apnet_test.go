package apnet

import (
	"crypto/rand"
	"fmt"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/card"
)

// REQ: HW-1, CH-7

func TestEveryCardNetworkIsValidAndRoundTrips(t *testing.T) {
	if alphabet != card.Alphabet {
		t.Fatal("apnet's alphabet drifted from the card's")
	}
	// The card no longer carries a network (WIFI-del-e, #3365): these are
	// drawn as the card drew them, a four-symbol name and a 16-symbol
	// password in groups of four.
	syms := func(k int) string {
		b := make([]byte, k)
		rand.Read(b)
		for i := range b {
			b[i] = card.Alphabet[b[i]&31]
		}
		return string(b)
	}
	for i := 0; i < 50; i++ {
		n := Network{SSID: "AgentOS-" + syms(4), Password: strings.Join([]string{syms(4), syms(4), syms(4), syms(4)}, "-")}
		b, err := n.Marshal()
		if err != nil {
			t.Fatalf("a generated card's network refused: %v", err)
		}
		got, err := Parse(b)
		if err != nil || got != n {
			t.Fatalf("round trip: %v", err)
		}
	}
}

func TestRefusesAnythingTheCardDoesNotPrint(t *testing.T) {
	good := Network{SSID: "AgentOS-AB2C", Password: "ABCD-EFGH-JKLM-NP23"}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, n := range []Network{
		{SSID: "AgentOS-Setup-AB2C", Password: good.Password},
		{SSID: "AgentOS-AB2", Password: good.Password},
		{SSID: "AgentOS-AB0C", Password: good.Password},
		{SSID: "Home", Password: good.Password},
		{SSID: good.SSID, Password: "ABCDEFGHJKLMNP23"},
		{SSID: good.SSID, Password: "ABCD-EFGH-JKLM-NP2"},
		{SSID: good.SSID, Password: "abcd-efgh-jklm-np23"},
		{SSID: good.SSID, Password: "ABCD-EFGH-JKLM-NP23 "},
		{SSID: good.SSID, Password: "ABCD-EFGH-JKLM-NP2|"},
		{},
	} {
		if n.Validate() == nil {
			t.Errorf("accepted %q / %q", n.SSID, n.Password)
		}
		if _, err := n.Marshal(); err == nil {
			t.Errorf("marshalled %q", n.SSID)
		}
	}
	for _, b := range []string{
		``, `{}`, `null`,
		`{"ssid":"AgentOS-AB2C","password":"ABCD-EFGH-JKLM-NP23","extra":1}`,
		`{"ssid":"AgentOS-AB2C","password":"ABCD-EFGH-JKLM-NP23"}{}`,
		`{"ssid":"AgentOS-AB2C","password":"ABCD-EFGH-JKLM-NP2"}`,
	} {
		if _, err := Parse([]byte(b)); err == nil {
			t.Errorf("parsed %s", b)
		}
	}
}

func TestPasswordStaysOutOfLogs(t *testing.T) {
	n := Network{SSID: "AgentOS-AB2C", Password: "CANA-RYCA-NARY-CANA"}
	for _, s := range []string{fmt.Sprint(n), fmt.Sprintf("%v %+v %#v %s", n, n, n, n)} {
		if strings.Contains(s, "CANA") {
			t.Fatalf("password logged: %s", s)
		}
	}
}

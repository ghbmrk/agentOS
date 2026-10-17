// Package netjoin is agentos-netjoin's contract: the one request that has
// NetworkManager write the home Wi-Fi connection during setup (P2-2w c3;
// Security L8 on the P2-2w plan, reviews/security/2026-10-08-p2-2w-l6-l8.md).
//
// The helper runs as its own user and holds only polkit's
// settings.modify.system (L8.1, L8.2). It serves agentosd's uid alone on
// one unix socket (L8.3), writes the one connection with the fixed UUID
// (L8.4), checks both strings before any D-Bus call (L8.5) and never logs or
// keeps the password (L8.6). The D-Bus client itself lives in
// cmd/agentos-netjoin behind the NM seam, so agentosd, which links this
// package's Client, never links it.
package netjoin

import (
	"time"
	"unicode"
	"unicode/utf8"
)

// The one connection the helper writes (L8.4).
const (
	UUID = "8907ba39-4053-4e84-9cbf-931587303e08"
	ID   = "agentos-home"
)

// Socket is the helper's socket, in its runtime directory.
const Socket = "netjoin.sock"

// OpJoin is the helper's write: Request in, Answer out.
const OpJoin = "join"

// OpScan is the helper's read (P2-2w c4b): no args in, Networks out. It
// reads the access points NetworkManager already knows, requests no scan
// and writes nothing, so it needs no polkit action.
const OpScan = "scan"

// MaxNetworks is the most names a scan answers. ScanWait bounds the
// helper's reads; ScanTimeout bounds agentosd's call to the helper and is
// longer, and both sit inside the setup page's 10 second call.
const (
	MaxNetworks = 20
	ScanWait    = 3 * time.Second
	ScanTimeout = 4 * time.Second
)

// Networks is OpScan's result: the home network names in range, strongest
// first, each Showable and listed once. It carries names only: no BSSID,
// frequency, strength or security (CRED-1).
type Networks struct {
	SSIDs []string `json:"ssids"`
}

// Wait is how long the helper watches for the connection to come up after
// the write (L8.4: at most 40 seconds). CallTimeout bounds agentosd's call
// to the helper and is longer, so the helper's answer always arrives.
const (
	Wait        = 25 * time.Second
	CallTimeout = 30 * time.Second
)

// Code is the helper's answer (L8.4).
type Code string

const (
	// Joined: an active connection with UUID reached ACTIVATED.
	Joined Code = "joined"
	// NotJoined: one appeared, then reached DEACTIVATED or went away.
	NotJoined Code = "not_joined"
	// Saved: written, but none appeared within Wait.
	Saved Code = "saved"
	// Refused: the request failed Valid or was malformed; nothing written.
	Refused Code = "refused"
	// Busy: another join is still running.
	Busy Code = "busy"
	// Failed: a D-Bus or NetworkManager error, polkit's refusal included.
	Failed Code = "failed"
)

// Known reports whether c is one of the six codes.
func (c Code) Known() bool {
	switch c {
	case Joined, NotJoined, Saved, Refused, Busy, Failed:
		return true
	}
	return false
}

// Request is OpJoin's only argument. PSK is reusable authentication
// material (CRED-1): it goes only to NetworkManager.
type Request struct {
	SSID string `json:"ssid"`
	PSK  string `json:"psk"`
}

// String and GoString keep the password out of logs.
func (Request) String() string   { return "[home Wi-Fi join]" }
func (Request) GoString() string { return "[home Wi-Fi join]" }

// Answer is OpJoin's result.
type Answer struct {
	Code Code `json:"code"`
}

// Valid is L8.5: an SSID of 1 to 32 bytes, and a PSK of 8 to 63 printable
// ASCII characters or exactly 64 hex digits.
func Valid(ssid, psk string) bool {
	if len(ssid) < 1 || len(ssid) > 32 {
		return false
	}
	if len(psk) == 64 {
		for i := 0; i < len(psk); i++ {
			if !isHex(psk[i]) {
				return false
			}
		}
		return true
	}
	if len(psk) < 8 || len(psk) > 63 {
		return false
	}
	for i := 0; i < len(psk); i++ {
		if psk[i] < 0x20 || psk[i] > 0x7e {
			return false
		}
	}
	return true
}

func isHex(b byte) bool {
	return '0' <= b && b <= '9' || 'a' <= b && b <= 'f' || 'A' <= b && b <= 'F'
}

// Settings is a NetworkManager connection's settings: setting name, then
// property name, then value (D-Bus a{sa{sv}}).
type Settings map[string]map[string]any

// ConnectionSettings is exactly L8.4's list plus the station interface
// (S-R4, ASSUMPTIONS N13), and nothing else: the request sets only the
// SSID and the PSK, and the interface is the helper's own -station, never
// the request's. No address, DNS, route, MAC, priority, proxy, 802.1X or
// permissions are set.
func ConnectionSettings(ssid, psk, station string) Settings {
	return Settings{
		"connection": {
			"type":        "802-11-wireless",
			"id":          ID,
			"uuid":        UUID,
			"autoconnect": true,
			// The one device NetworkManager may activate it on (S-R4):
			// never the access point's.
			"interface-name": station,
		},
		"802-11-wireless": {
			"mode":   "infrastructure",
			"ssid":   []byte(ssid),
			"hidden": false,
		},
		"802-11-wireless-security": {
			"key-mgmt": "wpa-psk",
			"psk":      psk,
			// 0: a system-owned secret, kept by NetworkManager (L8.6).
			"psk-flags": uint32(0),
		},
		"ipv4": {"method": "auto"},
		"ipv6": {"method": "auto"},
	}
}

// Showable reports whether an access point's SSID may be listed: 1 to 32
// bytes of UTF-8 with no control or format character. A hidden network's
// empty or all-NUL SSID is not, nor is a name that could rewrite how the
// page draws its neighbours (a bidi override); such a network can still be
// typed.
func Showable(ssid []byte) bool {
	if len(ssid) < 1 || len(ssid) > 32 || !utf8.Valid(ssid) {
		return false
	}
	for _, r := range string(ssid) {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

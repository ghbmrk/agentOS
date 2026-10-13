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

import "time"

// The one connection the helper writes (L8.4).
const (
	UUID = "8907ba39-4053-4e84-9cbf-931587303e08"
	ID   = "agentos-home"
)

// Socket is the helper's socket, in its runtime directory.
const Socket = "netjoin.sock"

// OpJoin is the helper's one op: Request in, Answer out.
const OpJoin = "join"

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

// ConnectionSettings is exactly L8.4's list, and nothing else: the caller
// sets only the SSID and the PSK. No interface, address, DNS, route, MAC,
// priority, proxy, 802.1X or permissions are set.
func ConnectionSettings(ssid, psk string) Settings {
	return Settings{
		"connection": {
			"type":        "802-11-wireless",
			"id":          ID,
			"uuid":        UUID,
			"autoconnect": true,
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

package localui

import (
	"net/netip"
	"regexp"
)

// UIPort is the local UI's TCP port.
const UIPort = 80

// HTTPSPort is the owner page's TCP port over HTTPS (#3153).
const HTTPSPort = 443

// DefaultPageName is the owner page's name (pageca.DefaultName, which this
// package does not link): one leaf under ICANN's private-use TLD.
const DefaultPageName = "agentos.internal"

// pageNameRe is a lowercase DNS name of two or more labels.
var pageNameRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ifaceRe is a Linux interface name.
var ifaceRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)

func isAddr(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

package netguard

import "syscall"

// netlinkChange reports whether a netlink read holds an address, route or
// link change. A truncated or unparsable read holds none.
func netlinkChange(b []byte) bool {
	msgs, err := syscall.ParseNetlinkMessage(b)
	if err != nil {
		return false
	}
	for _, m := range msgs {
		switch m.Header.Type {
		case syscall.RTM_NEWADDR, syscall.RTM_DELADDR, syscall.RTM_NEWROUTE, syscall.RTM_DELROUTE, syscall.RTM_NEWLINK, syscall.RTM_DELLINK:
			return true
		}
	}
	return false
}

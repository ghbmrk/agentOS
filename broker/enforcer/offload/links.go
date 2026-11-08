package offload

import (
	"fmt"
	"slices"
	"syscall"
)

const iflaLinkNetnsid = 37 // IFLA_LINK_NETNSID

type link struct {
	index  int32
	name   string
	parent int32 // IFLA_LINK in this namespace, 0 if none
	master int32 // IFLA_MASTER, 0 if none
}

// under is each port and every device whose received packets reach it:
// the parent of a VLAN, macvlan or ipvlan (IFLA_LINK), the members of a
// bond or bridge (whose IFLA_MASTER is the port), and so on down. A
// parent in another namespace (a veth's peer) is not one. A port that
// does not exist is an error.
func under(ports []string) ([]string, error) {
	links, err := readLinks()
	if err != nil {
		return nil, err
	}
	byName := map[string]link{}
	byIndex := map[int32]link{}
	for _, l := range links {
		byName[l.name], byIndex[l.index] = l, l
	}
	var out []string
	seen := map[int32]bool{}
	var walk func(l link)
	walk = func(l link) {
		if seen[l.index] {
			return
		}
		seen[l.index] = true
		out = append(out, l.name)
		if p, ok := byIndex[l.parent]; ok && l.parent != 0 {
			walk(p)
		}
		for _, m := range links {
			if m.master == l.index {
				walk(m)
			}
		}
	}
	for _, p := range ports {
		l, ok := byName[p]
		if !ok {
			return nil, fmt.Errorf("offload: port %s: no such device", p)
		}
		walk(l)
	}
	return out, nil
}

// readLinks dumps the calling thread's namespace's links (RTM_GETLINK).
func readLinks() ([]link, error) {
	b, err := syscall.NetlinkRIB(syscall.RTM_GETLINK, syscall.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("offload: links: %w", err)
	}
	msgs, err := syscall.ParseNetlinkMessage(b)
	if err != nil {
		return nil, fmt.Errorf("offload: links: %w", err)
	}
	var links []link
	for _, m := range msgs {
		if m.Header.Type != syscall.RTM_NEWLINK {
			continue
		}
		if len(m.Data) < syscall.SizeofIfInfomsg {
			return nil, fmt.Errorf("offload: links: short message")
		}
		l := link{index: int32(ne.Uint32(m.Data[4:8]))}
		elsewhere := false
		each(m.Data[syscall.SizeofIfInfomsg:], func(t uint16, d []byte) {
			switch {
			case t == syscall.IFLA_IFNAME && len(d) > 0:
				l.name = string(d[:len(d)-1])
			case t == syscall.IFLA_LINK && len(d) == 4:
				l.parent = int32(ne.Uint32(d))
			case t == syscall.IFLA_MASTER && len(d) == 4:
				l.master = int32(ne.Uint32(d))
			case t == iflaLinkNetnsid:
				elsewhere = true
			}
		})
		if elsewhere || l.parent == l.index {
			l.parent = 0
		}
		links = append(links, l)
	}
	slices.SortFunc(links, func(a, b link) int { return int(a.index - b.index) })
	return links, nil
}

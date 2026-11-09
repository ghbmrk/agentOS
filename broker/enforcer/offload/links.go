package offload

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type link struct {
	index  int32
	name   string
	kind   string // IFLA_INFO_KIND: "veth", "macvlan", "vlan", ...; "" for hardware
	parent int32  // IFLA_LINK, 0 if none
	master int32  // IFLA_MASTER, 0 if none
	// elsewhere is a parent in another namespace (IFLA_LINK_NETNSID):
	// parent is then that namespace's index, not one of these links'.
	elsewhere bool
}

// under is every device whose received packets reach the ports, each
// before the devices on it: the parent of a VLAN, macvlan or ipvlan
// (IFLA_LINK) and the members of a bond or bridge (whose IFLA_MASTER is
// the port), and so on down, then the port. An upper device takes its
// merging features from its lower one, so the lower one is set first or
// the upper one reads back still on (ASSUMPTIONS ENF-gro-3). A veth's
// peer in another namespace is not under it: its packets are the other
// namespace's sends. Any other parent in another namespace is an error,
// since it cannot be reached from here; so is a parent that is no link
// here, and a port that does not exist.
func under(ports []string, end time.Time) ([]string, error) {
	links, err := readLinks(end)
	if err != nil {
		return nil, err
	}
	return walk(links, ports)
}

// walk is under over links, the namespace's links in index order.
func walk(links []link, ports []string) ([]string, error) {
	byName := map[string]link{}
	byIndex := map[int32]link{}
	for _, l := range links {
		byName[l.name], byIndex[l.index] = l, l
	}
	var out []string
	var errs []error
	seen := map[int32]bool{}
	var down func(l link)
	down = func(l link) {
		if seen[l.index] {
			return
		}
		seen[l.index] = true
		switch {
		case l.elsewhere && l.kind != "veth":
			errs = append(errs, fmt.Errorf("offload: %s: its parent is in another namespace", l.name))
		case l.elsewhere:
		case l.parent != 0 && l.parent != l.index:
			if p, ok := byIndex[l.parent]; ok {
				down(p)
			} else {
				errs = append(errs, fmt.Errorf("offload: %s: its parent %d is not a link here", l.name, l.parent))
			}
		}
		for _, m := range links {
			if m.master == l.index {
				down(m)
			}
		}
		out = append(out, l.name)
	}
	for _, p := range ports {
		l, ok := byName[p]
		if !ok {
			return nil, fmt.Errorf("offload: port %s: no such device", p)
		}
		down(l)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return out, nil
}

// readLinks dumps the calling thread's namespace's links (RTM_GETLINK) on
// a route socket of its own, reading only the kernel's replies, by end.
// A dump the kernel ends in error or marks interrupted is an error, not
// retried: the port is held at its caps until the next reading.
func readLinks(end time.Time) ([]link, error) {
	c, err := open(unix.NETLINK_ROUTE, end)
	if err != nil {
		return nil, fmt.Errorf("offload: links: %w", err)
	}
	defer c.close()
	msgs, err := c.request(syscall.RTM_GETLINK, syscall.NLM_F_DUMP, make([]byte, syscall.SizeofIfInfomsg))
	if err != nil {
		return nil, fmt.Errorf("offload: links: %w", err)
	}
	var links []link
	for _, b := range msgs {
		if len(b) < syscall.SizeofIfInfomsg {
			return nil, fmt.Errorf("offload: links: short message")
		}
		l := link{index: int32(ne.Uint32(b[4:8]))}
		each(b[syscall.SizeofIfInfomsg:], func(t uint16, d []byte) {
			switch {
			case t == unix.IFLA_IFNAME && len(d) > 0:
				l.name = string(d[:len(d)-1])
			case t == unix.IFLA_LINK && len(d) == 4:
				l.parent = int32(ne.Uint32(d))
			case t == unix.IFLA_MASTER && len(d) == 4:
				l.master = int32(ne.Uint32(d))
			case t == unix.IFLA_LINK_NETNSID:
				l.elsewhere = true
			case t == unix.IFLA_LINKINFO:
				if k := find(d, unix.IFLA_INFO_KIND); len(k) > 0 {
					l.kind = strings.TrimSuffix(string(k), "\x00")
				}
			}
		})
		links = append(links, l)
	}
	slices.SortFunc(links, func(a, b link) int { return int(a.index - b.index) })
	return links, nil
}

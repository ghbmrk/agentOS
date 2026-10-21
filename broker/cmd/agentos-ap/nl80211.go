package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"

	"github.com/ghbmrk/agentos/broker/localui"
)

// nl80211 is localui.Radio over generic netlink (#936): it lists the
// wireless interfaces, reads a radio's interface combinations and creates
// the station. It reuses mdlayher/genetlink (D-144) rather than running
// iw, whose output is for people, or hand-rolling netlink.
type nl80211 struct {
	c   *genetlink.Conn
	fam genetlink.Family
	// deadline bounds each request; c.SetDeadline, which tests replace.
	deadline func(time.Time) error
}

// dialNL80211 opens generic netlink and finds the nl80211 family.
func dialNL80211() (*nl80211, error) {
	c, err := genetlink.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("nl80211: %w", err)
	}
	return newNL80211(c)
}

// newNL80211 finds the nl80211 family on c, which it closes on failure.
func newNL80211(c *genetlink.Conn) (*nl80211, error) {
	f, err := c.GetFamily(unix.NL80211_GENL_NAME)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("nl80211: %w", err)
	}
	return &nl80211{c: c, fam: f, deadline: c.SetDeadline}, nil
}

func (n *nl80211) Close() error { return n.c.Close() }

// nlTimeout bounds a request when ctx has no deadline: the kernel answers
// at once, and a loader stuck on a socket serves nobody.
const nlTimeout = 5 * time.Second

// do sends one request and reads its answers, within ctx's deadline.
func (n *nl80211) do(ctx context.Context, cmd uint8, attrs func(*netlink.AttributeEncoder), flags netlink.HeaderFlags) ([]genetlink.Message, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d, ok := ctx.Deadline()
	if !ok {
		d = time.Now().Add(nlTimeout)
	}
	if err := n.deadline(d); err != nil {
		return nil, err
	}
	var body []byte
	if attrs != nil {
		ae := netlink.NewAttributeEncoder()
		attrs(ae)
		b, err := ae.Encode()
		if err != nil {
			return nil, err
		}
		body = b
	}
	return n.c.Execute(genetlink.Message{
		Header: genetlink.Header{Command: cmd, Version: n.fam.Version},
		Data:   body,
	}, n.fam.ID, flags)
}

func (n *nl80211) Interfaces(ctx context.Context) ([]localui.RadioIface, error) {
	msgs, err := n.do(ctx, unix.NL80211_CMD_GET_INTERFACE, nil, netlink.Request|netlink.Dump)
	if err != nil {
		return nil, fmt.Errorf("nl80211: listing interfaces: %w", err)
	}
	out := make([]localui.RadioIface, 0, len(msgs))
	for _, m := range msgs {
		i, err := parseIface(m.Data)
		if errors.Is(err, errNoNetdev) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, nil
}

// errNoNetdev marks an interface with no network device, which nl80211
// lists without a name: a P2P device or a NAN interface. A radio that
// supports P2P has one beside every netdev (hwsim, and the M6 Ultra's
// MT7922 as wpa_supplicant brings it up), so it is skipped, not refused.
var errNoNetdev = errors.New("nl80211: an interface with no network device")

// parseIface reads one interface. One without a name is malformed, unless
// its type has no network device (errNoNetdev).
func parseIface(b []byte) (localui.RadioIface, error) {
	var i localui.RadioIface
	ad, err := netlink.NewAttributeDecoder(b)
	if err != nil {
		return i, fmt.Errorf("nl80211: interface: %w", err)
	}
	for ad.Next() {
		switch ad.Type() {
		case unix.NL80211_ATTR_IFNAME:
			i.Name = ad.String()
		case unix.NL80211_ATTR_WIPHY:
			i.Phy = ad.Uint32()
		case unix.NL80211_ATTR_IFTYPE:
			i.Type = localui.IfaceType(ad.Uint32())
		case unix.NL80211_ATTR_WIPHY_FREQ:
			i.Freq = ad.Uint32()
		case unix.NL80211_ATTR_MAC:
			i.MAC = net.HardwareAddr(ad.Bytes())
		}
	}
	if err := ad.Err(); err != nil {
		return i, fmt.Errorf("nl80211: interface: %w", err)
	}
	if i.Name == "" {
		if i.Type == unix.NL80211_IFTYPE_P2P_DEVICE || i.Type == unix.NL80211_IFTYPE_NAN {
			return i, errNoNetdev
		}
		return i, errors.New("nl80211: an interface with no name")
	}
	return i, nil
}

func (n *nl80211) Combinations(ctx context.Context, phy uint32) ([]localui.IfaceCombination, error) {
	msgs, err := n.do(ctx, unix.NL80211_CMD_GET_WIPHY, func(ae *netlink.AttributeEncoder) {
		ae.Uint32(unix.NL80211_ATTR_WIPHY, phy)
		ae.Flag(unix.NL80211_ATTR_SPLIT_WIPHY_DUMP, true)
	}, netlink.Request|netlink.Dump)
	if err != nil {
		return nil, fmt.Errorf("nl80211: reading phy%d: %w", phy, err)
	}
	return parseCombinations(msgs, phy)
}

// parseCombinations reads phy's interface combinations from a split
// wiphy dump. It fails closed: a dump that never names phy, a second
// combinations attribute, or any malformed or missing field is an error,
// so a guard never reads a combination the radio did not give. A radio
// that lists none has none.
func parseCombinations(msgs []genetlink.Message, phy uint32) ([]localui.IfaceCombination, error) {
	var out []localui.IfaceCombination
	seen, found := false, false
	for _, m := range msgs {
		ad, err := netlink.NewAttributeDecoder(m.Data)
		if err != nil {
			return nil, fmt.Errorf("nl80211: phy%d: %w", phy, err)
		}
		var (
			wiphy    uint32
			hasWiphy bool
			combs    []localui.IfaceCombination
			hasCombs bool
		)
		for ad.Next() {
			switch ad.Type() {
			case unix.NL80211_ATTR_WIPHY:
				wiphy, hasWiphy = ad.Uint32(), true
			case unix.NL80211_ATTR_INTERFACE_COMBINATIONS:
				if hasCombs {
					return nil, fmt.Errorf("nl80211: phy%d: two interface combination lists", phy)
				}
				hasCombs = true
				ad.Nested(func(nad *netlink.AttributeDecoder) error {
					var err error
					combs, err = decodeCombinations(nad)
					return err
				})
			}
		}
		if err := ad.Err(); err != nil {
			return nil, fmt.Errorf("nl80211: phy%d: %w", phy, err)
		}
		if !hasWiphy {
			return nil, fmt.Errorf("nl80211: phy%d: a wiphy message names no radio", phy)
		}
		if wiphy != phy {
			continue
		}
		found = true
		if hasCombs {
			if seen {
				return nil, fmt.Errorf("nl80211: phy%d: two interface combination lists", phy)
			}
			seen, out = true, combs
		}
	}
	if !found {
		return nil, fmt.Errorf("nl80211: phy%d is not listed", phy)
	}
	return out, nil
}

// decodeCombinations reads NL80211_ATTR_INTERFACE_COMBINATIONS: an
// indexed list of combinations.
func decodeCombinations(ad *netlink.AttributeDecoder) ([]localui.IfaceCombination, error) {
	var out []localui.IfaceCombination
	for ad.Next() {
		var c localui.IfaceCombination
		var err error
		ad.Nested(func(nad *netlink.AttributeDecoder) error {
			c, err = decodeCombination(nad)
			return err
		})
		if ad.Err() != nil {
			return nil, ad.Err()
		}
		out = append(out, c)
	}
	return out, ad.Err()
}

// decodeCombination reads one combination. Each of its limits, its total
// and its channel count must be there exactly once.
func decodeCombination(ad *netlink.AttributeDecoder) (localui.IfaceCombination, error) {
	var c localui.IfaceCombination
	var limits, total, channels int
	for ad.Next() {
		switch ad.Type() {
		case unix.NL80211_IFACE_COMB_LIMITS:
			limits++
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				for nad.Next() {
					var l localui.IfaceLimit
					nad.Nested(func(lad *netlink.AttributeDecoder) error {
						var err error
						l, err = decodeLimit(lad)
						return err
					})
					c.Limits = append(c.Limits, l)
				}
				return nad.Err()
			})
		case unix.NL80211_IFACE_COMB_MAXNUM:
			total++
			c.Total = ad.Uint32()
		case unix.NL80211_IFACE_COMB_NUM_CHANNELS:
			channels++
			c.Channels = ad.Uint32()
		}
	}
	if err := ad.Err(); err != nil {
		return c, err
	}
	if limits != 1 || total != 1 || channels != 1 || len(c.Limits) == 0 {
		return c, errors.New("an interface combination without exactly one limit list, total and channel count")
	}
	return c, nil
}

// decodeLimit reads one limit: its maximum and its interface types, each
// a flag whose attribute type is the nl80211 interface type.
func decodeLimit(ad *netlink.AttributeDecoder) (localui.IfaceLimit, error) {
	var l localui.IfaceLimit
	var max, types int
	for ad.Next() {
		switch ad.Type() {
		case unix.NL80211_IFACE_LIMIT_MAX:
			max++
			l.Max = ad.Uint32()
		case unix.NL80211_IFACE_LIMIT_TYPES:
			types++
			ad.Nested(func(tad *netlink.AttributeDecoder) error {
				for tad.Next() {
					if len(tad.Bytes()) != 0 {
						return fmt.Errorf("interface type %d is not a flag", tad.Type())
					}
					l.Types = append(l.Types, localui.IfaceType(tad.Type()))
				}
				return tad.Err()
			})
		}
	}
	if err := ad.Err(); err != nil {
		return l, err
	}
	if max != 1 || types != 1 || len(l.Types) == 0 {
		return l, errors.New("an interface limit without exactly one maximum and type list")
	}
	return l, nil
}

// NewStation asks without NLM_F_ACK: nl80211 answers NEW_INTERFACE with
// the new interface, and an acknowledgement as well would sit unread on
// the socket and answer the next request out of sequence, failing every
// later one (the hwsim boot, #936 r4b-2). A failure still comes back as an
// error message.
func (n *nl80211) NewStation(ctx context.Context, phy uint32, name string, mac net.HardwareAddr) error {
	_, err := n.do(ctx, unix.NL80211_CMD_NEW_INTERFACE, func(ae *netlink.AttributeEncoder) {
		ae.Uint32(unix.NL80211_ATTR_WIPHY, phy)
		ae.String(unix.NL80211_ATTR_IFNAME, name)
		ae.Uint32(unix.NL80211_ATTR_IFTYPE, uint32(localui.IfaceStation))
		ae.Bytes(unix.NL80211_ATTR_MAC, mac)
	}, netlink.Request)
	if err != nil {
		return fmt.Errorf("nl80211: creating %s on phy%d: %w", name, phy, err)
	}
	return nil
}

package main

// REQ: ONB-3, DEV-2, STO-2, HW-4

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/genetlink/genltest"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"

	"github.com/ghbmrk/agentos/broker/localui"
)

var nlFamily = genetlink.Family{ID: 0x1c, Name: unix.NL80211_GENL_NAME, Version: 1}

// dialFake is the nl80211 radio over a fake generic netlink that answers
// with fn, and records each request's deadline in deadlines.
func dialFake(t *testing.T, fn genltest.Func) (*nl80211, *[]time.Time) {
	t.Helper()
	n, err := newNL80211(genltest.Dial(genltest.ServeFamily(nlFamily, fn)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	var ds []time.Time
	n.deadline = func(d time.Time) error { ds = append(ds, d); return nil }
	return n, &ds
}

func enc(t *testing.T, f func(*netlink.AttributeEncoder)) []byte {
	t.Helper()
	ae := netlink.NewAttributeEncoder()
	f(ae)
	b, err := ae.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func msg(data []byte) genetlink.Message {
	return genetlink.Message{Header: genetlink.Header{Version: nlFamily.Version}, Data: data}
}

// limit encodes one NL80211_IFACE_COMB_LIMITS entry.
func limit(max uint32, types ...uint16) func(*netlink.AttributeEncoder) {
	return func(ae *netlink.AttributeEncoder) {
		ae.Uint32(unix.NL80211_IFACE_LIMIT_MAX, max)
		ae.Nested(unix.NL80211_IFACE_LIMIT_TYPES, func(nae *netlink.AttributeEncoder) error {
			for _, ty := range types {
				nae.Flag(ty, true)
			}
			return nil
		})
	}
}

// comb encodes one combination, as mac80211 sends it.
func comb(total, channels uint32, limits ...func(*netlink.AttributeEncoder)) func(*netlink.AttributeEncoder) {
	return func(ae *netlink.AttributeEncoder) {
		ae.Nested(unix.NL80211_IFACE_COMB_LIMITS, func(nae *netlink.AttributeEncoder) error {
			for i, l := range limits {
				nae.Nested(uint16(i+1), func(lae *netlink.AttributeEncoder) error { l(lae); return nil })
			}
			return nil
		})
		ae.Uint32(unix.NL80211_IFACE_COMB_MAXNUM, total)
		ae.Uint32(unix.NL80211_IFACE_COMB_NUM_CHANNELS, channels)
	}
}

// wiphy encodes a split wiphy dump message for phy with the given
// combinations; with none, it has no combinations attribute.
func wiphy(t *testing.T, phy uint32, combs ...func(*netlink.AttributeEncoder)) genetlink.Message {
	return msg(enc(t, func(ae *netlink.AttributeEncoder) {
		ae.Uint32(unix.NL80211_ATTR_WIPHY, phy)
		if len(combs) == 0 {
			return
		}
		ae.Nested(unix.NL80211_ATTR_INTERFACE_COMBINATIONS, func(nae *netlink.AttributeEncoder) error {
			for i, c := range combs {
				nae.Nested(uint16(i+1), func(cae *netlink.AttributeEncoder) error { c(cae); return nil })
			}
			return nil
		})
	}))
}

const (
	sta = unix.NL80211_IFTYPE_STATION
	ap  = unix.NL80211_IFTYPE_AP
)

// usual is mac80211's usual "#{ managed } <= 1, #{ AP } <= 1, total <= 2,
// #channels <= 1".
func usual() func(*netlink.AttributeEncoder) { return comb(2, 1, limit(1, sta), limit(1, ap)) }

func TestNL80211Interfaces(t *testing.T) {
	mac := net.HardwareAddr{0, 0x11, 0x22, 0x33, 0x44, 0x55}
	n, ds := dialFake(t, genltest.CheckRequest(nlFamily.ID, unix.NL80211_CMD_GET_INTERFACE, netlink.Request|netlink.Dump,
		func(genetlink.Message, netlink.Message) ([]genetlink.Message, error) {
			return []genetlink.Message{
				msg(enc(t, func(ae *netlink.AttributeEncoder) {
					ae.String(unix.NL80211_ATTR_IFNAME, "wlan0")
					ae.Uint32(unix.NL80211_ATTR_WIPHY, 0)
					ae.Uint32(unix.NL80211_ATTR_IFTYPE, ap)
					ae.Uint32(unix.NL80211_ATTR_WIPHY_FREQ, 2437)
					ae.Bytes(unix.NL80211_ATTR_MAC, mac)
				})),
				msg(enc(t, func(ae *netlink.AttributeEncoder) {
					ae.String(unix.NL80211_ATTR_IFNAME, localui.StationIface)
					ae.Uint32(unix.NL80211_ATTR_WIPHY, 0)
					ae.Uint32(unix.NL80211_ATTR_IFTYPE, sta)
				})),
			}, nil
		}))
	got, err := n.Interfaces(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "wlan0" || got[0].Type != localui.IfaceAP || got[0].Freq != 2437 || !bytes.Equal(got[0].MAC, mac) ||
		got[1].Name != localui.StationIface || got[1].Type != localui.IfaceStation || got[1].Freq != 0 {
		t.Fatalf("Interfaces = %+v", got)
	}
	if len(*ds) != 1 || (*ds)[0].IsZero() {
		t.Fatalf("deadlines %v: a request ran unbounded", *ds)
	}
}

func TestNL80211InterfacesRefusesMalformed(t *testing.T) {
	for name, data := range map[string][]byte{
		"no name": enc(t, func(ae *netlink.AttributeEncoder) { ae.Uint32(unix.NL80211_ATTR_WIPHY, 0) }),
		"short phy": enc(t, func(ae *netlink.AttributeEncoder) {
			ae.String(unix.NL80211_ATTR_IFNAME, "wlan0")
			ae.Uint16(unix.NL80211_ATTR_WIPHY, 0)
		}),
		"truncated": {8, 0, 4},
	} {
		t.Run(name, func(t *testing.T) {
			n, _ := dialFake(t, func(genetlink.Message, netlink.Message) ([]genetlink.Message, error) {
				return []genetlink.Message{msg(data)}, nil
			})
			if got, err := n.Interfaces(context.Background()); err == nil {
				t.Fatalf("Interfaces = %+v, want an error", got)
			}
		})
	}
}

// The combinations request is a split dump filtered to phy; the answer's
// combinations may come in any of its messages, and another radio's are
// not this one's.
func TestNL80211Combinations(t *testing.T) {
	n, _ := dialFake(t, genltest.CheckRequest(nlFamily.ID, unix.NL80211_CMD_GET_WIPHY, netlink.Request|netlink.Dump,
		func(greq genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
			ad, err := netlink.NewAttributeDecoder(greq.Data)
			if err != nil {
				return nil, err
			}
			var phy uint32
			split := false
			for ad.Next() {
				switch ad.Type() {
				case unix.NL80211_ATTR_WIPHY:
					phy = ad.Uint32()
				case unix.NL80211_ATTR_SPLIT_WIPHY_DUMP:
					split = true
				}
			}
			if phy != 1 || !split {
				t.Errorf("request for phy%d, split %v", phy, split)
			}
			return []genetlink.Message{
				wiphy(t, 0, comb(2, 2, limit(1, sta), limit(1, ap))),
				wiphy(t, 1),
				wiphy(t, 1, usual(), comb(4, 1, limit(4, ap))),
			}, nil
		}))
	got, err := n.Combinations(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	want := []localui.IfaceCombination{
		{Limits: []localui.IfaceLimit{{Max: 1, Types: []localui.IfaceType{localui.IfaceStation}}, {Max: 1, Types: []localui.IfaceType{localui.IfaceAP}}}, Total: 2, Channels: 1},
		{Limits: []localui.IfaceLimit{{Max: 4, Types: []localui.IfaceType{localui.IfaceAP}}}, Total: 4, Channels: 1},
	}
	if !sameCombs(got, want) {
		t.Fatalf("Combinations = %+v, want %+v", got, want)
	}
	if localui.StationChannels(got) != 1 {
		t.Fatalf("StationChannels = %d", localui.StationChannels(got))
	}
}

func sameCombs(a, b []localui.IfaceCombination) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Total != b[i].Total || a[i].Channels != b[i].Channels || len(a[i].Limits) != len(b[i].Limits) {
			return false
		}
		for j := range a[i].Limits {
			x, y := a[i].Limits[j], b[i].Limits[j]
			if x.Max != y.Max || len(x.Types) != len(y.Types) {
				return false
			}
			for k := range x.Types {
				if x.Types[k] != y.Types[k] {
					return false
				}
			}
		}
	}
	return true
}

func TestNL80211NoCombinationsIsNone(t *testing.T) {
	n, _ := dialFake(t, func(genetlink.Message, netlink.Message) ([]genetlink.Message, error) {
		return []genetlink.Message{wiphy(t, 0), wiphy(t, 0)}, nil
	})
	if got, err := n.Combinations(context.Background(), 0); err != nil || len(got) != 0 {
		t.Fatalf("Combinations = %+v, %v; want none", got, err)
	}
}

// Fail closed: every malformed or doubtful answer is an error, never a
// combination the radio did not give, and so never a station.
func TestNL80211CombinationsRefusesMalformed(t *testing.T) {
	raw := func(f func(*netlink.AttributeEncoder)) func(*testing.T) []genetlink.Message {
		return func(t *testing.T) []genetlink.Message {
			return []genetlink.Message{msg(enc(t, func(ae *netlink.AttributeEncoder) {
				ae.Uint32(unix.NL80211_ATTR_WIPHY, 0)
				ae.Nested(unix.NL80211_ATTR_INTERFACE_COMBINATIONS, func(nae *netlink.AttributeEncoder) error {
					nae.Nested(1, func(cae *netlink.AttributeEncoder) error { f(cae); return nil })
					return nil
				})
			}))}
		}
	}
	cases := map[string]func(*testing.T) []genetlink.Message{
		"phy not listed": func(t *testing.T) []genetlink.Message { return []genetlink.Message{wiphy(t, 1, usual())} },
		"no wiphy":       func(t *testing.T) []genetlink.Message { return []genetlink.Message{msg(nil)} },
		"two lists across messages": func(t *testing.T) []genetlink.Message {
			return []genetlink.Message{wiphy(t, 0, usual()), wiphy(t, 0, usual())}
		},
		"two lists in one message": func(t *testing.T) []genetlink.Message {
			m := wiphy(t, 0, usual())
			extra := enc(t, func(ae *netlink.AttributeEncoder) {
				ae.Nested(unix.NL80211_ATTR_INTERFACE_COMBINATIONS, func(nae *netlink.AttributeEncoder) error {
					nae.Nested(1, func(cae *netlink.AttributeEncoder) error { usual()(cae); return nil })
					return nil
				})
			})
			m.Data = append(m.Data, extra...)
			return []genetlink.Message{m}
		},
		"no channels": raw(func(ae *netlink.AttributeEncoder) {
			ae.Nested(unix.NL80211_IFACE_COMB_LIMITS, func(nae *netlink.AttributeEncoder) error {
				nae.Nested(1, func(l *netlink.AttributeEncoder) error { limit(2, sta, ap)(l); return nil })
				return nil
			})
			ae.Uint32(unix.NL80211_IFACE_COMB_MAXNUM, 2)
		}),
		"no total": raw(func(ae *netlink.AttributeEncoder) {
			ae.Nested(unix.NL80211_IFACE_COMB_LIMITS, func(nae *netlink.AttributeEncoder) error {
				nae.Nested(1, func(l *netlink.AttributeEncoder) error { limit(2, sta, ap)(l); return nil })
				return nil
			})
			ae.Uint32(unix.NL80211_IFACE_COMB_NUM_CHANNELS, 1)
		}),
		"no limits": raw(func(ae *netlink.AttributeEncoder) {
			ae.Uint32(unix.NL80211_IFACE_COMB_MAXNUM, 2)
			ae.Uint32(unix.NL80211_IFACE_COMB_NUM_CHANNELS, 1)
		}),
		"two channel counts": raw(func(ae *netlink.AttributeEncoder) {
			usual()(ae)
			ae.Uint32(unix.NL80211_IFACE_COMB_NUM_CHANNELS, 2)
		}),
		"short channel count": raw(func(ae *netlink.AttributeEncoder) {
			ae.Nested(unix.NL80211_IFACE_COMB_LIMITS, func(nae *netlink.AttributeEncoder) error {
				nae.Nested(1, func(l *netlink.AttributeEncoder) error { limit(2, sta, ap)(l); return nil })
				return nil
			})
			ae.Uint32(unix.NL80211_IFACE_COMB_MAXNUM, 2)
			ae.Uint16(unix.NL80211_IFACE_COMB_NUM_CHANNELS, 2)
		}),
		"limit without max": raw(func(ae *netlink.AttributeEncoder) {
			ae.Nested(unix.NL80211_IFACE_COMB_LIMITS, func(nae *netlink.AttributeEncoder) error {
				nae.Nested(1, func(l *netlink.AttributeEncoder) error {
					l.Nested(unix.NL80211_IFACE_LIMIT_TYPES, func(t *netlink.AttributeEncoder) error { t.Flag(sta, true); t.Flag(ap, true); return nil })
					return nil
				})
				return nil
			})
			ae.Uint32(unix.NL80211_IFACE_COMB_MAXNUM, 2)
			ae.Uint32(unix.NL80211_IFACE_COMB_NUM_CHANNELS, 1)
		}),
		"limit without types": raw(func(ae *netlink.AttributeEncoder) {
			ae.Nested(unix.NL80211_IFACE_COMB_LIMITS, func(nae *netlink.AttributeEncoder) error {
				nae.Nested(1, func(l *netlink.AttributeEncoder) error { l.Uint32(unix.NL80211_IFACE_LIMIT_MAX, 2); return nil })
				return nil
			})
			ae.Uint32(unix.NL80211_IFACE_COMB_MAXNUM, 2)
			ae.Uint32(unix.NL80211_IFACE_COMB_NUM_CHANNELS, 1)
		}),
		"short limit max": raw(func(ae *netlink.AttributeEncoder) {
			ae.Nested(unix.NL80211_IFACE_COMB_LIMITS, func(nae *netlink.AttributeEncoder) error {
				nae.Nested(1, func(l *netlink.AttributeEncoder) error {
					l.Uint8(unix.NL80211_IFACE_LIMIT_MAX, 2)
					l.Nested(unix.NL80211_IFACE_LIMIT_TYPES, func(t *netlink.AttributeEncoder) error { t.Flag(sta, true); t.Flag(ap, true); return nil })
					return nil
				})
				return nil
			})
			ae.Uint32(unix.NL80211_IFACE_COMB_MAXNUM, 2)
			ae.Uint32(unix.NL80211_IFACE_COMB_NUM_CHANNELS, 1)
		}),
		"type that is not a flag": raw(func(ae *netlink.AttributeEncoder) {
			ae.Nested(unix.NL80211_IFACE_COMB_LIMITS, func(nae *netlink.AttributeEncoder) error {
				nae.Nested(1, func(l *netlink.AttributeEncoder) error {
					l.Uint32(unix.NL80211_IFACE_LIMIT_MAX, 2)
					l.Nested(unix.NL80211_IFACE_LIMIT_TYPES, func(t *netlink.AttributeEncoder) error { t.Flag(sta, true); t.Uint32(ap, 1); return nil })
					return nil
				})
				return nil
			})
			ae.Uint32(unix.NL80211_IFACE_COMB_MAXNUM, 2)
			ae.Uint32(unix.NL80211_IFACE_COMB_NUM_CHANNELS, 1)
		}),
		"truncated list": func(t *testing.T) []genetlink.Message {
			m := wiphy(t, 0, usual())
			m.Data = m.Data[:len(m.Data)-3]
			return []genetlink.Message{m}
		},
	}
	for name, msgs := range cases {
		t.Run(name, func(t *testing.T) {
			ms := msgs(t)
			n, _ := dialFake(t, func(genetlink.Message, netlink.Message) ([]genetlink.Message, error) { return ms, nil })
			if got, err := n.Combinations(context.Background(), 0); err == nil {
				t.Fatalf("Combinations = %+v, want an error", got)
			}
		})
	}
}

// NewStation asks for a managed wlsta0 on phy with the station's address,
// without NLM_F_ACK: the kernel answers with the interface, and an
// acknowledgement on top stayed unread and put every later request out of
// sequence on the hwsim boot (#936 r4b-2).
func TestNL80211NewStation(t *testing.T) {
	mac := net.HardwareAddr{2, 0x11, 0x22, 0x33, 0x44, 0x55}
	var got localui.RadioIface
	n, _ := dialFake(t, genltest.CheckRequest(nlFamily.ID, unix.NL80211_CMD_NEW_INTERFACE, netlink.Request,
		func(greq genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
			i, err := parseIface(greq.Data)
			got = i
			return []genetlink.Message{msg(nil)}, err
		}))
	if err := n.NewStation(context.Background(), 3, localui.StationIface, mac); err != nil {
		t.Fatal(err)
	}
	if got.Name != localui.StationIface || got.Phy != 3 || got.Type != localui.IfaceStation || !bytes.Equal(got.MAC, mac) {
		t.Fatalf("NewStation sent %+v", got)
	}
}

func TestNL80211StopsAtADoneContext(t *testing.T) {
	n, _ := dialFake(t, func(genetlink.Message, netlink.Message) ([]genetlink.Message, error) {
		t.Fatal("a request ran on a done context")
		return nil, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := n.Interfaces(ctx); err == nil {
		t.Fatal("Interfaces on a done context")
	}
}

// End to end over the fake netlink: a malformed combinations answer makes
// no station, and the loader never sends NEW_INTERFACE.
func TestMalformedCombinationsMakeNoStation(t *testing.T) {
	made := false
	n, _ := dialFake(t, func(greq genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		switch greq.Header.Command {
		case unix.NL80211_CMD_GET_INTERFACE:
			return []genetlink.Message{msg(enc(t, func(ae *netlink.AttributeEncoder) {
				ae.String(unix.NL80211_ATTR_IFNAME, "wlan0")
				ae.Uint32(unix.NL80211_ATTR_WIPHY, 0)
				ae.Uint32(unix.NL80211_ATTR_IFTYPE, ap)
				ae.Bytes(unix.NL80211_ATTR_MAC, net.HardwareAddr{0, 1, 2, 3, 4, 5})
			}))}, nil
		case unix.NL80211_CMD_GET_WIPHY:
			m := wiphy(t, 0, usual())
			m.Data = m.Data[:len(m.Data)-2]
			return []genetlink.Message{m}, nil
		case unix.NL80211_CMD_NEW_INTERFACE:
			made = true
		}
		return nil, nil
	})
	l := &localui.APLoader{Radio: n}
	s, err := l.EnsureStation(context.Background(), "wlan0")
	if err == nil || s != localui.StationNone || made || l.Station() {
		t.Fatalf("EnsureStation = %v, %v; made %v", s, err, made)
	}
	if !strings.Contains(err.Error(), "phy0") {
		t.Fatalf("error %v does not name the radio", err)
	}
}

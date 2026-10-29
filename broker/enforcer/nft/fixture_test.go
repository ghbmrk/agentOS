package nft

import (
	"net/netip"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

// The fixture home: one device per path NET-2 names, a radio-only lock, a
// device-to-device pair, a Household-to-device pair and an isolated device.
// The netns tests build this same layout.
func fixtureLayout() Layout {
	return Layout{
		WAN: "wan0", Owner: "own0", Household: "hh0", Guests: "gst0", Admin: "adm0",
		Core: "core0", Edge: "edge0", Trunk: "ap0", APMgmt: "apm0",
		APAdmin:      []netip.Addr{netip.MustParseAddr("10.70.0.2")},
		ISP:          []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("2001:db8:1::/64")},
		EdgeGateway:  netip.MustParseAddr("10.60.0.1"),
		PagePort:     8443,
		ChannelPort:  7443,
		CorePagePort: 443,
	}
}

func fixturePolicy() policy.Document {
	return policy.Document{
		Version:      7,
		Destinations: []string{"core.example"},
		Devices: []policy.Device{
			{ID: "tv", Network: policy.NetDevices, WiFi: "vlan101", Allow: []string{"tv.example"}, VendorCloud: true, Everyday: true},
			{ID: "speaker", Network: policy.NetDevices, WiFi: "vlan102", Everyday: true},
			{ID: "plug", Network: policy.NetDevices, WiFi: "vlan103", Allow: []string{"plug.example"}, VendorCloud: true, Secure: "off"},
			{ID: "cam", Network: policy.NetDevices, WiFi: "vlan104"},
			{ID: "printer", Network: policy.NetDevices, WiFi: "vlan105", Everyday: true},
			{ID: "sensor-a", Network: policy.NetDevices, WiFi: "vlan106"},
			{ID: "sensor-b", Network: policy.NetDevices, WiFi: "vlan107"},
			{ID: "old-tv", Network: policy.NetDevices, WiFi: "vlan108", Allow: []string{"tv.example"}, VendorCloud: true, Everyday: true, Isolated: true},
			{ID: "lock", Network: policy.NetDevices, Secure: "lock"},
			{ID: "laptop", Network: policy.NetHousehold, Everyday: true},
		},
		Pairs: []policy.Pair{{A: "laptop", B: "printer"}, {A: "sensor-a", B: "sensor-b"}, {A: "old-tv", B: "laptop"}},
	}
}

// Package nft compiles one enforcer policy version into one nftables
// ruleset (SPEC NET-2 Segments, The core's list, Device paths, NET-3,
// NET-1; briefs/ENF.md slice e, decision 4). The ruleset is default deny on
// every segment, and the subpackage load replaces the running one
// atomically.
//
// Nothing the core or a device chooses reaches the ruleset text: devices
// appear only by their VLAN number, and host names never appear (slice f's
// resolver fills the allow sets this package declares). Layout fields are
// checked before they are written. It is enforcer code: it imports the
// standard library and broker/enforcer/policy only
// (broker/daemon/arc2_test.go). Its assumptions are in ASSUMPTIONS.md.
package nft

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

var ErrPolicy = errors.New("nft: policy cannot be compiled")

// Table is the one inet table the ruleset defines; ARPTable filters ARP on
// the edge's segment; NeighTable filters ARP on the shared segments, from
// its own copy of their leases (neighbour).
const (
	Table      = "enforcer"
	ARPTable   = "enforcer_arp"
	NeighTable = "enforcer_neigh"
)

// CoreSet is the allow set slice f's resolver fills with the addresses the
// core's signed destinations resolve to.
func CoreSet(v6 bool) string { return "core" + fam(v6) }

// DeviceSet is the allow set slice f's resolver fills for the device on
// vlan with the addresses its allow list resolves to.
func DeviceSet(vlan int, v6 bool) string { return "d" + strconv.Itoa(vlan) + fam(v6) }

// TrafficSet is the set that counts, per internet address, the bytes the
// device on vlan exchanged on connections the ruleset accepted, both ways
// (NET-5):
// at most TrafficSize addresses per family, each dropped a day after its
// last packet. TrafficOut and TrafficIn are the device's byte counters for
// the same connections. Slice i's summaries read them; nothing is kept per
// packet.
func TrafficSet(vlan int, v6 bool) string { return "t" + strconv.Itoa(vlan) + fam(v6) }
func TrafficOut(vlan int) string          { return "t" + strconv.Itoa(vlan) + "_out" }
func TrafficIn(vlan int) string           { return "t" + strconv.Itoa(vlan) + "_in" }

// TrafficRefused counts every packet refused from the device on vlan, by
// any rule that logs its refusals, and RefusedSet counts them per
// destination address: at most RefusedSize addresses per family, each
// dropped a day after its last refused packet. Both count every packet,
// however few are logged (#4432), so a device cannot choose which of its
// refusals its summary shows (#4765); only more than RefusedSize addresses
// in a day leave some out, which a full set shows.
func TrafficRefused(vlan int) string      { return "t" + strconv.Itoa(vlan) + "_refused" }
func RefusedSet(vlan int, v6 bool) string { return "t" + strconv.Itoa(vlan) + "_refused" + fam(v6) }

// TrafficSize bounds a device's TrafficSet, the internet addresses its
// allow list reached. RefusedSize bounds its RefusedSet, which holds any
// address the device chooses, so it is larger: a device refused at
// RefusedSize addresses in a day has made itself conspicuous.
const (
	TrafficSize = 64
	RefusedSize = 1024
)

// The shared segments are the ones several hosts share (Guests, Owner,
// Household): each is one interface pair to the enforcer, so the
// connection mark cannot tell one host's connection from another's, and
// the reverse-path filter passes any source address on the segment. Each
// has its own sets and chains, named by its name, so what one segment's
// hosts make the enforcer keep never takes another's room.
type segment struct{ name, iface string }

// segments are the shared segments by name: "guests", "owner", "household".
func segments(l Layout) []segment {
	return []segment{{"guests", l.Guests}, {"owner", l.Owner}, {"household", l.Household}}
}

// LeaseSet and LeasedSet follow the IPv4 leases the enforcer's own DHCP
// server grants on shared segment seg: LeaseSet holds each leased address
// with its client's hardware address, LeasedSet each leased hardware
// address. The output chain reads both from the server's DHCPACK as it
// leaves on the segment's interface, before the client has it (snoop), and
// a load seeds them from the server's lease file (Seed) and carries them
// (Reload). An IPv4 packet from a shared segment passes only from an
// address and hardware address LeaseSet holds (claim, ENF-shared-src-1).
// An element never lasts longer than its lease (snoop). The server can
// end a lease early (a client's RELEASE or DECLINE, or a REQUEST that
// moves the client or is refused), so LeaseAddrSet holds each address
// LeaseSet holds, and an answer from the server that would give such an
// address to another hardware address never leaves (snoop): an address is
// another host's only once its element has run out; each such answer is
// counted on LeaseHeld. nft cannot type a
// payload field read at an offset, so the three sets (and MACSet, which
// LeasedSet is checked beside) are typed by their raw fields, the IPv4
// source (@nh,96,32) and the hardware source (@ll,48,48), and nft lists
// their elements as integers.
func LeaseSet(seg string) string     { return "lease_" + seg + "_4" }
func LeaseAddrSet(seg string) string { return "leaseaddr_" + seg + "_4" }
func LeasedSet(seg string) string    { return "leased_" + seg }

// LeaseTimeout is the lease, in seconds, every dhcp-range offers, and the
// longest one the snoop reads: dns.LeaseHours, which dns pins to it, so
// dns fails to compile when the two differ.
const LeaseTimeout = 12 * 3600

// HeldSet, ClaimSet and MACSet bind each IPv6 address a host on segment seg
// sends from to the hardware address it first sent from (claim), one
// address per hardware address, and only for a hardware address with an
// IPv4 lease (LeasedSet): HeldSet holds the addresses, ClaimSet each
// address with its hardware address, MACSet the hardware addresses that
// hold one. An IPv6 packet from a shared segment passes only from the
// hardware address that holds its source address, or from a free address
// when its hardware address is leased and holds none, which it then
// holds. Each hold lasts ClaimTimeout from the address's last forwarded
// packet, at most half the DHCPv6 lease (the constant below fails to
// compile otherwise), so an address the server gives again after its
// lease ran out is free by then, unless the client had requested a
// shorter lease (ENF-shared-src-1); each set holds at most HostSize
// elements. The shared segments' IPv6 is stateful DHCPv6 only (dns), so a
// host has one address to send from.
func HeldSet(seg string) string  { return "held_" + seg + "_6" }
func ClaimSet(seg string) string { return "claim_" + seg + "_6" }
func MACSet(seg string) string   { return "mac6_" + seg }

const ClaimTimeout = 6 * 3600 // seconds

// NeighSet and NeighAddrSet hold, for each IPv6 address on shared segment
// seg, the one hardware address its neighbour entry may name (#4686):
// NeighSet the address with its hardware address, NeighAddrSet the address.
// The first hardware address to hold the address (ClaimSet) takes it, and
// every packet it forwards from the address keeps it, for ClaimTimeout;
// NeighTCPSet and NeighTCPAddrSet keep it the same way for HostTCPTimeout
// from each packet of a TCP connection both ends answered. So a hardware
// address keeps its neighbour hold at least as long as its hold of the
// address (ClaimSet) and every host record of its connections from it
// (HostSet), and another hardware address that takes the address once its
// holder fell silent (ENF-shared-src-1) never moves the holder's neighbour
// entry while any of those records lives (neigh). Neighbour discovery from
// the segment that would set an entry for an address to another hardware
// address is dropped (nd).
func NeighSet(seg string) string        { return "neigh_" + seg + "_6" }
func NeighAddrSet(seg string) string    { return "neighaddr_" + seg + "_6" }
func NeighTCPSet(seg string) string     { return "neightcp_" + seg + "_6" }
func NeighTCPAddrSet(seg string) string { return "neightcpaddr_" + seg + "_6" }

// neighKey is a NeighSet element as nft reads it from a forwarded packet:
// its source address and its raw hardware source address (hwField), the
// form neighbour discovery's link-layer option is read in (nd).
const neighKey = "ip6 saddr . " + hwField

const _ uint = LeaseTimeout - 2*ClaimTimeout

// HostSet is the set that records, for each connection a host on shared
// segment seg started, the connection's conntrack ID and original source,
// and the source address and hardware address its first packet came from
// (live.go, learn, hostKey). Every later packet of the connection from the
// segment, in its original direction (an established one, a related one
// such as an ICMP error, or a new one before any reply), passes only with
// that record, which it refreshes (bound): for HostTCPTimeout on a TCP
// connection both ends have answered, which is how long conntrack keeps
// one idle by default, and for HostTimeout otherwise, longer than conntrack
// keeps any other idle connection. The set holds at most HostSize records
// per family. A load carries every record, hold and claim to the new sets
// (Reload). A connection without a record (its record expired or could not
// be written, the set was full, or it opened while the ruleset was being
// replaced) fails closed: its later packets from the segment are dropped,
// never another host's passed.
func HostSet(seg string, v6 bool) string { return "host_" + seg + fam(v6) }

// AnswerTimeout is how long, in seconds, an answer lets a new connection
// open to its addresses: a Recent set's timeout, counted from the Refresh
// after the answer, so at least this long from the answer itself. It is
// the Fresh set's timeout too, counted from the answer's first add since
// the last Refresh that moved it, so an answer no Refresh moves (the step
// keeps failing) takes new connections for no longer than this. dns
// keeps it at least twice the longest TTL its resolver hands out, so a
// device that dials an answer within its TTL, or retries for as long
// again, is never dropped.
const AnswerTimeout = 600

const (
	HostTimeout    = 3600      // seconds
	HostTCPTimeout = 5 * 86400 // seconds
	HostSize       = 65535
)

// hostLabel is the conntrack label bit learn sets on a connection it has
// recorded (or tried to), so it records each connection once. Nothing else
// on the enforcer sets or reads a label.
const hostLabel = "0"

// learn records the host of a connection from shared segment seg and
// accepts it; bound passes a later packet of a connection from seg only
// with its record; claim passes a packet from seg only from the hardware
// address that holds its source address.
func learn(seg string) string { return "learn_" + seg }
func bound(seg string) string { return "bound_" + seg }
func claim(seg string) string { return "claim_" + seg }

// ndForms are the neighbour discovery messages that can set the
// enforcer's neighbour entries, as nd reads them: the message type, the
// length of its fixed part in bytes, the address whose entry it sets, and
// the type and length (one 8-byte unit) of the link-layer option it names
// it with (RFC 4861 4.1, 4.3, 4.4, 4.6.1). Linux reads only the first
// option of a type (ndisc_parse_options), so with that option first and
// alone the address nd reads is the one the kernel stores.
var ndForms = []struct {
	typ     string
	hdr     int
	subject string
	opt     string
}{
	{"nd-router-solicit", 8, "ip6 saddr", "0x0101"},
	{"nd-neighbor-solicit", 24, "ip6 saddr", "0x0101"},
	{"nd-neighbor-advert", 24, "icmpv6 taddr", "0x0201"},
}

// neigh keeps the neighbour holds (NeighSet) of a packet claim passed from
// shared segment seg; nd drops neighbour discovery from seg that would set
// a held address's entry to another hardware address; arpIn (ARP that
// reaches the enforcer on seg) and ackOut (the server's DHCPACK leaving on
// seg) are NeighTable's chains for seg.
func neigh(seg string) string  { return "neigh_" + seg }
func nd(seg string) string     { return "nd_" + seg }
func arpIn(seg string) string  { return "arp_" + seg }
func ackOut(seg string) string { return "ack_" + seg }

// hostKey is a HostSet element as nft reads it from a packet: its
// connection's ID and original source address, then the packet's own
// source address and hardware source address. At the first packet the two
// addresses are the same, so a later packet matches only from the address
// and the hardware address that started the connection; the original
// source keeps a record of another host's from matching a connection whose
// ID it happens to share.
func hostKey(v6 bool) string {
	f := family(v6)
	return "ct id . ct original " + f + " saddr . " + f + " saddr . ether saddr"
}

// claimKey is a ClaimSet element as nft reads it from a packet.
const claimKey = "ip6 saddr . ether saddr"

// hwField is a packet's hardware source address as a raw field, and
// leaseKey a LeaseSet element read from an IPv4 packet: its source
// address, then hwField.
const (
	hwField   = "@ll,48,48"
	addrField = "@nh,96,32"
	leaseKey  = addrField + " . " + hwField
)

// snoop is the rules that read a lease into segment seg's sets from the
// server's DHCPACK as it leaves on iface. The ACK is a BOOTP reply (op 2,
// Ethernet, hardware address length 6, at UDP payload offset 0) with the
// DHCP magic cookie, and dnsmasq writes its first options in one order:
// the message type (53, ACK), the server identifier (54, an IPv4 address)
// and the lease time (51). The lease is yiaddr (payload offset 16) with
// chaddr (offset 28); an ACK with no address (one to an INFORM) carries
// none. A client may ask for a shorter lease than LeaseTimeout, which
// dnsmasq grants down to 120 s, and nft cannot take a timeout from the
// packet, so there is one rule per band of lease times (leaseBands): its
// elements last the band's floor, never longer than the lease, and at
// least two thirds of it, so a renewal at half the lease refreshes them
// before they run out. update refreshes a renewed lease's elements. The
// offsets are measured against real dnsmasq (ASSUMPTIONS
// ENF-shared-src-1).
//
// First, any answer from the server (an OFFER or ACK) whose address
// LeaseAddrSet holds for another hardware address is dropped and counted
// on LeaseHeld, so the server cannot give an address it freed early to
// another host while the old holder may still send from it
// (ENF-shared-src-1, #5300). Each rule
// updates LeaseAddrSet before LeaseSet: if the first set is full, no
// element is added; if only the second is, the address is held by no
// one's lease and its answers are dropped until it runs out (fails
// closed).
func snoop(seg, iface string) []string {
	out := []string{"oifname " + iface + " udp sport 67 udp dport 68 @th,64,24 0x020106 " + yiaddr + " @" + LeaseAddrSet(seg) +
		" " + yiaddr + " . " + chaddr + " != @" + LeaseSet(seg) + " counter name " + strconv.Quote(LeaseHeld) + " drop"}
	for _, b := range leaseBands() {
		out = append(out, "oifname "+iface+" "+ackMatch(b)+leaseUpdates(seg, b[0])+
			" update @"+LeasedSet(seg)+" { "+chaddr+" timeout "+secs(b[0])+" }")
	}
	return out
}

// The leased address (yiaddr) and the client's hardware address (chaddr)
// in a DHCPACK.
const (
	yiaddr = "@th,192,32"
	chaddr = "@th,288,48"
)

// ackMatch matches a DHCPACK, as snoop reads it, whose lease time is in band b.
func ackMatch(b [2]int) string {
	times := strconv.Itoa(b[0])
	if b[1] > b[0] {
		times += "-" + strconv.Itoa(b[1])
	}
	return "udp sport 67 udp dport 68 @th,64,24 0x020106 " + yiaddr + " != 0 @th,1952,32 0x63825363" +
		" @th,1984,40 0x3501053604 @th,2056,16 0x3304 @th,2072,32 " + times
}

// leaseUpdates is the updates that read an ACK's lease into segment seg's
// LeaseAddrSet and LeaseSet for timeout seconds, the address first.
func leaseUpdates(seg string, timeout int) string {
	return " update @" + LeaseAddrSet(seg) + " { " + yiaddr + " timeout " + secs(timeout) + " }" +
		" update @" + LeaseSet(seg) + " { " + yiaddr + " . " + chaddr + " timeout " + secs(timeout) + " }"
}

// MinLease is the shortest lease dnsmasq grants, in seconds.
const MinLease = 120

// leaseFloors are the floors of the lease bands, in seconds, from
// MinLease to LeaseTimeout: after MinLease, each is two thirds of the next
// one, rounded up, so each band's top (one below the next floor) is under
// one and a half times its floor. A table, not a loop, so no change to it
// can spin; TestLeaseBandsCoverEveryLease checks it.
var leaseFloors = []int{MinLease, 149, 223, 334, 500, 750, 1125, 1687, 2530, 3794, 5690, 8534, 12800, 19200, 28800, LeaseTimeout}

// leaseBands are the lease times, in seconds, each snoop rule reads: each
// band is its floor and its top (both included), every top below one and
// a half times its floor, and the last band LeaseTimeout alone.
func leaseBands() [][2]int {
	out := make([][2]int, len(leaseFloors))
	for i, lo := range leaseFloors {
		top := LeaseTimeout
		if i+1 < len(leaseFloors) {
			top = leaseFloors[i+1] - 1
		}
		out[i] = [2]int{lo, top}
	}
	return out
}

// secs is a timeout of n seconds as nft reads it.
func secs(n int) string { return strconv.Itoa(n) + "s" }

func nfproto(v6 bool) string {
	if v6 {
		return "ipv6"
	}
	return "ipv4"
}

// named is the set that records which addresses one name's answers put in
// the allow set list, for the list's holder ("core", or a device's ID): the
// resolver fills both (ASSUMPTIONS ENF-set-keep-1). Its name is list's and a
// hash of holder and name, so no host name reaches the ruleset text, and a
// device that takes over another's VLAN never inherits its answers.
func named(list, holder, name string) string {
	h := sha256.Sum256([]byte(holder + "\x00" + name))
	return list + "_" + hex.EncodeToString(h[:8])
}

func fam(v6 bool) string {
	if v6 {
		return "_6"
	}
	return "_4"
}

// Counter names. Guests are counted only as a whole network (NET-3); the
// rest count what the log rules log.
const (
	GuestsOut   = "guests_out"
	GuestsIn    = "guests_in"
	GuestsConns = "guests_conns"
	Inbound     = "inbound"      // new connections from the internet
	Blocked     = "blocked"      // forwarded traffic no rule allowed
	Expired     = "expired"      // new connections to an address a listed name answered, but not within AnswerTimeout
	CoreDevice  = "core_device"  // connections the core starts to a device's control port
	CoreStream  = "core_stream"  // connections the core starts to a camera's or microphone's stream port
	EdgeDevice  = "edge_device"  // connections the edge starts to a device
	EdgeIn      = "edge_in"      // anything the edge sends the enforcer itself
	RADropped   = "ra_dropped"   // router advertisements from any segment
	DNSOutside  = "dns_outside"  // a device's outside or encrypted DNS
	DNSRedirect = "dns_redirect" // a device's port-53 traffic answered by the enforcer
	Spoofed     = "spoofed"      // a source not routed back out of its interface, or an IPv4 broadcast, multicast or 0.0.0.0 one outside DHCP (rpf)
	APAdminDrop = "ap_admin"     // the access point's admin from anywhere but the admin port
	ISPDrop     = "isp"          // the ISP router's admin or LAN
	CoreEdge    = "core_edge"    // between the core's and the edge's segments
	EdgeCut     = "edge_cut"     // every packet to or from the edge's segment while the edge is cut (Drop.EdgeCut)
	LeaseHeld   = "lease_held"   // the address server's answers giving a host an address another still holds (snoop), on every shared segment
	LogLines    = "log_lines"    // lines written to the kernel log (logged)
)

// Log prefixes. Each names a refusal or a box's connection to a device,
// and each rule that logs with one ends in that prefix's chain (logged),
// so no other rule writes a line. A refusal's line comes in on the
// interface that sent it, a box's connection's goes out on the device's
// VLAN (OUT=). The lines are for the journal only: a device's summary
// counts its refusals from TrafficRefused and RefusedSet, not from lines.
const (
	LogInbound    = "enf inbound "
	LogAPAdmin    = "enf ap-admin "
	LogISP        = "enf isp "
	LogNonGlobal  = "enf nonglobal "
	LogCoreEdge   = "enf core-edge "
	LogDNS        = "enf dns "
	LogDrop       = "enf drop "
	LogExpired    = "enf expired "
	LogEdgeDevice = "enf edge-dev "
	LogCoreDevice = "enf core-dev "
	LogCoreStream = "enf core-stream "
)

// prefix is one log prefix, the counter that counts every packet its
// rules log, and the verdict its chain ends in.
type prefix struct{ prefix, counter, verdict string }

// refusals are the prefixes of the packets the enforcer refuses; accepts
// those of the connections a box starts to a device (ENF-e-2).
var (
	refusals = []prefix{
		{LogInbound, Inbound, "drop"}, {LogAPAdmin, APAdminDrop, "drop"}, {LogISP, ISPDrop, "drop"}, {LogNonGlobal, Blocked, "drop"},
		{LogCoreEdge, CoreEdge, "drop"}, {LogDNS, DNSOutside, "drop"}, {LogDrop, Blocked, "drop"}, {LogExpired, Expired, "drop"}, {LogCap, CapDrop, "drop"},
	}
	accepts = []prefix{{LogEdgeDevice, EdgeDevice, "accept"}, {LogCoreDevice, CoreDevice, "accept"}, {LogCoreStream, CoreStream, "accept"}}
)

// Lines are the enforcer's to rate, not a sender's: each prefix logs at
// most LineRate packets a minute, after a burst of LineBurst, per
// interface (a refusal's incoming one: a device's VLAN, the WAN, a
// segment; a box's connection's outgoing one, the device's VLAN), so
// neither a flood of refused packets nor a box opening connection after
// connection can fill the journal (#4432, #4762, P4). The count and the
// verdict never wait on a bucket. Lines sets hold one bucket per interface
// for at most LineSize interfaces (more than the 4094 VLANs and the named
// networks); an interface idle for LineIdle seconds has a full bucket
// again, so its entry goes.
const (
	LineRate  = 10
	LineBurst = 10
	LineSize  = 8192
	LineIdle  = 60
)

// logged is the chain a packet logged with prefix p ends in: it is
// counted on p's counter (and a refused one on its device's, loggedDecls),
// logged within its interface's bucket of p's lines set, and given p's
// verdict.
func logged(p string) string { return "log_" + slug(p) }
func lines(p string) string  { return "lines_" + slug(p) }
func slug(p string) string   { return strings.NewReplacer("enf ", "", " ", "", "-", "_").Replace(p) }

var counters = []string{GuestsOut, GuestsIn, GuestsConns, Inbound, Blocked, Expired, CoreDevice, CoreStream, EdgeDevice, EdgeIn, RADropped, DNSOutside, DNSRedirect, Spoofed, APAdminDrop, ISPDrop, CoreEdge, EdgeOut, CapDrop, EdgeCut, LeaseHeld, LogLines}

// The relays' ports (slice f): the mDNS pair relay hears 224.0.0.251:5353
// and [ff02::fb]:5353 only on the interfaces of signed pairs, and the
// Wake-on-LAN relay hears the core only.
const (
	MDNSPort   = 5353
	MDNSGroup  = "224.0.0.251"
	MDNSGroup6 = "ff02::fb"
	WoLPort    = 9
)

// Addresses that are not the internet (the IANA special-purpose blocks
// that route nowhere public). No segment reaches them through the WAN.
var nonGlobal4 = []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3"}
var nonGlobal6 = []string{"::/127", "::ffff:0.0.0.0/96", "64:ff9b:1::/48", "fc00::/7", "fe80::/10", "ff00::/8"}

// Known outside encrypted-DNS resolvers (NET-3), blocked from Devices on
// every port. Plain DNS to anywhere but the enforcer is blocked by port.
var doh4 = []string{"1.0.0.1", "1.1.1.1", "8.8.4.4", "8.8.8.8", "9.9.9.9", "45.90.28.0/24", "45.90.30.0/24", "94.140.14.14", "94.140.15.15", "149.112.112.112", "185.228.168.9", "208.67.220.220", "208.67.222.222"}
var doh6 = []string{"2001:4860:4860::8844", "2001:4860:4860::8888", "2606:4700:4700::1001", "2606:4700:4700::1111", "2620:fe::9", "2620:fe::fe", "2a07:a8c0::/33", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"}

// device is one Devices-network device with its own VLAN, which is its
// identity at the enforcer (D-225): what the access point or the device
// reports, its hardware address included, is never used.
type device struct {
	vlan  int
	iface string
	d     policy.Device
}

// Path rules (NET-2 Device paths, Cameras and microphones), from the
// document's fields: a device reaches the internet (its allow set) only
// while its vendor cloud is allowed; an everyday device with its cloud is
// online and the edge reaches its control ports; an everyday device
// without is offline and the core reaches its control ports. Of a
// safety-list device, the core reaches only an offline camera's or
// microphone's stream ports, and the edge nothing. An isolated device gets
// nothing.
func (v device) internet() bool { return !v.d.Isolated && v.d.VendorCloud }
func (v device) online() bool   { return !v.d.Isolated && v.d.Everyday && v.d.VendorCloud }
func (v device) offline() bool  { return !v.d.Isolated && v.d.Everyday && !v.d.VendorCloud }
func (v device) stream() bool   { return !v.d.Isolated && v.d.Recorder() && !v.d.VendorCloud }

// dports is one match per protocol for ports, such as "tcp dport { 80, 443 }",
// in a fixed order; none for no ports.
func dports(ports []policy.Port) []match {
	var out []match
	for _, proto := range []string{policy.ProtoTCP, policy.ProtoUDP} {
		var nums []string
		for _, p := range ports {
			if p.Proto == proto {
				nums = append(nums, port(p.Num))
			}
		}
		if len(nums) > 0 {
			out = append(out, l4Ports(proto, "{ "+strings.Join(nums, ", ")+" }"))
		}
	}
	return out
}

// VLAN reads a device's Wi-Fi identity, "vlan<N>" with N from 2 to 4094 in
// its shortest form; ok is false for anything else.
func VLAN(wifi string) (int, bool) {
	s, found := strings.CutPrefix(wifi, "vlan")
	if !found || s == "" || len(s) > 4 || s[0] == '0' {
		return 0, false
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, n >= 2 && n <= 4094
}

func devices(d policy.Document, l Layout) ([]device, error) {
	var out []device
	seen := map[int]string{}
	for _, dev := range d.Devices {
		if dev.WiFi == "" {
			continue // a radio or wired device without a VLAN: no IP path
		}
		n, ok := VLAN(dev.WiFi)
		if !ok {
			return nil, fmt.Errorf("%w: device %q has Wi-Fi identity %q", ErrPolicy, dev.ID, dev.WiFi)
		}
		if dev.Network != policy.NetDevices {
			return nil, fmt.Errorf("%w: device %q has a VLAN but is on %q", ErrPolicy, dev.ID, dev.Network)
		}
		if other, dup := seen[n]; dup {
			return nil, fmt.Errorf("%w: devices %q and %q share VLAN %d", ErrPolicy, other, dev.ID, n)
		}
		seen[n] = dev.ID
		out = append(out, device{vlan: n, iface: l.deviceIface(n), d: dev})
	}
	slices.SortFunc(out, func(a, b device) int { return a.vlan - b.vlan })
	return out, nil
}

// Path is one signed pair compiled to interfaces: From may start
// connections to To, and both may when Both (two devices). Slice f's mDNS
// relay passes records along the same paths (Paths).
type Path struct {
	From, To string
	Both     bool
}

// pairs compiles the signed pairs (NET-3, NET-2 Device paths). A pair is
// between two Devices-network devices, or from an Owner or Household
// device to one: those two networks share one password each, so that side
// of the pair is the whole network. A pair has a path only when both ends
// are policy.Document.Linked: never with an isolated, unpatched (NET-7) or
// VLAN-less device.
func pairs(d policy.Document, l Layout, devs []device) ([]Path, error) {
	byID := map[string]device{}
	for _, v := range devs {
		byID[v.d.ID] = v
	}
	end := func(id string) (iface string, isDevice, live bool, err error) {
		dev := d.Device(id)
		switch {
		case dev == nil:
			return "", false, false, fmt.Errorf("%w: pair names %q", ErrPolicy, id)
		case dev.Network == policy.NetOwner:
			return l.Owner, false, true, nil
		case dev.Network == policy.NetHousehold:
			return l.Household, false, true, nil
		case dev.Network != policy.NetDevices:
			return "", false, false, fmt.Errorf("%w: pair with %q on %q", ErrPolicy, id, dev.Network)
		}
		v, ok := byID[id]
		return v.iface, true, ok && d.Linked(id), nil
	}
	var out []Path
	for _, p := range d.Pairs {
		a, aDev, aLive, err := end(p.A)
		if err != nil {
			return nil, err
		}
		b, bDev, bLive, err := end(p.B)
		if err != nil {
			return nil, err
		}
		switch {
		case !aDev && !bDev:
			return nil, fmt.Errorf("%w: pair %q-%q has no device on the devices network", ErrPolicy, p.A, p.B)
		case !aLive || !bLive:
		case aDev && bDev:
			out = append(out, Path{From: a, To: b, Both: true})
		case aDev:
			out = append(out, Path{From: b, To: a})
		default:
			out = append(out, Path{From: a, To: b})
		}
	}
	slices.SortFunc(out, func(x, y Path) int { return strings.Compare(x.From+" "+x.To, y.From+" "+y.To) })
	return slices.Compact(out), nil
}

// compiled checks the layout and the document and gives the devices with a
// VLAN and the signed pairs' paths, which every export below shares.
func compiled(d policy.Document, l Layout) ([]device, []Path, error) {
	if err := l.Check(); err != nil {
		return nil, nil, err
	}
	if _, err := policy.Encode(d); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrPolicy, err)
	}
	devs, err := devices(d, l)
	if err != nil {
		return nil, nil, err
	}
	paths, err := pairs(d, l, devs)
	if err != nil {
		return nil, nil, err
	}
	return devs, paths, nil
}

// Paths is the signed pairs' paths the ruleset opens, which are the only
// paths slice f's mDNS relay passes records on (NET-3 Casting).
func Paths(d policy.Document, l Layout) ([]Path, error) {
	_, paths, err := compiled(d, l)
	return paths, err
}

// AllowSet is one allow set the ruleset declares and the names whose
// answers slice f's resolver puts in it.
//
// Each holder's answers live in four sets per family (#4453). The resolver
// puts each answer's addresses in the allow set itself, in the name's own
// set (Named) and in the fresh set (Fresh). The allow set and the name
// sets hold every address a listed name answered: the allow set is what
// an open connection's later packets are checked against (the live
// chains), and the name sets let a load keep the answers of the names
// still listed (Reload). A connection's first packet passes only to an
// address in the fresh set or the recent set (Recent), so an address no
// answer has returned for AnswerTimeout takes no new connection, while a
// connection already open to it goes on. The fresh set holds the answers
// since the last Refresh; Refresh moves them into the recent set with a
// full AnswerTimeout each, which re-adding to a set with a timeout never
// gives (dns ASSUMPTIONS ENF-f-3). The fresh set's own AnswerTimeout,
// which a re-added answer does not restart, ends an answer's first-packet
// admission when no Refresh moves it (#5116).
type AllowSet struct {
	Set4, Set6 string
	Names      []string
	holder     string
}

// Named is the set that records the addresses name's answers put in the
// family's allow set, which the resolver fills alongside it, so a load can
// keep the answers of the names still listed (Reload).
func (a AllowSet) Named(name string, v6 bool) string {
	return named(a.set(v6), a.holder, name)
}

// Fresh is the set of the family's answers since the last Refresh, which
// the resolver fills alongside the allow set, each for at most
// AnswerTimeout from when it was first added.
func (a AllowSet) Fresh(v6 bool) string { return a.set(v6) + "_f" }

// Recent is the set of the family's addresses some listed name answered in
// the last AnswerTimeout, each until then (Refresh).
func (a AllowSet) Recent(v6 bool) string { return a.set(v6) + "_r" }

func (a AllowSet) set(v6 bool) string {
	if v6 {
		return a.Set6
	}
	return a.Set4
}

// names is the set's names, each once, in order.
func (a AllowSet) names() []string {
	n := slices.Clone(a.Names)
	slices.Sort(n)
	return slices.Compact(n)
}

// AllowSets is every allow set the ruleset declares: the core's, with its
// signed destinations, then each device's that reaches the internet, with
// its allow list, by VLAN. A device the ruleset gives no internet has no
// set, so no answer reaches it (NET-2 The core's list, NET-3).
func AllowSets(d policy.Document, l Layout) ([]AllowSet, error) {
	devs, _, err := compiled(d, l)
	if err != nil {
		return nil, err
	}
	return allowSets(d, devs), nil
}

func allowSets(d policy.Document, devs []device) []AllowSet {
	out := []AllowSet{{Set4: CoreSet(false), Set6: CoreSet(true), Names: slices.Clone(d.Destinations), holder: "core"}}
	for _, v := range devs {
		if v.internet() {
			out = append(out, AllowSet{Set4: DeviceSet(v.vlan, false), Set6: DeviceSet(v.vlan, true), Names: slices.Clone(v.d.Allow), holder: v.d.ID})
		}
	}
	return out
}

// Compile is the ruleset for one policy document on one layout: a single
// text that starts by flushing the running ruleset, so loading it replaces
// everything in one transaction. The same inputs give the same bytes.
func Compile(d policy.Document, l Layout) (string, error) {
	text, _, err := compile(d, l)
	return text, err
}

// compile is Compile's ruleset and the devices it was compiled for.
func compile(d policy.Document, l Layout) (string, []device, error) {
	devs, paths, err := compiled(d, l)
	if err != nil {
		return "", nil, err
	}
	var isp4, isp6, ap4, ap6 []string
	for _, p := range l.ISP {
		if p.Addr().Is4() {
			isp4 = append(isp4, p.Masked().String())
		} else {
			isp6 = append(isp6, p.Masked().String())
		}
	}
	for _, a := range l.APAdmin {
		if a.Is4() {
			ap4 = append(ap4, a.String())
		} else {
			ap6 = append(ap6, a.String())
		}
	}

	w := &writer{}
	q := strconv.Quote
	T := q(l.Trunk + ".*")
	w.line("flush ruleset")
	w.line("")
	w.open("table inet " + Table)
	for _, c := range counters {
		w.line("counter " + c + " { }")
	}
	var counted []device // an isolated device has no traffic to count
	for _, v := range devs {
		if !v.d.Isolated {
			counted = append(counted, v)
		}
	}
	for _, v := range counted {
		w.line("counter " + TrafficOut(v.vlan) + " { }")
		w.line("counter " + TrafficIn(v.vlan) + " { }")
	}
	for _, v := range devs {
		w.line("counter " + TrafficRefused(v.vlan) + " { }")
	}
	w.set("isp_4", "ipv4_addr", "interval", isp4)
	w.set("isp_6", "ipv6_addr", "interval", isp6)
	w.set("nonglobal_4", "ipv4_addr", "interval", nonGlobal4)
	w.set("nonglobal_6", "ipv6_addr", "interval", nonGlobal6)
	w.set("doh_4", "ipv4_addr", "interval", doh4)
	w.set("doh_6", "ipv6_addr", "interval", doh6)
	w.set("ap_4", "ipv4_addr", "", ap4)
	w.set("ap_6", "ipv6_addr", "", ap6)
	for _, a := range allowSets(d, devs) {
		for _, v6 := range []bool{false, true} {
			typ := map[bool]string{false: "ipv4_addr", true: "ipv6_addr"}[v6]
			w.set(a.set(v6), typ, "timeout", nil)
			for _, s := range []string{a.Fresh(v6), a.Recent(v6)} {
				w.open("set " + s)
				w.line("type " + typ + ";")
				w.line("flags timeout;")
				w.line("timeout " + secs(AnswerTimeout) + ";")
				w.close()
			}
			for _, n := range a.names() {
				w.set(a.Named(n, v6), typ, "timeout", nil)
			}
		}
	}

	capDecls(w)
	loggedDecls(w, devs)
	for _, sg := range segments(l) {
		for _, v6 := range []bool{false, true} {
			w.dynamic(HostSet(sg.name, v6), hostKey(v6), HostTimeout)
		}
		w.dynamic(LeaseSet(sg.name), leaseKey, LeaseTimeout)
		w.dynamic(LeaseAddrSet(sg.name), addrField, LeaseTimeout)
		w.dynamic(LeasedSet(sg.name), hwField, LeaseTimeout)
		w.dynamic(HeldSet(sg.name), "ip6 saddr", ClaimTimeout)
		w.dynamic(ClaimSet(sg.name), claimKey, ClaimTimeout)
		w.dynamic(MACSet(sg.name), hwField, ClaimTimeout)
		w.dynamic(NeighAddrSet(sg.name), "ip6 saddr", ClaimTimeout)
		w.dynamic(NeighSet(sg.name), neighKey, ClaimTimeout)
		w.dynamic(NeighTCPAddrSet(sg.name), "ip6 saddr", HostTCPTimeout)
		w.dynamic(NeighTCPSet(sg.name), neighKey, HostTCPTimeout)
	}
	for _, v := range counted {
		for _, v6 := range []bool{false, true} {
			w.open("set " + TrafficSet(v.vlan, v6))
			w.line("type " + map[bool]string{false: "ipv4_addr", true: "ipv6_addr"}[v6] + ";")
			w.line("size " + strconv.Itoa(TrafficSize) + ";")
			w.line("flags dynamic,timeout;")
			w.line("timeout 1d;")
			w.close()
		}
	}

	served := "{ " + strings.Join([]string{q(l.Owner), q(l.Household), q(l.Guests), q(l.Admin), q(l.Core), T}, ", ") + " }"
	edge, core, wan := q(l.Edge), q(l.Core), q(l.WAN)

	// Reverse path, on every interface: a packet whose source address is
	// not routed back out of the interface it came in on is dropped before
	// conntrack or any service sees it, so no segment can pose as the
	// upstream resolver, the internet or another segment, and a forged
	// answer never reaches the resolver that fills the allow sets (NET-2
	// The core's list). The unspecified sources of a DHCP request (UDP 68
	// to 67) and of IPv6 address setup have no route and pass to the rules
	// below. Then an IPv4 broadcast or multicast source (the limited
	// broadcast, a subnet's broadcast, a group) is dropped and counted on
	// every interface: the fib routes the WAN subnet's own broadcast back
	// out of the WAN, so the general check below would pass it, and with
	// rp_filter off the kernel would deliver it (#4841). The fib types
	// 0.0.0.0 as broadcast, so any other unspecified source is dropped and
	// counted here too, by intent: nothing can answer it, though the general
	// check passes one to the limited broadcast or a link-local group
	// (#4855). IPv6 has no broadcast, and its stack drops a
	// multicast source before this hook. A DHCP or DHCPv6 answer to the
	// enforcer's own client on the WAN passes: until the WAN has its lease,
	// no route leads back to the server (NET-2 Fails safe, #4078). Only an
	// answer addressed to the enforcer itself, from a source no interface
	// routes and none of the enforcer's own addresses, passes: once leased
	// the server is routed out of the WAN and passes the check below, and a
	// source another interface routes (the core, a person's network, a
	// device) or the enforcer holds (its address on any segment) is the
	// internet posing as a segment or as the enforcer and is dropped (#4764,
	// #4771); the fib reports a local source as missing too, so the second
	// test is needed. A DHCPv6 server
	// answering from such an address first resolves the client's link-local
	// address, so its neighbour discovery, on the link (hop limit 255) and
	// to the enforcer, passes on the same terms. An answer to be forwarded
	// is checked like any other packet.
	w.open("chain rpf")
	w.line("type filter hook prerouting priority raw; policy accept;")
	w.line(`iif "lo" accept`)
	w.line("ip saddr 0.0.0.0 udp sport 68 udp dport 67 accept")
	w.line("ip6 saddr :: meta l4proto ipv6-icmp accept")
	w.line("meta nfproto ipv4 fib saddr type { broadcast, multicast } counter name " + q(Spoofed) + " drop")
	w.line("iifname " + q(l.WAN) + " meta nfproto ipv4 udp sport 67 udp dport 68 fib daddr . iif type { local, broadcast } fib saddr oif missing fib saddr type != { local, broadcast, anycast, multicast } accept")
	w.line("iifname " + q(l.WAN) + " meta nfproto ipv6 udp sport 547 udp dport 546 fib daddr . iif type local fib saddr oif missing fib saddr type != { local, broadcast, anycast, multicast } accept")
	w.line("iifname " + q(l.WAN) + " icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } ip6 hoplimit 255 fib daddr . iif type { local, multicast } fib saddr oif missing fib saddr type != { local, broadcast, anycast, multicast } accept")
	w.line("fib saddr . iif oif missing counter name " + q(Spoofed) + " drop")
	w.close()

	w.open("chain input")
	w.line("type filter hook input priority filter; policy drop;")
	w.line(`iif "lo" accept`)
	// The edge's segment hears nothing (NET-2 Segments): no DHCP, DNS, NTP,
	// mDNS, page or other listener, before any other rule can answer it.
	w.line("iifname " + edge + " counter name " + q(EdgeIn) + " drop")
	// A DHCPRELEASE from a shared segment, its message type the first
	// option as dhclient, udhcpc and dhcpcd write it, never reaches the server,
	// even on a connection a renewal opened: the lease, and the address
	// with it, lasts its full time, as the lease sets do. One written
	// otherwise reaches the server and frees the address there, but snoop
	// still keeps it from any other host until its element runs out
	// (ENF-shared-src-1, #5300).
	var sharedIfs []string
	for _, sg := range segments(l) {
		sharedIfs = append(sharedIfs, q(sg.iface))
	}
	w.line("iifname { " + strings.Join(sharedIfs, ", ") + " } udp dport 67 @th,1952,56 0x63825363350107 drop")
	// Neighbour discovery from a shared segment is judged by its segment's
	// nd chain before anything accepts it (#4686). It is never tracked, so
	// no established accept would take it, but the order does not rest on
	// that.
	for _, sg := range segments(l) {
		w.line("iifname " + q(sg.iface) + " icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit } jump " + nd(sg.name))
	}
	w.line("ct state invalid drop")
	w.line("ct state established,related accept")
	w.line("icmpv6 type nd-router-advert iifname != " + wan + " counter name " + q(RADropped) + " drop")
	w.line("iifname " + wan + " udp sport 67 udp dport 68 accept")
	w.line("iifname " + wan + " udp sport 547 udp dport 546 accept")
	w.line("iifname " + wan + " icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept")
	w.line("iifname " + wan + " goto " + logged(LogInbound))
	w.line("icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit } accept")
	w.line("iifname " + served + " udp dport { 53, 67, 547 } accept")
	w.line("iifname " + served + " tcp dport 53 accept")
	w.line("iifname { " + q(l.Owner) + ", " + q(l.Admin) + " } tcp dport " + port(l.PagePort) + " accept")
	w.line("iifname " + core + " tcp dport " + port(l.ChannelPort) + " accept")
	// Slice f's relays: the Wake-on-LAN relay hears only the core, and the
	// mDNS relay the two ends of a signed pair, every device's VLAN and
	// the Owner and Household networks, whose own names it hears without
	// passing them on (NET-2, NET-3, D-266, #4411).
	w.line("iifname " + core + " udp dport " + strconv.Itoa(WoLPort) + " accept")
	var ends []string
	for _, e := range hears(devs, l) {
		ends = append(ends, q(e))
	}
	w.line("iifname { " + strings.Join(ends, ", ") + " } ip daddr " + MDNSGroup + " udp dport " + strconv.Itoa(MDNSPort) + " accept")
	w.line("iifname { " + strings.Join(ends, ", ") + " } ip6 daddr " + MDNSGroup6 + " udp dport " + strconv.Itoa(MDNSPort) + " accept")
	w.close()

	// A device's DNS to anywhere is answered by the enforcer's own
	// resolver (NET-3), so only names on a list resolve.
	w.open("chain prerouting")
	w.line("type nat hook prerouting priority dstnat; policy accept;")
	w.line("iifname " + T + " meta l4proto { tcp, udp } th dport 53 counter name " + q(DNSRedirect) + " redirect")
	w.close()

	// The forward chain's rules after the established accept decide a
	// connection's first packet. The same rules, read from each
	// connection's own record (ct.go), make the live chain, which every
	// established or related packet passes first: a connection lives only
	// while the ruleset in force would still admit its first packet, so a
	// load that removes a path ends the connections open along it, both
	// ways (NET-3, NET-7).
	g := q(l.Guests)
	var fwd []rule
	add := func(in, out, verdict string, m ...match) {
		fwd = append(fwd, rule{in: in, out: out, m: m, verdict: verdict})
	}
	refused := func(in, out, prefix string, m ...match) {
		fwd = append(fwd, rule{in: in, out: out, m: m, verdict: "drop", logged: logged(prefix)})
	}
	admitted := func(in, out, prefix string, m ...match) {
		fwd = append(fwd, rule{in: in, out: out, m: m, verdict: "accept", logged: logged(prefix)})
	}
	refused(wan, "", LogInbound)
	add(g, wan, "accept", daddr(false, "!= @isp_4"), daddr(false, "!= @nonglobal_4"))
	add(g, wan, "accept", daddr(true, "!= @isp_6"), daddr(true, "!= @nonglobal_6"))
	add(g, "", "drop")
	add("{ "+q(l.Owner)+", "+q(l.Household)+" }", "", "jump people")
	add(q(l.Admin), q(l.APMgmt), "accept", daddr(false, "@ap_4"))
	add(q(l.Admin), q(l.APMgmt), "accept", daddr(true, "@ap_6"))
	refused("", "", LogAPAdmin, daddr(false, "@ap_4"))
	refused("", "", LogAPAdmin, daddr(true, "@ap_6"))
	refused("", "", LogISP, daddr(false, "@isp_4"))
	refused("", "", LogISP, daddr(true, "@isp_6"))
	refused("", wan, LogNonGlobal, daddr(false, "@nonglobal_4"))
	refused("", wan, LogNonGlobal, daddr(true, "@nonglobal_6"))
	refused(edge, core, LogCoreEdge)
	refused(core, edge, LogCoreEdge)
	// From here on, oifname WAN is the internet.
	add(q(l.Admin), core, "accept", l4Ports("tcp", port(l.CorePagePort)))
	add(edge, wan, "accept")
	// An answer's addresses take new connections while it is fresh or
	// recent, and an open connection lives while its name is listed
	// (AllowSet); the second rule's live form would be the first's. A new
	// connection to an address a listed name answered, but not within
	// AnswerTimeout, is refused with its own reason (LogExpired, #5116);
	// it judges first packets only, so the live chains are as before.
	answered := func(in string, a AllowSet) {
		for _, v6 := range []bool{false, true} {
			f := family(v6)
			k := "ct original " + f + " daddr @" + a.set(v6)
			add(in, wan, "accept", match{f + " daddr @" + a.Recent(v6), k})
			add(in, wan, "accept", match{f + " daddr @" + a.Fresh(v6), k})
			fwd[len(fwd)-1].firstOnly = true
			refused(in, wan, LogExpired, daddr(v6, "@"+a.set(v6)))
			fwd[len(fwd)-1].firstOnly = true
		}
	}
	answered(core, AllowSet{Set4: CoreSet(false), Set6: CoreSet(true)})
	// Devices: outside DNS and known encrypted-DNS resolvers are blocked
	// before any allow set is consulted (NET-3).
	refused(T, wan, LogDNS, daddr(false, "@doh_4"))
	refused(T, wan, LogDNS, daddr(true, "@doh_6"))
	refused(T, wan, LogDNS, match{"meta l4proto { tcp, udp } th dport { 53, 853 }", "ct protocol { tcp, udp } ct original proto-dst { 53, 853 }"})
	for _, v := range devs {
		i := q(v.iface)
		if v.internet() {
			answered(i, AllowSet{Set4: DeviceSet(v.vlan, false), Set6: DeviceSet(v.vlan, true)})
		}
		for _, m := range dports(v.d.Control) {
			if v.online() {
				admitted(edge, i, LogEdgeDevice, m)
			}
			if v.offline() {
				admitted(core, i, LogCoreDevice, m)
			}
		}
		for _, m := range dports(v.d.Stream) {
			if v.stream() {
				admitted(core, i, LogCoreStream, m)
			}
		}
	}
	for _, p := range paths {
		if p.Both {
			add(q(p.From), q(p.To), "accept")
			add(q(p.To), q(p.From), "accept")
		}
	}

	// Owner and Household: the internet, their signed pairs and, from Owner
	// only, the core's page (CH-9). They are not inspected (NET-1), so what
	// they are refused is dropped without a log line or a counter.
	var people []rule
	padd := func(in, out, verdict string, m ...match) {
		people = append(people, rule{in: in, out: out, m: m, verdict: verdict})
	}
	padd("", "", "drop", daddr(false, "@ap_4"))
	padd("", "", "drop", daddr(true, "@ap_6"))
	padd("", "", "drop", daddr(false, "@isp_4"))
	padd("", "", "drop", daddr(true, "@isp_6"))
	padd("", wan, "drop", daddr(false, "@nonglobal_4"))
	padd("", wan, "drop", daddr(true, "@nonglobal_6"))
	padd(q(l.Owner), wan, "accept")
	padd(q(l.Household), wan, "accept")
	padd(q(l.Owner), core, "accept", l4Ports("tcp", port(l.CorePagePort)))
	for _, p := range paths {
		if !p.Both {
			padd(q(p.From), q(p.To), "accept")
		}
	}

	// Every accept binds its connection to its interface pair (live.go,
	// bind), so every accept names one interface each way.
	idx := map[string]uint32{}
	for k, n := range []string{l.WAN, l.Owner, l.Household, l.Guests, l.Admin, l.Core, l.Edge, l.APMgmt} {
		idx[q(n)] = 0x1001 + uint32(k)
	}
	for _, v := range devs {
		idx[q(v.iface)] = uint32(v.vlan)
	}
	shared := map[string]string{} // a shared segment's quoted interface -> its name
	for _, sg := range segments(l) {
		shared[q(sg.iface)] = sg.name
	}
	vmap := func(chain func(string) string) string {
		var es []string
		for _, sg := range segments(l) {
			es = append(es, q(sg.iface)+" : jump "+chain(sg.name))
		}
		return "iifname vmap { " + strings.Join(es, ", ") + " }"
	}
	for _, rs := range [][]rule{fwd, people} {
		if err := bindAll(idx, shared, rs); err != nil {
			return "", nil, err
		}
	}
	// A related packet that reaches the end of a live chain names a
	// connection that does not run on the interfaces it crossed: an ICMP
	// error forged from another segment, or a genuine one about a connection
	// a load cut (#4113, A18 Segments). It is dropped and, like any other
	// refusal, logged and counted, except when it touches the networks that
	// are never observed (NET-1, NET-3): sent from or to one of them, or
	// naming a connection with a Guests, Owner or Household end, which its
	// inner header (and so the log line) would show. The connection's mark
	// says which interfaces it runs on; an unbound one (mark 0, opened
	// before this ruleset was loaded) may be theirs, so it is not logged
	// either. Every packet people_live sees has an Owner or Household end,
	// so only forward_live logs. A cut connection's own later packets are
	// dropped without a line, since a load can cut many at once.
	unseen := "{ " + g + ", " + q(l.Owner) + ", " + q(l.Household) + " }"
	var lows, highs []string
	for _, n := range []string{l.Guests, l.Owner, l.Household} {
		lows = append(lows, fmt.Sprintf("0x%08x", idx[q(n)]))
		highs = append(highs, fmt.Sprintf("0x%08x", idx[q(n)]<<16))
	}
	related := "ct state related iifname != " + unseen + " oifname != " + unseen + " ct mark != 0x00000000 ct mark and 0x0000ffff != { " + strings.Join(lows, ", ") + " }" +
		" ct mark and 0xffff0000 != { " + strings.Join(highs, ", ") + " } goto " + logged(LogDrop)

	w.open("chain forward")
	w.line("type filter hook forward priority filter; policy drop;")
	// A cut edge (Drop.EdgeCut) is cut before any other rule, established
	// and related packets included, so its open connections end with it.
	for _, r := range cutJumps(l) {
		w.line(r)
	}
	// Guests: counted only as a whole network, never per device or per
	// destination, and never logged (NET-3).
	w.line("iifname " + g + " counter name " + q(GuestsOut))
	w.line("oifname " + g + " counter name " + q(GuestsIn))
	w.line("iifname " + g + " ct state new counter name " + q(GuestsConns))
	w.line("ct state invalid drop")
	// Every byte the core sends to its allow set, and the edge to the
	// internet, is counted and charged to its cap first, so a byte the cap
	// drops still counts and trips (caps.go, NET-2 Byte caps).
	for _, r := range capJumps(l) {
		w.line(r)
	}
	// A packet from a shared segment must come from the hardware address
	// that holds its source address (claim), and every one after its
	// connection's first, in the connection's original direction, from the
	// host that started the connection (bound; live.go, #4324, #4480): an
	// established or related one, or a new one on a connection already
	// recorded (conntrack calls original-direction packets new until a
	// reply). In the reply direction none comes from a shared segment,
	// since no accept leads into one.
	w.line(vmap(claim))
	w.line("ct state established,related ct direction original " + vmap(bound))
	w.line("ct state new ct label " + hostLabel + " " + vmap(bound))
	w.line("ct state established,related jump " + live("forward"))
	// Each device's traffic on accepted connections is counted before the
	// accept below (NET-5). Only established packets count: an address the
	// device was refused never enters its set, and neither does the sender
	// of a related packet such as an ICMP error, which anyone can forge.
	if len(counted) > 0 {
		var outs, ins []string
		for _, v := range counted {
			outs = append(outs, q(v.iface)+" : jump "+trafficChain(v.vlan, "out"))
			ins = append(ins, q(v.iface)+" : jump "+trafficChain(v.vlan, "in"))
		}
		w.line("ct state established iifname vmap { " + strings.Join(outs, ", ") + " }")
		w.line("ct state established oifname vmap { " + strings.Join(ins, ", ") + " }")
	}
	w.line("ct state established,related accept")
	for _, r := range fwd {
		w.line(r.first())
	}
	w.line("goto " + logged(LogDrop))
	w.close()

	w.open("chain people")
	for _, r := range people {
		w.line(r.first())
	}
	w.line("drop")
	w.close()

	// A connection is recorded once, from its first packet: conntrack calls
	// every original-direction packet new until a reply comes, and another
	// host could send one from the host's address and port to add a record
	// of its own. The label is set, then read back, before the record is
	// added: a connection conntrack created while no loaded rule used
	// labels has no room for one, so setting it does nothing, and such a
	// connection (open across the first load of a ruleset with labels) is
	// never recorded; one whose record could not be written has none.
	//
	// Shared segments are never observed (NET-1, NET-3): what their chains
	// refuse is dropped without a log line or a count.
	for _, sg := range segments(l) {
		w.open("chain " + learn(sg.name))
		w.line("ct label " + hostLabel + " accept")
		for _, v6 := range []bool{false, true} {
			w.line("meta nfproto " + nfproto(v6) + " ct label set " + hostLabel + " ct label " + hostLabel + " add @" + HostSet(sg.name, v6) + " { " + hostKey(v6) + " }")
		}
		w.line("accept")
		w.close()

		// The record is refreshed by every packet it passes, for as long
		// as conntrack keeps the connection idle: a TCP connection both
		// ends answered for HostTCPTimeout (ct status reads the
		// connection's, also for a related packet), any other for the
		// set's HostTimeout.
		w.open("chain " + bound(sg.name))
		for _, v6 := range []bool{false, true} {
			k, set := hostKey(v6), HostSet(sg.name, v6)
			w.line("meta nfproto " + nfproto(v6) + " " + k + " @" + set + " ct protocol tcp ct status assured update @" + set + " { " + k + " timeout " + secs(HostTCPTimeout) + " } return")
			w.line("meta nfproto " + nfproto(v6) + " " + k + " @" + set + " update @" + set + " { " + k + " } return")
		}
		w.line("drop")
		w.close()

		// IPv4 passes only from a lease. An IPv6 address is held by the
		// hardware address it was first sent from: a packet from its
		// holder refreshes the hold, one from any other hardware address
		// is dropped, and a free address is taken by a leased hardware
		// address that holds none (its claim first, so a set with no room
		// leaves no hold without its claim).
		w.open("chain " + claim(sg.name))
		w.line("meta nfproto ipv4 " + leaseKey + " @" + LeaseSet(sg.name) + " return")
		pre := "meta nfproto ipv6 "
		cs, hs, ms := ClaimSet(sg.name), HeldSet(sg.name), MACSet(sg.name)
		w.line(pre + claimKey + " @" + cs + " update @" + cs + " { " + claimKey + " } update @" + hs + " { ip6 saddr } update @" + ms + " { " + hwField + " } goto " + neigh(sg.name))
		w.line(pre + "ip6 saddr @" + hs + " drop")
		w.line(pre + hwField + " != @" + LeasedSet(sg.name) + " drop")
		w.line(pre + hwField + " @" + ms + " drop")
		w.line(pre + "add @" + cs + " { " + claimKey + " } add @" + hs + " { ip6 saddr } add @" + ms + " { " + hwField + " } goto " + neigh(sg.name))
		w.line("drop")
		w.close()

		// An IPv6 packet claim passed keeps its hardware address's
		// neighbour hold of its source address, or takes the address's
		// hold when no other hardware address has one: in NeighSet for
		// ClaimTimeout, and in NeighTCPSet for HostTCPTimeout when it is
		// of a TCP connection both ends answered, each address before its
		// key, as claim does. A packet from an address another hardware
		// address holds in either pair passes on with no hold (#4702).
		// Every verdict here returns to the forward chain, as claim's
		// would.
		w.open("chain " + neigh(sg.name))
		ns, na, ts, ta := NeighSet(sg.name), NeighAddrSet(sg.name), NeighTCPSet(sg.name), NeighTCPAddrSet(sg.name)
		w.line("ip6 saddr @" + ta + " " + neighKey + " != @" + ts + " return")
		w.line("ip6 saddr @" + na + " " + neighKey + " != @" + ns + " return")
		w.line("ct protocol tcp ct status assured update @" + ta + " { ip6 saddr } update @" + ts + " { " + neighKey + " }")
		w.line("update @" + na + " { ip6 saddr } update @" + ns + " { " + neighKey + " }")
		w.close()

		// Neighbour discovery from the segment that names a link-layer
		// address sets the enforcer's entry for its subject (#4686): a
		// solicitation's or router solicitation's source, an
		// advertisement's target. Such a message passes only in the one
		// form whose link-layer address nft reads where the kernel does:
		// no extension header, and that option alone, first, of its
		// Ethernet length; then only when no other hardware address holds
		// its subject's neighbour entry (NeighSet, NeighTCPSet). One with
		// no option sets no address, and a solicitation from the
		// unspecified address none for its source; both pass on.
		w.open("chain " + nd(sg.name))
		w.line("ip6 nexthdr != ipv6-icmp drop")
		w.line("icmpv6 type { nd-neighbor-solicit, nd-router-solicit } ip6 saddr :: return")
		for _, m := range ndForms {
			w.line("icmpv6 type " + m.typ + " ip6 length " + strconv.Itoa(m.hdr) + " return")
			form := "icmpv6 type " + m.typ + " ip6 length " + strconv.Itoa(m.hdr+8) + " @th," + strconv.Itoa(8*m.hdr) + ",16 " + m.opt + " "
			key := m.subject + " . @th," + strconv.Itoa(8*m.hdr+16) + ",48"
			w.line(form + key + " @" + ts + " return")
			w.line(form + key + " @" + ns + " return")
			w.line(form + m.subject + " @" + ta + " drop")
			w.line(form + m.subject + " @" + na + " drop")
			w.line(form + "return")
			w.line("icmpv6 type " + m.typ + " drop")
		}
		w.close()
	}

	w.open("chain " + live("forward"))
	for _, r := range fwd {
		for _, s := range r.later() {
			w.line(s)
		}
	}
	w.line(related)
	w.line("drop")
	w.close()

	w.open("chain " + live("people"))
	for _, r := range people {
		for _, s := range r.later() {
			w.line(s)
		}
	}
	w.line("drop")
	w.close()

	// A device's counting chains: all its bytes are counted, and its
	// internet traffic by address, what it sends by destination and what it
	// receives by source. A peer at home (a box, a paired device, a person
	// on Owner or Household) is never recorded by address (NET-1).
	for _, v := range counted {
		for _, dir := range []string{"out", "in"} {
			c, addr, side := TrafficOut(v.vlan), "daddr", "oifname "
			if dir == "in" {
				c, addr, side = TrafficIn(v.vlan), "saddr", "iifname "
			}
			w.open("chain " + trafficChain(v.vlan, dir))
			w.line("counter name " + q(c))
			w.line(side + wan + " update @" + TrafficSet(v.vlan, false) + " { ip " + addr + " counter }")
			w.line(side + wan + " update @" + TrafficSet(v.vlan, true) + " { ip6 " + addr + " counter }")
			w.close()
		}
	}

	capChains(w, l)

	w.open("chain output")
	w.line("type filter hook output priority filter; policy accept;")
	w.line("oifname " + edge + " drop")
	for _, sg := range segments(l) {
		for _, r := range snoop(sg.name, q(sg.iface)) {
			w.line(r)
		}
	}
	w.close()

	w.open("chain postrouting")
	w.line("type nat hook postrouting priority srcnat; policy accept;")
	w.line("oifname " + wan + " masquerade")
	w.close()
	w.close()
	w.line("")

	// ARP on the edge's segment is answered only for the gateway (NET-2
	// Segments); the kernel would otherwise answer for any of its addresses.
	w.open("table arp " + ARPTable)
	w.open("chain input")
	w.line("type filter hook input priority filter; policy accept;")
	w.line("iifname " + edge + " arp operation request arp daddr ip != " + l.EdgeGateway.String() + " drop")
	w.close()
	w.close()
	w.line("")

	// ARP that reaches the enforcer on a shared segment sets its entry for
	// the sender's address to the sender's hardware address, request or
	// reply, asked for or not (#4686). It passes only from the hardware
	// address that holds a lease of that address, or for an address no
	// lease holds. An inet table never sees ARP and an arp table never sees
	// DHCP, and a table's chains read only its own sets, so this netdev
	// table keeps its own LeaseSet and LeaseAddrSet per segment: its egress
	// chain reads each ACK that leaves the segment's interface (the output
	// chain has already dropped one the inet sets hold for another host)
	// with snoop's own matches, and each load seeds and carries them as it
	// does the inet sets (Seed, Reload). An ARP header with Ethernet and
	// IPv4 addresses, the only one Linux takes on an Ethernet interface,
	// has the sender's hardware address at byte 8 and its address at byte
	// 14.
	w.open("table netdev " + NeighTable)
	for _, sg := range segments(l) {
		w.dynamic(LeaseSet(sg.name), leaseKey, LeaseTimeout)
		w.dynamic(LeaseAddrSet(sg.name), addrField, LeaseTimeout)
	}
	for _, sg := range segments(l) {
		w.open("chain " + arpIn(sg.name))
		w.line("type filter hook ingress device " + q(sg.iface) + " priority filter; policy accept;")
		w.line("meta protocol arp @nh,112,32 . @nh,64,48 @" + LeaseSet(sg.name) + " accept")
		w.line("meta protocol arp @nh,112,32 @" + LeaseAddrSet(sg.name) + " drop")
		w.close()
		w.open("chain " + ackOut(sg.name))
		w.line("type filter hook egress device " + q(sg.iface) + " priority filter; policy accept;")
		for _, b := range leaseBands() {
			w.line(ackMatch(b) + leaseUpdates(sg.name, b[0]))
		}
		w.close()
	}
	w.close()
	return w.b.String(), devs, nil
}

// loggedDecls declares each prefix's lines set and chain, and for each
// device its RefusedSet and the chain that counts its refusals, which the
// refused map reaches from the device's VLAN interface. A logged packet is
// counted first, on its prefix's counter and, refused from a device's
// VLAN, on the device's counter and its destination's, so all stay exact;
// the lines rule then logs it only while its interface's bucket holds a
// token, and the last rule gives the prefix's verdict whether or not it
// did. A failed map lookup, a full set or an empty bucket ends only its
// own rule.
func loggedDecls(w *writer, devs []device) {
	q := strconv.Quote
	var byDev []string
	for _, v := range devs {
		byDev = append(byDev, q(v.iface)+" : jump "+trafficChain(v.vlan, "refused"))
		for _, v6 := range []bool{false, true} {
			w.open("set " + RefusedSet(v.vlan, v6))
			w.line("type " + map[bool]string{false: "ipv4_addr", true: "ipv6_addr"}[v6] + ";")
			w.line("size " + strconv.Itoa(RefusedSize) + ";")
			w.line("flags dynamic,timeout;")
			w.line("timeout 1d;")
			w.close()
		}
		w.open("chain " + trafficChain(v.vlan, "refused"))
		w.line("counter name " + q(TrafficRefused(v.vlan)))
		w.line("update @" + RefusedSet(v.vlan, false) + " { ip daddr counter }")
		w.line("update @" + RefusedSet(v.vlan, true) + " { ip6 daddr counter }")
		w.close()
	}
	w.open("map refused")
	w.line("type ifname : verdict;")
	if len(byDev) > 0 {
		w.line("elements = { " + strings.Join(byDev, ", ") + " }")
	}
	w.close()
	limit := "limit rate " + strconv.Itoa(LineRate) + "/minute burst " + strconv.Itoa(LineBurst) + " packets"
	for _, r := range slices.Concat(refusals, accepts) {
		key, refusal := "iif", r.verdict == "drop"
		if !refusal {
			key = "oif"
		}
		w.open("set " + lines(r.prefix))
		w.line("typeof " + key + ";")
		w.line("size " + strconv.Itoa(LineSize) + ";")
		w.line("flags dynamic,timeout;")
		w.line("timeout " + secs(LineIdle) + ";")
		w.close()
		w.open("chain " + logged(r.prefix))
		w.line("counter name " + q(r.counter))
		if refusal {
			w.line("iifname vmap @refused")
		}
		w.line("update @" + lines(r.prefix) + " { " + key + " " + limit + " } counter name " + q(LogLines) + " log prefix " + q(r.prefix))
		w.line(r.verdict)
		w.close()
	}
}

func trafficChain(vlan int, dir string) string {
	return "t" + strconv.Itoa(vlan) + "_" + dir + "_count"
}

func port(p uint16) string { return strconv.Itoa(int(p)) }

type writer struct {
	b     strings.Builder
	depth int
}

func (w *writer) line(s string) {
	if s != "" {
		w.b.WriteString(strings.Repeat("\t", w.depth))
		w.b.WriteString(s)
	}
	w.b.WriteByte('\n')
}

func (w *writer) open(s string) { w.line(s + " {"); w.depth++ }
func (w *writer) close()        { w.depth--; w.line("}") }

func (w *writer) set(name, typ, flags string, elems []string) {
	w.open("set " + name)
	w.line("type " + typ + ";")
	if flags != "" {
		w.line("flags " + flags + ";")
	}
	if len(elems) > 0 {
		w.line("elements = { " + strings.Join(elems, ", ") + " }")
	}
	w.close()
}

// dynamic declares a set the ruleset's rules fill, of elements typed as key
// reads them, each lasting timeout seconds unless refreshed, HostSize at
// most.
func (w *writer) dynamic(name, key string, timeout int) {
	w.open("set " + name)
	w.line("typeof " + key + ";")
	w.line("size " + strconv.Itoa(HostSize) + ";")
	w.line("flags dynamic,timeout;")
	w.line("timeout " + secs(timeout) + ";")
	w.close()
}

package traffic

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/ghbmrk/agentos/broker/enforcer/nft"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

// BootFile holds the kernel's boot id, a random value the kernel draws
// once per boot.
const BootFile = "/proc/sys/kernel/random/boot_id"

// BootID is this boot's id, from BootFile.
func BootID() (string, error) {
	b, err := os.ReadFile(BootFile)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(b))
	if id == "" {
		return "", fmt.Errorf("traffic: %s is empty", BootFile)
	}
	return id, nil
}

// ReadingOf is one reading of the firewall's byte-cap counters
// (ASSUMPTIONS ENF-cap-1): listing is the running table as nft's JSON
// (load.Loader.List of nft.Table), d and l the policy and layout it was
// compiled from, and boot this boot's id (BootID).
//
// Gen names the ruleset load the counters started at: the table's handle,
// which the kernel gives each new table and never again within a boot,
// with the boot id, which no other boot has. So a load at boot never reuses
// a saved Gen, and a counter of a new load is never taken for a later value
// of an old one (ENF-cap-6). A drop update (load.Loader.Update) keeps the
// table, its counters and so its Gen.
//
// Listing is listing itself, which the counter keeps for the next drop
// update's Drop.Read (Counter.Drop).
func ReadingOf(d policy.Document, l nft.Layout, boot string, listing []byte) (Reading, error) {
	if boot == "" {
		return Reading{}, fmt.Errorf("%w: no boot id", ErrListing)
	}
	sets, err := nft.AllowSets(d, l)
	if err != nil {
		return Reading{}, err
	}
	var doc struct {
		Nftables []struct {
			Table *struct {
				Family, Name string
				Handle       *uint64
			} `json:"table"`
			Counter *struct {
				Family, Table, Name string
				Bytes               uint64
			} `json:"counter"`
			Set *struct {
				Family, Table, Name string
				Elem                []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.NewDecoder(bytes.NewReader(listing)).Decode(&doc); err != nil {
		return Reading{}, fmt.Errorf("%w: %v", ErrListing, err)
	}
	var handle *uint64
	edge := false
	r := Reading{Core: map[netip.Addr]uint64{}, Named: map[string][]netip.Addr{}, Listing: listing}
	elems := map[string][]json.RawMessage{}
	for _, o := range doc.Nftables {
		switch {
		case o.Table != nil && o.Table.Family == "inet" && o.Table.Name == nft.Table:
			handle = o.Table.Handle
		case o.Counter != nil && o.Counter.Family == "inet" && o.Counter.Table == nft.Table && o.Counter.Name == nft.EdgeOut:
			r.Edge, edge = o.Counter.Bytes, true
		case o.Set != nil && o.Set.Family == "inet" && o.Set.Table == nft.Table:
			elems[o.Set.Name] = o.Set.Elem
		}
	}
	core4, ok4 := elems[nft.CapSet(false)]
	core6, ok6 := elems[nft.CapSet(true)]
	if handle == nil || !edge || !ok4 || !ok6 {
		return Reading{}, fmt.Errorf("%w: no byte-cap counters", ErrListing)
	}
	h := sha256.Sum256([]byte(boot + "\x00" + strconv.FormatUint(*handle, 10)))
	r.Gen = binary.BigEndian.Uint64(h[:8])
	for _, raw := range append(core4, core6...) {
		a, n, ok := elem(raw)
		if !ok {
			return Reading{}, fmt.Errorf("%w: counting set element %s", ErrListing, raw)
		}
		r.Core[a] = sat(r.Core[a], n)
	}
	core := sets[0]
	for _, name := range core.Names {
		for _, v6 := range []bool{false, true} {
			for _, raw := range elems[core.Named(name, v6)] {
				if a, _, ok := elem(raw); ok {
					r.Named[name] = append(r.Named[name], a)
				}
			}
		}
	}
	return r, nil
}

// elem is one set element in nft's JSON: a bare address, or an address with
// its counter's bytes (and perhaps a timeout). ok is false for anything
// else, such as an interval.
func elem(raw json.RawMessage) (netip.Addr, uint64, bool) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		a, err := netip.ParseAddr(s)
		return a.Unmap(), 0, err == nil && a.Zone() == ""
	}
	var e struct {
		Elem *struct {
			Val     *string `json:"val"`
			Counter *struct {
				Bytes uint64 `json:"bytes"`
			} `json:"counter"`
		} `json:"elem"`
	}
	if json.Unmarshal(raw, &e) != nil || e.Elem == nil || e.Elem.Val == nil {
		return netip.Addr{}, 0, false
	}
	a, err := netip.ParseAddr(*e.Elem.Val)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, 0, false
	}
	var n uint64
	if e.Elem.Counter != nil {
		n = e.Elem.Counter.Bytes
	}
	return a.Unmap(), n, true
}

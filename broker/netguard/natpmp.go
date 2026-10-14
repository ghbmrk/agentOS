package netguard

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"time"
)

// natpmpPort is the NAT-PMP server port (RFC 6886). A PCP gateway answers
// opcode 0 through its NAT-PMP compatibility (RFC 6887 Appendix A).
const natpmpPort = 5351

// natpmpDeadline bounds the wait for the router's answer to one request.
const natpmpDeadline = 2 * time.Second

// ExternalAddr asks the learned gateway for the router's external address:
// the one NAT-PMP request the broker sends, opcode 0 only. It is not a
// connection under the DEV-2 rule. The box never sends a PCP MAP or PEER
// and uses no UPnP or SSDP.
func ExternalAddr(ctx context.Context, gateway netip.Addr) (netip.Addr, error) {
	return externalAddr(ctx, netip.AddrPortFrom(gateway, natpmpPort))
}

func externalAddr(ctx context.Context, gw netip.AddrPort) (netip.Addr, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", gw.String())
	if err != nil {
		return netip.Addr{}, err
	}
	defer c.Close()
	deadline := time.Now().Add(natpmpDeadline)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	c.SetDeadline(deadline)
	if _, err := c.Write([]byte{0, 0}); err != nil { // version 0, opcode 0
		return netip.Addr{}, err
	}
	buf := make([]byte, 16)
	n, err := c.Read(buf)
	if err != nil {
		return netip.Addr{}, err
	}
	if n != 12 || buf[0] != 0 || buf[1] != 128 {
		return netip.Addr{}, errors.New("netguard: not a NAT-PMP external address answer")
	}
	if rc := binary.BigEndian.Uint16(buf[2:4]); rc != 0 {
		return netip.Addr{}, errors.New("netguard: gateway refused the external address query")
	}
	return netip.AddrFrom4([4]byte(buf[8:12])), nil
}

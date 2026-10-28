package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The test network: the host end of a tap, in a network namespace of its own (the CI step runs
// the driver under `ip netns exec`), with a DHCP server that gives the node one address and a
// default route through the host. The namespace has no route anywhere else, so "the internet
// is cut" from the first boot, and anything the node sends towards it shows on the tap.
const (
	hostIP  = "10.77.0.1"
	guestIP = "10.77.0.10"
	tapName = "camtap0"
	port    = 8443
)

type lan struct {
	dnsmasq *exec.Cmd
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %v: %s", name, args, err, bytes.TrimSpace(out))
	}
	return nil
}

func setupLAN(work, mac string) (*lan, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("the end-to-end run needs root, in a network namespace of its own")
	}
	if out, err := exec.Command("ip", "route", "show", "default").Output(); err != nil || len(bytes.TrimSpace(out)) > 0 {
		return nil, errors.New("this namespace has a default route: run the driver under `ip netns exec` in a fresh namespace")
	}
	for _, a := range [][]string{
		{"link", "set", "lo", "up"},
		{"tuntap", "add", "dev", tapName, "mode", "tap"},
		{"addr", "add", hostIP + "/24", "dev", tapName},
		{"link", "set", tapName, "up"},
	} {
		if err := run("ip", a...); err != nil {
			return nil, err
		}
	}
	d := exec.Command("dnsmasq", "--keep-in-foreground", "--no-resolv", "--no-hosts", "--port=0",
		"--interface="+tapName, "--bind-interfaces", "--dhcp-authoritative",
		"--dhcp-range="+guestIP+","+guestIP+",255.255.255.0,1h",
		"--dhcp-host="+mac+","+guestIP, "--dhcp-option=option:router,"+hostIP,
		"--dhcp-leasefile="+filepath.Join(work, "leases"), "--log-dhcp", "--log-facility=-")
	d.Stdout, d.Stderr = os.Stderr, os.Stderr
	if err := d.Start(); err != nil {
		return nil, err
	}
	return &lan{dnsmasq: d}, nil
}

func (l *lan) close() {
	if l.dnsmasq != nil && l.dnsmasq.Process != nil {
		l.dnsmasq.Process.Kill()
		l.dnsmasq.Wait()
	}
	exec.Command("ip", "link", "del", tapName).Run()
}

// waitPort waits for the node's stream port to accept a TCP connection.
func waitPort(timeout time.Duration) error {
	end := time.Now().Add(timeout)
	for time.Now().Before(end) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", guestIP, port), 2*time.Second)
		if err == nil {
			c.Close()
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("port %d did not open within %v", port, timeout)
}

// scanTCP connects to every TCP port and returns those that accept.
func scanTCP() []int {
	var mu sync.Mutex
	var open []int
	ports := make(chan int)
	var wg sync.WaitGroup
	for range 512 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range ports {
				c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", guestIP, p), 1500*time.Millisecond)
				if err == nil {
					c.Close()
					mu.Lock()
					open = append(open, p)
					mu.Unlock()
				}
			}
		}()
	}
	for p := 1; p <= 65535; p++ {
		ports <- p
	}
	close(ports)
	wg.Wait()
	sort.Ints(open)
	return open
}

// scanUDP sends one datagram to every UDP port; the capture running beside it shows whether the
// node answered any, with a datagram or an ICMP error.
func scanUDP() error {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(hostIP)})
	if err != nil {
		return err
	}
	defer c.Close()
	for p := 1; p <= 65535; p++ {
		if _, err := c.WriteToUDP([]byte("camnode-e2e probe"), &net.UDPAddr{IP: net.ParseIP(guestIP), Port: p}); err != nil {
			return err
		}
		if p%1024 == 0 {
			time.Sleep(20 * time.Millisecond)
		}
	}
	return nil
}

// capture records every frame the node sends on the tap.
type capture struct {
	fd    int
	mac   net.HardwareAddr
	mu    sync.Mutex
	odd   []string // frames from the node that are not ARP, DHCP or the stream port's replies
	video int      // TCP segments from the stream port
	done  chan struct{}
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func startCapture(mac string) (*capture, error) {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return nil, err
	}
	ifc, err := net.InterfaceByName(tapName)
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return nil, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ALL), Ifindex: ifc.Index}); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	tv := syscall.Timeval{Usec: 200000}
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	c := &capture{fd: fd, mac: hw, done: make(chan struct{})}
	go c.loop()
	return c, nil
}

func (c *capture) loop() {
	buf := make([]byte, 65536)
	for {
		select {
		case <-c.done:
			return
		default:
		}
		n, _, err := syscall.Recvfrom(c.fd, buf, 0)
		if err != nil || n < 14 {
			continue
		}
		f := buf[:n]
		if !bytes.Equal(f[6:12], c.mac) {
			continue // not from the node
		}
		if why := c.classify(f); why != "" {
			c.mu.Lock()
			if len(c.odd) < 50 {
				c.odd = append(c.odd, why)
			}
			c.mu.Unlock()
		}
	}
}

// classify returns "" for a frame the node may send, or a description of one it may not: it
// may send ARP, DHCP requests (UDP 68 to 67), and TCP from the stream port; nothing else, no
// IPv6, no ICMP, no other TCP or UDP.
func (c *capture) classify(f []byte) string {
	et := binary.BigEndian.Uint16(f[12:14])
	switch et {
	case 0x0806:
		return ""
	case 0x0800:
	default:
		return fmt.Sprintf("ethertype %#04x", et)
	}
	ip := f[14:]
	if len(ip) < 20 {
		return "short IPv4"
	}
	ihl := int(ip[0]&0x0F) * 4
	if len(ip) < ihl+8 {
		return "short IPv4"
	}
	proto := ip[9]
	src, dst := net.IP(ip[12:16]), net.IP(ip[16:20])
	l4 := ip[ihl:]
	sp, dp := binary.BigEndian.Uint16(l4[0:2]), binary.BigEndian.Uint16(l4[2:4])
	switch {
	case proto == 17 && sp == 68 && dp == 67:
		return ""
	case proto == 6 && sp == port && src.Equal(net.ParseIP(guestIP)) && dst.Equal(net.ParseIP(hostIP)):
		c.mu.Lock()
		c.video++
		c.mu.Unlock()
		return ""
	}
	return fmt.Sprintf("IPv4 proto %d %s:%d -> %s:%d", proto, src, sp, dst, dp)
}

func (c *capture) stop() (odd []string, video int) {
	close(c.done)
	time.Sleep(300 * time.Millisecond)
	syscall.Close(c.fd)
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.odd...), c.video
}

func joinPorts(ps []int) string {
	var s []string
	for _, p := range ps {
		s = append(s, fmt.Sprint(p))
	}
	return strings.Join(s, ",")
}

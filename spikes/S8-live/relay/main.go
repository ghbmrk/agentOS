// In-machine stand-in for #1014's forwarder listener: 127.0.0.1:18432 -> the egress unix socket.
package main

import (
	"io"
	"net"
	"os"
)

func main() {
	l, err := net.Listen("tcp", "127.0.0.1:18432")
	if err != nil {
		os.Exit(1)
	}
	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			u, err := net.Dial("unix", os.Args[1])
			if err != nil {
				return
			}
			defer u.Close()
			go io.Copy(u, c)
			io.Copy(c, u)
		}(c)
	}
}

// Command guest is the agent-machine stand-in for gvisor's integration test.
//
//	guest serve      hold a random token in memory and serve requests
//	guest <cmd> ...  send one request to the server and print the answer
//
// Requests: token; write PATH TEXT; read PATH; remove PATH; stat PATH.
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
)

const sock = "/tmp/guest.sock"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		serve()
		return
	}
	c, err := net.Dial("unix", sock)
	if err != nil {
		fmt.Println("ERR", err)
		os.Exit(1)
	}
	fmt.Fprintln(c, strings.Join(os.Args[1:], " "))
	line, _ := bufio.NewReader(c).ReadString('\n')
	fmt.Print(line)
}

func serve() {
	var b [16]byte
	rand.Read(b[:])
	token := hex.EncodeToString(b[:]) // lives only in memory
	// Keep some heap busy so a checkpoint has pages to save.
	ballast := make([]byte, 32<<20)
	for i := range ballast {
		ballast[i] = byte(i)
	}
	os.Remove(sock)
	l, err := net.Listen("unix", sock)
	if err != nil {
		panic(err)
	}
	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		line, _ := bufio.NewReader(c).ReadString('\n')
		f := strings.SplitN(strings.TrimSpace(line), " ", 3)
		var out string
		switch f[0] {
		case "token":
			out = token + fmt.Sprint(ballast[len(ballast)-1]*0)
		case "write":
			if err := os.WriteFile(f[1], []byte(f[2]), 0o644); err != nil {
				out = "ERR " + err.Error()
			} else {
				out = "ok"
			}
		case "read":
			b, err := os.ReadFile(f[1])
			if err != nil {
				out = "ERR " + err.Error()
			} else {
				out = string(b)
			}
		case "remove":
			if err := os.RemoveAll(f[1]); err != nil {
				out = "ERR " + err.Error()
			} else {
				out = "ok"
			}
		case "stat":
			if _, err := os.Stat(f[1]); err != nil {
				out = "absent"
			} else {
				out = "present"
			}
		default:
			out = "ERR unknown"
		}
		fmt.Fprintln(c, out)
		c.Close()
	}
}

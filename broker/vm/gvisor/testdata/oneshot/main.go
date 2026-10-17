// Command oneshot is the program the RunOnce integration tests run in a
// one-shot sandbox. Its first argument picks what it tries.
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"
)

func main() {
	switch os.Args[1] {
	case "echo": // stdin to stdout
		io.Copy(os.Stdout, os.Stdin)
	case "net": // every interface, then a dial out
		ifs, _ := net.Interfaces()
		for _, i := range ifs {
			fmt.Println("iface", i.Name)
		}
		c, err := net.DialTimeout("tcp", os.Args[2], 2*time.Second)
		if err == nil {
			c.Close()
			fmt.Println("dialed")
			return
		}
		fmt.Println("dial failed")
	case "write": // a file anywhere it might land
		for _, p := range []string{"/x", "/tmp/x", "/proc/x", os.Args[0]} {
			if err := os.WriteFile(p, []byte("x"), 0o644); err == nil {
				fmt.Println("wrote", p)
			}
		}
		fmt.Println("done")
	case "alloc": // MiB of heap, each page touched
		n, _ := strconv.Atoi(os.Args[2])
		b := make([][]byte, n)
		for i := range b {
			b[i] = make([]byte, 1<<20)
			for j := 0; j < len(b[i]); j += 4096 {
				b[i][j] = 1
			}
		}
		fmt.Println("allocated", len(b))
	case "sleep":
		time.Sleep(time.Hour)
	}
}

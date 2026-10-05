// Command hog holds N MiB of touched memory and keeps rewriting it, standing
// in for a working guest (an OpenClaw machine, local inference, a browser).
//
//	hog MiB
package main

import (
	"os"
	"strconv"
	"time"
)

func main() {
	n, err := strconv.Atoi(os.Args[1])
	if err != nil || n <= 0 {
		os.Exit(2)
	}
	b := make([]byte, n<<20)
	for i := 0; ; i++ {
		for p := 0; p < len(b); p += 4096 {
			b[p] = byte(i + p)
		}
		time.Sleep(time.Second)
	}
}

// Command deafdriver reads one case and then ignores everything, signals
// included, so only a kill ends it (sandbox_real_test.go).
package main

import (
	"os"
	"os/signal"
	"time"
)

func main() {
	signal.Ignore()
	var b [5]byte
	os.Stdin.Read(b[:])
	for {
		time.Sleep(time.Hour)
	}
}

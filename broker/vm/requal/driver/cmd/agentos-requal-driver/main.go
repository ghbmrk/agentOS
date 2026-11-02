// Command agentos-requal-driver is the requalification sandbox's in-image
// case driver (package driver, UPD-5r-b2). This release has no suite
// evaluator yet, so every case is a case error and requalification holds
// (UPD-5r-b2-5).
package main

import (
	"fmt"
	"os"

	"github.com/ghbmrk/agentos/broker/vm/requal/driver"
)

func main() {
	if err := driver.Serve(os.Stdin, os.Stdout, driver.Refuse); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

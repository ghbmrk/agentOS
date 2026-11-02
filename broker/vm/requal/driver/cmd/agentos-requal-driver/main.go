// Command agentos-requal-driver is the requalification sandbox's in-image
// case driver (package driver, UPD-5r-b2). It runs each case through the
// security evaluator (UPD-5r-b7); a case of another suite does not decode as
// a security input and is a case error, so those suites hold until their
// evaluators land (UPD-5r-b7-4).
package main

import (
	"fmt"
	"os"

	"github.com/ghbmrk/agentos/broker/vm/requal/driver"
)

func main() {
	if err := driver.Serve(os.Stdin, os.Stdout, driver.Security); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

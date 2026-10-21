// Command slice runs the inbox slice once: Input as JSON on stdin, Outcome as
// JSON on stdout. The eval adapter drives it; nothing else does.
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	var in Input
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		fmt.Fprintln(os.Stderr, "slice:", err)
		os.Exit(2)
	}
	out, err := Run(in)
	if err != nil {
		fmt.Fprintln(os.Stderr, "slice:", err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "slice:", err)
		os.Exit(1)
	}
}

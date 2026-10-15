//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "box-e2e runs only in the booted Linux image")
	os.Exit(2)
}

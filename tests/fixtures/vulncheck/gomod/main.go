// Command vulnfix is the planted target of tools/vulncheck.py control: it calls the
// symbol the synthetic database marks vulnerable in example.com/dep, and imports
// example.com/quiet without calling its vulnerable symbol.
package main

import (
	"fmt"

	"example.com/dep"
	"example.com/quiet"
)

func main() {
	dep.Bad()
	quiet.Safe()
	fmt.Println("vulnfix")
}

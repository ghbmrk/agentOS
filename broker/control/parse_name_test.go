package control

import "testing"

// REQ: CH-21
func TestCH21ParseNAME(t *testing.T) {
	if c := Parse("NAME"); c.Word != WordName || len(c.Args) != 0 {
		t.Fatalf("NAME alone: %+v", c)
	}
	if c := Parse("name Dave Smith"); c.Word != WordName || len(c.Args) != 2 || c.Args[0] != "DAVE" || c.Args[1] != "SMITH" {
		t.Fatalf("NAME Dave Smith: %+v", c)
	}
	if c := Parse("NAME please"); c.Word != WordName {
		t.Fatalf("NAME please: %+v", c)
	}
}

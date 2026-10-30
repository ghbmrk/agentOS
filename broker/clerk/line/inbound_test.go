package line

import "testing"

// REQ: CLK-8, CH-1
// A provider-vouched E.164 sender is the owner only when it is the owner's
// number exactly: a foreign number whose digits end with the owner's, or
// that the owner's digits end with, is an untrusted item like any other
// text (#3882, L3 6503790799). The national form still matches, but only
// with no country code in it.
func TestForeignNumberEndingInOwnersDigitsIsAnItem(t *testing.T) {
	r := newRig(t, true)
	for i, from := range []string{"+5550000001", "+715550000001", "+4415550000001", "15550000001", "0015550000001", "+15550000002"} {
		it, reply := r.c.Inbound(Text{From: from, Words: "approve 1234", At: t0 + int64(i)})
		if it == nil || reply != nil || it.Sender != from || it.Label != Label {
			t.Fatalf("%s: item %+v reply %+v", from, it, reply)
		}
	}
	for i, from := range []string{ownerNum, "5550000001", "05550000001", "555-000-0001"} {
		it, reply := r.c.Inbound(Text{From: from, Words: "hi", At: t0 + int64(i+1)*2*mainEvery})
		if it != nil || reply == nil || reply.To != ownerNum {
			t.Fatalf("%s: item %+v reply %+v", from, it, reply)
		}
	}
}

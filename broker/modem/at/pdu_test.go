package at

import (
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/modem"
)

// REQ: HW-2, CH-1, CH-12

// Published vectors (the "hellohello" pair from the GSM 03.40 tutorials)
// pin the codec against an outside reference, so the simulator, which
// decodes with the same code, cannot hide a symmetric bug.
func TestSubmitMatchesPublishedVector(t *testing.T) {
	got, err := EncodeSubmit("+46708251358", "hellohello", 0)
	if err != nil {
		t.Fatal(err)
	}
	want := "0001000B916407281553F800000AE8329BFD4697D9EC37"
	if len(got) != 1 || got[0].Hex != want || got[0].Len != len(want)/2-1 {
		t.Fatalf("got %+v, want %s", got, want)
	}
}

func TestDeliverMatchesPublishedVector(t *testing.T) {
	d, err := DecodeDeliver("07917283010010F5040BC87238880900F10000993092516195800AE8329BFD4697D9EC37")
	if err != nil {
		t.Fatal(err)
	}
	if d.Addr != "27838890001" || d.Text != "hellohello" || d.Concat != nil {
		t.Fatalf("got %+v", d)
	}
}

func TestRoundTripsEveryAlphabetAndSplitsLikeTheSegmentBudget(t *testing.T) {
	cases := []string{
		"STOP",
		"Running. 2 tasks; next digest 08:00 {ok} [x] ~ ^ | \\ €",
		strings.Repeat("a", 160),
		strings.Repeat("a", 161),
		strings.Repeat("€", 80) + "a", // escapes never split across parts
		"Grüße — 日本語 ok",
		strings.Repeat("ж", 70),
		strings.Repeat("ж", 71),
		strings.Repeat("😀", 40), // surrogate pairs never split
		strings.Repeat("YES K3 482913 ", 30),
	}
	for _, text := range cases {
		subs, err := EncodeSubmit("+15550000001", text, 7)
		if err != nil {
			t.Fatalf("%q: %v", text, err)
		}
		if n, _ := modem.Segments(text); n != len(subs) {
			t.Errorf("%q: %d parts, modem.Segments says %d", text, len(subs), n)
		}
		var sub, del strings.Builder
		dels, err := EncodeDeliver("+15550000001", text, 7)
		if err != nil {
			t.Fatal(err)
		}
		for i, s := range subs {
			if len(s.Hex)/2-1 != s.Len || s.Len > 164 {
				t.Fatalf("%q part %d: len %d for %d octets", text, i, s.Len, len(s.Hex)/2)
			}
			d, err := DecodeSubmit(s.Hex)
			if err != nil {
				t.Fatalf("%q part %d: %v", text, i, err)
			}
			if d.Addr != "+15550000001" {
				t.Fatalf("addr %q", d.Addr)
			}
			if len(subs) > 1 && (d.Concat == nil || d.Concat.Ref != 7 || d.Concat.Total != len(subs) || d.Concat.Seq != i+1) {
				t.Fatalf("%q part %d: concat %+v", text, i, d.Concat)
			}
			sub.WriteString(d.Text)
			dd, err := DecodeDeliver(dels[i])
			if err != nil {
				t.Fatal(err)
			}
			del.WriteString(dd.Text)
		}
		if sub.String() != text || del.String() != text {
			t.Errorf("round trip:\n got %q\n and %q\nwant %q", sub.String(), del.String(), text)
		}
	}
}

func TestDecodesAlphanumericSendersAndSixteenBitReferences(t *testing.T) {
	// Sender "Bank" (type 0xD0, 4 septets in 7 nibbles), UDH with a 16-bit
	// reference 0x1234, part 2 of 3, GSM-7 "hi".
	pdu := "00" + "44" + "07D0" + "C2B07B0D" + "00" + "00" + "62014021000000" + "0A" + "06080412340302E834"
	d, err := DecodeDeliver(pdu)
	if err != nil {
		t.Fatal(err)
	}
	if d.Addr != "Bank" || d.Concat == nil || *d.Concat != (Concat{Ref: 0x1234, Total: 3, Seq: 2}) {
		t.Fatalf("got %+v %+v", d, d.Concat)
	}
	if d.Text != "hi" {
		t.Fatalf("text %q", d.Text)
	}
}

func TestRejectsMalformedAndNonTextPDUs(t *testing.T) {
	bad := []string{
		"",
		"zz",
		"00",
		"0004",                       // truncated address
		"00040B915155000000F1000462", // 8-bit data, truncated
		"00040B915155000000F10004620140210000000101", // 8-bit data
		"00040B915155000000F10000620140210000009F00", // UDL beyond data
		"00010B915155000000F1000000",                 // a SUBMIT where a DELIVER belongs
	}
	for _, h := range bad {
		if _, err := DecodeDeliver(h); err == nil {
			t.Errorf("%q decoded", h)
		}
	}
}

func FuzzDecodeDeliver(f *testing.F) {
	f.Add("07917283010010F5040BC87238880900F10000993092516195800AE8329BFD4697D9EC37")
	f.Add("00" + "44" + "07D0" + "C2B07B0D" + "00" + "00" + "62014021000000" + "0A" + "06080412340302E834")
	f.Fuzz(func(t *testing.T, h string) {
		_, _ = DecodeDeliver(h) // must not panic
	})
}

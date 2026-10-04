package modem

import (
	"strings"
	"testing"
	"time"
)

// REQ: CH-1, CH-12

func TestCarrierDeliversTextsBetweenLinesWithSenderNumber(t *testing.T) {
	c := NewCarrier()
	box := c.Line("+15550000100")
	phone := c.Line("+15550000001")
	if err := phone.Send("+15550000100", "status"); err != nil {
		t.Fatal(err)
	}
	got := recv(t, box)
	if got.From != "+15550000001" || got.To != "+15550000100" || got.Text != "status" || got.Spoofed {
		t.Fatalf("got %+v", got)
	}
	if err := box.Send("+15550000001", "Running."); err != nil {
		t.Fatal(err)
	}
	if got := recv(t, phone); got.Text != "Running." || got.From != "+15550000100" {
		t.Fatalf("got %+v", got)
	}
	if n := len(c.Log()); n != 2 {
		t.Fatalf("log has %d texts, want 2", n)
	}
}

func TestInjectForgesASenderAndMarksItForTheTestOnly(t *testing.T) {
	c := NewCarrier()
	box := c.Line("+15550000100")
	c.Inject("+15550000001", "+15550000100", "STOP")
	got := recv(t, box)
	if got.From != "+15550000001" || !got.Spoofed {
		t.Fatalf("got %+v", got)
	}
}

func TestDownLineRefusesToSend(t *testing.T) {
	c := NewCarrier()
	box := c.Line("+15550000100")
	box.SetDown(true)
	if err := box.Send("+15550000001", "x"); err == nil {
		t.Fatal("a down modem sent a text")
	}
}

func TestSegmentsFollowGSM7AndUCS2Rules(t *testing.T) {
	cases := []struct {
		text string
		want int
		gsm  bool
	}{
		{"", 1, true},
		{strings.Repeat("a", 160), 1, true},
		{strings.Repeat("a", 161), 2, true},
		{strings.Repeat("a", 306), 2, true},
		{strings.Repeat("a", 307), 3, true},
		{strings.Repeat("{", 80), 1, true}, // extension characters cost two septets
		{strings.Repeat("{", 81), 2, true},
		{"ok \U0001F44D", 1, false}, // one emoji forces UCS-2
		{strings.Repeat("a", 70) + "é", 1, true},
		{strings.Repeat("a", 70) + "ą", 2, false},
	}
	for _, c := range cases {
		n, gsm := Segments(c.text)
		if n != c.want || gsm != c.gsm {
			t.Errorf("Segments(%q...) = %d,%v want %d,%v", trunc(c.text), n, gsm, c.want, c.gsm)
		}
	}
}

func TestLogRecordsSegments(t *testing.T) {
	c := NewCarrier()
	c.Line("+15550000100")
	a := c.Line("+15550000001")
	_ = a.Send("+15550000100", strings.Repeat("x", 200))
	if l := c.Log(); l[0].Segments != 2 {
		t.Fatalf("segments %d", l[0].Segments)
	}
}

func recv(t *testing.T, l *Line) SMS {
	t.Helper()
	select {
	case m := <-l.Inbox():
		return m
	case <-time.After(2 * time.Second):
		t.Fatal("no text arrived")
	}
	return SMS{}
}

func trunc(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

package at

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modem"
)

// REQ: HW-2, CH-1, CH-5, CH-17

// script answers each command line the engine writes with the next canned
// reply. A reply may hold URCs mixed in among the response lines.
func script(t *testing.T, replies map[string]string) (*Engine, net.Conn) {
	t.Helper()
	host, dev := net.Pipe()
	go func() {
		br := bufio.NewReader(dev)
		for {
			l, err := br.ReadString('\r')
			if err != nil {
				return
			}
			cmd := strings.TrimSpace(l)
			if strings.HasPrefix(cmd, "AT+CMGS") {
				_, _ = dev.Write([]byte(cmd + "\r\r\n> "))
				pdu, _ := br.ReadString(0x1A)
				_, _ = dev.Write([]byte("\r\n+CMGS: " + pdu[:2] + "\r\n\r\nOK\r\n"))
				continue
			}
			if r, ok := replies[cmd]; ok {
				_, _ = dev.Write([]byte(r))
			}
		}
	}()
	e := NewEngine(host, []string{"+QTONEDET:"})
	t.Cleanup(func() { _ = e.Close() })
	return e, dev
}

func TestEngineSeparatesResponsesFromURCs(t *testing.T) {
	e, _ := script(t, map[string]string{
		// Echo, a +CMTI and a RING in the middle of a +CLCC response, and a
		// PDU line after +CMGR.
		"AT+CLCC":     "AT+CLCC\r\r\n+CLCC: 1,1,4,0,0,\"+15550000001\",145\r\n+CMTI: \"ME\",3\r\nRING\r\n\r\nOK\r\n",
		"AT+CMGR=3":   "\r\n+CMGR: 0,,23\r\n07917283010010F5040BC87238880900F10000993092516195800AE8329BFD4697D9EC37\r\n+QTONEDET: 49\r\nOK\r\n",
		"AT+CMGD=9":   "\r\n+CMS ERROR: 321\r\n",
		"ATD5551234;": "\r\nNO CARRIER\r\n",
	})
	ctx := context.Background()
	lines, err := e.Do(ctx, "AT+CLCC", time.Second)
	if err != nil || len(lines) != 1 || !strings.HasPrefix(lines[0], "+CLCC: 1,1,4") {
		t.Fatalf("CLCC: %q %v", lines, err)
	}
	lines, err = e.Do(ctx, "AT+CMGR=3", time.Second)
	if err != nil || len(lines) != 2 || !strings.HasPrefix(lines[1], "0791") {
		t.Fatalf("CMGR: %q %v", lines, err)
	}
	var urcs []string
	for len(urcs) < 3 {
		select {
		case u := <-e.URCs():
			urcs = append(urcs, u)
		case <-time.After(time.Second):
			t.Fatalf("URCs %q", urcs)
		}
	}
	if strings.Join(urcs, "|") != `+CMTI: "ME",3|RING|+QTONEDET: 49` {
		t.Fatalf("URCs %q", urcs)
	}
	var ae *Error
	if _, err := e.Do(ctx, "AT+CMGD=9", time.Second); !errors.As(err, &ae) || ae.Result != "+CMS ERROR: 321" {
		t.Fatalf("CMGD: %v", err)
	}
	if _, err := e.Do(ctx, "ATD5551234;", time.Second); !errors.As(err, &ae) || ae.Result != "NO CARRIER" {
		t.Fatalf("ATD: %v", err)
	}
}

func TestEngineSendsPromptPayloadsAndResyncsAfterATimeout(t *testing.T) {
	e, dev := script(t, map[string]string{"AT": "\r\nOK\r\n", "AT+CSQ": "\r\n+CSQ: 20,99\r\nOK\r\n"})
	ctx := context.Background()
	lines, err := e.DoPrompt(ctx, "AT+CMGS=22", "0001000B916407281553F800000AE8329BFD4697D9EC37", time.Second)
	if err != nil || len(lines) != 1 || lines[0] != "+CMGS: 00" {
		t.Fatalf("CMGS: %q %v", lines, err)
	}
	// A command the modem never answers times out; its late OK must not be
	// taken as the answer to the next command.
	if _, err := e.Do(ctx, "AT+SLOW", 20*time.Millisecond); err != ErrTimeout {
		t.Fatalf("slow: %v", err)
	}
	_, _ = dev.Write([]byte("\r\nOK\r\n"))
	lines, err = e.Do(ctx, "AT+CSQ", time.Second)
	if err != nil || len(lines) != 1 || lines[0] != "+CSQ: 20,99" {
		t.Fatalf("after resync: %q %v", lines, err)
	}
	_ = dev.Close()
	<-e.Done()
	if _, err := e.Do(ctx, "AT", time.Second); !errors.Is(err, modem.ErrDown) {
		t.Fatalf("after close: %v", err)
	}
}

func TestParsersReadQuotedFieldsAndVoiceCallsOnly(t *testing.T) {
	got := parseCLCC([]string{
		`+CLCC: 1,0,0,0,0,"+15550000777",145`,
		`+CLCC: 2,1,5,0,0,"+15550000001",145`, // waiting: parsed, ignored by reconcile
		`+CLCC: 3,0,0,1,0,"",129`,             // data call
		`+CLCC: x`,
	})
	if len(got) != 2 || got[0] != (clcc{id: 1, stat: 0, number: "+15550000777"}) || got[1].stat != 5 || !got[1].incoming {
		t.Fatalf("%+v", got)
	}
	if f := fields(` "usbcfg",0x2C7C,"a,b",3`); strings.Join(f, "|") != "usbcfg|0x2C7C|a,b|3" {
		t.Fatalf("%q", f)
	}
}

func TestEngineDiscardsOverlongLines(t *testing.T) {
	e, _ := script(t, map[string]string{"AT+CSQ": "\r\n" + strings.Repeat("A", 10000) + "\r\n+CSQ: 20,99\r\nOK\r\n"})
	lines, err := e.Do(context.Background(), "AT+CSQ", time.Second)
	if err != nil || len(lines) != 1 || lines[0] != "+CSQ: 20,99" {
		t.Fatalf("%d lines %v", len(lines), err)
	}
}

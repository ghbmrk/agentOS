// Command agentos-modem is the modem bridge (P2-3w; CH-1, CH-2, ADP-12).
// It runs as its own user, agentos-modem, which alone may open the
// modems' serial and sound nodes (modem/at/udev/71-agentos-modem.rules),
// and carries texts between the owner line's modem and agentosd's owner
// socket, which admits only this uid. It parses hostile input (any
// sender's PDUs), so it holds no secret and decides nothing: agentosd
// addresses every text and stamps every arrival (bridgeproto).
//
// The owner line's SIM serial recorded at setup is read from -roles at
// each open, so a SIM the owner confirms on the local page is taken
// without a restart. Part 1 serves the owner line only; the second line
// (ADP-12) is part 2.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/ghbmrk/agentos/broker/bridgeclient"
	"github.com/ghbmrk/agentos/broker/modem/at"
	"github.com/ghbmrk/agentos/broker/modem/bridge"
)

func main() {
	var ownerSock, roles, boxNumber, ownerNumber, countryCode, sysRoot string
	flag.StringVar(&ownerSock, "owner-sock", "/run/agentosd/owner.sock", "agentosd's owner socket")
	flag.StringVar(&roles, "roles", "/var/lib/agentos/modem-roles.json", "the lines' SIM serials recorded at setup")
	flag.StringVar(&boxNumber, "box-number", "", "the owner line's own number, E.164 (AT+CNUM is tried when empty)")
	flag.StringVar(&ownerNumber, "owner-number", "", "the owner's number, E.164")
	flag.StringVar(&countryCode, "country-code", "", "the home country code, as in 1 or 44")
	flag.StringVar(&sysRoot, "sys-root", "/", "root of sysfs and procfs, for finding the modem")
	flag.Parse()
	if ownerNumber == "" || countryCode == "" {
		log.Fatal("-owner-number and -country-code are required")
	}
	log.SetFlags(0)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := bridge.Run(ctx, bridge.Config{
		Agentosd: bridgeclient.Client{Path: ownerSock},
		OpenOwner: func(ctx context.Context) (bridge.Owner, error) {
			found := at.Discover(sysRoot)
			if len(found) == 0 || found[0].ATPort == "" {
				return nil, errors.New("no qualified modem found")
			}
			f := found[0]
			port, err := at.OpenSerial(f.ATPort)
			if err != nil {
				return nil, err
			}
			m, err := at.Open(ctx, at.Config{Profile: f.Profile, Port: port, Number: boxNumber, CountryCode: countryCode, Owner: ownerNumber})
			if err != nil {
				port.Close()
				return nil, err
			}
			return m, nil
		},
		OwnerICCID: func() string { return ownerICCID(roles) },
		Logf:       log.Printf,
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}

// ownerICCID reads the owner line's recorded SIM serial; "" when there is
// none, which reads as unbound.
func ownerICCID(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var r struct {
		OwnerICCID string `json:"owner_iccid"`
	}
	if json.Unmarshal(b, &r) != nil {
		return ""
	}
	return r.OwnerICCID
}

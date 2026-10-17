package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"

	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/recovery"
)

var (
	// errNoCommittedWiFi is a vault with no Owner Card: setup has not
	// provisioned one, so there is no committed network.
	errNoCommittedWiFi = errors.New("I keep no Owner Card, so no Wi-Fi network is committed")
	// errWiFiOwed is a rotation that stopped part way with its Wi-Fi part
	// owed: the stored network may not be the one in effect (#1523).
	errWiFiOwed = errors.New("an unfinished card rotation owes the Wi-Fi network")
)

// committedWiFi reads the Owner Card's committed Wi-Fi network from the
// open vault, for agentosd to put back in ap-net.json at start and after
// unlock (#1696). It reads only: the one-shot permit (#1522) is left as
// it is.
func (c *custody) committedWiFi() (ssid, password string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph != open {
		return "", "", errLocked
	}
	b := &recovery.Box{V: c.v}
	card, err := b.LoadCard()
	if err != nil {
		return "", "", errNoCommittedWiFi
	}
	// A part-way commit holds the new network for agentosd but stores the
	// old: neither is certain, so nothing is answered.
	if owed, ok := recovery.RotationUnfinished(b); ok && slices.Contains(owed, recovery.PartWiFi) {
		return "", "", errWiFiOwed
	}
	return card.WiFiName, card.WiFiPassword, nil
}

// committedWiFiHandler answers GET /committed-wifi on the verify socket.
func committedWiFiHandler(c *custody, w http.ResponseWriter) {
	ssid, password, err := c.committedWiFi()
	switch {
	case err == errLocked:
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	case err == errNoCommittedWiFi:
		http.Error(w, err.Error(), http.StatusNotFound)
	case err == errWiFiOwed:
		http.Error(w, err.Error(), http.StatusConflict)
	case err != nil:
		http.Error(w, errInternal.Error(), http.StatusInternalServerError)
	default:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(modelroute.RotatedWiFi{SSID: ssid, Password: password})
	}
}

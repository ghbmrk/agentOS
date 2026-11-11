package main

import (
	"encoding/json"
	"errors"
	"sync"

	"github.com/ghbmrk/agentos/broker/enforcer/alert"
	"github.com/ghbmrk/agentos/broker/enforcer/channel"
)

// coreDevice is the name the enforcer's alerts give the core box.
const coreDevice = "core"

// cut is the core trip at the enforcer as far as this slice builds it
// (ASSUMPTIONS ENF-l-5): the channel's Cut and the page's Channel. A
// frame outside the format or a burst past a rate trips it; it survives a
// restart; only the page lifts it, after the owner's passkey (NET-4,
// KRN-12 Response). DECOY-d adds the firewall's cut, the "core reflashed"
// step and the head store's trip on top of it.
type cut struct {
	store  fileStore
	alerts *alert.Alerts
	logf   func(string)

	mu     sync.Mutex
	stage  channel.Stage
	reason string
	// unsaved: a trip decided here whose cut.json write failed. Persist
	// retries it each tick and at Close, and the channel listener takes
	// no connection meanwhile (#4755 item 1).
	unsaved bool
}

type cutState struct {
	Tripped bool   `json:"tripped"`
	Reason  string `json:"reason,omitempty"`
}

func openCut(store fileStore, alerts *alert.Alerts, logf func(string)) (*cut, error) {
	c := &cut{store: store, alerts: alerts, logf: logf}
	b, err := store.Load()
	if err != nil {
		return nil, err
	}
	if b == nil {
		// Provisioning wrote it (provisionState) and nothing removes it,
		// so its loss means root on the enforcer or lost state (#5399).
		c.stage, c.reason = channel.Tripped, "the record of the core's cut is missing. Someone may have tampered with the enforcer: check it before you resume the core's channel."
		logf("cut: " + fileCut + " missing, the core stays cut until you resume it on the page")
		recordMissing(alerts, coreDevice, logf)
		return c, nil
	}
	var st cutState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, errors.New("cut: state unreadable")
	}
	if st.Tripped {
		c.stage, c.reason = channel.Tripped, st.Reason
	}
	return c, nil
}

// Stage is the channel's question before every request. It takes only
// the cut's own lock and never calls the channel.
func (c *cut) Stage() channel.Stage {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stage
}

// Trip cuts the core. A core already cut costs nothing more: no write, no
// alert (#4606). The stage is in force before the write, so a failed
// write still leaves the core cut; the trip is then unsaved, and Persist
// retries the write until it lands (KRN-12 Response, #4755 item 1).
func (c *cut) Trip(reason string) {
	c.mu.Lock()
	if c.stage == channel.Tripped {
		c.mu.Unlock()
		return
	}
	c.stage, c.reason = channel.Tripped, reason
	err := c.saveLocked()
	c.mu.Unlock()
	if err != nil {
		c.logf("cut: trip not saved, retried each tick; the channel takes no connection until it is: " + err.Error())
	}
	if _, err := c.alerts.Raise(alert.Trip, coreDevice); err != nil {
		c.logf("cut: trip alert: " + err.Error())
	}
	c.alerts.Paused()
}

// saveLocked writes the stage in force; c.mu is held. A failure marks the
// state unsaved.
func (c *cut) saveLocked() error {
	b, _ := json.Marshal(cutState{Tripped: c.stage == channel.Tripped, Reason: c.reason})
	err := c.store.Save(b)
	c.unsaved = err != nil
	return err
}

// Persist retries an unsaved trip's write. The run loop calls it each
// tick and Close once more, so a trip outlives a disk that failed for a
// while; only a power loss before any write lands loses it (ASSUMPTIONS
// ENF-l-5).
func (c *cut) Persist() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.unsaved {
		return nil
	}
	if err := c.saveLocked(); err != nil {
		return err
	}
	c.logf("cut: trip saved")
	return nil
}

// Unsaved reports whether a trip decided here is not yet on disk.
func (c *cut) Unsaved() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.unsaved
}

// Paused is the page's view of the channel: paused while the core is
// cut.
func (c *cut) Paused() bool { return c.Stage() != channel.Open }

// Resume lifts the cut. The page calls it only after the owner's passkey
// assertion on the page's own resume challenge (page ActResume); nothing
// on the channel reaches it.
func (c *cut) Resume() error {
	c.mu.Lock()
	if c.stage == channel.Open {
		c.mu.Unlock()
		return nil
	}
	b, _ := json.Marshal(cutState{})
	if err := c.store.Save(b); err != nil {
		c.mu.Unlock()
		return err // still cut: a lift that is not saved does not happen
	}
	c.stage, c.reason, c.unsaved = channel.Open, "", false
	c.mu.Unlock()
	return errors.Join(c.alerts.Resumed(), c.alerts.Lifted(coreDevice))
}

// recordMissing raises the alert for a box whose cut record is missing or
// does not read back (#5399): the light turns red, and the owner's lift
// or resume resolves it (alert.Lifted).
func recordMissing(alerts *alert.Alerts, device string, logf func(string)) {
	if _, err := alerts.Raise(alert.RecordMissing, device); err != nil {
		logf("cut: missing record alert: " + err.Error())
	}
}

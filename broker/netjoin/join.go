package netjoin

import (
	"context"
	"errors"
	"regexp"
	"sync"
	"time"
)

// NM is the helper's whole reach into NetworkManager (L8.4). Each method is
// one D-Bus call or property read; the seam has no way to list, read back,
// delete or activate a connection, or to touch a device.
type NM interface {
	// GetConnectionByUuid is Settings.GetConnectionByUuid. It returns
	// ErrNoConnection when NetworkManager has no such connection.
	GetConnectionByUuid(ctx context.Context, uuid string) (path string, err error)
	// AddConnection2 is Settings.AddConnection2, saved to disk.
	AddConnection2(ctx context.Context, s Settings) (path string, err error)
	// Update2 is Settings.Connection.Update2 on path, saved to disk.
	Update2(ctx context.Context, path string, s Settings) error
	// ActiveConnections reads NetworkManager's ActiveConnections property.
	ActiveConnections(ctx context.Context) ([]string, error)
	// ActiveUUID reads an active connection's Uuid property.
	ActiveUUID(ctx context.Context, path string) (string, error)
	// ActiveState reads an active connection's State property.
	ActiveState(ctx context.Context, path string) (uint32, error)
}

// ErrNoConnection is GetConnectionByUuid's answer for no such connection.
var ErrNoConnection = errors.New("netjoin: no connection with that uuid")

// NetworkManager's active connection states (NMActiveConnectionState).
const (
	StateActivated   uint32 = 2
	StateDeactivated uint32 = 4
)

// poll is how often the helper reads the active connections while it
// waits.
const poll = 500 * time.Millisecond

// Joiner writes the home connection and watches for it to come up. It
// runs one join at a time.
type Joiner struct {
	nm NM
	// station is the one interface the home connection may use; ap the
	// interfaces agentos-ap may run the access point on (S-R4).
	station string
	ap      []string

	wait  time.Duration
	every time.Duration
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error

	mu sync.Mutex
}

// NewJoiner returns a Joiner over nm with the fixed Wait. station is the
// one interface the home connection may use (#936's station device) and
// ap every interface agentos-ap may run the access point on (its -iface),
// which are the only ones agentos_ap can hold. Join refuses unless station
// is a plain interface name outside ap (StationOK).
func NewJoiner(nm NM, station string, ap []string) *Joiner {
	return &Joiner{nm: nm, station: station, ap: append([]string(nil), ap...),
		wait: Wait, every: poll, now: time.Now, sleep: sleep}
}

// ifaceRe is a kernel interface name, as localui's access point config
// takes it.
var ifaceRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)

func ifaceName(s string) bool {
	return ifaceRe.MatchString(s) && s != "." && s != ".."
}

// StationOK reports whether the home connection may be written for
// station (S-R4, #1428): a plain interface name, not lo, with at least one
// access point interface known, every one of them a plain name and none
// equal to station. agentosd -> netjoin -> NetworkManager does not pass
// through localui.APLoader.Station, so this refusal, and the connection's
// interface-name, keep the join off the interface agentos_ap holds.
func StationOK(station string, ap []string) bool {
	if !ifaceName(station) || station == "lo" || len(ap) == 0 {
		return false
	}
	for _, a := range ap {
		if !ifaceName(a) || a == station {
			return false
		}
	}
	return true
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Join is the helper's one op. A request that fails Valid is refused
// before any D-Bus call; a second join while one runs is busy. Otherwise
// it writes the connection (created the first time, updated on its own
// path after that) and reports what autoconnect did within the wait. It
// takes nothing down and activates nothing: NetworkManager autoconnects
// the connection on the station interface, the only one it names. With no
// usable station (StationOK), a valid request answers failed before any
// D-Bus call: setup then says to use Ethernet (#1429).
//
// An active connection that already carried the UUID before the write is
// not counted, so a join while the home connection is up answers saved:
// NetworkManager keeps the old settings live until it reconnects.
func (j *Joiner) Join(ctx context.Context, ssid, psk string) Code {
	if !Valid(ssid, psk) {
		return Refused
	}
	if !StationOK(j.station, j.ap) {
		return Failed
	}
	if !j.mu.TryLock() {
		return Busy
	}
	defer j.mu.Unlock()
	before, err := j.ours(ctx)
	if err != nil {
		return Failed
	}
	s := ConnectionSettings(ssid, psk, j.station)
	path, err := j.nm.GetConnectionByUuid(ctx, UUID)
	switch {
	case errors.Is(err, ErrNoConnection):
		_, err = j.nm.AddConnection2(ctx, s)
	case err == nil:
		err = j.nm.Update2(ctx, path, s)
	}
	if err != nil {
		return Failed
	}
	return j.watch(ctx, before)
}

// ours is the set of active connections that carry UUID now.
func (j *Joiner) ours(ctx context.Context) (map[string]bool, error) {
	paths, err := j.nm.ActiveConnections(ctx)
	if err != nil {
		return nil, err
	}
	m := map[string]bool{}
	for _, p := range paths {
		// One that vanished between the two reads is not ours to skip.
		if u, err := j.nm.ActiveUUID(ctx, p); err == nil && u == UUID {
			m[p] = true
		}
	}
	return m, nil
}

// watch reads the active connections until one new to it with UUID
// reaches ACTIVATED (joined) or DEACTIVATED or goes away (not joined), or
// the wait runs out (saved).
func (j *Joiner) watch(ctx context.Context, before map[string]bool) Code {
	deadline := j.now().Add(j.wait)
	uuids := map[string]string{}
	seen := map[string]bool{}
	for {
		paths, err := j.nm.ActiveConnections(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return Saved
			}
			return Failed
		}
		present := map[string]bool{}
		for _, p := range paths {
			present[p] = true
		}
		for p := range seen {
			if !present[p] {
				return NotJoined
			}
		}
		for _, p := range paths {
			if before[p] {
				continue
			}
			u, ok := uuids[p]
			if !ok {
				if u, err = j.nm.ActiveUUID(ctx, p); err != nil {
					// Gone between the two reads; the next poll sees.
					continue
				}
				uuids[p] = u
			}
			if u != UUID {
				continue
			}
			seen[p] = true
			st, err := j.nm.ActiveState(ctx, p)
			if err != nil {
				return NotJoined
			}
			switch st {
			case StateActivated:
				return Joined
			case StateDeactivated:
				return NotJoined
			}
		}
		if !j.now().Before(deadline) {
			return Saved
		}
		if j.sleep(ctx, j.every) != nil {
			return Saved
		}
	}
}

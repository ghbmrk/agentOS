package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/nft"
)

// Config is the enforcer's own wiring, from its image and set-up, never
// from the core or the policy (nft ASSUMPTIONS ENF-e-6). It holds nothing
// the owner signs and no secret.
type Config struct {
	// Name is the enforcer's local name: the page's origin and the
	// passkey's relying party (NET-4).
	Name string `json:"name"`
	// Zone is the owner's time zone, an IANA name: every time the page
	// shows is in it (page ASSUMPTIONS ENF-b-11).
	Zone string `json:"zone"`
	// Layout is the firewall's view of the box's interfaces and ports.
	Layout nft.Layout `json:"layout"`
	// Page is the enforcer's own addresses on the Owner network and the
	// wired admin port, with the page's port; PageAllow those networks'
	// prefixes (NET-6). The page answers nothing else.
	Page      []netip.AddrPort `json:"page"`
	PageAllow []netip.Prefix   `json:"page_allow"`
	// Channel is the enforcer's address on the core's segment, with the
	// channel's port; CoreAllow the core's addresses there. A connection
	// from anywhere else is closed before the TLS handshake.
	Channel   netip.AddrPort `json:"channel"`
	CoreAllow []netip.Prefix `json:"core_allow"`
	// Nft is the absolute path of the image's nft binary.
	Nft string `json:"nft"`

	zone *time.Location
}

var errConfig = errors.New("config")

// parseConfig reads and checks the configuration file's bytes. Unknown
// fields are refused, so a misspelt key never leaves a default in place.
func parseConfig(b []byte) (Config, error) {
	var c Config
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("%w: %v", errConfig, err)
	}
	if dec.More() {
		return Config{}, fmt.Errorf("%w: trailing data", errConfig)
	}
	return c, c.check()
}

func (c *Config) check() error {
	fail := func(what string) error { return fmt.Errorf("%w: %s", errConfig, what) }
	if c.Name == "" {
		return fail("name is required")
	}
	z, err := time.LoadLocation(c.Zone)
	if err != nil || c.Zone == "" || c.Zone == "Local" {
		return fail("zone must be an IANA time zone name")
	}
	c.zone = z
	if err := c.Layout.Check(); err != nil {
		return fail("layout: " + err.Error())
	}
	if len(c.Page) == 0 || len(c.PageAllow) == 0 {
		return fail("page and page_allow are required")
	}
	if !c.Channel.IsValid() || c.Channel.Addr().IsUnspecified() || c.Channel.Port() == 0 || len(c.CoreAllow) == 0 {
		return fail("channel needs one specific address and port, and core_allow its peers")
	}
	for _, p := range c.CoreAllow {
		if !p.IsValid() || p.Bits() == 0 {
			return fail("core_allow holds an invalid or catch-all prefix")
		}
	}
	if c.Channel.Port() != c.Layout.ChannelPort {
		return fail("channel's port is not the layout's channel port")
	}
	for _, a := range c.Page {
		if a.Port() != c.Layout.PagePort {
			return fail("a page address's port is not the layout's page port")
		}
	}
	if !filepath.IsAbs(c.Nft) {
		return fail("nft must be an absolute path")
	}
	return nil
}

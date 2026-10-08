package pacingfile

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/grants"
)

const MaxManifestBytes = 16 * 1024

var ErrManifest = errors.New("provisioned accounting configuration unavailable")

// ProvisionedManifest is the explicit version-one wire image, serialized by
// encoding/json in this field order without trailing whitespace. No option can
// enable volatile accounting, first provisioning or disabled latency observation.
// The 1..4096 allowance matches the current durable pacing schema's limit.
type ProvisionedManifest struct {
	Version               int    `json:"version"`
	Ledger                string `json:"ledger"`
	RequestsPerHour       int    `json:"requests_per_hour"`
	MaxStoreLatencyMillis int64  `json:"max_store_latency_ms"`
}

// ManifestSettings can be constructed publicly only by validating an image
// against a caller-trusted digest. It stores values, not a live file/reader or
// mutable wire pointer. Expected digest custody/persistence/anti-restore remains
// external trust: fingerprint equality alone is not configuration integrity.
type ManifestSettings struct {
	manifest ProvisionedManifest
	valid    bool
}

// ReadProvisionedManifest consumes at most MaxManifestBytes+1 bytes, refusing
// overflow/read errors, absent expected digest and noncanonical/invalid JSON.
// Its reader is trusted synchronous I/O and can block indefinitely: establish
// independent owner controls before configuration loading. No writer, filesystem
// custody check, pin discovery, pin persistence or automatic provisioning exists.
func ReadProvisionedManifest(r io.Reader, expected [32]byte) (*ManifestSettings, error) {
	if r == nil || expected == [32]byte{} {
		return nil, ErrManifest
	}
	b, err := io.ReadAll(io.LimitReader(r, MaxManifestBytes+1))
	if err != nil || len(b) > MaxManifestBytes || sha256.Sum256(b) != expected {
		return nil, ErrManifest
	}
	var m ProvisionedManifest
	if json.Unmarshal(b, &m) != nil {
		return nil, ErrManifest
	}
	canonical, err := json.Marshal(m)
	if err != nil || !bytes.Equal(canonical, b) || !validManifest(m) {
		return nil, ErrManifest
	}
	return &ManifestSettings{manifest: m, valid: true}, nil
}

func validManifest(m ProvisionedManifest) bool {
	return m.Version == 1 && filepath.IsAbs(m.Ledger) && filepath.Clean(m.Ledger) == m.Ledger && m.Ledger != "/" &&
		!strings.ContainsRune(m.Ledger, 0) && !strings.HasSuffix(m.Ledger, ".lock") && !strings.HasSuffix(m.Ledger, ".tmp") &&
		m.RequestsPerHour >= 1 && m.RequestsPerHour <= 4096 && m.MaxStoreLatencyMillis >= 1 && m.MaxStoreLatencyMillis <= 300000
}

// Start applies exactly these pacing options to one supplied owner slot, requiring
// a caller-trusted clock. Leave RequestsPerHour and all three Pacing fields unset:
// competing bindings are refused, even if they happen to equal the manifest.
// Other Gate authority/quiet/priority callbacks are retained from cfg unchanged;
// their qualification and common approval/question/host identity remain external.
// Missing/mismatched ledger yields held recovery, never initialization or refund.
func (m *ManifestSettings) Start(slot *StartupSlot, cfg grants.Config) (*Startup, error) {
	if m == nil || !m.valid || slot == nil || cfg.Now == nil || cfg.RequestsPerHour != 0 || cfg.PacingStore != nil || cfg.PacingRequireExisting || cfg.PacingMaxStoreLatency != 0 {
		return nil, ErrManifest
	}
	cfg.RequestsPerHour = m.manifest.RequestsPerHour
	cfg.PacingRequireExisting = true
	cfg.PacingMaxStoreLatency = time.Duration(m.manifest.MaxStoreLatencyMillis) * time.Millisecond
	return slot.Start(m.manifest.Ledger, cfg)
}

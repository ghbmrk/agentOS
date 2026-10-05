package cleanroom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"
)

// Output limits for one clean-room result.
const (
	MaxResultBytes = 8 << 20
	MaxFiles       = 256
	MaxFileBytes   = 1 << 20
	maxPath        = 200
)

// ErrResult marks a result the clean room refuses.
var ErrResult = errors.New("cleanroom: result refused")

// ErrNoArtifact is returned when an ID names no stored artifact.
var ErrNoArtifact = errors.New("cleanroom: no such artifact")

var segment = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)

// Result is what a clean-room guest submits: the generalized skill, adapter,
// or regression it built from public information, as UTF-8 text files, and
// the outcome of running it on the synthetic fixtures.
type Result struct {
	Files    map[string]string `json:"files"`
	Fixtures Fixtures          `json:"fixtures"`
}

// Fixtures is the outcome of the result's own tests on synthetic fixtures.
type Fixtures struct {
	Passed int `json:"passed"`
	Failed int `json:"failed"`
}

func (r Result) check() error {
	if len(r.Files) == 0 || len(r.Files) > MaxFiles {
		return fmt.Errorf("%w: needs 1 to %d files", ErrResult, MaxFiles)
	}
	if r.Fixtures.Passed < 1 || r.Fixtures.Failed != 0 {
		return fmt.Errorf("%w: its tests must pass on the synthetic fixtures (passed >= 1, failed 0)", ErrResult)
	}
	for p, c := range r.Files {
		if !cleanPath(p) {
			return fmt.Errorf("%w: file path %q", ErrResult, clip(p, 64))
		}
		if len(c) > MaxFileBytes || !utf8.ValidString(c) {
			return fmt.Errorf("%w: %s must be UTF-8 text of at most %d bytes", ErrResult, p, MaxFileBytes)
		}
		for d := p; strings.Contains(d, "/"); {
			d = d[:strings.LastIndex(d, "/")]
			if _, ok := r.Files[d]; ok {
				return fmt.Errorf("%w: %s is both a file and a directory", ErrResult, d)
			}
		}
	}
	return nil
}

// cleanPath accepts relative slash paths of plain segments: no "..", no
// leading dot, no empty segment, nothing absolute.
func cleanPath(p string) bool {
	if p == "" || len(p) > maxPath {
		return false
	}
	for _, s := range strings.Split(p, "/") {
		if !segment.MatchString(s) {
			return false
		}
	}
	return true
}

// Output is what an artifact is, by hint kind: what the clean room was asked
// to build.
var Output = map[string]string{
	"skill_gap":   "skill",
	"adapter_gap": "adapter",
	"vuln":        "regression",
}

// Manifest is an artifact's provenance record (OSS-2).
type Manifest struct {
	ID      string          `json:"id"`
	Job     string          `json:"job"`
	Hint    json.RawMessage `json:"hint"` // the canonical hint it was built from
	Output  string          `json:"output"`
	Embargo bool            `json:"embargo"` // from the schema's mark on the hint's kind (OSS-5)
	Cleared bool            `json:"cleared"` // the embargo path has cleared it
	Image   string          `json:"image"`
	Machine string          `json:"machine"`
	Day     string          `json:"day"`
	// ClaimedFixtures is the clean room's own report of its fixture run.
	// Nothing re-ran it: never show it as an attestation (C7, K2).
	ClaimedFixtures Fixtures `json:"claimed_fixtures"`
	Files           []File   `json:"files"`
}

// File is one output file's record.
type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`
}

// Artifact is a stored clean-room output. Only this package makes one, and
// only from a clean-room machine's result, so a publisher that takes
// Artifacts can publish nothing else (OSS-2, OSS-3).
type Artifact struct {
	m   Manifest
	dir string
}

// Manifest returns the artifact's provenance record.
func (a Artifact) Manifest() Manifest {
	m := a.m
	m.Files = append([]File(nil), a.m.Files...)
	return m
}

// ReadFile returns one file of the artifact, checked against its manifest
// hash.
func (a Artifact) ReadFile(path string) ([]byte, error) {
	for _, f := range a.m.Files {
		if f.Path != path {
			continue
		}
		data, err := os.ReadFile(filepath.Join(a.dir, "files", filepath.FromSlash(path)))
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != f.SHA256 {
			return nil, fmt.Errorf("cleanroom: %s/%s does not match its manifest", a.m.ID, path)
		}
		return data, nil
	}
	return nil, fmt.Errorf("%w: %s has no file %s", ErrNoArtifact, a.m.ID, path)
}

// Store holds clean-room artifacts in a broker-held directory.
type Store struct {
	dir string
	mu  sync.Mutex
}

func openStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

// put writes an artifact under a temporary name and renames it into place,
// so a crash leaves either the whole artifact or none.
func (s *Store) put(m Manifest, files map[string]string) (Artifact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tmp, err := os.MkdirTemp(s.dir, ".put-")
	if err != nil {
		return Artifact{}, err
	}
	defer os.RemoveAll(tmp)
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	m.Files = nil
	for _, p := range paths {
		dst := filepath.Join(tmp, "files", filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return Artifact{}, err
		}
		if err := os.WriteFile(dst, []byte(files[p]), 0o600); err != nil {
			return Artifact{}, err
		}
		sum := sha256.Sum256([]byte(files[p]))
		m.Files = append(m.Files, File{Path: p, SHA256: hex.EncodeToString(sum[:]), Size: len(files[p])})
	}
	if err := writeJSON(filepath.Join(tmp, "manifest.json"), m); err != nil {
		return Artifact{}, err
	}
	dir := filepath.Join(s.dir, m.ID)
	if err := os.Rename(tmp, dir); err != nil {
		return Artifact{}, err
	}
	if err := syncDir(s.dir); err != nil {
		return Artifact{}, err
	}
	return Artifact{m: m, dir: dir}, nil
}

func (s *Store) remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.get(id); err != nil {
		return err
	}
	if err := os.RemoveAll(filepath.Join(s.dir, id)); err != nil {
		return err
	}
	return syncDir(s.dir)
}

// Get returns one artifact.
func (s *Store) Get(id string) (Artifact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.get(id)
}

func (s *Store) get(id string) (Artifact, error) {
	if !segment.MatchString(id) || strings.HasPrefix(id, ".") {
		return Artifact{}, ErrNoArtifact
	}
	dir := filepath.Join(s.dir, id)
	var m Manifest
	if err := readJSON(filepath.Join(dir, "manifest.json"), &m); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Artifact{}, ErrNoArtifact
		}
		return Artifact{}, err
	}
	return Artifact{m: m, dir: dir}, nil
}

func (s *Store) list(keep func(Manifest) bool) ([]Artifact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ents, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var out []Artifact
	for _, e := range ents {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		a, err := s.get(e.Name())
		if err != nil {
			return nil, err
		}
		if keep(a.m) {
			out = append(out, a)
		}
	}
	return out, nil
}

// Publishable lists the artifacts a publisher may take: clean-room output
// whose embargo, if its hint kind carries one, has cleared (OSS-5, hint K2).
func (s *Store) Publishable() ([]Artifact, error) {
	return s.list(func(m Manifest) bool { return !m.Embargo || m.Cleared })
}

// Embargoed lists the artifacts held for the encrypted private-report path
// (OSS-5): regressions rebuilt from vuln hints that have not cleared.
func (s *Store) Embargoed() ([]Artifact, error) {
	return s.list(func(m Manifest) bool { return m.Embargo && !m.Cleared })
}

// ClearEmbargo marks an embargoed artifact publishable. Only the embargo
// path calls it, once the maintainers' private report has cleared.
func (s *Store) ClearEmbargo(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, err := s.get(id)
	if err != nil {
		return err
	}
	if !a.m.Embargo {
		return fmt.Errorf("cleanroom: %s is not embargoed", id)
	}
	a.m.Cleared = true
	return writeJSON(filepath.Join(a.dir, "manifest.json"), a.m)
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

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

// errCommittedUnsynced: the artifact is committed, its directory sync failed.
var errCommittedUnsynced = errors.New("cleanroom: committed; directory sync failed")

// ErrNoArtifact is returned when an ID names no stored artifact.
var ErrNoArtifact = errors.New("cleanroom: no such artifact")

// errDamaged: a committed artifact's files do not match its manifest. Its
// job must be queued again and the artifact quarantined.
var errDamaged = errors.New("cleanroom: artifact output damaged")

var segment = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)

// errBadID: an artifact ID that is not one plain, visible directory name.
var errBadID = errors.New("cleanroom: not an artifact ID")

// validID reports whether id can name an artifact directory in the store:
// one segment with no leading dot, so never "", "." or "..".
func validID(id string) bool { return segment.MatchString(id) && !strings.HasPrefix(id, ".") }

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

// verify checks every file the manifest lists is present and matches its
// hash.
func (a Artifact) verify() error {
	for _, f := range a.m.Files {
		if _, err := a.ReadFile(f.Path); err != nil {
			return err
		}
	}
	return nil
}

// Store holds clean-room artifacts in a broker-held directory.
type Store struct {
	dir   string
	mu    sync.Mutex
	fault faultFn // tests only: sees, and may fail, each file operation
}

// openStore opens the store and checks every committed artifact. It returns
// those whose manifest does not parse, or whose files are missing or do not
// match it (output a crash lost), still in place: the caller queues their
// jobs again and only then quarantines them, so a crash between the two
// cannot lose a job. An artifact's identity is its directory name: an
// unreadable manifest, or one naming another ID, is returned with only the
// directory's name, so every returned ID is a name ReadDir listed (SR3-8-f1).
func openStore(dir string) (*Store, []Manifest, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	// Staged artifacts a crash left were never committed: not published.
	if old, err := filepath.Glob(filepath.Join(dir, ".stage-*")); err == nil {
		for _, d := range old {
			os.RemoveAll(d)
		}
	}
	s := &Store{dir: dir}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	var damaged []Manifest
	for _, e := range ents {
		if !e.IsDir() || !validID(e.Name()) {
			continue
		}
		a, err := s.get(e.Name())
		if err != nil {
			damaged = append(damaged, Manifest{ID: e.Name()})
			continue
		}
		if err := a.verify(); err != nil {
			damaged = append(damaged, a.m)
		}
	}
	return s, damaged, nil
}

// quarantine moves an artifact out of every listing and Get, kept aside
// for diagnosis. Its job must already be queued again (SR3-8). An id that
// is not an artifact directory name is refused and nothing is renamed.
func (s *Store) quarantine(id string) error {
	if !validID(id) {
		return fmt.Errorf("%w: %q", errBadID, clip(id, 64))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	q := filepath.Join(s.dir, ".quarantine")
	if err := os.MkdirAll(q, 0o700); err != nil {
		return err
	}
	// A symlink in its place would move the artifact out of the store.
	if fi, err := os.Lstat(q); err != nil {
		return err
	} else if !fi.IsDir() {
		return fmt.Errorf("cleanroom: %s is not a directory; not quarantining %s", q, id)
	}
	// The rename resolves inside the store's root, so a symlink put in
	// place after the check above fails it instead of leading out.
	r, err := os.OpenRoot(s.dir)
	if err != nil {
		return err
	}
	defer r.Close()
	name := id + "-" + newID()
	if err := s.fault.hit("rename", filepath.Join(q, name)); err != nil {
		return err
	}
	if err := r.Rename(id, filepath.Join(".quarantine", name)); err != nil {
		return err
	}
	if err := s.fault.dirSync(q); err != nil {
		return err
	}
	return s.fault.dirSync(s.dir)
}

// losses counts the quarantined copies of an artifact: how often its output
// was found damaged, across restarts.
func (s *Store) losses(id string) (int, error) {
	r, err := os.OpenRoot(s.dir)
	if err != nil {
		return 0, err
	}
	defer r.Close()
	f, err := r.Open(".quarantine")
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()
	ents, err := f.ReadDir(-1)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range ents {
		rest, ok := strings.CutPrefix(e.Name(), id+"-")
		if ok && quarantineSuffix.MatchString(rest) {
			n++
		}
	}
	return n, nil
}

// quarantineSuffix is the random part quarantine appends (newID).
var quarantineSuffix = regexp.MustCompile(`^[0-9a-f]{12}$`)

// settle establishes that a committed artifact is durable before its job
// is recorded complete: its files match the manifest, and the rename that
// committed it is synced. Damaged output is left in place (errDamaged):
// the caller queues its job again, then quarantines it.
func (s *Store) settle(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, err := s.get(id)
	if err != nil {
		return err
	}
	if err := a.verify(); err != nil {
		return fmt.Errorf("%w: %s: %v", errDamaged, id, err)
	}
	return s.fault.dirSync(s.dir)
}

// stage writes an artifact under a hidden name, which no listing or Get
// sees, so it is not publishable until commit.
func (s *Store) stage(m Manifest, files map[string]string) (string, Manifest, error) {
	tmp, err := os.MkdirTemp(s.dir, ".stage-")
	if err != nil {
		return "", m, err
	}
	m, err = s.fill(tmp, m, files)
	if err != nil {
		os.RemoveAll(tmp)
		return "", m, err
	}
	return tmp, m, nil
}

// fill writes and syncs each file, then syncs every directory it created,
// deepest first, so each file and directory entry is durable before its
// parent's is; only then is the manifest, the record that the output is
// complete, written durably (SR3-8).
func (s *Store) fill(tmp string, m Manifest, files map[string]string) (Manifest, error) {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	dirs := []string{tmp}
	made := map[string]bool{tmp: true}
	var mkdirs func(d string) error
	mkdirs = func(d string) error {
		if made[d] {
			return nil
		}
		if err := mkdirs(filepath.Dir(d)); err != nil {
			return err
		}
		if err := s.fault.hit("mkdir", d); err != nil {
			return err
		}
		if err := os.Mkdir(d, 0o700); err != nil {
			return err
		}
		made[d] = true
		dirs = append(dirs, d)
		return nil
	}
	m.Files = nil
	for _, p := range paths {
		dst := filepath.Join(tmp, "files", filepath.FromSlash(p))
		if err := mkdirs(filepath.Dir(dst)); err != nil {
			return m, err
		}
		if err := writeSynced(s.fault, dst, []byte(files[p])); err != nil {
			return m, err
		}
		sum := sha256.Sum256([]byte(files[p]))
		m.Files = append(m.Files, File{Path: p, SHA256: hex.EncodeToString(sum[:]), Size: len(files[p])})
	}
	// Created parents precede their children in dirs: sync in reverse.
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := s.fault.dirSync(dirs[i]); err != nil {
			return m, err
		}
	}
	data, err := json.Marshal(m)
	if err != nil {
		return m, err
	}
	return m, writeFileWith(s.fault, filepath.Join(tmp, "manifest.json"), data)
}

// commit makes a staged artifact visible under its ID by one rename.
func (s *Store) commit(staged string, m Manifest) (Artifact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := filepath.Join(s.dir, m.ID)
	if err := s.fault.hit("rename", dir); err != nil {
		return Artifact{}, err
	}
	if err := os.Rename(staged, dir); err != nil { // durable:exempt synced through the fault seam (dirSync), C14
		return Artifact{}, err
	}
	// Once renamed the artifact is in place: a failed directory sync is
	// not a failed commit, or a stored artifact would outlive a job logged
	// as failed. It is reported for the log; the job is recorded complete
	// only once settle has synced it.
	a := Artifact{m: m, dir: dir}
	if err := s.fault.dirSync(s.dir); err != nil {
		return a, fmt.Errorf("%w: %v", errCommittedUnsynced, err)
	}
	return a, nil
}

// put stages and commits at once.
func (s *Store) put(m Manifest, files map[string]string) (Artifact, error) {
	staged, m, err := s.stage(m, files)
	if err != nil {
		return Artifact{}, err
	}
	a, err := s.commit(staged, m)
	if err != nil {
		os.RemoveAll(staged)
	}
	return a, err
}

// Get returns one artifact.
func (s *Store) Get(id string) (Artifact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.get(id)
}

func (s *Store) get(id string) (Artifact, error) {
	if !validID(id) {
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
	if m.ID != id {
		return Artifact{}, fmt.Errorf("%w: %s: manifest names %q", errDamaged, id, clip(m.ID, 64))
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
		if !e.IsDir() || !validID(e.Name()) {
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

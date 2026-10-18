package photo

// REQ: CH-23, ARC-5

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const decoderPkg = "github.com/ghbmrk/agentos/broker/photo/decoder"

// decoders are the packages that parse image files.
var decoders = []string{"image/jpeg", "image/png", "image/gif", decoderPkg}

// TestPhotoImportsNoDecoder: no image decoder links into this package or
// into agentosd, so a hostile photo is parsed only inside the one-shot
// sandbox; and only agentos-photo imports photo/decoder.
func TestPhotoImportsNoDecoder(t *testing.T) {
	out, err := exec.Command("go", "list", "-C", "..", "-deps", "./photo", "./cmd/agentosd").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		if strings.HasPrefix(dep, "golang.org/x/image") || contains(decoders, dep) {
			t.Errorf("photo or agentosd links %s", dep)
		}
	}
	err = filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "vendor" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		dir := filepath.ToSlash(filepath.Dir(path))
		if dir == "../cmd/agentos-photo" || dir == "../photo/decoder" {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, im := range f.Imports {
			if p, _ := strconv.Unquote(im.Path.Value); p == decoderPkg {
				t.Errorf("%s imports %s; only agentos-photo may", path, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

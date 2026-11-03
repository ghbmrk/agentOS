package camera

// REQ: NET-2, DEV-7, DEV-8

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
	"github.com/ghbmrk/agentos/broker/cmd/agentos-camdecode/camdecode"
)

var picture = camwire.Shape{Width: 8, Height: 6}

// fakeProc is a decoder sandbox in this process: run reads what the
// decoder feeds and writes what it reads back; a nil run reads nothing
// and sends nothing. Stop closes every pipe, which ends run, and waits
// for it.
type fakeProc struct {
	inR, outR *io.PipeReader
	inW, outW *io.PipeWriter
	stop      chan struct{}
	done      chan struct{}
	once      sync.Once
}

func newFakeProc(run func(in io.Reader, out io.Writer)) *fakeProc {
	p := &fakeProc{stop: make(chan struct{}), done: make(chan struct{})}
	p.inR, p.inW = io.Pipe()
	p.outR, p.outW = io.Pipe()
	go func() {
		defer close(p.done)
		if run == nil {
			<-p.stop
		} else {
			run(p.inR, p.outW)
		}
		p.outW.Close()
		p.inR.Close()
	}()
	return p
}

func (p *fakeProc) In() io.Writer         { return p.inW }
func (p *fakeProc) Out() io.Reader        { return p.outR }
func (p *fakeProc) Done() <-chan struct{} { return p.done }
func (p *fakeProc) Stop() {
	p.once.Do(func() {
		close(p.stop)
		p.inW.Close()
		p.inR.Close()
		p.outW.Close()
		p.outR.Close()
	})
	<-p.done
}

// decodes runs the sandbox's own decoder on the declared shapes.
func decodes(in io.Reader, out io.Writer) {
	camdecode.Run(in, out, camdecode.Config{Video: picture, Thermal: lepton})
}

// starts records each sandbox start and gives the n-th start the n-th
// behaviour (the last one repeats).
type starts struct {
	mu    sync.Mutex
	runs  []func(io.Reader, io.Writer)
	at    []time.Time
	specs []Spec
	procs []*fakeProc
}

func (s *starts) start(_ context.Context, st Spec) (Proc, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run := s.runs[min(len(s.at), len(s.runs)-1)]
	s.at = append(s.at, time.Now())
	s.specs = append(s.specs, st)
	p := newFakeProc(run)
	s.procs = append(s.procs, p)
	return p, nil
}

func (s *starts) n() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.at)
}

type outs struct {
	mu sync.Mutex
	d  []Decoded
}

func (o *outs) add(d Decoded) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.d = append(o.d, d)
}

func (o *outs) all() []Decoded {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.d)
}

type reports struct {
	mu sync.Mutex
	k  []Kind
}

func (r *reports) add(_ string, k Kind) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.k = append(r.k, k)
}

func (r *reports) count(k Kind) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, x := range r.k {
		if x == k {
			n++
		}
	}
	return n
}

type decRig struct {
	d   *Decoder
	st  *starts
	out *outs
	rep *reports
	log *lines
}

func newDecRig(t *testing.T, mut func(*DecodeConfig), runs ...func(io.Reader, io.Writer)) *decRig {
	t.Helper()
	r := &decRig{st: &starts{runs: runs}, out: &outs{}, rep: &reports{}, log: &lines{}}
	cfg := DecodeConfig{
		Start: r.st.start,
		Stall: 200 * time.Millisecond, Idle: 5 * time.Second,
		Backoff: Backoff{Min: 100 * time.Millisecond, Max: 400 * time.Millisecond},
		Out:     r.out.add, Report: r.rep.add, Log: r.log.add,
	}
	if mut != nil {
		mut(&cfg)
	}
	var err error
	if r.d, err = NewDecoder(cfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.d.Close)
	if err := r.d.Add(testID, picture, lepton); err != nil {
		t.Fatal(err)
	}
	return r
}

// thermalN is a thermal frame with counter n and the marker in its
// samples.
func thermalN(n uint32) camwire.Frame {
	s := make([]byte, 2*int(lepton.Width)*int(lepton.Height))
	copy(s, marker)
	return camwire.Frame{Type: camwire.TypeThermal, Payload: camwire.AppendThermal(nil, camwire.Thermal{Width: lepton.Width, Height: lepton.Height, Counter: n, Samples: s})}
}

// TestDecodeFormatMatchesDecoder: the clerk's copy of the output format,
// the argv it passes and its bounds are the sandbox decoder's own, which
// the clerk must not link (design point 4).
func TestDecodeFormatMatchesDecoder(t *testing.T) {
	if outHeaderLen != camdecode.HeaderLen || outVideo != camdecode.KindVideo || outThermal != camdecode.KindThermal ||
		maxVideoSide != camdecode.MaxVideoSide {
		t.Fatal("format constants differ from camdecode's")
	}
	for _, s := range []camwire.Shape{{Width: 1, Height: 1}, {Width: 7, Height: 5}, picture, lepton, {Width: 4096, Height: 4096}} {
		for _, k := range []byte{outVideo, outThermal} {
			if outLen(k, s) != camdecode.Len(k, s) {
				t.Errorf("outLen(%d, %v) = %d, camdecode %d", k, s, outLen(k, s), camdecode.Len(k, s))
			}
		}
	}
	r := newDecRig(t, nil, decodes)
	r.d.Frame(testID, thermalN(1))
	waitFor(t, "a start", func() bool { return r.st.n() == 1 })
	spec := r.st.specs[0]
	argv := spec.Argv()
	c, err := camdecode.ParseArgs(argv[1:])
	if argv[0] != decoderBinary || err != nil || c.Video != picture || c.Thermal != lepton {
		t.Errorf("argv %q parses to %+v, %v", argv, c, err)
	}
	if spec != (Spec{Video: picture, Thermal: lepton}) {
		t.Errorf("spec %+v", spec)
	}
}

// TestClerkDoesNotLinkDecoder: no file of the clerk links the sandbox's
// decoder, so no stream payload is decoded in the trusted base (design
// point 3); and the decoder binary links nothing that reaches a network,
// another process or memory outside Go (NET-2: no network in the
// sandbox, by its build as well as its namespace). The decoder side is
// checked on what the go tool links, untagged and with image/camdecode.sh's
// tags: no net, os/exec or plugin anywhere in the dependency graph; no
// package outside the standard library but camwire, camdecode and the
// program; and in those, no source but Go, even one a build tag leaves
// out (.c, .s, .syso, ...), and in every Go file of them, whatever its
// build constraint, only the imports each needs today (no os, reflect,
// unsafe, syscall or net; the program's os limited to Args, Exit and the
// three standard streams). The one
// exception is camdecode/h264.go's cgo, the libavcodec-tagged file that
// links the pinned H.264-only libavcodec (image/libavcodec.sh), built
// with --disable-network and run in the sandbox's namespace.
func TestClerkDoesNotLinkDecoder(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("clerk: %v", err)
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range f.Imports {
			if p, _ := strconv.Unquote(im.Path.Value); strings.Contains(p, "camdecode") {
				t.Errorf("%s imports %s", name, p)
			}
		}
	}

	const mod = "github.com/ghbmrk/agentos/broker/"
	ours := []string{mod + "camwire", mod + "cmd/agentos-camdecode", mod + "cmd/agentos-camdecode/camdecode"}
	for _, tags := range []string{"", "libavcodec,netgo,osusergo"} {
		cmd := exec.Command("go", "list", "-e", "-deps", "-json", "-tags="+tags, "../../cmd/agentos-camdecode")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=1", "GOFLAGS=")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list -tags=%q: %v", tags, err)
		}
		seen := 0
		for dec := json.NewDecoder(bytes.NewReader(out)); dec.More(); {
			var p struct {
				ImportPath                                       string
				Standard                                         bool
				Error                                            *struct{ Err string }
				CgoFiles, IgnoredOtherFiles                      []string
				CFiles, CXXFiles, MFiles, HFiles, FFiles, SFiles []string
				SwigFiles, SwigCXXFiles, SysoFiles, EmbedFiles   []string
			}
			if err := dec.Decode(&p); err != nil {
				t.Fatal(err)
			}
			where := fmt.Sprintf("tags %q: %s", tags, p.ImportPath)
			if p.Error != nil {
				t.Errorf("%s: %s", where, p.Error.Err)
			}
			if p.ImportPath == "net" || strings.HasPrefix(p.ImportPath, "net/") || p.ImportPath == "os/exec" || p.ImportPath == "plugin" {
				t.Errorf("%s is linked", where)
			}
			if p.Standard {
				continue
			}
			if !slices.Contains(ours, p.ImportPath) {
				t.Errorf("%s is linked; the decoder links only camwire and its own packages", where)
				continue
			}
			seen++
			cgo := []string{}
			if tags != "" && p.ImportPath == ours[2] {
				cgo = []string{"h264.go"}
			}
			if !slices.Equal(p.CgoFiles, cgo) {
				t.Errorf("%s has cgo files %v, want %v", where, p.CgoFiles, cgo)
			}
			for _, other := range [][]string{p.IgnoredOtherFiles, p.CFiles, p.CXXFiles, p.MFiles, p.HFiles, p.FFiles,
				p.SFiles, p.SwigFiles, p.SwigCXXFiles, p.SysoFiles, p.EmbedFiles} {
				if len(other) > 0 {
					t.Errorf("%s holds %v: the decoder's only non-Go code is h264.go's cgo", where, other)
				}
			}
		}
		if seen != len(ours) {
			t.Errorf("tags %q: %d of the decoder's own packages listed, want %d", tags, seen, len(ours))
		}
	}

	// Every Go file of the decoder's own packages, whatever its build
	// constraint (GOOS, GOARCH, GOAMD64 or any tag), imports only what
	// that package needs today: no os, reflect, unsafe, syscall or net, so
	// no file, process, socket or raw memory is reachable from Go. The
	// program alone takes os, and uses only its five names below.
	allowed := map[string][]string{
		"../../camwire": {"bytes", "crypto/ecdsa", "crypto/ed25519", "crypto/elliptic", "crypto/sha256",
			"encoding/base64", "encoding/binary", "encoding/json", "errors", "io"},
		"../../cmd/agentos-camdecode/camdecode": {"bufio", "encoding/binary", "errors", "fmt", "io", "strconv", "strings", ours[0]},
		"../../cmd/agentos-camdecode":           {"fmt", "io", "os", "runtime/debug", ours[2]},
	}
	names := map[string][]string{"os": {"Args", "Exit", "Stderr", "Stdin", "Stdout"}, "runtime/debug": {"SetMemoryLimit"}}
	for dir, ok := range allowed {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("%s: %v", dir, err)
		}
		for _, name := range files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			local := map[string]string{}
			for _, im := range f.Imports {
				p, _ := strconv.Unquote(im.Path.Value)
				switch {
				case im.Name != nil:
					t.Errorf("%s imports %s as %s", name, p, im.Name.Name)
				case p == "C" && filepath.Base(name) == "h264.go" && strings.HasSuffix(dir, "/camdecode"):
				case !slices.Contains(ok, p):
					t.Errorf("%s imports %s", name, p)
				case names[p] != nil:
					local[p[strings.LastIndex(p, "/")+1:]] = p
				}
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if sel, isSel := n.(*ast.SelectorExpr); isSel {
					if x, isIdent := sel.X.(*ast.Ident); isIdent && local[x.Name] != "" &&
						!slices.Contains(names[local[x.Name]], sel.Sel.Name) {
						t.Errorf("%s uses %s.%s", name, local[x.Name], sel.Sel.Name)
					}
				}
				return true
			})
		}
	}
}

// decoderCgo is the decoder's one cgo file (TestClerkDoesNotLinkDecoder).
const decoderCgo = "../../cmd/agentos-camdecode/camdecode/h264.go"

// cgoPin is everything h264.go's cgo may name today: the preamble's
// preprocessor lines, in order; every identifier of its C code, which
// holds no comment the C compiler would see and no string or character
// literal; and every C name its Go code uses. A preamble that adds a
// local name has to add it here too.
var cgoPin = struct{ directives, cIdents, goNames []string }{
	directives: []string{
		"#cgo pkg-config: libavcodec libavutil",
		"#cgo LDFLAGS: -lm",
		"#include <errno.h>",
		"#include <string.h>",
		"#include <libavcodec/avcodec.h>",
		"#include <libavutil/log.h>",
		"#include <libavutil/pixfmt.h>",
	},
	cIdents: strings.Fields(`AVCodec AVCodecContext AVERROR AVERROR_EOF AVFrame AVPacket AV_CODEC_ID_H264
		AV_LOG_QUIET AV_PIX_FMT_YUV420P AV_PIX_FMT_YUVJ420P EAGAIN ENOMEM NULL av_frame_free
		av_log_set_level av_new_packet av_packet_free av_packet_unref avcodec_alloc_context3
		avcodec_find_decoder avcodec_free_context avcodec_open2 avcodec_send_packet c cd_close
		cd_eagain cd_eof cd_i420 cd_open cd_pack cd_send char const ctx data dst f for fr h i if
		int int64_t linesize max_pixels memcpy n p ph pkt pw r return size_t static thread_count
		unsigned void w y`),
	goNames: strings.Fields(`AVCodecContext AVFrame AVPacket av_frame_alloc av_frame_unref av_packet_alloc
		avcodec_receive_frame cd_close cd_eagain cd_eof cd_i420 cd_open cd_pack cd_send int uchar`),
}

// cgoFaults lists how src, as h264.go, steps outside cgoPin. It reads the
// preamble the way the C compiler does: the doc comment of the one
// import "C", which must be a single block comment; backslash-newlines
// spliced first; %: and ??= read as #; a line whose first token is # a
// directive; // to the end of a line a comment, so a literal, which could
// hold one, is a fault. It reads the #cgo lines the way go/build does:
// every raw line, unspliced, whose trimmed text starts #cgo, so a comment
// the C compiler sees cannot hide one; and it asks go/build itself which
// flags it would apply (cgoBuildFaults).
func cgoFaults(src []byte) []string {
	f, err := parser.ParseFile(token.NewFileSet(), decoderCgo, src, parser.ParseComments)
	if err != nil {
		return []string{err.Error()}
	}
	var faults []string
	var doc *ast.CommentGroup
	imports := 0
	for _, d := range f.Decls {
		g, isGen := d.(*ast.GenDecl)
		if !isGen || g.Tok != token.IMPORT {
			continue
		}
		for _, s := range g.Specs {
			if s.(*ast.ImportSpec).Path.Value != `"C"` {
				continue
			}
			imports++
			if doc = s.(*ast.ImportSpec).Doc; doc == nil && len(g.Specs) == 1 {
				doc = g.Doc
			}
		}
	}
	if imports != 1 {
		return []string{fmt.Sprintf("%d imports of C, want 1", imports)}
	}
	if doc == nil || len(doc.List) != 1 || !strings.HasPrefix(doc.List[0].Text, "/*") {
		return []string{"the preamble is not a single block comment"}
	}
	pre := strings.TrimSuffix(strings.TrimPrefix(doc.List[0].Text, "/*"), "*/")
	if strings.IndexFunc(pre, func(r rune) bool { return r >= 0x80 }) >= 0 {
		faults = append(faults, "the preamble holds a character outside ASCII")
	}
	var cgoLines []string
	for _, line := range strings.Split(pre, "\n") {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, "#cgo") {
			cgoLines = append(cgoLines, line)
		}
	}
	if !slices.Equal(cgoLines, cgoPin.directives[:2]) {
		faults = append(faults, fmt.Sprintf("the preamble's #cgo lines are %q, want %q", cgoLines, cgoPin.directives[:2]))
	}
	faults = append(faults, cgoBuildFaults(src)...)
	pre = strings.NewReplacer("\\\r\n", "", "\\\n", "").Replace(pre)
	pre = strings.NewReplacer("%:", "#", "??=", "#").Replace(pre)
	var directives []string
	idents := map[string]bool{}
	for _, line := range strings.Split(pre, "\n") {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, "#") {
			directives = append(directives, line)
			continue
		}
		if line, _, _ = strings.Cut(line, "//"); strings.ContainsAny(line, `"'`) {
			faults = append(faults, "the preamble's code holds a literal: "+line)
		}
		for _, tok := range strings.FieldsFunc(line, func(r rune) bool {
			return r != '_' && (r < '0' || r > '9') && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z')
		}) {
			if tok[0] < '0' || tok[0] > '9' {
				idents[tok] = true
			}
		}
	}
	if !slices.Equal(directives, cgoPin.directives) {
		faults = append(faults, fmt.Sprintf("the preamble's directives are %q, want %q", directives, cgoPin.directives))
	}
	for _, id := range slices.Sorted(maps.Keys(idents)) {
		if !slices.Contains(cgoPin.cIdents, id) {
			faults = append(faults, "the preamble names "+id)
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if sel, isSel := n.(*ast.SelectorExpr); isSel {
			if x, isIdent := sel.X.(*ast.Ident); isIdent && x.Name == "C" && !slices.Contains(cgoPin.goNames, sel.Sel.Name) {
				faults = append(faults, "the Go code uses C."+sel.Sel.Name)
			}
		}
		return true
	})
	return faults
}

// cgoBuildFaults lists how the flags go/build applies to camdecode, with
// src as h264.go, step outside cgoPin's two #cgo lines: on linux/amd64,
// the x86-64 controller camdecode runs on (SPEC HW-3), where
// image/camdecode.sh, called from image/build.sh, builds it; and on
// linux/arm64, as extra coverage only, since the arm64 camera node builds
// with CGO_ENABLED=0 (image/camnode/build.sh). A #cgo line limited to any
// other platform is still a fault of the raw #cgo lines in cgoFaults.
func cgoBuildFaults(src []byte) []string {
	var faults []string
	for _, arch := range []string{"amd64", "arm64"} {
		ctxt := build.Default
		ctxt.GOOS, ctxt.GOARCH, ctxt.CgoEnabled, ctxt.BuildTags = "linux", arch, true, []string{"libavcodec"}
		ctxt.OpenFile = func(path string) (io.ReadCloser, error) {
			if filepath.Base(path) == filepath.Base(decoderCgo) {
				return io.NopCloser(bytes.NewReader(src)), nil
			}
			return os.Open(path)
		}
		p, err := ctxt.ImportDir(filepath.Dir(decoderCgo), 0)
		if err != nil {
			faults = append(faults, fmt.Sprintf("go/build on linux/%s: %v", arch, err))
			continue
		}
		for _, f := range []struct {
			name      string
			got, want []string
		}{
			{"pkg-config", p.CgoPkgConfig, []string{"libavcodec", "libavutil"}},
			{"LDFLAGS", p.CgoLDFLAGS, []string{"-lm"}},
			{"CFLAGS", p.CgoCFLAGS, nil},
			{"CPPFLAGS", p.CgoCPPFLAGS, nil},
			{"CXXFLAGS", p.CgoCXXFLAGS, nil},
			{"FFLAGS", p.CgoFFLAGS, nil},
		} {
			if !slices.Equal(f.got, f.want) {
				faults = append(faults, fmt.Sprintf("go/build on linux/%s applies %s %q, want %q", arch, f.name, f.got, f.want))
			}
		}
	}
	return faults
}

// TestDecoderCgoIsPinned: h264.go, the one file TestClerkDoesNotLinkDecoder
// lets use cgo, links the pinned libavcodec and libavutil and libm, and
// nothing else: its #cgo lines are exactly pkg-config libavcodec libavutil
// and -lm, its includes exactly today's five, its C code names nothing
// new (a socket call, a prototype, asm or a pragma), and its Go code calls
// no C function but today's (NET-2; #3724). Each edit below, one way a
// later change could link more into the sandbox, must fail the check
// with the fault that names it.
func TestDecoderCgoIsPinned(t *testing.T) {
	src, err := os.ReadFile(decoderCgo)
	if err != nil {
		t.Fatal(err)
	}
	if faults := cgoFaults(src); len(faults) > 0 {
		t.Fatalf("h264.go steps outside cgoPin in broker/clerk/camera/decode_test.go, and a change to cgoPin needs a NET-2 review: %q", faults)
	}
	const (
		pc      = "#cgo pkg-config: libavcodec libavutil\n"
		ld      = "#cgo LDFLAGS: -lm\n"
		inc     = "#include <libavutil/pixfmt.h>\n"
		cOpen   = "static AVCodecContext *cd_open(int w, int h) {\n"
		cBody   = "\tctx->thread_count = 1;\n"
		goClose = "\td.ctx, d.pkt, d.fr = nil, nil, nil\n"
		imC     = "import \"C\"\n"
	)
	edits := []struct{ name, old, new, want string }{
		{"another library", ld, ld + "#cgo LDFLAGS: -lcurl\n", "directives"},
		{"a changed LDFLAGS", ld, "#cgo LDFLAGS: -lm -lcurl\n", "directives"},
		{"an object file", ld, "#cgo LDFLAGS: -lm /usr/lib/x86_64-linux-gnu/libc.a\n", "directives"},
		{"another pkg-config module", pc, "#cgo pkg-config: libavcodec libavutil libcurl\n", "directives"},
		{"a CFLAGS line", pc, pc + "#cgo CFLAGS: -include sys/socket.h\n", "directives"},
		{"a dropped LDFLAGS", ld, "", "directives"},
		{"another include", inc, inc + "#include <sys/socket.h>\n", "directives"},
		{"a changed include", "#include <string.h>\n", "#include <stdlib.h>\n", "directives"},
		{"a digraph include", inc, inc + "%:include <sys/socket.h>\n", "directives"},
		{"a spliced digraph include", inc, inc + "%\\\n:include <sys/socket.h>\n", "directives"},
		{"a trigraph include", inc, inc + "??=include <sys/socket.h>\n", "directives"},
		{"an indented define", inc, inc + "  #define cd_eof socket\n", "directives"},
		{"a pragma", inc, inc + "#pragma GCC poison memcpy\n", "directives"},
		{"a socket call", cBody, cBody + "\tsocket(2, 1, 0);\n", "names socket"},
		{"a prototype", cOpen, "int socket(int, int, int);\n" + cOpen, "names socket"},
		{"a typedef'd declaration", cOpen, "typedef int fn(int, int, int);\nextern fn connect;\n" + cOpen, "names connect"},
		{"asm", cBody, cBody + "\t__asm__ volatile (\"syscall\");\n", "names __asm__"},
		{"a universal character name", cBody, cBody + "\t\\u0073ocket(2, 1, 0);\n", "names u0073ocket"},
		{"a _Pragma operator", cBody, cBody + "\t_Pragma(\"GCC diagnostic ignored\")\n", "names _Pragma"},
		{"a spliced name", cBody, cBody + "\tsock\\\net(2, 1, 0);\n", "names socket"},
		{"a name outside ASCII", cBody, cBody + "\ts\u043ecket(2, 1, 0);\n", "outside ASCII"},
		{"a call behind a literal", cBody, cBody + "\tchar *s = \"//\"; socket(2, 1, 0);\n", "literal"},
		{"a Go call to a C function", goClose, goClose + "\tC.system(nil)\n", "uses C.system"},
		{"a second import of C", imC, imC + "\n// #cgo LDFLAGS: -lcurl\nimport \"C\"\n", "2 imports of C"},
		{"a split preamble", "/*\n" + pc, "/*\n#cgo LDFLAGS: -lcurl\n*/\n/*\n" + pc, "not a single block comment"},
		{"a #cgo line behind a continued comment", inc, inc + "// plain note \\\n#cgo LDFLAGS: -lcurl\n", "#cgo lines"},
		{"a #cgo line go/build applies behind a continued comment", inc, inc + "// plain note \\\n#cgo LDFLAGS: -lcurl\n", "go/build on linux/amd64 applies LDFLAGS"},
		{"an arm64-only #cgo line", inc, inc + "#cgo arm64 LDFLAGS: -lcurl\n", "go/build on linux/arm64 applies LDFLAGS"},
		{"a line-comment preamble", "/*\n" + pc, "// #cgo LDFLAGS: -lcurl\n/*\n" + pc, "not a single block comment"},
	}
	for _, e := range edits {
		if bytes.Count(src, []byte(e.old)) != 1 {
			t.Errorf("%s: %q is not in h264.go exactly once", e.name, e.old)
			continue
		}
		if faults := cgoFaults(bytes.Replace(src, []byte(e.old), []byte(e.new), 1)); !slices.ContainsFunc(faults,
			func(f string) bool { return strings.Contains(f, e.want) }) {
			t.Errorf("%s: faults %q, want one with %q", e.name, faults, e.want)
		}
	}
}

// camdecodeSh is the decoder's build script.
const camdecodeSh = "../../../image/camdecode.sh"

// TestDecoderLinkHasNoNetworkCall: image/camdecode.sh links the decoder
// with a cross-reference map and stops the build on any network call that
// linkfaults finds in it, after pinning go env's cgo tools and flags and
// pkg-config's flags for cgoPin's pkg-config modules (NET-2; #3816). Run
// on maps shaped as ld writes them, linkfaults passes what libc's static
// start-up references and names each network call that a file outside
// libc.a defines or uses: Go's objects, libavcodec, any library a flag
// adds.
func TestDecoderLinkHasNoNetworkCall(t *testing.T) {
	b, err := os.ReadFile(camdecodeSh)
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	modules := strings.TrimPrefix(cgoPin.directives[0], "#cgo pkg-config: ")
	for _, want := range []string{
		"go env CC CGO_CFLAGS CGO_CPPFLAGS CGO_CXXFLAGS CGO_FFLAGS CGO_LDFLAGS PKG_CONFIG)\" = \"$env_pin\" ]",
		"for f in --cflags --libs '--libs --static'; do",
		"pkg-config $f " + modules + "))\" = \"$want\" ]",
		"-Wl,-Map=$lib/camdecode.map,--cref",
		"faults=$(linkfaults \"$lib/camdecode.map\")\n[ -z \"$faults\" ] || {",
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("image/camdecode.sh no longer holds %q", want)
		}
	}
	start := strings.Index(src, "\nlinkfaults() {\n")
	end := strings.Index(src[max(start, 0):], "\n}\n")
	if start < 0 || end < 0 {
		t.Fatal("image/camdecode.sh no longer defines linkfaults")
	}
	fn := src[start : start+end+3]

	const libc = "/usr/lib/gcc/x86_64-linux-gnu/13/../../../x86_64-linux-gnu/libc.a"
	row := func(sym string, files ...string) string {
		line := sym + strings.Repeat(" ", max(1, 50-len(sym))) + files[0] + "\n"
		for _, f := range files[1:] {
			line += strings.Repeat(" ", 50) + f + "\n"
		}
		return line
	}
	head := "Archive member included to satisfy reference by file (symbol)\n\n" +
		"/w/lib/libavcodec.a(net.o)\n" + strings.Repeat(" ", 30) + "/tmp/go-link-1/go.o (socket)\n\n" +
		"Cross Reference Table\n\nSymbol" + strings.Repeat(" ", 44) + "File\n"
	startup := row("__socket", libc+"(socket.o)", libc+"(opensock.o)", libc+"(ifaddrs.o)", libc+"(res_hconf.o)") +
		row("bind", libc+"(bind.o)") + row("sendto", libc+"(sendto.o)") + row("socket", libc+"(socket.o)") +
		row("pthread_create", libc+"(pthread_create.o)", "/tmp/go-link-1/000008.o") +
		row("_dl_tunable_set_elision_skip_trylock_internal_abort", libc+"(elision-conf.o)")
	for _, c := range []struct{ name, m, want string }{
		{"libc's static start-up", head + startup, ""},
		{"Go code calling connect", head + startup + row("connect", libc+"(connect.o)", "/tmp/go-link-1/go.o"),
			"connect in /tmp/go-link-1/go.o\n"},
		{"libavcodec defining socket", head + row("socket", "/w/lib/libavcodec.a(net.o)"), "socket in /w/lib/libavcodec.a(net.o)\n"},
		{"a flag's library using __libc_sendmsg", head + startup + row("__libc_sendmsg", libc+"(sendmsg.o)", "/usr/lib/libcurl.a(cf.o)"),
			"__libc_sendmsg in /usr/lib/libcurl.a(cf.o)\n"},
		{"cgo calling getaddrinfo", head + row("getaddrinfo", libc+"(getaddrinfo.o)", "/tmp/go-link-1/000001.o"),
			"getaddrinfo in /tmp/go-link-1/000001.o\n"},
		{"a library named like libc", head + row("recvfrom", "/usr/lib/notlibc.a(r.o)"), "recvfrom in /usr/lib/notlibc.a(r.o)\n"},
		{"a symbol whose file starts the next line", head + "accept4\n" + strings.Repeat(" ", 50) + "/tmp/go-link-1/go.o\n",
			"accept4 in /tmp/go-link-1/go.o\n"},
		{"a map without the table", "Archive member included to satisfy reference by file (symbol)\n", "no cross-reference table\n"},
	} {
		m := filepath.Join(t.TempDir(), "camdecode.map")
		if err := os.WriteFile(m, []byte(c.m), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command("sh", "-c", fn+"linkfaults \"$1\"", "sh", m).Output()
		if err != nil || string(out) != c.want {
			t.Errorf("%s: linkfaults printed %q (%v), want %q", c.name, out, err, c.want)
		}
	}
}

// TestDecoderThermalThroughSandbox: thermal frames go through the
// sandbox's own decoder and come back checked, one per frame fed, with
// their counters; no fault is raised and no line carries a sample.
func TestDecoderThermalThroughSandbox(t *testing.T) {
	r := newDecRig(t, nil, decodes)
	for i := uint32(1); i <= 3; i++ {
		if err := r.d.Frame(testID, thermalN(i)); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "three frames", func() bool { return len(r.out.all()) == 3 })
	for i, d := range r.out.all() {
		if !d.Thermal || d.Camera != testID || d.Width != lepton.Width || d.Height != lepton.Height ||
			d.Counter != uint32(i+1) || !bytes.HasPrefix(d.Pixels, marker) || len(d.Pixels) != outLen(outThermal, lepton) {
			t.Errorf("frame %d = %+v", i, d)
		}
	}
	if r.rep.count(DecoderFault) != 0 || r.st.n() != 1 {
		t.Errorf("faults %d, starts %d", r.rep.count(DecoderFault), r.st.n())
	}
	if strings.Contains(r.log.all(), string(marker)) {
		t.Error("a sample reached the log")
	}
}

// liar reads each frame and answers it with write, the decoder's lie.
func liar(write func(out io.Writer, f camwire.Frame)) func(io.Reader, io.Writer) {
	return func(in io.Reader, out io.Writer) {
		for {
			f, err := camwire.ReadFrame(in, camwire.ToCore, lepton)
			if err != nil {
				return
			}
			write(out, f)
		}
	}
}

func header(kind byte, s camwire.Shape) []byte {
	return camdecode.AppendHeader(nil, kind, s, 1)
}

// TestDecoderOutputMustMatchDeclaredSize: an output frame whose kind,
// dimensions, padding or length is not what the bundle declares, or one
// more than the frames fed, ends the sandbox as a fault before any of it
// reaches a consumer (design point 4).
func TestDecoderOutputMustMatchDeclaredSize(t *testing.T) {
	good := func(out io.Writer) {
		out.Write(header(outThermal, lepton))
		out.Write(make([]byte, outLen(outThermal, lepton)))
	}
	cases := map[string]func(io.Writer, camwire.Frame){
		"wider": func(out io.Writer, _ camwire.Frame) {
			s := camwire.Shape{Width: lepton.Width + 1, Height: lepton.Height}
			out.Write(header(outThermal, s))
			out.Write(make([]byte, outLen(outThermal, s)))
		},
		"video shape for thermal": func(out io.Writer, _ camwire.Frame) {
			out.Write(header(outThermal, picture))
			out.Write(make([]byte, outLen(outThermal, picture)))
		},
		"short": func(out io.Writer, _ camwire.Frame) {
			out.Write(header(outThermal, lepton))
			out.Write(make([]byte, outLen(outThermal, lepton)-1))
		},
		"unknown kind": func(out io.Writer, _ camwire.Frame) {
			out.Write(header(9, lepton))
			out.Write(make([]byte, outLen(outThermal, lepton)))
		},
		"padding": func(out io.Writer, _ camwire.Frame) {
			h := header(outThermal, lepton)
			h[2] = 1
			out.Write(h)
			out.Write(make([]byte, outLen(outThermal, lepton)))
		},
		"video never fed": func(out io.Writer, _ camwire.Frame) {
			out.Write(header(outVideo, picture))
			out.Write(make([]byte, outLen(outVideo, picture)))
		},
		"two for one": func(out io.Writer, _ camwire.Frame) { good(out); good(out) },
	}
	for name, lie := range cases {
		t.Run(name, func(t *testing.T) {
			r := newDecRig(t, func(c *DecodeConfig) { c.Backoff = Backoff{Min: time.Hour, Max: time.Hour} }, liar(lie))
			r.d.Frame(testID, thermalN(1))
			waitFor(t, "a fault", func() bool { return r.rep.count(DecoderFault) == 1 })
			want := 0
			if name == "two for one" {
				want = 1
			}
			if n := len(r.out.all()); n != want {
				t.Errorf("%d frames reached the consumer, want %d", n, want)
			}
			waitFor(t, "the sandbox stopped", func() bool {
				select {
				case <-r.st.procs[0].done:
					return true
				default:
					return false
				}
			})
		})
	}
	// The same lies with no thermal core declared: a thermal frame out is
	// never accepted.
	r := newDecRig(t, nil, liar(func(out io.Writer, _ camwire.Frame) { good(out) }))
	if err := r.d.Add(testID, picture, camwire.Shape{}); err != nil {
		t.Fatal(err)
	}
	r.st.runs = []func(io.Reader, io.Writer){func(in io.Reader, out io.Writer) {
		io.ReadFull(in, make([]byte, camwire.HeaderLen))
		good(out)
		io.Copy(io.Discard, in)
	}}
	r.d.Frame(testID, video())
	waitFor(t, "a fault", func() bool { return r.rep.count(DecoderFault) == 1 })
	if len(r.out.all()) != 0 {
		t.Error("a thermal frame from a camera with no thermal core reached the consumer")
	}
}

// TestDecoderStallKilled: a sandbox that takes frames and sends nothing
// back is stopped once a frame has waited past the stall deadline, as a
// fault.
func TestDecoderStallKilled(t *testing.T) {
	r := newDecRig(t, nil, func(in io.Reader, _ io.Writer) { io.Copy(io.Discard, in) })
	start := time.Now()
	r.d.Frame(testID, thermalN(1))
	waitFor(t, "a fault", func() bool { return r.rep.count(DecoderFault) == 1 })
	if el := time.Since(start); el < 200*time.Millisecond {
		t.Errorf("stopped after %v, before the 200ms deadline", el)
	}
	<-r.st.procs[0].done
	// A sandbox that stops reading its input is caught the same way.
	r = newDecRig(t, nil, nil)
	r.d.Frame(testID, thermalN(1))
	waitFor(t, "a fault", func() bool { return r.rep.count(DecoderFault) == 1 })
}

// TestDecoderCrashRestartsWithBackoff: a sandbox that exits is a fault
// and is restarted on a later frame only after the backoff, which
// doubles with each fault in a row; frames that arrive meanwhile are
// dropped and counted; the first good frame after raises
// DecoderRecovered, and the backoff starts over.
func TestDecoderCrashRestartsWithBackoff(t *testing.T) {
	crash := func(in io.Reader, _ io.Writer) { io.ReadFull(in, make([]byte, camwire.HeaderLen)) }
	r := newDecRig(t, nil, crash, crash, decodes)
	stop := make(chan struct{})
	fed := make(chan struct{})
	go func() {
		defer close(fed)
		for i := uint32(1); ; i++ {
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
				r.d.Frame(testID, thermalN(i))
			}
		}
	}()
	waitFor(t, "a recovery", func() bool { return r.rep.count(DecoderRecovered) == 1 })
	waitFor(t, "a frame after it", func() bool { return len(r.out.all()) > 0 })
	close(stop)
	<-fed
	if n := r.rep.count(DecoderFault); n != 2 {
		t.Errorf("%d faults, want 2", n)
	}
	r.st.mu.Lock()
	at := slices.Clone(r.st.at)
	r.st.mu.Unlock()
	if len(at) != 3 {
		t.Fatalf("%d starts, want 3", len(at))
	}
	if gap := at[1].Sub(at[0]); gap < 100*time.Millisecond {
		t.Errorf("first restart after %v, before the 100ms backoff", gap)
	}
	if gap := at[2].Sub(at[1]); gap < 200*time.Millisecond {
		t.Errorf("second restart after %v, before the doubled 200ms backoff", gap)
	}
	if dropped, faults := r.d.Dropped(testID); dropped == 0 || faults != 2 {
		t.Errorf("dropped %d, faults %d", dropped, faults)
	}
	if !strings.Contains(r.log.all(), "decoder recovered") || strings.Contains(r.log.all(), string(marker)) {
		t.Errorf("log %q", r.log.all())
	}
}

// TestDecoderIdleStopsWithoutFault: a sandbox fed nothing for the idle
// time is stopped without a fault, and the camera's next frame starts a
// new one at once.
func TestDecoderIdleStopsWithoutFault(t *testing.T) {
	r := newDecRig(t, func(c *DecodeConfig) {
		c.Idle = 50 * time.Millisecond
		c.Backoff = Backoff{Min: time.Hour, Max: time.Hour}
	}, decodes)
	r.d.Frame(testID, thermalN(1))
	waitFor(t, "the first frame", func() bool { return len(r.out.all()) == 1 })
	<-r.st.procs[0].done
	r.d.Frame(testID, thermalN(2))
	waitFor(t, "the second frame", func() bool { return len(r.out.all()) == 2 })
	if r.st.n() != 2 || r.rep.count(DecoderFault) != 0 {
		t.Errorf("starts %d, faults %d", r.st.n(), r.rep.count(DecoderFault))
	}
}

// TestDecoderRemoveStops: frames for a camera never added are refused;
// removing a camera stops its sandbox and no frame of it reaches the
// consumer after.
func TestDecoderRemoveStops(t *testing.T) {
	r := newDecRig(t, nil, decodes)
	if err := r.d.Frame("other", thermalN(1)); !errors.Is(err, ErrNotDecoding) {
		t.Errorf("unknown camera: %v", err)
	}
	r.d.Frame(testID, thermalN(1))
	waitFor(t, "a frame", func() bool { return len(r.out.all()) == 1 })
	r.d.Remove(testID)
	select {
	case <-r.st.procs[0].done:
	default:
		t.Error("sandbox still running after Remove")
	}
	if err := r.d.Frame(testID, thermalN(2)); !errors.Is(err, ErrNotDecoding) {
		t.Errorf("removed camera: %v", err)
	}
}

// TestDecoderAddRefusesShapes: a video side over the bound, a zero side,
// a thermal shape the camera wire could not carry, or a bad ID is
// refused.
func TestDecoderAddRefusesShapes(t *testing.T) {
	r := newDecRig(t, nil, decodes)
	for _, c := range []struct {
		id      string
		v, th   camwire.Shape
		wantErr error
	}{
		{testID, camwire.Shape{Width: 4097, Height: 8}, lepton, ErrShapes},
		{testID, camwire.Shape{Width: 0, Height: 8}, lepton, ErrShapes},
		{testID, picture, camwire.Shape{Width: 1024, Height: 1024}, ErrShapes},
		{testID, picture, camwire.Shape{Width: 4, Height: 0}, ErrShapes},
		{"Bad ID", picture, lepton, ErrNode},
	} {
		if err := r.d.Add(c.id, c.v, c.th); !errors.Is(err, c.wantErr) {
			t.Errorf("Add(%q, %v, %v) = %v", c.id, c.v, c.th, err)
		}
	}
	if _, err := NewDecoder(DecodeConfig{}); !errors.Is(err, ErrDecodeConfig) {
		t.Errorf("empty config: %v", err)
	}
}

// TestDecoderBehindClerk: the clerk hands a pinned node's thermal frames
// to the decoder, its faults go out as the clerk's rate-limited, verified
// events, and no sample reaches the clerk's log or events (DEV-7, DEV-8).
func TestDecoderBehindClerk(t *testing.T) {
	out := &outs{}
	var d *Decoder
	rig := newRig(t, func(c *Config, _ *Node) {
		var err error
		st := &starts{runs: []func(io.Reader, io.Writer){decodes}}
		d, err = NewDecoder(DecodeConfig{Start: st.start, Out: out.add,
			Report: func(id string, k Kind) {}})
		if err != nil {
			t.Fatal(err)
		}
		c.Frames = d
	})
	defer d.Close()
	if err := d.Add(testID, picture, lepton); err != nil {
		t.Fatal(err)
	}
	rig.node.serve = func(_ int, c *tlsConn) { write(c, thermal(), thermal()); hold(c) }
	stop := rig.start(func(ctx context.Context) error { return rig.c.Run(ctx, testID) })
	waitFor(t, "decoded frames", func() bool { return len(out.all()) == 2 })
	stop()
	rig.c.Report(testID, DecoderFault)
	rig.c.Report(testID, Silent)
	if len(rig.ev.of(DecoderFault)) != 1 || len(rig.ev.of(Silent)) != 0 {
		t.Errorf("events %+v", rig.ev.ev)
	}
	if e := rig.ev.of(DecoderFault)[0]; !e.Verified || e.Label != Label || e.Camera != testID {
		t.Errorf("event %+v", e)
	}
	if strings.Contains(rig.log.all(), string(marker)) {
		t.Error("a sample reached the clerk's log")
	}
}
